package authorproject

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsAmbiguousProjectConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"redevplugin.project.v1","output":"../outside","build":["node","build.mjs"],"test":["node","--test"],"watch":["src"]}`,
		`{"schema_version":"redevplugin.project.v1","output":"dist","build":[],"test":[],"watch":["src"]}`,
		`{"schema_version":"redevplugin.project.v1","output":"dist","build":["node"],"test":["node"],"watch":["src"],"unknown":true}`,
		`{"schema_version":"redevplugin.project.v1","output":"dist","output":"other","build":["node"],"test":["node"],"watch":["src"]}`,
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, ConfigFile), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(root); err == nil {
			t.Fatalf("accepted invalid project: %s", raw)
		}
	}
}

func TestSnapshotTracksContentAndRejectsSymlinkInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"schema_version":"redevplugin.project.v1","output":"dist","build":["node","build.mjs"],"test":["node","--test"],"watch":["src"]}`
	if err := os.WriteFile(filepath.Join(root, ConfigFile), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "app.ts"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("source change did not change snapshot")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "src", "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatal("accepted symlink input")
	}
}

func TestSnapshotRequiresRestartForChangedConfiguration(t *testing.T) {
	root := t.TempDir()
	raw := "{\"schema_version\":\"redevplugin.project.v1\",\"output\":\"dist\",\"build\":[\"node\"],\"test\":[\"node\"],\"watch\":[\"src\"]}"
	path := filepath.Join(root, ConfigFile)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw+" "), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatal("changed configuration silently reused old commands")
	}
}

func TestLoadRejectsConfigurationSymlinkAndCaseAliases(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.json")
	raw := "{\"Schema_Version\":\"redevplugin.project.v1\",\"output\":\"dist\",\"build\":[\"node\"],\"test\":[\"node\"],\"watch\":[\"src\"]}"
	if err := os.WriteFile(source, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, filepath.Join(root, ConfigFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted symlink configuration")
	}
	if err := os.Remove(filepath.Join(root, ConfigFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, filepath.Join(root, ConfigFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted case alias outside canonical schema")
	}
}

func TestPublicationBuildUsesCompiledIdentityBeforeCommands(t *testing.T) {
	root := t.TempDir()
	source, err := os.ReadFile("../../examples/plugins/weather/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	source, err = manifest.AuthorSource(source, "weather")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "manifest.json"), source, 0600); err != nil {
		t.Fatal(err)
	}
	config := `{"schema_version":"redevplugin.project.v1","output":"dist","build":["node","build.mjs"],"test":["node","build.mjs"],"watch":["build.mjs"],"bindings":"generated"}`
	if err = os.WriteFile(filepath.Join(root, ConfigFile), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	// No plugin code is needed to prove ordering: the declared build observes the
	// generated identity, then copies real package assets and that exact manifest.
	fixture, err := filepath.Abs("../../examples/plugins/weather")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(fixture)
	script := `const fs=require('node:fs');const assert=require('node:assert/strict');const manifest=JSON.parse(fs.readFileSync('generated/manifest.json'));assert.equal(manifest.plugin.plugin_id,process.env.TEST_EXPECTED_PLUGIN);fs.cpSync(` + string(encoded) + `, 'dist',{recursive:true});fs.copyFileSync('generated/manifest.json','dist/manifest.json');`
	script = "import {createRequire} from 'node:module';\n" + strings.ReplaceAll(script, "require(", "createRequire(import.meta.url)(")
	if err = os.WriteFile(filepath.Join(root, "build.mjs"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pluginidentity.GitHub(42, "weather")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_EXPECTED_PLUGIN", identity.PluginID)
	result, err := project.Build(context.Background(), PipelineOptions{Generate: true, Identity: identity})
	if err != nil {
		t.Fatal(err, result.Commands)
	}
	if result.Package.Manifest.PluginID() != identity.PluginID {
		t.Fatal("wrong package identity")
	}
	after, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil || !bytes.Equal(source, after) {
		t.Fatal("source changed", err)
	}
	t.Setenv("TEST_EXPECTED_PLUGIN", "weather")
	local, err := project.Build(context.Background(), PipelineOptions{Generate: true})
	if err != nil {
		t.Fatal(err, local.Commands)
	}
	if local.Package.Manifest.PluginID() != "weather" {
		t.Fatal("release identity leaked to local build")
	}
}
