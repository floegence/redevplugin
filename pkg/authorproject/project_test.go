package authorproject

import (
	"context"
	"os"
	"path/filepath"
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
