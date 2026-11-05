package repositoryindex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validIndex() Index {
	return Index{SchemaVersion: SchemaVersion, Targets: []Target{{Ecosystem: "redevplugin", Host: "redeven", Plugins: []Plugin{{PluginID: "github.alice.weather-tools.weather", Path: "plugins/weather", Manifest: "manifest.json", Release: &Release{TagTemplate: "v{version}", PackageAssetTemplate: "weather-{version}.redevplugin", ReleaseRefAssetTemplate: "weather-{version}.release-ref.json"}}}}}}
}

func TestDecodeAndRender(t *testing.T) {
	raw, err := json.Marshal(validIndex())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].Plugins[0].PluginID != "github.alice.weather-tools.weather" {
		t.Fatalf("unexpected plugin: %#v", got)
	}
	if value, err := Render("redeven-weather-v{version}", "1.2.3"); err != nil || value != "redeven-weather-v1.2.3" {
		t.Fatalf("render=%q err=%v", value, err)
	}
}

func TestDecodeRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	cases := []string{
		`{"schema_version":"redevplugin.repository-index.v1","schema_version":"redevplugin.repository-index.v1","targets":[]}`,
		`{"schema_version":"redevplugin.repository-index.v2","targets":[]}`,
		`{"schema_version":"redevplugin.repository-index.v1","targets":[{"ecosystem":"redevplugin","host":"redeven","plugins":[{"plugin_id":"x","path":"../outside","manifest":"manifest.json","release":{"tag_template":"v{version}","package_asset_template":"x-{version}.redevplugin","release_ref_asset_template":"x-{version}.release-ref.json"}}]}]}`,
	}
	for _, raw := range cases {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid input: %s", raw)
		}
	}
}

func TestStrictShapeAndStableVersion(t *testing.T) {
	raw, _ := json.Marshal(validIndex())
	for _, invalid := range []string{
		strings.Replace(string(raw), `"host":"redeven"`, `"Host":"redeven"`, 1),
		strings.Replace(string(raw), `"host":"redeven"`, `"host":null`, 1),
		strings.Replace(string(raw), `"ecosystem":"redevplugin"`, `"ecosystem":"other"`, 1),
		strings.Replace(string(raw), `"manifest":"manifest.json"`, `"manifest":"."`, 1),
	} {
		if _, err := Decode([]byte(invalid)); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
	for _, value := range []string{"1.0", "01.0.0", "1.0.0-rc.1", "1.0.0+build", "1.0.0/other"} {
		if _, err := Render("v{version}", value); err == nil {
			t.Fatalf("accepted version %q", value)
		}
	}
	if got, err := VersionFromTag("plugin-v{version}-stable", "plugin-v1.2.3-stable"); err != nil || got != "1.2.3" {
		t.Fatalf("tag version %q: %v", got, err)
	}
	if _, err := VersionFromTag("plugin-v{version}", "other-plugin-v1.2.3"); err == nil {
		t.Fatal("accepted unanchored tag")
	}
}

func TestPolicyDigestIndependentOfSiblings(t *testing.T) {
	index := validIndex()
	plugin := index.Targets[0].Plugins[0]
	first, err := PolicyDigest("redeven", plugin)
	if err != nil {
		t.Fatal(err)
	}
	index.Targets[0].Plugins = append(index.Targets[0].Plugins, Plugin{PluginID: "other"})
	second, err := PolicyDigest("redeven", index.Targets[0].Plugins[0])
	if err != nil || first != second {
		t.Fatalf("digest changed: %q %q %v", first, second, err)
	}
	plugin.Path = "other"
	third, err := PolicyDigest("redeven", plugin)
	if err != nil || third == first {
		t.Fatalf("changed policy did not change digest: %v", err)
	}
}

func TestRejectCollidingAssets(t *testing.T) {
	index := validIndex()
	other := index.Targets[0].Plugins[0]
	other.PluginID = "github.alice.weather-tools.other"
	index.Targets[0].Plugins = append(index.Targets[0].Plugins, other)
	if err := Validate(index); err == nil {
		t.Fatal("accepted colliding release assets")
	}
	other.Release = &Release{TagTemplate: "v{version}", PackageAssetTemplate: "other-{version}.redevplugin", ReleaseRefAssetTemplate: "other-{version}.release-ref.json"}
	index.Targets[0].Plugins[1] = other
	if err := Validate(index); err != nil {
		t.Fatal(err)
	}
}

func TestSharedTemplateFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/repository-index-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Templates       []struct{ Template, Version, Tag string } `json:"templates"`
		InvalidVersions []string                                  `json:"invalid_versions"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixtures.Templates {
		if got, err := Render(item.Template, item.Version); err != nil || got != item.Tag {
			t.Fatalf("render %q: %q %v", item.Template, got, err)
		}
		if got, err := VersionFromTag(item.Template, item.Tag); err != nil || got != item.Version {
			t.Fatalf("match %q: %q %v", item.Tag, got, err)
		}
	}
	for _, value := range fixtures.InvalidVersions {
		if _, err := Render("v{version}", value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestRepositoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".redevplugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(validIndex())
	outside := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, IndexPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted symlink index")
	}
}

func TestValidateRepositoryChecksManifestIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "plugins", "weather"), 0o755); err != nil {
		t.Fatal(err)
	}
	index := validIndex()
	index.Targets[0].Plugins[0].Path = "plugins/weather"
	index.Targets[0].Plugins[0].Manifest = "manifest.json"
	raw, _ := json.Marshal(index)
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, IndexPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, IndexPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example"},"plugin":{"plugin_id":"github.alice.weather-tools.weather","display_name":"Weather","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[]}`
	if err := os.WriteFile(filepath.Join(root, "plugins/weather/manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRepository(root); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(manifest, "github.alice.weather-tools.weather", "github.alice.weather-tools.other", 1)
	if err := os.WriteFile(filepath.Join(root, "plugins/weather/manifest.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRepository(root); err == nil {
		t.Fatal("accepted mismatched manifest identity")
	}
}
