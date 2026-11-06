package repositoryindex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeIndexProject(t *testing.T, root, project, id string) {
	t.Helper()
	dir := filepath.Join(root, project)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	raw := `{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example"},"plugin":{"plugin_id":"PLUGIN","display_name":"Example","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(strings.Replace(raw, "PLUGIN", id, 1)), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestUpsertPreservesEntriesAndRequiresExplicitReplacement(t *testing.T) {
	root := t.TempDir()
	writeIndexProject(t, root, "alpha", "example.alpha")
	writeIndexProject(t, root, "beta", "example.beta")
	a := Release{TagTemplate: "alpha-v{version}", PackageAssetTemplate: "plugin.redevplugin"}
	b := Release{TagTemplate: "beta-v{version}", PackageAssetTemplate: "plugin.redevplugin"}
	if changed, err := Upsert(root, "redeven", "alpha", "manifest.json", a, false); err != nil || !changed {
		t.Fatalf("initial: %v %v", changed, err)
	}
	before, _ := os.ReadFile(filepath.Join(root, IndexPath))
	if changed, err := Upsert(root, "redeven", "alpha", "manifest.json", a, false); err != nil || changed {
		t.Fatalf("idempotent: %v %v", changed, err)
	}
	after, _ := os.ReadFile(filepath.Join(root, IndexPath))
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent update rewrote index")
	}
	if _, err := Upsert(root, "redeven", "beta", "manifest.json", b, false); err != nil {
		t.Fatal(err)
	}
	a.PackageAssetTemplate = "alpha-{version}.redevplugin"
	if _, err := Upsert(root, "redeven", "alpha", "manifest.json", a, false); err == nil {
		t.Fatal("changed declaration did not require replacement")
	}
	if _, err := Upsert(root, "redeven", "alpha", "manifest.json", a, true); err != nil {
		t.Fatal(err)
	}
	repo, err := ValidateRepository(root)
	if err != nil || len(repo.Entries) != 2 {
		t.Fatalf("entries lost: %+v %v", repo, err)
	}
}
func TestUpsertRejectsSymlinkDirectoryWithoutWritingOutside(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeIndexProject(t, root, ".", "example.alpha")
	if err := os.Symlink(outside, filepath.Join(root, ".redevplugin")); err != nil {
		t.Fatal(err)
	}
	if _, err := Upsert(root, "redeven", ".", "manifest.json", Release{TagTemplate: "alpha-v{version}", PackageAssetTemplate: "plugin.redevplugin"}, false); err == nil {
		t.Fatal("accepted index directory symlink")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside repository")
	}
}

func TestUpsertReplacesMovedProject(t *testing.T) {
	root := t.TempDir()
	writeIndexProject(t, root, "old", "example.alpha")
	release := Release{TagTemplate: "alpha-v{version}", PackageAssetTemplate: "plugin.redevplugin"}
	if _, err := Upsert(root, "redeven", "old", "manifest.json", release, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "old"), filepath.Join(root, "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := Upsert(root, "redeven", "new", "manifest.json", release, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRepository(root); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertReplacesGeneratedIdentityWithoutDuplicateEntry(t *testing.T) {
	root := t.TempDir()
	writeIndexProject(t, root, "alpha", "example.alpha")
	release := Release{TagTemplate: "alpha-v{version}", PackageAssetTemplate: "plugin.redevplugin"}
	if _, err := Upsert(root, "redeven", "alpha", "manifest.json", release, false); err != nil {
		t.Fatal(err)
	}
	writeIndexProject(t, root, "alpha", "example.renamed")
	if _, err := Upsert(root, "redeven", "alpha", "manifest.json", release, false); err == nil {
		t.Fatal("identity replacement did not require --replace")
	}
	if changed, err := Upsert(root, "redeven", "alpha", "manifest.json", release, true); err != nil || !changed {
		t.Fatalf("replace: %v %v", changed, err)
	}
	repo, err := ValidateRepository(root)
	if err != nil || len(repo.Entries) != 1 || repo.Entries[0].Plugin.PluginID != "example.renamed" {
		t.Fatalf("replacement: %+v %v", repo, err)
	}
}

func TestUpsertConcurrentWritersPreserveBothEntries(t *testing.T) {
	root := t.TempDir()
	writeIndexProject(t, root, "alpha", "example.alpha")
	writeIndexProject(t, root, "beta", "example.beta")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"alpha", "beta"} {
		go func(name string) {
			<-start
			_, err := Upsert(root, "redeven", name, "manifest.json", Release{TagTemplate: name + "-v{version}", PackageAssetTemplate: "plugin.redevplugin"}, false)
			results <- err
		}(name)
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	repo, err := ValidateRepository(root)
	if err != nil || len(repo.Entries) != 2 {
		t.Fatalf("lost concurrent update: %+v %v", repo, err)
	}
}
