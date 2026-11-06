package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryIndexScaffoldAndAuthorCheck(t *testing.T) {
	root := t.TempDir()
	manifest := `{"schema_version":"redevplugin.source.v1","publisher":{"display_name":"Example"},"plugin":{"slug":"plugin","display_name":"Plugin","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[]}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scaffoldRepositoryIndex([]string{root, "redeven", "--tag-template", "plugin-v{version}", "--package-asset-template", "plugin-{version}.redevplugin"}); err != nil {
		t.Fatal(err)
	}
	if err := runRepositoryIndex([]string{"validate", root}); err != nil {
		t.Fatal(err)
	}
	if err := runRepositoryIndex([]string{"inspect", root, "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := checkEnclosingRepositoryIndex(root, "plugin"); err != nil {
		t.Fatal(err)
	}
	if err := checkEnclosingRepositoryIndex(root, "other"); err == nil {
		t.Fatal("accepted unlisted project")
	}
	if err := scaffoldRepositoryIndex([]string{root, "redeven", "--tag-template", "plugin-v{version}", "--package-asset-template", "plugin-{version}.redevplugin"}); err != nil {
		t.Fatalf("idempotent upsert failed: %v", err)
	}
}

func TestAuthorCheckDoesNotRequireIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkEnclosingRepositoryIndex(root, "example"); err != nil {
		t.Fatal(err)
	}
}
