package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryIndexScaffoldAndAuthorCheck(t *testing.T) {
	root := t.TempDir()
	manifest := `{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example"},"plugin":{"plugin_id":"github.alice.repo.plugin","display_name":"Plugin","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[]}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scaffoldRepositoryIndex([]string{root, "redeven"}); err != nil {
		t.Fatal(err)
	}
	if err := runRepositoryIndex([]string{"validate", root}); err != nil {
		t.Fatal(err)
	}
	if err := runRepositoryIndex([]string{"inspect", root, "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := checkEnclosingRepositoryIndex(root, "github.alice.repo.plugin"); err != nil {
		t.Fatal(err)
	}
	if err := checkEnclosingRepositoryIndex(root, "github.alice.repo.other"); err == nil {
		t.Fatal("accepted unlisted project")
	}
	if err := scaffoldRepositoryIndex([]string{root, "redeven"}); err == nil {
		t.Fatal("overwrote index")
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
