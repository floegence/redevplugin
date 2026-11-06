package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestRepositoryIdentityGenerationAndIdempotence(t *testing.T) {
	root := t.TempDir()
	if _, err := createPluginTemplate("mind-map", "Mind Map", root, "web"); err != nil {
		t.Fatal(err)
	}
	id, err := writeRepositoryIdentity(root, 42, "mind-map")
	if err != nil {
		t.Fatal(err)
	}
	if id.PublisherID != "github.repo.42" || id.PluginID != "github.repo.42.mind-map" {
		t.Fatal(id)
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil || m.Publisher.PublisherID != id.PublisherID {
		t.Fatal(m, err)
	}
	if _, err := writeRepositoryIdentity(root, 42, "mind-map"); err != nil {
		t.Fatal(err)
	}
	next, _ := os.ReadFile(filepath.Join(root, "manifest.json"))
	if !bytes.Equal(raw, next) {
		t.Fatal("non-idempotent generation")
	}
	if _, err := writeRepositoryIdentity(root, 0, "mind-map"); err == nil {
		t.Fatal("invalid source accepted")
	}
}

func TestRepositoryIdentityRejectsSymlinkAndPreservesOtherFields(t *testing.T) {
	root := t.TempDir()
	if _, err := createPluginTemplate("example", "Original Name", root, "web"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "manifest.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRepositoryIdentity(root, 42, "example"); err == nil {
		t.Fatal("accepted symlink manifest")
	}
	after, _ := os.ReadFile(outside)
	if !bytes.Equal(original, after) {
		t.Fatal("modified symlink target")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRepositoryIdentity(root, 42, "example"); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	var beforeDoc, afterDoc map[string]any
	if err := json.Unmarshal(original, &beforeDoc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &afterDoc); err != nil {
		t.Fatal(err)
	}
	beforeDoc["publisher"].(map[string]any)["publisher_id"] = "github.repo.42"
	beforeDoc["plugin"].(map[string]any)["plugin_id"] = "github.repo.42.example"
	if !reflect.DeepEqual(beforeDoc, afterDoc) {
		t.Fatal("identity generation modified unrelated fields")
	}
}
