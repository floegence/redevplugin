package host

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func buildHostReleasePackageFromManifest(t *testing.T, manifestJSON string) []byte {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "ui", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		"manifest.json":    []byte(manifestJSON),
		"ui/index.html":    []byte(`<!doctype html><title>Fixture</title><script type="module" src="assets/app.js"></script>`),
		"ui/assets/app.js": []byte("void 0;"),
	} {
		if err := os.WriteFile(filepath.Join(directory, path), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), directory, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func hostReleaseManifestJSON() string {
	document := map[string]any{
		"schema_version": "redevplugin.manifest.v9",
		"publisher":      map[string]any{"publisher_id": "fixture.publisher", "display_name": "Fixture"},
		"plugin": map[string]any{
			"plugin_id": "fixture.plugin", "display_name": "Fixture", "version": "1.0.0",
		},
		"api":         map[string]any{"major": 1, "required_features": []any{}, "optional_features": []any{}},
		"permissions": []any{},
		"presentation": map[string]any{
			"locales": map[string]any{"default": "en-US"},
		},
		"surfaces": []any{map[string]any{"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html", "web": map[string]any{"root": "ui", "spa": false}}},
		"workers":  []any{},
		"methods":  []any{},
		"storage":  map[string]any{"stores": []any{}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
