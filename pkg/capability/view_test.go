package capability

import (
	"encoding/json"
	"testing"
)

func TestViewBundleFreezesAndValidatesAssets(t *testing.T) {
	js := []byte("export function mount() {}")
	view, err := NewViewBundle("index.js", []string{"style.css"}, map[string]ViewAsset{
		"index.js":  {ContentType: "text/javascript", Content: js},
		"style.css": {ContentType: "text/css", Content: []byte("div{}")},
	})
	if err != nil {
		t.Fatal(err)
	}
	js[0] = 'X'
	asset, ok := view.Read("index.js")
	if !ok || asset.Content[0] != 'e' {
		t.Fatal("caller changed retained bytes")
	}
	asset.Content[0] = 'Y'
	asset, _ = view.Read("index.js")
	if asset.Content[0] != 'e' {
		t.Fatal("reader changed retained bytes")
	}
	asset, _ = view.Read("view.json")
	var manifest ViewManifest
	if err := json.Unmarshal(asset.Content, &manifest); err != nil || manifest.SchemaVersion != ViewSchemaVersion || manifest.Module != "index.js" || len(manifest.Styles) != 1 {
		t.Fatalf("manifest: %+v, %v", manifest, err)
	}
	for _, name := range []string{"", "../index.js", "/index.js", "a/../index.js", "a//index.js", "a/%2e", "a?b", "a#b", "a\\b", ".hidden", "a/.hidden"} {
		if ValidViewPath(name) {
			t.Errorf("accepted path %q", name)
		}
	}
	if _, err := NewViewBundle("index.js", nil, map[string]ViewAsset{"index.js": {ContentType: "text/html"}}); err == nil {
		t.Fatal("HTML accepted as executable module")
	}
	if _, err := NewViewBundle("missing.js", nil, map[string]ViewAsset{"index.js": {ContentType: "text/javascript"}}); err == nil {
		t.Fatal("missing module accepted")
	}
	if _, err := NewViewBundle("index.js", []string{"index.js"}, map[string]ViewAsset{"index.js": {ContentType: "text/javascript"}}); err == nil {
		t.Fatal("JavaScript accepted as stylesheet")
	}
	if _, err := NewViewBundle("index.js", nil, map[string]ViewAsset{"index.js": {ContentType: "text/javascript", Content: make([]byte, MaxViewBundleBytes+1)}}); err == nil {
		t.Fatal("oversized bundle accepted")
	}
}
