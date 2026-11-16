package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// ViewSchemaVersion identifies the framework-neutral module mounting contract.
// A view runs inside the plugin's existing sandbox and receives only its bridge.
const ViewSchemaVersion = "redevplugin.capability_view.v1"

const MaxViewBundleBytes = 32 << 20

var ErrInvalidView = errors.New("capability view is invalid")

type ViewAsset struct {
	ContentType string
	Content     []byte
}

// ViewManifest lists relative paths in one immutable bundle. Module exports a
// mount({container, bridge, input, signal}) function returning {dispose()}.
type ViewManifest struct {
	SchemaVersion string   `json:"schema_version"`
	Module        string   `json:"module"`
	Styles        []string `json:"styles"`
}

// ViewBundle contains host-owned presentation assets, never authority or user
// data. Construction freezes bytes; reads return copies. All execution still
// goes through the capability's ordinary validated bridge methods.
type ViewBundle struct{ assets map[string]ViewAsset }

func ValidViewPath(name string) bool {
	if name == "" || len(name) > 512 || strings.ContainsAny(name, "\\%?#\x00\r\n") || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._@+-", r)) {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || part == "" {
			return false
		}
	}
	return true
}

func NewViewBundle(module string, styles []string, assets map[string]ViewAsset) (*ViewBundle, error) {
	if len(assets) == 0 || len(assets) > 1024 || !ValidViewPath(module) {
		return nil, ErrInvalidView
	}
	view := &ViewBundle{assets: make(map[string]ViewAsset, len(assets)+1)}
	total := 0
	for name, asset := range assets {
		if !ValidViewPath(name) || name == "view.json" || !validViewContentType(asset.ContentType) {
			return nil, fmt.Errorf("%w: asset %q", ErrInvalidView, name)
		}
		total += len(asset.Content)
		if total > MaxViewBundleBytes {
			return nil, fmt.Errorf("%w: bundle exceeds size limit", ErrInvalidView)
		}
		view.assets[name] = ViewAsset{ContentType: asset.ContentType, Content: bytes.Clone(asset.Content)}
	}
	if a, ok := view.assets[module]; !ok || a.ContentType != "text/javascript" {
		return nil, fmt.Errorf("%w: module must be JavaScript", ErrInvalidView)
	}
	seen := make(map[string]bool, len(styles))
	for _, name := range styles {
		if a, ok := view.assets[name]; !ok || a.ContentType != "text/css" || seen[name] {
			return nil, fmt.Errorf("%w: stylesheet %q", ErrInvalidView, name)
		}
		seen[name] = true
	}
	manifest, err := json.Marshal(ViewManifest{SchemaVersion: ViewSchemaVersion, Module: module, Styles: append([]string{}, styles...)})
	if err != nil {
		return nil, err
	}
	view.assets["view.json"] = ViewAsset{ContentType: "application/json", Content: manifest}
	return view, nil
}

func (v *ViewBundle) Read(name string) (ViewAsset, bool) {
	if v == nil || !ValidViewPath(name) {
		return ViewAsset{}, false
	}
	a, ok := v.assets[name]
	a.Content = bytes.Clone(a.Content)
	return a, ok
}

func validViewContentType(value string) bool {
	switch value {
	case "text/javascript", "text/css", "application/json", "image/png", "image/jpeg", "image/webp", "image/svg+xml", "font/woff", "font/woff2":
		return true
	default:
		return false
	}
}
