package manifest

import (
	"bytes"
	"strings"
	"testing"
)

func TestStoredPreWebManifestRetainsExactIdentityWithoutAdmission(t *testing.T) {
	raw := bytes.Replace(v9TestManifest(""), []byte(`"surfaces":[]`), []byte(`"surfaces":[{"surface_id":"main","kind":"view","label":"Main","entry":"ui/index.html"}]`), 1)
	want, err := CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	value, canonical, err := DecodeStoredCanonical(bytes.NewReader(raw))
	if err != nil || !bytes.Equal(canonical, want) {
		t.Fatalf("stored identity: %s %v", canonical, err)
	}
	if value.Surfaces[0].Web.Root != "" {
		t.Fatal("invented Web authority")
	}
	if Validate(value) == nil {
		t.Fatal("retired surface admitted by current validator")
	}
	if _, _, err := DecodeCanonical(bytes.NewReader(canonical)); err == nil {
		t.Fatal("retired package admitted")
	}
	if _, err := MarshalCanonical(value); err == nil {
		t.Fatal("retired package rewritten as current")
	}
	if _, repeated, err := DecodeStoredCanonical(bytes.NewReader(canonical)); err != nil || !bytes.Equal(repeated, canonical) {
		t.Fatal("stored identity not stable")
	}
	for name, invalid := range map[string][]byte{
		"partial web":    bytes.Replace(raw, []byte(`"entry":"ui/index.html"`), []byte(`"entry":"ui/index.html","web":{"root":"ui"}`), 1),
		"null web":       bytes.Replace(raw, []byte(`"entry":"ui/index.html"`), []byte(`"entry":"ui/index.html","web":null`), 1),
		"unknown field":  bytes.Replace(raw, []byte(`"entry":"ui/index.html"`), []byte(`"entry":"ui/index.html","unknown":true`), 1),
		"duplicate":      bytes.Replace(raw, []byte(`"label":"Main"`), []byte(`"label":"Main","label":"Other"`), 1),
		"invalid method": bytes.Replace(raw, []byte(`"methods":[]`), []byte(`"methods":[{"method":"run","route":{"kind":"unknown"}}]`), 1),
		"future schema":  bytes.Replace(raw, []byte(`redevplugin.manifest.v9`), []byte(`redevplugin.manifest.v10`), 1),
		"mixed surfaces": bytes.Replace(raw, []byte(`"entry":"ui/index.html"}`), []byte(`"entry":"ui/index.html"},{"surface_id":"new","kind":"view","label":"New","entry":"ui/index.html","web":{"root":"ui","spa":false}}`), 1),
		"empty label":    bytes.Replace(raw, []byte(`"label":"Main"`), []byte(`"label":""`), 1),
		"trailing":       append(append([]byte{}, raw...), []byte(`{}`)...),
		"oversized":      []byte(strings.Repeat(" ", 1<<20+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, canonical, err := DecodeStoredCanonical(bytes.NewReader(invalid)); err == nil || canonical != nil {
				t.Fatalf("invalid stored manifest accepted: %v", err)
			}
		})
	}
}
