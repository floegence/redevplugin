package manifest

import (
	"bytes"
	"strings"
	"testing"
)

func v9TestManifest(extra string) []byte {
	return []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]}` + extra + `}`)
}

func TestV9UnknownFieldIsRejected(t *testing.T) {
	withUnknown := v9TestManifest(`,"future":{"nested":true}`)
	if _, err := Decode(bytes.NewReader(withUnknown)); err == nil {
		t.Fatal("Decode() accepted unknown field")
	}
}

func TestV9RejectsDuplicateKeysAndNonCanonicalNumbers(t *testing.T) {
	duplicate := v9TestManifest(`,"plugin":{"plugin_id":"duplicate"}`)
	if _, err := Decode(bytes.NewReader(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("duplicate key error = %v", err)
	}
	nonCanonical := bytes.Replace(v9TestManifest(""), []byte(`"major":1`), []byte(`"major":1e0`), 1)
	if _, err := Decode(bytes.NewReader(nonCanonical)); err == nil || !strings.Contains(err.Error(), "non-canonical JSON number") {
		t.Fatalf("non-canonical number error = %v", err)
	}
}

func TestDecodeCanonicalPreservesSignedWireRepresentation(t *testing.T) {
	raw := bytes.Replace(v9TestManifest(""), []byte(`"permissions":[]`), []byte(`"permissions":["fs.workspace.write","fs.workspace.read"]`), 1)
	decoded, canonical, err := DecodeCanonical(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Permissions[0] != PermissionFSWorkspaceRead {
		t.Fatal("decoded permissions must retain their normalized order")
	}
	if !bytes.Contains(canonical, []byte(`"permissions":["fs.workspace.write","fs.workspace.read"]`)) {
		t.Fatal("canonical bytes must retain signed array order")
	}
	if bytes.Contains(canonical, []byte(`"capability_bindings"`)) {
		t.Fatal("canonical bytes must not add omitted fields from normalized values")
	}
	_, repeated, err := DecodeCanonical(bytes.NewReader(canonical))
	if err != nil || !bytes.Equal(repeated, canonical) {
		t.Fatalf("canonical decode is not stable: %v", err)
	}
}

func TestDecodeCanonicalNeverReturnsBytesForInvalidManifest(t *testing.T) {
	for name, raw := range map[string][]byte{
		"unknown field":    v9TestManifest(`,"unknown":true`),
		"duplicate key":    v9TestManifest(`,"plugin":{"plugin_id":"duplicate"}`),
		"invalid number":   bytes.Replace(v9TestManifest(""), []byte(`"major":1`), []byte(`"major":1e0`), 1),
		"invalid contract": bytes.Replace(v9TestManifest(""), []byte(`"major":1`), []byte(`"major":2`), 1),
		"trailing value":   append(v9TestManifest(""), []byte(`{}`)...),
		"oversized":        bytes.Repeat([]byte(" "), (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, canonical, err := DecodeCanonical(bytes.NewReader(raw))
			if err == nil || canonical != nil {
				t.Fatalf("invalid manifest returned canonical bytes: %q, error: %v", canonical, err)
			}
		})
	}
}
