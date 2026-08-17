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
