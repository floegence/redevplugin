package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func v9TestManifest(extra string) []byte {
	return []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"surface":1,"worker":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]}` + extra + `}`)
}

func TestV9UnknownOptionalFieldIsIgnoredButHashInputIsRetained(t *testing.T) {
	withUnknown := v9TestManifest(`,"future":{"nested":true}`)
	withoutUnknown := v9TestManifest("")
	withModel, err := DecodeModel(bytes.NewReader(withUnknown))
	if err != nil {
		t.Fatalf("DecodeModel(with unknown): %v", err)
	}
	withoutModel, err := DecodeModel(bytes.NewReader(withoutUnknown))
	if err != nil {
		t.Fatalf("DecodeModel(without unknown): %v", err)
	}
	if withModel.PluginID() != withoutModel.PluginID() || withModel.API.Surface == nil || *withModel.API.Surface != 1 {
		t.Fatalf("unknown field changed normalized behavior: %#v %#v", withModel, withoutModel)
	}
	first, err := CanonicalJSON(withUnknown)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalJSON(withoutUnknown)
	if err != nil {
		t.Fatal(err)
	}
	firstSum := sha256.Sum256(first)
	secondSum := sha256.Sum256(second)
	if hex.EncodeToString(firstSum[:]) == hex.EncodeToString(secondSum[:]) {
		t.Fatal("unknown optional field was lost from the manifest hash input")
	}
}

func TestV9RejectsDuplicateKeysAndNonCanonicalNumbers(t *testing.T) {
	duplicate := v9TestManifest(`,"plugin":{"plugin_id":"duplicate"}`)
	if _, err := DecodeModel(bytes.NewReader(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("duplicate key error = %v", err)
	}
	nonCanonical := bytes.Replace(v9TestManifest(""), []byte(`"surface":1`), []byte(`"surface":1e0`), 1)
	if _, err := DecodeModel(bytes.NewReader(nonCanonical)); err == nil || !strings.Contains(err.Error(), "non-canonical JSON number") {
		t.Fatalf("non-canonical number error = %v", err)
	}
}
