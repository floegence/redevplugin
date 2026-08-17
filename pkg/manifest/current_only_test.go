package manifest

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDecodeRejectsLegacyManifestV8(t *testing.T) {
	legacy := strings.Replace(validManifestJSON(), SchemaVersionV9, "redevplugin.manifest.v8", 1)
	_, err := Decode(strings.NewReader(legacy))
	if err == nil {
		t.Fatal("Decode() accepted retired manifest v8")
	}
	var validationError ValidationError
	if !errors.As(err, &validationError) || validationError.Field != "schema_version" {
		t.Fatalf("Decode() error = %v, want schema_version validation error", err)
	}
}

func TestDecodeAcceptsOnlyPluginAPIMajorOne(t *testing.T) {
	current := currentOnlyManifestJSON("")
	decoded, err := Decode(bytes.NewReader(current))
	if err != nil {
		t.Fatalf("Decode(current plugin_api=1) error = %v", err)
	}
	if decoded.SchemaVersion != SchemaVersionV9 || decoded.API.Major != PluginAPIMajor {
		t.Fatalf("Decode() identity = schema %q plugin API %d", decoded.SchemaVersion, decoded.API.Major)
	}

	legacyAPI := bytes.Replace(current, []byte(`"major":1`), []byte(`"surface":1,"worker":1`), 1)
	if _, err := Decode(bytes.NewReader(legacyAPI)); err == nil {
		t.Fatal("Decode() accepted retired api.surface/api.worker fields")
	}
}

func TestDecodeCurrentManifestIsClosed(t *testing.T) {
	raw := currentOnlyManifestJSON(`,"future":{"opaque":true}`)
	if _, err := Decode(bytes.NewReader(raw)); err == nil {
		t.Fatal("Decode() accepted an unknown top-level field")
	}
}

func TestDescriptorHashInputOmitsRetiredAuthorVersionAxes(t *testing.T) {
	current, err := Decode(bytes.NewReader(currentOnlyManifestJSON("")))
	if err != nil {
		t.Fatal(err)
	}
	current.Workers = []WorkerSpec{{
		WorkerID: "worker", Artifact: "workers/main.wasm", Mode: WorkerModeJob,
		Scope: "environment", MemoryLimitBytes: 16 << 20,
	}}
	raw, err := DescriptorHashInput(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range [][]byte{
		[]byte(`"api_version"`),
		[]byte(`"min_runtime_version"`),
		[]byte(`"ui_protocol_version"`),
		[]byte(`"abi"`),
	} {
		if bytes.Contains(raw, retired) {
			t.Fatalf("DescriptorHashInput() retained old axis %s: %s", retired, raw)
		}
	}
}

func currentOnlyManifestJSON(extra string) []byte {
	return []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.current","display_name":"Current","version":"1.0.0"},"api":{"major":1,"required_features":[],"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]}}` + extra)
}
