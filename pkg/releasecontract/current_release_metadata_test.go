package releasecontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReleaseMetadataUsesOneCurrentSchemaWithoutCompatibilityAxes(t *testing.T) {
	if ReleaseMetadataSchemaVersion != "redevplugin.release_metadata" {
		t.Fatalf("ReleaseMetadataSchemaVersion = %q, want fixed current schema kind", ReleaseMetadataSchemaVersion)
	}

	fields := make(map[string]struct{})
	typ := reflect.TypeOf(ReleaseMetadata{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Tag.Get("json")
		if comma := bytes.IndexByte([]byte(name), ','); comma >= 0 {
			name = name[:comma]
		}
		fields[name] = struct{}{}
	}
	for _, retired := range []string{"compatibility", "host_requirements", "ui_protocol_version", "min_redevplugin_version", "min_runtime_version", "supported_targets"} {
		if _, ok := fields[retired]; ok {
			t.Fatalf("release metadata retains compatibility field %q", retired)
		}
	}

	metadata := ReleaseMetadata{SchemaVersion: ReleaseMetadataSchemaVersion}
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"compatibility", "ui_protocol", "min_runtime", "min_redevplugin", "host_requirements"} {
		if bytes.Contains(raw, []byte(retired)) {
			t.Fatalf("release metadata JSON retains %q: %s", retired, raw)
		}
	}
}

func TestReleaseMetadataSchemaHasOneCanonicalFilename(t *testing.T) {
	root := filepath.Join("..", "..", "spec", "plugin")
	if _, err := os.Stat(filepath.Join(root, "release-metadata.schema.json")); err != nil {
		t.Fatalf("canonical release metadata schema is unavailable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "release-metadata-v8.schema.json")); !os.IsNotExist(err) {
		t.Fatalf("versioned release metadata schema still exists: %v", err)
	}
}
