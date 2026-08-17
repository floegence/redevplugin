package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentOnlyContractTreeRejectsRetiredVersionAxes(t *testing.T) {
	root := repoRoot(t)
	retired := []string{
		"spec/plugin/manifest-v8.schema.json",
		"spec/plugin/ipc-v6.schema.json",
		"spec/plugin/ipc-v7.schema.json",
		"spec/plugin/compatibility-manifest-v19.schema.json",
		"spec/plugin/compatibility-manifest-v20.schema.json",
		"spec/plugin/runtime-descriptor-v2.schema.json",
		"spec/plugin/runtime-descriptor-v3.schema.json",
		"spec/plugin/public-api-v1.json",
		"spec/plugin/error-codes-v6.schema.json",
		"spec/plugin/error-codes-v8.schema.json",
		"spec/plugin/bridge-v7.schema.json",
		"spec/plugin/wasm-worker-v2.schema.json",
		"spec/plugin/worker-invocation-v3.schema.json",
		"spec/plugin/performance-contract-v3.json",
		"spec/plugin/performance-contract-v4.json",
		"spec/openapi/plugin-platform-v16.yaml",
		"spec/openapi/plugin-platform-v17.yaml",
	}
	for _, relative := range retired {
		if _, err := os.Stat(filepath.Join(root, relative)); err == nil {
			t.Errorf("retired contract still exists: %s", relative)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", relative, err)
		}
	}
}

func TestCurrentPluginAPIAndInternalWireHaveOneIdentity(t *testing.T) {
	root := repoRoot(t)
	pluginAPI := readJSONObject(t, filepath.Join(root, "spec", "plugin", "plugin-api.json"))
	if got := pluginAPI["plugin_api"]; got != float64(1) {
		t.Fatalf("plugin_api = %#v, want 1", got)
	}
	wire := readJSONObject(t, filepath.Join(root, "spec", "internal", "runtime-wire.schema.json"))
	if got := wire["internal_wire"]; got != float64(1) {
		t.Fatalf("internal_wire = %#v, want 1", got)
	}
}

func TestCurrentManifestSchemaUsesPluginAPIIdentity(t *testing.T) {
	root := repoRoot(t)
	document := readJSONObject(t, filepath.Join(root, "spec", "plugin", "manifest-v9.schema.json"))
	if got := document["$id"]; got != "https://schemas.redevplugin.dev/plugin-api/1/manifest-v9.schema.json" {
		t.Fatalf("manifest schema $id = %#v", got)
	}
	if got := document["additionalProperties"]; got != false {
		t.Fatalf("manifest schema additionalProperties = %#v, want false", got)
	}
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		t.Fatalf("manifest properties = %#v", document["properties"])
	}
	api, ok := properties["api"].(map[string]any)
	if !ok {
		t.Fatalf("manifest api schema = %#v", properties["api"])
	}
	apiProperties, ok := api["properties"].(map[string]any)
	if !ok || apiProperties["major"] == nil || apiProperties["surface"] != nil || apiProperties["worker"] != nil {
		t.Fatalf("manifest api properties = %#v", apiProperties)
	}
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return document
}
