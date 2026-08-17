package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestManifestSchemaMatchesCurrentGoContract(t *testing.T) {
	schema := readManifestSchema(t)
	if schema["additionalProperties"] != false {
		t.Fatalf("manifest additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, schema["required"], "manifest required"), []string{
		"schema_version", "publisher", "plugin", "api", "permissions", "presentation", "surfaces", "workers", "methods",
	}, "manifest required")

	properties := requireNestedObject(t, schema, "properties")
	if got := requireNestedObject(t, properties, "schema_version")["const"]; got != manifest.SchemaVersionV9 {
		t.Fatalf("schema_version = %#v, want %q", got, manifest.SchemaVersionV9)
	}
	plugin := requireNestedObject(t, properties, "plugin")
	assertStringSet(t, requireStringSlice(t, plugin["required"], "plugin required"), []string{"plugin_id", "display_name", "version"}, "plugin required")
	pluginProperties := requireNestedObject(t, plugin, "properties")
	for _, retired := range []string{"api_version", "min_runtime_version", "ui_protocol_version"} {
		if _, exists := pluginProperties[retired]; exists {
			t.Fatalf("plugin schema retained %q", retired)
		}
	}
	if got := requireNestedObject(t, properties, "api", "properties", "major")["const"]; got != float64(manifest.PluginAPIMajor) {
		t.Fatalf("api.major = %#v, want %d", got, manifest.PluginAPIMajor)
	}
	workerProperties := requireNestedObject(t, properties, "workers", "items", "properties")
	for _, retired := range []string{"abi", "abi_version", "idle_timeout_ms"} {
		if _, exists := workerProperties[retired]; exists {
			t.Fatalf("worker schema retained %q", retired)
		}
	}
	if got := requireNestedObject(t, workerProperties, "mode")["const"]; got != string(manifest.WorkerModeJob) {
		t.Fatalf("worker mode = %#v, want %q", got, manifest.WorkerModeJob)
	}
	methodProperties := requireNestedObject(t, properties, "methods", "items", "properties")
	if requireNestedObject(t, methodProperties, "route")["additionalProperties"] != false {
		t.Fatal("method route must be closed")
	}
}

func TestManifestSchemaAndGoDecoderAcceptOnlyCurrentContract(t *testing.T) {
	compiled := compileManifestSchema(t)
	fixturePath := filepath.Join(repoRoot(t), "testdata", "generated_plugins", "method-contract", "manifest.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var current map[string]any
	if err := json.Unmarshal(raw, &current); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{name: "current", valid: true},
		{name: "legacy schema", mutate: func(value map[string]any) { value["schema_version"] = "redevplugin.manifest.v8" }},
		{name: "unknown root field", mutate: func(value map[string]any) { value["future"] = true }},
		{name: "unknown plugin field", mutate: func(value map[string]any) { value["plugin"].(map[string]any)["api_version"] = "plugin-v1" }},
		{name: "unknown plugin API", mutate: func(value map[string]any) { value["api"].(map[string]any)["major"] = float64(2) }},
		{name: "missing workers", mutate: func(value map[string]any) { delete(value, "workers") }},
		{name: "worker ABI axis", mutate: func(value map[string]any) {
			value["workers"] = []any{map[string]any{"worker_id": "legacy", "artifact": "workers/legacy.wasm", "abi": "redevplugin-wasm-worker-v2", "mode": "job", "scope": "user", "memory_limit_bytes": float64(1024)}}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value := cloneJSONDocument(t, current)
			if tc.mutate != nil {
				tc.mutate(value)
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			machineErr := compiled.Validate(value)
			_, goErr := manifest.Decode(bytes.NewReader(raw))
			if (machineErr == nil) != tc.valid {
				t.Fatalf("machine valid = %t, want %t: %v", machineErr == nil, tc.valid, machineErr)
			}
			if (goErr == nil) != tc.valid {
				t.Fatalf("Go valid = %t, want %t: %v", goErr == nil, tc.valid, goErr)
			}
		})
	}
}

func readManifestSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", "manifest-v9.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func compileManifestSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "manifest-v9.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "host-capability-pin-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource("https://schemas.redevplugin.dev/plugin-api/1/host-capability-pin-v1.schema.json", bytes.NewReader(pin)); err != nil {
		t.Fatal(err)
	}
	const resource = "urn:redevplugin:manifest-v9"
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func cloneJSONDocument(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
