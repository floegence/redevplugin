package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCompatibilityManifestSchemaDefinesReleasedMatrix(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "compatibility-manifest-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	properties := requireNestedObject(t, schema, "properties")
	schemaVersion := requireNestedObject(t, properties, "schema_version")
	if got := schemaVersion["const"]; got != "redevplugin.compatibility.v1" {
		t.Fatalf("schema_version const = %#v", got)
	}

	matrix := requireNestedObject(t, properties, "matrix")
	matrixProps := requireNestedObject(t, matrix, "properties")
	for name, want := range map[string]string{
		"plugin_host_protocol_version":     "plugin-host-v1",
		"rust_ipc_version":                 "rust-ipc-v1",
		"wasm_abi_version":                 "redevplugin-wasm-worker-v1",
		"manifest_schema_version":          "manifest-v1",
		"package_signature_schema_version": "package-signature-v1",
		"token_ticket_schema_version":      "token-ticket-v1",
		"bridge_schema_version":            "bridge-v1",
		"target_classifier_version":        "target-classifier-v1",
		"network_grant_schema_version":     "network-grant-v1",
		"plugin_platform_openapi_version":  "plugin-platform-v1",
		"compatibility_schema_version":     "compatibility-manifest-v1",
		"worker_invocation_schema_version": "worker-invocation-v1",
		"error_codes_schema_version":       "error-codes-v1",
	} {
		property := requireNestedObject(t, matrixProps, name)
		if got := property["const"]; got != want {
			t.Fatalf("%s const = %#v, want %q", name, got, want)
		}
	}

	required := map[string]bool{}
	for _, item := range requireStringSlice(t, matrix["required"], "matrix required") {
		required[item] = true
	}
	for _, name := range []string{
		"plugin_host_protocol_version",
		"rust_ipc_version",
		"wasm_abi_version",
		"manifest_schema_version",
		"package_signature_schema_version",
		"token_ticket_schema_version",
		"bridge_schema_version",
		"target_classifier_version",
		"network_grant_schema_version",
		"plugin_platform_openapi_version",
		"compatibility_schema_version",
		"worker_invocation_schema_version",
		"error_codes_schema_version",
	} {
		if !required[name] {
			t.Fatalf("matrix required fields missing %s", name)
		}
	}

	defs := requireNestedObject(t, schema, "$defs")
	contract := requireNestedObject(t, defs, "contract")
	contractProps := requireNestedObject(t, contract, "properties")
	if sha := requireNestedObject(t, contractProps, "sha256"); sha["pattern"] != "^[0-9a-f]{64}$" {
		t.Fatalf("sha256 pattern = %#v", sha["pattern"])
	}
}
