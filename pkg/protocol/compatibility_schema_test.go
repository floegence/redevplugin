package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCompatibilityManifestSchemaDefinesReleasedMatrix(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "compatibility-manifest-v8.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	properties := requireNestedObject(t, schema, "properties")
	schemaVersion := requireNestedObject(t, properties, "schema_version")
	if got := schemaVersion["const"]; got != "redevplugin.compatibility.v8" {
		t.Fatalf("schema_version const = %#v", got)
	}

	matrix := requireNestedObject(t, properties, "matrix")
	matrixProps := requireNestedObject(t, matrix, "properties")
	expectedMatrix := map[string]string{
		"plugin_ui_protocol_version":                   "plugin-ui-v5",
		"plugin_host_protocol_version":                 "plugin-host-v6",
		"rust_ipc_version":                             "rust-ipc-v6",
		"wasm_abi_version":                             "redevplugin-wasm-worker-v2",
		"manifest_schema_version":                      "manifest-v5",
		"package_signature_schema_version":             "package-signature-v1",
		"release_metadata_schema_version":              "release-metadata-v5",
		"release_root_delegation_schema_version":       "release-root-delegation-v1",
		"release_source_policy_schema_version":         "release-source-policy-v2",
		"release_source_policy_pointer_schema_version": "release-source-policy-pointer-v1",
		"release_revocation_schema_version":            "release-revocation-v2",
		"release_revocation_pointer_schema_version":    "release-revocation-pointer-v1",
		"release_trust_state_schema_version":           "release-trust-state-v1",
		"token_ticket_schema_version":                  "token-ticket-v4",
		"bridge_schema_version":                        "bridge-v5",
		"opaque_surface_document_schema_version":       "opaque-surface-document-v3",
		"opaque_surface_transport_schema_version":      "opaque-surface-transport-v4",
		"target_classifier_version":                    "target-classifier-v2",
		"network_grant_schema_version":                 "network-grant-v2",
		"resource_scope_schema_version":                "resource-scope-v1",
		"plugin_platform_openapi_version":              "plugin-platform-v8",
		"compatibility_schema_version":                 "compatibility-manifest-v8",
		"worker_invocation_schema_version":             "worker-invocation-v3",
		"error_codes_schema_version":                   "error-codes-v6",
		"performance_contract_version":                 "performance-contract-v4",
		"performance_evidence_schema_version":          "performance-evidence-v4",
		"contract_registry_version":                    "contract-registry-v2",
		"platform_package_set_schema_version":          "platform-package-set-v1",
		"runtime_admission_schema_version":             "runtime-admission-v1",
		"runtime_descriptor_schema_version":            "runtime-descriptor-v2",
		"process_containment_schema_version":           "process-containment-v1",
		"runtime_exec_journal_schema_version":          "runtime-exec-journal-v1",
	}
	for name, want := range expectedMatrix {
		property := requireNestedObject(t, matrixProps, name)
		if got := property["const"]; got != want {
			t.Fatalf("%s const = %#v, want %q", name, got, want)
		}
	}

	required := map[string]bool{}
	for _, item := range requireStringSlice(t, matrix["required"], "matrix required") {
		required[item] = true
	}
	for name := range expectedMatrix {
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

func TestContractRegistryPublishesOnlyCurrentPlatformContracts(t *testing.T) {
	root := repoRoot(t)
	registryRaw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "contract-registry-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{
		"plugin-platform-v4",
		"compatibility-manifest-v4",
		"release-metadata-v4",
		"release-manifest-v3",
		"error-codes-v2",
		"bridge-v4",
		"opaque-surface-document-v2",
		"opaque-surface-transport-v3",
		"ipc-v2",
		"token-ticket-v2",
		"rust-ipc-v3",
		"network-grant-v1",
		"worker-invocation-v2",
		"release-manifest-v4",
		"source-policy-v1",
		"source-revocations-v1",
	} {
		if bytes.Contains(registryRaw, []byte(identifier)) {
			t.Fatalf("contract registry retains superseded identifier %q", identifier)
		}
	}
	for _, path := range []string{
		"spec/openapi/plugin-platform-v4.yaml",
		"spec/plugin/manifest-v4.schema.json",
		"spec/plugin/compatibility-manifest-v4.schema.json",
		"spec/plugin/release-metadata-v4.schema.json",
		"spec/plugin/release-manifest-v3.schema.json",
		"spec/plugin/error-codes-v2.schema.json",
		"spec/plugin/bridge-v4.schema.json",
		"spec/plugin/opaque-surface-document-v2.schema.json",
		"spec/plugin/opaque-surface-transport-v3.schema.json",
		"spec/plugin/ipc-v2.schema.json",
		"spec/plugin/token-ticket-v2.schema.json",
		"spec/plugin/ipc-v3.schema.json",
		"spec/plugin/network-grant-v1.schema.json",
		"spec/plugin/worker-invocation-v2.schema.json",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); !os.IsNotExist(err) {
			t.Fatalf("superseded contract %s must be absent, stat error = %v", path, err)
		}
	}
	errorCodeSchemas, err := filepath.Glob(filepath.Join(root, "spec", "plugin", "error-codes-v*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(errorCodeSchemas) != 1 || filepath.Base(errorCodeSchemas[0]) != "error-codes-v6.schema.json" {
		t.Fatalf("stable error-code schemas = %#v, want only error-codes-v6.schema.json", errorCodeSchemas)
	}
}
