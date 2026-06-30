package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIPCSchemaReferencesWorkerInvocationContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatal("ipc schema missing allOf")
	}
	for _, item := range allOf {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		thenBlock, ok := block["then"].(map[string]any)
		if !ok {
			continue
		}
		properties := requireNestedObject(t, thenBlock, "properties", "payload", "properties")
		invocation, ok := properties["invocation"].(map[string]any)
		if !ok {
			continue
		}
		if invocation["$ref"] != "https://schemas.redevplugin.dev/plugin/worker-invocation-v1.schema.json" {
			t.Fatalf("invoke_worker invocation ref = %#v", invocation["$ref"])
		}
		return
	}
	t.Fatal("ipc schema missing invoke_worker invocation reference")
}

func TestIPCSchemaDefinesOpenHandlePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "open_handle_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"package_hash", "artifact", "artifact_sha256"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("open_handle request missing %s", name)
		}
	}
	response := requireNestedObject(t, defs, "open_handle_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "sha256", "content_base64", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("open_handle response missing %s", name)
		}
	}
	artifact := requireNestedObject(t, defs, "worker_artifact_path")
	if artifact["pattern"] != "^workers/(?!.*(?:^|/)\\.)(?!.*//)(?!.*\\\\).+\\.wasm$" {
		t.Fatalf("worker artifact pattern = %#v", artifact["pattern"])
	}
}

func TestIPCSchemaDefinesHandleGrantValidationPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "validate_handle_grant_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "policy_revision", "management_revision", "revoke_epoch"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("validate_handle_grant request missing %s", name)
		}
	}
	response := requireNestedObject(t, defs, "validate_handle_grant_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "handle_grant_id", "handle_id", "method", "runtime_generation_id", "max_total_bytes", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("validate_handle_grant response missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesStorageFilePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_file_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "path", "data_base64"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_file request missing %s", name)
		}
	}
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.files" {
		t.Fatalf("storage_file method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_file_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "path", "data_base64", "entries", "usage", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("storage_file response missing %s", name)
		}
	}
}
