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

func TestIPCSchemaBindsHelloChannelNonce(t *testing.T) {
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
	assertPayload := func(frameType string) {
		t.Helper()
		for _, item := range allOf {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
			if ifBlock["const"] != frameType {
				continue
			}
			payload := requireNestedObject(t, block, "then", "properties", "payload")
			required := requireStringSlice(t, payload["required"], frameType+" payload required")
			hasChannelNonce := false
			for _, name := range required {
				if name == "channel_nonce" {
					hasChannelNonce = true
					break
				}
			}
			if !hasChannelNonce {
				t.Fatalf("%s payload required missing channel_nonce: %#v", frameType, required)
			}
			props := requireNestedObject(t, payload, "properties")
			channelNonce := requireNestedObject(t, props, "channel_nonce")
			if channelNonce["type"] != "string" || channelNonce["minLength"] != float64(16) {
				t.Fatalf("%s channel_nonce schema = %#v", frameType, channelNonce)
			}
			return
		}
		t.Fatalf("ipc schema missing %s block", frameType)
	}
	assertPayload("hello")
	assertPayload("hello_ack")
}

func TestIPCSchemaRequiresWorkerLeaseNonce(t *testing.T) {
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
		ifBlock := requireNestedObject(t, block, "if", "properties", "frame_type")
		if ifBlock["const"] != "invoke_worker" {
			continue
		}
		lease := requireNestedObject(t, block, "then", "properties", "payload", "properties", "lease")
		required := requireStringSlice(t, lease["required"], "invoke_worker lease required")
		hasLeaseNonce := false
		for _, name := range required {
			if name == "lease_nonce" {
				hasLeaseNonce = true
				break
			}
		}
		if !hasLeaseNonce {
			t.Fatalf("invoke_worker lease required missing lease_nonce: %#v", required)
		}
		leaseNonce := requireNestedObject(t, lease, "properties", "lease_nonce")
		if leaseNonce["type"] != "string" || leaseNonce["minLength"] != float64(16) {
			t.Fatalf("invoke_worker lease_nonce schema = %#v", leaseNonce)
		}
		return
	}
	t.Fatal("ipc schema missing invoke_worker block")
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

func TestIPCSchemaDefinesStorageKVPayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "storage_kv") {
		t.Fatalf("frame_type enum missing storage_kv: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_kv_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "key", "value_base64", "prefix"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_kv request missing %s", name)
		}
	}
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.kv" {
		t.Fatalf("storage_kv method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_kv_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "key", "value_base64", "entries", "usage", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("storage_kv response missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesStorageSQLitePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "storage_sqlite") {
		t.Fatalf("frame_type enum missing storage_sqlite: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "storage_sqlite_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"handle_grant_token", "plugin_instance_id", "active_fingerprint", "runtime_generation_id", "handle_id", "method", "operation", "store_id", "database", "sql", "args", "max_rows", "max_response_bytes", "timeout_ms"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("storage_sqlite request missing %s", name)
		}
	}
	method := requireNestedObject(t, requestProps, "method")
	if method["const"] != "storage.sqlite" {
		t.Fatalf("storage_sqlite method = %#v", method["const"])
	}
	response := requireNestedObject(t, defs, "storage_sqlite_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "database", "rows_affected", "last_insert_id", "columns", "rows", "usage", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("storage_sqlite response missing %s", name)
		}
	}
	value := requireNestedObject(t, defs, "storage_sqlite_value")
	valueProps := requireNestedObject(t, value, "properties")
	for _, name := range []string{"null", "int", "float", "text", "blob_base64"} {
		if _, ok := valueProps[name].(map[string]any); !ok {
			t.Fatalf("storage_sqlite value missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesNetworkGrantPayloads(t *testing.T) {
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
	request := requireNestedObject(t, defs, "network_grant_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"plugin_instance_id", "active_fingerprint", "runtime_generation_id", "policy_revision", "management_revision", "revoke_epoch", "connector_id", "transport", "destination", "ttl_ms"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("network_grant request missing %s", name)
		}
	}
	transport := requireNestedObject(t, requestProps, "transport")
	enum, ok := transport["enum"].([]any)
	if !ok || len(enum) != 4 {
		t.Fatalf("network_grant transport enum = %#v", transport["enum"])
	}
	response := requireNestedObject(t, defs, "network_grant_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "grant_id", "connector_id", "transport", "destination", "runtime_generation_id", "target_classifier_version", "expires_at", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("network_grant response missing %s", name)
		}
	}
	destination := requireNestedObject(t, defs, "network_destination")
	destinationProps := requireNestedObject(t, destination, "properties")
	for _, name := range []string{"transport", "scheme", "host", "port"} {
		if _, ok := destinationProps[name].(map[string]any); !ok {
			t.Fatalf("network_destination missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesNetworkExecutePayloads(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "ipc-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	frameType := requireNestedObject(t, schema, "properties", "frame_type")
	frameEnum, ok := frameType["enum"].([]any)
	if !ok || !containsString(frameEnum, "network_execute") {
		t.Fatalf("frame_type enum missing network_execute: %#v", frameType["enum"])
	}
	defs := requireNestedObject(t, schema, "$defs")
	request := requireNestedObject(t, defs, "network_execute_request_payload")
	requestProps := requireNestedObject(t, request, "properties")
	for _, name := range []string{"plugin_instance_id", "active_fingerprint", "runtime_generation_id", "policy_revision", "management_revision", "revoke_epoch", "connector_id", "transport", "destination", "operation", "method", "path", "headers", "body_base64", "payload_base64", "max_response_bytes", "timeout_ms"} {
		if _, ok := requestProps[name].(map[string]any); !ok {
			t.Fatalf("network_execute request missing %s", name)
		}
	}
	operation := requireNestedObject(t, requestProps, "operation")
	if enum, ok := operation["enum"].([]any); !ok || !containsString(enum, "websocket_round_trip") || !containsString(enum, "udp_round_trip") {
		t.Fatalf("network_execute operation enum = %#v", operation["enum"])
	}
	response := requireNestedObject(t, defs, "network_execute_response_payload")
	responseProps := requireNestedObject(t, response, "properties")
	for _, name := range []string{"ok", "transport", "destination", "status_code", "headers", "message_type", "body_base64", "payload_base64", "grant_id", "connector_id", "runtime_generation_id", "code", "message"} {
		if _, ok := responseProps[name].(map[string]any); !ok {
			t.Fatalf("network_execute response missing %s", name)
		}
	}
}

func TestIPCSchemaDefinesRevokeEpochAckResult(t *testing.T) {
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
	payload := requireNestedObject(t, defs, "revoke_epoch_ack_response_payload")
	payloadRequired := requireStringSlice(t, payload["required"], "revoke_epoch_ack payload required")
	if !containsRequiredString(payloadRequired, "ok") {
		t.Fatalf("revoke_epoch_ack payload required missing ok: %#v", payloadRequired)
	}
	payloadProps := requireNestedObject(t, payload, "properties")
	if _, ok := payloadProps["result"].(map[string]any); !ok {
		t.Fatalf("revoke_epoch_ack payload missing result: %#v", payloadProps)
	}
	result := requireNestedObject(t, defs, "revoke_epoch_ack_result")
	required := requireStringSlice(t, result["required"], "revoke_epoch_ack result required")
	for _, name := range []string{"plugin_instance_id", "revoke_epoch", "closed_actor_count", "closed_socket_count", "closed_stream_count", "closed_storage_handle_count"} {
		if !containsRequiredString(required, name) {
			t.Fatalf("revoke_epoch_ack result required missing %s: %#v", name, required)
		}
	}
	resultProps := requireNestedObject(t, result, "properties")
	for _, name := range []string{"revoke_epoch", "closed_actor_count", "closed_socket_count", "closed_stream_count", "closed_storage_handle_count"} {
		field := requireNestedObject(t, resultProps, name)
		if field["type"] != "integer" || field["minimum"] != float64(0) {
			t.Fatalf("revoke_epoch_ack result %s schema = %#v", name, field)
		}
	}
	pluginInstanceID := requireNestedObject(t, resultProps, "plugin_instance_id")
	if pluginInstanceID["type"] != "string" || pluginInstanceID["minLength"] != float64(1) {
		t.Fatalf("revoke_epoch_ack plugin_instance_id schema = %#v", pluginInstanceID)
	}
}

func containsString(values []any, want string) bool {
	for _, value := range values {
		if got, ok := value.(string); ok && got == want {
			return true
		}
	}
	return false
}

func containsRequiredString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
