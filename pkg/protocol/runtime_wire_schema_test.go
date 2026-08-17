package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func TestRuntimeWireSchemaHasOneHandshakeIdentity(t *testing.T) {
	root := runtimeWireRepoRoot(t)
	schema := readRuntimeWireJSON(t, filepath.Join(root, "spec", "internal", "runtime-wire.schema.json"))
	if schema["$id"] != "https://schemas.redevplugin.dev/internal/runtime-wire.schema.json" {
		t.Fatalf("runtime wire $id = %#v", schema["$id"])
	}
	if schema["internal_wire"] != float64(1) {
		t.Fatalf("internal_wire = %#v, want 1", schema["internal_wire"])
	}
	definitions := runtimeWireObject(t, schema, "$defs")
	for _, name := range []string{"hello_payload", "hello_ack_payload"} {
		definition := runtimeWireObject(t, definitions, name)
		properties := runtimeWireObject(t, definition, "properties")
		if got := runtimeWireObject(t, properties, "internal_wire")["const"]; got != float64(1) {
			t.Fatalf("%s internal_wire = %#v, want 1", name, got)
		}
		for _, field := range []string{"platform_version", "runtime_artifact_sha256", "connection_nonce"} {
			if properties[field] == nil {
				t.Fatalf("%s missing %s", name, field)
			}
		}
		for _, retired := range []string{"ipc_version", "rust_ipc_version", "host_ipc_version", "wasm_abi_version", "contract_set_sha256"} {
			if properties[retired] != nil {
				t.Fatalf("%s retains retired field %s", name, retired)
			}
		}
	}
	ordinary := runtimeWireObject(t, definitions, "semantic_frame")
	properties := runtimeWireObject(t, ordinary, "properties")
	if properties["internal_wire"] != nil || properties["ipc_version"] != nil {
		t.Fatalf("ordinary frame carries wire identity: %#v", properties)
	}
}

func TestRuntimeWireSchemaFixesUnversionedBinaryHeader(t *testing.T) {
	schema := readRuntimeWireJSON(t, filepath.Join(runtimeWireRepoRoot(t), "spec", "internal", "runtime-wire.schema.json"))
	header := runtimeWireObject(t, schema, "x-binary-header")
	if header["byte_order"] != "big-endian" || header["magic_hex"] != "52445046" || header["size"] != float64(19) {
		t.Fatalf("binary header identity = %#v", header)
	}
	wantNames := []string{"magic", "kind", "flags", "correlation_id", "payload_len"}
	rawFields, ok := header["fields"].([]any)
	if !ok {
		t.Fatalf("binary header fields = %#v", header["fields"])
	}
	gotNames := make([]string, 0, len(rawFields))
	for _, raw := range rawFields {
		field, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("binary header field = %#v", raw)
		}
		gotNames = append(gotNames, field["name"].(string))
		if field["name"] == "version" || field["name"] == "internal_wire" {
			t.Fatalf("binary header carries version: %#v", field)
		}
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("binary header fields = %#v, want %#v", gotNames, wantNames)
	}
	payload := runtimeWireObject(t, schema, "x-binary-payload")
	if payload["metadata_length_prefix_bytes"] != float64(4) || payload["metadata_length_byte_order"] != "big-endian" {
		t.Fatalf("binary payload identity = %#v", payload)
	}
}

func TestRuntimeWireSchemaOwnsExactSemanticFramePayloads(t *testing.T) {
	schema := readRuntimeWireJSON(t, filepath.Join(runtimeWireRepoRoot(t), "spec", "internal", "runtime-wire.schema.json"))
	definitions := runtimeWireObject(t, schema, "$defs")
	contracts := runtimeWireObject(t, schema, "x-frame-contracts")
	want := map[string]string{
		"hello":                   "hello_payload",
		"hello_ack":               "hello_ack_payload",
		"heartbeat":               "heartbeat_payload",
		"invoke_worker":           "invoke_worker_payload",
		"invoke_worker_result":    "invoke_worker_result_payload",
		"cancel_invoke":           "cancel_invoke_payload",
		"cancel_invoke_ack":       "cancel_invoke_ack_payload",
		"compile_flight_register": "compile_flight_payload",
		"compile_flight_complete": "compile_flight_payload",
		"open_handle":             "open_handle_payload",
		"revoke_epoch":            "revoke_epoch_payload",
		"revoke_epoch_ack":        "revoke_epoch_ack_payload",
		"session_revoke":          "session_revoke_payload",
		"session_revoke_ack":      "session_revoke_ack_payload",
	}
	if len(contracts) != len(want) {
		t.Fatalf("runtime frame contract count = %d, want %d", len(contracts), len(want))
	}
	gotNames := make([]string, 0, len(contracts))
	for frameType, payloadName := range want {
		gotNames = append(gotNames, frameType)
		contract := runtimeWireObject(t, contracts, frameType)
		if contract["payload"] != "#/$defs/"+payloadName {
			t.Fatalf("%s payload contract = %#v, want %s", frameType, contract["payload"], payloadName)
		}
		payload := runtimeWireObject(t, definitions, payloadName)
		if payload["type"] != "object" || payload["additionalProperties"] != false {
			t.Fatalf("%s is not a closed object payload: %#v", payloadName, payload)
		}
		properties := runtimeWireObject(t, payload, "properties")
		if frameType != "hello" && frameType != "hello_ack" && (properties["internal_wire"] != nil || properties["ipc_version"] != nil) {
			t.Fatalf("%s carries wire identity: %#v", payloadName, properties)
		}
	}
	sort.Strings(gotNames)
	wantNames := make([]string, 0, len(want))
	for frameType := range want {
		wantNames = append(wantNames, frameType)
	}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("runtime frame types = %#v, want %#v", gotNames, wantNames)
	}
	semantic := runtimeWireObject(t, definitions, "semantic_frame")
	frameType := runtimeWireObject(t, runtimeWireObject(t, semantic, "properties"), "frame_type")
	gotEnum, ok := frameType["enum"].([]any)
	if !ok || len(gotEnum) != len(want) {
		t.Fatalf("semantic frame enum = %#v, want exact current frame set", frameType["enum"])
	}
	gotNames = gotNames[:0]
	for _, raw := range gotEnum {
		name, ok := raw.(string)
		if !ok {
			t.Fatalf("semantic frame name = %#v, want string", raw)
		}
		gotNames = append(gotNames, name)
	}
	sort.Strings(gotNames)
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("semantic frame enum = %#v, want %#v", gotNames, wantNames)
	}
}

func TestRuntimeWireRetiredContractsAreAbsent(t *testing.T) {
	root := runtimeWireRepoRoot(t)
	for _, path := range []string{
		filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"),
		filepath.Join(root, "spec", "plugin", "ipc-v7.schema.json"),
		filepath.Join(root, "spec", "plugin", "ipc-v7-fixtures.json"),
	} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("retired runtime wire contract still exists: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func runtimeWireObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, parent[key])
	}
	return value
}

func runtimeWireRepoRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate runtime wire contract test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func readRuntimeWireJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}
