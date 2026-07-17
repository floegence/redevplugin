package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerInvocationSchemaDefinesHostRuntimePayload(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "worker-invocation-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	properties := requireNestedObject(t, schema, "properties")
	requireConst(t, map[string]any{"worker_invocation": map[string]any{"properties": properties}}, "worker_invocation", "abi", "redevplugin-wasm-worker-v2")

	for name, want := range map[string][]string{
		"effect":    {"read", "write", "execute", "delete", "admin"},
		"execution": {"sync", "operation", "subscription"},
	} {
		property := requireNestedObject(t, properties, name)
		got := requireStringSlice(t, property["enum"], name+" enum")
		if !stringSetEqual(got, want) {
			t.Fatalf("%s enum = %#v, want %#v", name, got, want)
		}
	}
	if got := requireNestedObject(t, properties, "worker_mode")["const"]; got != "job" {
		t.Fatalf("worker_mode const = %#v, want job", got)
	}
	required := map[string]bool{}
	for _, item := range requireStringSlice(t, schema["required"], "worker invocation required") {
		required[item] = true
	}
	for _, name := range []string{"plugin_instance_id", "active_fingerprint", "runtime_instance_id", "runtime_generation_id", "package_hash", "worker_id", "artifact_sha256", "method", "broker_access", "broker_access_sha256", "params_sha256", "params"} {
		if !required[name] {
			t.Fatalf("worker invocation schema missing required field %q", name)
		}
	}
	for _, name := range []string{"surface_instance_id", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash", "bridge_channel_id", "storage_handle_grants"} {
		if _, ok := properties[name].(map[string]any); !ok {
			t.Fatalf("worker invocation schema missing optional audience field %q", name)
		}
	}
	if ref := requireNestedObject(t, properties, "broker_access")["$ref"]; ref != "#/$defs/broker_access" {
		t.Fatalf("broker_access ref = %#v, want #/$defs/broker_access", ref)
	}
	brokerAccess := requireNestedObject(t, schema, "$defs", "broker_access")
	if brokerAccess["additionalProperties"] != false {
		t.Fatalf("broker_access additionalProperties = %#v, want false", brokerAccess["additionalProperties"])
	}
	if property := requireNestedObject(t, properties, "broker_access_sha256"); property["$ref"] != "#/$defs/sha256" {
		t.Fatalf("broker_access_sha256 ref = %#v, want #/$defs/sha256", property["$ref"])
	}
	for _, name := range []string{"package_hash", "artifact_sha256"} {
		property := requireNestedObject(t, properties, name)
		if property["$ref"] != "#/$defs/sha256" {
			t.Fatalf("%s ref = %#v, want #/$defs/sha256", name, property["$ref"])
		}
	}
	sha256Def := requireNestedObject(t, schema, "$defs", "sha256")
	if sha256Def["pattern"] != "^sha256:[a-f0-9]{64}$" {
		t.Fatalf("sha256 pattern = %#v", sha256Def["pattern"])
	}
	params := requireNestedObject(t, properties, "params")
	if params["type"] != "object" {
		t.Fatalf("params type = %#v, want object", params["type"])
	}
}

func TestWorkerInvocationSchemaBindsOperationAndStreamHandlesByExecution(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "worker-invocation-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	conditions := requireObjectArray(t, schema["allOf"], "worker invocation allOf")
	wantRequired := map[string][]string{
		"operation":    {"operation_id"},
		"subscription": {"operation_id", "stream_id"},
	}
	for execution, want := range wantRequired {
		var matched map[string]any
		for _, condition := range conditions {
			if requireNestedObject(t, condition, "if", "properties", "execution")["const"] == execution {
				matched = condition
				break
			}
		}
		if matched == nil {
			t.Fatalf("worker invocation schema missing %q execution condition", execution)
		}
		then := requireNestedObject(t, matched, "then")
		assertStringSet(t, requireStringSlice(t, then["required"], execution+" required"), want, execution+" required")
	}
}

func stringSetEqual(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, item := range got {
		seen[item]++
	}
	for _, item := range want {
		if seen[item] == 0 {
			return false
		}
		seen[item]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}
