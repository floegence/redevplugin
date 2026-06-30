package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerInvocationSchemaDefinesHostRuntimePayload(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "worker-invocation-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	properties := requireNestedObject(t, schema, "properties")
	requireConst(t, map[string]any{"worker_invocation": map[string]any{"properties": properties}}, "worker_invocation", "abi", "redeven-wasm-worker-v1")

	for name, want := range map[string][]string{
		"worker_mode": {"job", "actor"},
		"effect":      {"read", "write", "execute", "delete", "admin"},
		"execution":   {"sync", "operation", "subscription"},
		"export":      {"redeven_worker_invoke", "redeven_actor_start", "redeven_actor_stop"},
	} {
		property := requireNestedObject(t, properties, name)
		got := requireStringSlice(t, property["enum"], name+" enum")
		if !stringSetEqual(got, want) {
			t.Fatalf("%s enum = %#v, want %#v", name, got, want)
		}
	}

	required := map[string]bool{}
	for _, item := range requireStringSlice(t, schema["required"], "worker invocation required") {
		required[item] = true
	}
	for _, name := range []string{"plugin_instance_id", "active_fingerprint", "worker_id", "method", "params"} {
		if !required[name] {
			t.Fatalf("worker invocation schema missing required field %q", name)
		}
	}
	params := requireNestedObject(t, properties, "params")
	if params["type"] != "object" {
		t.Fatalf("params type = %#v, want object", params["type"])
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
