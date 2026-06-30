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
