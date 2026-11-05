package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestKnownHostCapabilitySchemasContainOnlyContractAndLocalIdentity(t *testing.T) {
	root := hostCapabilityRepositoryRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	for _, name := range []string{"host-capability-contract-v1.schema.json", "host-capability-pin-v1.schema.json"} {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		if document["additionalProperties"] != false {
			t.Fatalf("%s must be a closed object", name)
		}
		id, _ := document["$id"].(string)
		if id == "" {
			t.Fatalf("%s has no schema id", name)
		}
		if err := compiler.AddResource(id, bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := compiler.Compile(id); err != nil {
			t.Fatal(err)
		}
	}
}

func hostCapabilityRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
