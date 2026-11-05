package authoring

import (
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestScaffoldEchoResponseSchemaIsClosedAndMinimal(t *testing.T) {
	compiled, err := manifest.CompileMethodSchemas(manifest.MethodSpec{
		Method:         "worker.echo",
		RequestSchema:  closedMethodObjectSchema(nil),
		ResponseSchema: scaffoldEchoResponseSchema(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.ValidateResponse(map[string]any{
		"method":    "worker.echo",
		"worker_id": "backend",
		"backend":   "executed wasm worker scaffold",
		"transport": "rust runtime ipc",
		"message":   "hello",
	}); err != nil {
		t.Fatalf("scaffold echo response schema rejected valid data: %v", err)
	}
	if err := compiled.ValidateResponse(map[string]any{
		"method":          "worker.echo",
		"worker_id":       "backend",
		"backend":         "executed wasm worker scaffold",
		"transport":       "rust runtime ipc",
		"message":         "hello",
		"network_execute": map[string]any{},
	}); err == nil {
		t.Fatal("scaffold echo response schema accepted undeclared network data")
	}
}
