package authoring

import (
	"encoding/json"
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

func TestTemplatesDeclareFirstPresentationCompatibility(t *testing.T) {
	for _, name := range []string{"worker", "web", "data", "files", "monitor"} {
		t.Run(name, func(t *testing.T) {
			files, err := templateFiles("example", "Example", name)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				API manifest.PublicAPIRequirement `json:"api"`
			}
			if err := json.Unmarshal(files["manifest.json"], &doc); err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, feature := range doc.API.RequiredFeatures {
				if feature == manifest.FeatureSurfacePresentation {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("template must declare first-presentation compatibility exactly once: %#v", doc.API)
			}
		})
	}
}
