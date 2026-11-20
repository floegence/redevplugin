package manifest_test

import (
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/agentconversation"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestCapabilityResultUnionRequiresClosedObjectVariants(t *testing.T) {
	object := map[string]any{"type": "object", "additionalProperties": false}
	for _, variant := range []any{true, map[string]any{"type": "string"}, map[string]any{"type": "object"}, map[string]any{"type": "object", "additionalProperties": true}} {
		spec := manifest.MethodSpec{Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability}, RequestSchema: object, ResponseSchema: map[string]any{"oneOf": []any{object, variant}}}
		if _, err := manifest.CompileMethodSchemas(spec); err == nil {
			t.Fatalf("accepted non-closed variant %v", variant)
		}
	}
	union := map[string]any{"oneOf": []any{object}}
	for _, spec := range []manifest.MethodSpec{{RequestSchema: object, ResponseSchema: union}, {Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability}, RequestSchema: union, ResponseSchema: object}} {
		if _, err := manifest.CompileMethodSchemas(spec); err == nil {
			t.Fatal("accepted union outside a capability response")
		}
	}
}

func TestPublishedConversationResultMethodSchemas(t *testing.T) {
	known, err := agentconversation.Contract()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, method := range known.Contract.Methods {
		if method.ClientMethod != "result" && method.ClientMethod != "libraryResult" {
			continue
		}
		count++
		t.Run(method.Name, func(t *testing.T) {
			spec := manifest.MethodSpec{Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability}, RequestSchema: method.RequestSchema, ResponseSchema: method.ResponseSchema}
			compiled, err := manifest.CompileMethodSchemas(spec)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []map[string]any{{"state": "completed", "text": "done"}, {"state": "failed", "failure_code": "provider_unavailable"}, {"state": "running"}} {
				if err := compiled.ValidateResponse(value); err != nil {
					t.Errorf("valid response: %v", err)
				}
			}
			for _, value := range []any{"running", map[string]any{"state": "running", "text": "extra"}, map[string]any{"state": "failed", "private": true}} {
				if compiled.ValidateResponse(value) == nil {
					t.Errorf("accepted invalid response: %v", value)
				}
			}
		})
	}
	if count != 2 {
		t.Fatalf("expected two original result contracts, found %d", count)
	}
}
