package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSurfaceMethodRouteContract(t *testing.T) {
	for _, tc := range []struct {
		name      string
		route     map[string]any
		execution string
		wantError bool
	}{
		{"sync", map[string]any{"kind": "surface", "surface_id": "resources.panel"}, "sync", false},
		{"operation", map[string]any{"kind": "surface", "surface_id": "resources.panel"}, "operation", false},
		{"missing target", map[string]any{"kind": "surface"}, "sync", true},
		{"unknown target", map[string]any{"kind": "surface", "surface_id": "unknown"}, "sync", true},
		{"foreign route field", map[string]any{"kind": "surface", "surface_id": "resources.panel", "worker_id": "worker"}, "sync", true},
		{"subscription", map[string]any{"kind": "surface", "surface_id": "resources.panel"}, "subscription", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal([]byte(validManifestJSON()), &raw); err != nil {
				t.Fatal(err)
			}
			surface := raw["surfaces"].([]any)[0].(map[string]any)
			surface["surface_id"] = "resources.panel"
			raw["methods"] = []any{map[string]any{"method": "document.read", "route": tc.route, "effect": "read", "execution": tc.execution, "request_schema": map[string]any{"type": "object", "additionalProperties": false}, "response_schema": map[string]any{"type": "object", "additionalProperties": false}}}
			if tc.execution != "sync" {
				raw["methods"].([]any)[0].(map[string]any)["cancel_policy"] = map[string]any{"cancelable": true, "ack_timeout_ms": 1000, "disable_behavior": "cancel", "uninstall_behavior": "cancel_then_block_delete"}
			}
			delete(raw, "intents")
			delete(raw, "background")
			encoded, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Decode(strings.NewReader(string(encoded)))
			if (err != nil) != tc.wantError {
				t.Fatalf("Decode()=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}
