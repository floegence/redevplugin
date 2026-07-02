package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenTicketSchemaBindsEveryTokenKind(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "token-ticket-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	defs := requireNestedObject(t, schema, "$defs")
	tokenKinds := requireStringSlice(t, requireNestedObject(t, defs, "token_kind")["enum"], "token_kind enum")
	conditions := tokenTicketConditionsByKind(t, schema)
	if len(conditions) != len(tokenKinds) {
		t.Fatalf("token-ticket schema conditions = %d, want one per token kind %#v", len(conditions), tokenKinds)
	}
	for _, kind := range tokenKinds {
		if _, ok := conditions[kind]; !ok {
			t.Fatalf("token-ticket schema missing conditional binding for %q", kind)
		}
	}

	assertTokenTicketCondition(t, conditions, "asset_ticket", "single_use", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"surface_instance_id",
	})
	assertTokenTicketCondition(t, conditions, "asset_session", "reusable", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"surface_instance_id",
	})
	assertTokenTicketCondition(t, conditions, "plugin_gateway_token", "reusable", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"surface_instance_id",
		"bridge_channel_id",
	})
	assertTokenTicketCondition(t, conditions, "confirmation_token", "single_use", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"surface_instance_id",
		"confirmation_id",
		"bridge_channel_id",
		"method",
		"request_hash",
	})
	assertTokenTicketCondition(t, conditions, "runtime_execution_lease", "reusable", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"runtime_generation_id",
		"method",
	})
	assertTokenTicketCondition(t, conditions, "handle_grant", "reusable", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"runtime_generation_id",
		"handle_id",
		"method",
	})
	assertTokenTicketCondition(t, conditions, "stream_ticket", "single_use", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"surface_instance_id",
		"bridge_channel_id",
		"stream_id",
		"stream_direction",
		"method",
	})
}

type tokenTicketCondition struct {
	useConst         string
	audienceRequired []string
}

func tokenTicketConditionsByKind(t *testing.T, schema map[string]any) map[string]tokenTicketCondition {
	t.Helper()
	rawConditions, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatalf("token-ticket schema allOf = %#v, want array", schema["allOf"])
	}
	out := map[string]tokenTicketCondition{}
	for _, rawCondition := range rawConditions {
		condition, ok := rawCondition.(map[string]any)
		if !ok {
			t.Fatalf("token-ticket condition = %#v, want object", rawCondition)
		}
		kind, ok := requireNestedObject(t, condition, "if", "properties", "token_kind")["const"].(string)
		if !ok || kind == "" {
			t.Fatalf("token-ticket condition missing token_kind const: %#v", condition)
		}
		if _, exists := out[kind]; exists {
			t.Fatalf("duplicate token-ticket condition for %q", kind)
		}
		then := requireNestedObject(t, condition, "then")
		useConst, ok := requireNestedObject(t, then, "properties", "use")["const"].(string)
		if !ok || useConst == "" {
			t.Fatalf("token-ticket condition %q missing use const: %#v", kind, condition)
		}
		audienceRequired := requireStringSlice(t, requireNestedObject(t, then, "properties", "audience")["required"], kind+" audience required")
		out[kind] = tokenTicketCondition{useConst: useConst, audienceRequired: audienceRequired}
	}
	return out
}

func assertTokenTicketCondition(t *testing.T, conditions map[string]tokenTicketCondition, kind string, useConst string, requiredAudience []string) {
	t.Helper()
	condition, ok := conditions[kind]
	if !ok {
		t.Fatalf("missing token-ticket condition for %q", kind)
	}
	if condition.useConst != useConst {
		t.Fatalf("%s use const = %q, want %q", kind, condition.useConst, useConst)
	}
	if !stringSetEqual(condition.audienceRequired, requiredAudience) {
		t.Fatalf("%s audience required = %#v, want %#v", kind, condition.audienceRequired, requiredAudience)
	}
}
