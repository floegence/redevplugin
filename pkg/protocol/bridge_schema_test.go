package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeSchemaDefinesIframeMessages(t *testing.T) {
	schema := readBridgeSchema(t)
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("bridge schema missing $defs")
	}

	requireConst(t, defs, "handshake", "type", "redevplugin.bridge.handshake")
	requireConst(t, defs, "call", "type", "redevplugin.bridge.call")
	requireConst(t, defs, "lifecycle", "type", "redevplugin.bridge.lifecycle")
	requireNestedConst(t, defs, "handshake", []string{"properties", "ui_protocol_version"}, "plugin-ui-v1")

	call := requireDef(t, defs, "call")
	request := requireNestedObject(t, call, "properties", "request")
	params := requireNestedObject(t, request, "properties", "params")
	if params["type"] != "object" {
		t.Fatalf("call params type = %#v, want object", params["type"])
	}

	lifecycle := requireDef(t, defs, "lifecycle")
	event := requireNestedObject(t, lifecycle, "properties", "event")
	eventType := requireNestedObject(t, event, "properties", "type")
	wantLifecycle := map[string]bool{"ready": false, "visible": false, "hidden": false, "dispose": false}
	for _, raw := range requireStringSlice(t, eventType["enum"], "lifecycle enum") {
		if _, ok := wantLifecycle[raw]; ok {
			wantLifecycle[raw] = true
		}
	}
	for value, found := range wantLifecycle {
		if !found {
			t.Fatalf("lifecycle enum missing %q", value)
		}
	}
}

func TestBridgeSchemaKeepsParentOnlyTokensOutOfIframeMessages(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := schema["$defs"].(map[string]any)
	responseRaw, err := json.Marshal(defs["response"])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"plugin_gateway_token", "confirmation_token"} {
		if strings.Contains(string(responseRaw), forbidden) {
			t.Fatalf("bridge response schema must not expose %s", forbidden)
		}
	}
}

func readBridgeSchema(t *testing.T) map[string]any {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func requireDef(t *testing.T, defs map[string]any, name string) map[string]any {
	t.Helper()
	def, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("bridge schema missing definition %q", name)
	}
	return def
}

func requireConst(t *testing.T, defs map[string]any, defName string, propertyName string, want string) {
	t.Helper()
	def := requireDef(t, defs, defName)
	requireNestedConst(t, map[string]any{defName: def}, defName, []string{"properties", propertyName}, want)
}

func requireNestedConst(t *testing.T, defs map[string]any, defName string, path []string, want string) {
	t.Helper()
	current := requireDef(t, defs, defName)
	for _, part := range path {
		current = requireNestedObjectFrom(t, current, part)
	}
	if got := current["const"]; got != want {
		t.Fatalf("%s.%s const = %#v, want %q", defName, strings.Join(path, "."), got, want)
	}
}

func requireNestedObject(t *testing.T, from map[string]any, path ...string) map[string]any {
	t.Helper()
	current := from
	for _, part := range path {
		current = requireNestedObjectFrom(t, current, part)
	}
	return current
}

func requireNestedObjectFrom(t *testing.T, from map[string]any, key string) map[string]any {
	t.Helper()
	next, ok := from[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object at key %q in %#v", key, from)
	}
	return next
}

func requireStringSlice(t *testing.T, value any, label string) []string {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array", label, value)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("%s item = %#v, want string", label, item)
		}
		out = append(out, text)
	}
	return out
}
