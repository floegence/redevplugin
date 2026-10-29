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

	requireConst(t, defs, "call", "type", "redevplugin.bridge.call")
	requireConst(t, defs, "cancel", "type", "redevplugin.bridge.cancel")
	requireConst(t, defs, "execution_cancel", "type", "redevplugin.bridge.execution.cancel")
	requireConst(t, defs, "execution_query", "type", "redevplugin.bridge.execution.query")
	requireConst(t, defs, "execution_events", "type", "redevplugin.bridge.execution.events")
	requireConst(t, defs, "file_export", "type", "redevplugin.ui.file.export")
	requireConst(t, defs, "lifecycle", "type", "redevplugin.bridge.lifecycle")
	requireConst(t, defs, "lifecycle_ack", "type", "redevplugin.bridge.lifecycle_ack")
	if _, ok := defs["handshake"]; ok {
		t.Fatal("plugin-visible bridge schema must not expose the trusted-parent HTTP handshake")
	}

	call := requireDef(t, defs, "call")
	request := requireNestedObject(t, call, "properties", "request")
	params := requireNestedObject(t, request, "properties", "params")
	if params["type"] != "object" {
		t.Fatalf("call params type = %#v, want object", params["type"])
	}
	requestID := requireDef(t, defs, "request_id")
	if got := requestID["pattern"]; got != "^(rpc|execution|file)_[1-9][0-9]{0,15}$" {
		t.Fatalf("request id pattern = %#v", got)
	}
	cancel := requireDef(t, defs, "cancel")
	if got := requireNestedObject(t, cancel, "properties", "id")["$ref"]; got != "#/$defs/request_id" {
		t.Fatalf("cancel request id ref = %#v", got)
	}
	executionCancel := requireDef(t, defs, "execution_cancel")
	assertStringSet(t, requireStringSlice(t, executionCancel["required"], "execution cancel required"), []string{"type", "id", "execution_id"}, "execution cancel required")
	if got := requireNestedObject(t, executionCancel, "properties", "execution_id")["$ref"]; got != "#/$defs/opaque_handle" {
		t.Fatalf("execution cancel handle ref = %#v", got)
	}
	executionQuery := requireDef(t, defs, "execution_query")
	assertStringSet(t, requireStringSlice(t, executionQuery["required"], "execution query required"), []string{"type", "id", "execution_id"}, "execution query required")
	executionEvents := requireDef(t, defs, "execution_events")
	assertStringSet(t, requireStringSlice(t, executionEvents["required"], "execution events required"), []string{"type", "id", "execution_id", "after_cursor"}, "execution events required")
	fileExport := requireDef(t, defs, "file_export")
	assertStringSet(t, requireStringSlice(t, fileExport["required"], "file export required"), []string{"type", "id", "file_name", "media_type", "content"}, "file export required")
	assertStringSet(t, requireStringSlice(t, fileExport["x-redevplugin-transfer"], "file export transfer"), []string{"content"}, "file export transfer")

	response := requireDef(t, defs, "response")
	responseVariants, ok := response["oneOf"].([]any)
	if !ok || len(responseVariants) != 2 {
		t.Fatalf("bridge response variants = %#v, want success and error", response["oneOf"])
	}
	errorResponse, ok := responseVariants[1].(map[string]any)
	if !ok || errorResponse["additionalProperties"] != false {
		t.Fatalf("bridge error response must be closed: %#v", responseVariants[1])
	}
	mutationOutcome := requireNestedObject(t, errorResponse, "properties", "mutation_outcome")
	assertStringSet(t, requireStringSlice(t, mutationOutcome["enum"], "bridge mutation outcome enum"), []string{"not_committed", "unknown"}, "bridge mutation outcome enum")

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
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	bridgeRaw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"plugin_gateway_token",
		"confirmation_token",
		"active_fingerprint",
		"bridge_nonce",
		"asset_session_nonce",
		"management_revision",
		"revoke_epoch",
	} {
		if strings.Contains(string(bridgeRaw), forbidden) {
			t.Fatalf("plugin-visible bridge schema must not expose %s", forbidden)
		}
	}
}

func TestBridgeHasNoPlatformRenderingProtocol(t *testing.T) {
	raw, err := json.Marshal(readBridgeSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, obsolete := range []string{"vnode", "ui.mount", "ui.patch", "ui.keyboard", "ui.canvas", "ui.asset", "render-policy"} {
		if strings.Contains(string(raw), obsolete) {
			t.Fatalf("retired rendering protocol %q", obsolete)
		}
	}
}

func readBridgeSchema(t *testing.T) map[string]any {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge.schema.json"))
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
