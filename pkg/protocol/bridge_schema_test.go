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
	requireConst(t, defs, "operation_cancel", "type", "redevplugin.bridge.operation.cancel")
	requireConst(t, defs, "canvas_open", "type", "redevplugin.ui.canvas.open")
	requireConst(t, defs, "canvas_accessibility", "type", "redevplugin.ui.canvas.accessibility")
	requireConst(t, defs, "canvas_ready", "type", "redevplugin.ui.canvas.ready")
	requireConst(t, defs, "canvas_input", "type", "redevplugin.ui.canvas.input")
	requireConst(t, defs, "image_open", "type", "redevplugin.ui.asset.image.open")
	requireConst(t, defs, "image_ready", "type", "redevplugin.ui.asset.image.ready")
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
	if got := requestID["pattern"]; got != "^(rpc|stream|render|operation|canvas|asset)_[1-9][0-9]{0,15}$" {
		t.Fatalf("request id pattern = %#v", got)
	}
	cancel := requireDef(t, defs, "cancel")
	if got := requireNestedObject(t, cancel, "properties", "id")["$ref"]; got != "#/$defs/request_id" {
		t.Fatalf("cancel request id ref = %#v", got)
	}
	operationCancel := requireDef(t, defs, "operation_cancel")
	assertStringSet(t, requireStringSlice(t, operationCancel["required"], "operation cancel required"), []string{"type", "id", "operation_id"}, "operation cancel required")
	if got := requireNestedObject(t, operationCancel, "properties", "operation_id")["$ref"]; got != "#/$defs/opaque_handle" {
		t.Fatalf("operation cancel handle ref = %#v", got)
	}
	canvasAccessibility := requireDef(t, defs, "canvas_accessibility")
	assertStringSet(t, requireStringSlice(t, canvasAccessibility["required"], "canvas accessibility required"), []string{"type", "id", "canvas_id", "label", "description"}, "canvas accessibility required")

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

func TestBridgeSchemaDefinesRevisionedKeyedRendering(t *testing.T) {
	schema := readBridgeSchema(t)
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("bridge schema missing $defs")
	}

	requireConst(t, defs, "mount", "type", "redevplugin.ui.mount")
	mount := requireDef(t, defs, "mount")
	assertStringSet(t, requireStringSlice(t, mount["required"], "mount required"), []string{"type", "id", "revision", "tree"}, "mount required")
	if got := requireNestedObject(t, mount, "properties", "revision")["const"]; got != float64(1) {
		t.Fatalf("mount revision = %#v, want 1", got)
	}
	if got := requireNestedObject(t, mount, "properties", "tree")["$ref"]; got != "#/$defs/element_vnode" {
		t.Fatalf("mount tree ref = %#v", got)
	}

	requireConst(t, defs, "patch", "type", "redevplugin.ui.patch")
	patch := requireDef(t, defs, "patch")
	assertStringSet(t, requireStringSlice(t, patch["required"], "patch required"), []string{"type", "id", "base_revision", "revision", "operations"}, "patch required")
	if got := requireNestedObject(t, patch, "properties", "operations", "items")["$ref"]; got != "#/$defs/patch_operation" {
		t.Fatalf("patch operation ref = %#v", got)
	}

	element := requireDef(t, defs, "element_vnode")
	if !containsStringValue(requireStringSlice(t, element["required"], "element vnode required"), "key") {
		t.Fatal("element vnode must require an explicit key")
	}
	if got := requireNestedObject(t, element, "properties", "key")["$ref"]; got != "#/$defs/ui_identifier" {
		t.Fatalf("element vnode key ref = %#v", got)
	}

	operations := requireDef(t, defs, "patch_operation")
	variants, ok := operations["oneOf"].([]any)
	if !ok || len(variants) != 6 {
		t.Fatalf("patch operation variants = %#v, want six closed operations", operations["oneOf"])
	}
	wantOperations := map[string]bool{
		"set_text":         false,
		"patch_attributes": false,
		"patch_control":    false,
		"insert_child":     false,
		"remove_child":     false,
		"move_child":       false,
	}
	for _, raw := range variants {
		variant, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("patch operation variant = %#v, want object", raw)
		}
		if variant["additionalProperties"] != false {
			t.Fatalf("patch operation must be closed: %#v", variant)
		}
		operation, ok := requireNestedObject(t, variant, "properties", "type")["const"].(string)
		if !ok {
			t.Fatalf("patch operation type = %#v, want const string", variant)
		}
		if _, known := wantOperations[operation]; !known {
			t.Fatalf("unknown patch operation %q", operation)
		}
		wantOperations[operation] = true
	}
	for operation, found := range wantOperations {
		if !found {
			t.Fatalf("patch operation missing %q", operation)
		}
	}

	action := requireDef(t, defs, "action")
	actionRequired := requireStringSlice(t, action["required"], "action required")
	for _, field := range []string{"target_key", "edit_revision", "is_composing"} {
		if !containsStringValue(actionRequired, field) {
			t.Fatalf("action must require %q", field)
		}
	}
}

func TestBridgeSchemaKeepsParentOnlyTokensOutOfIframeMessages(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge-v4.schema.json"))
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
		"plugin_state_version",
		"revoke_epoch",
	} {
		if strings.Contains(string(bridgeRaw), forbidden) {
			t.Fatalf("plugin-visible bridge schema must not expose %s", forbidden)
		}
	}
}

func TestBridgeSchemaDefinesClosedRenderPolicy(t *testing.T) {
	schema := readBridgeSchema(t)
	policy, ok := schema["x-redevplugin-render-policy"].(map[string]any)
	if !ok {
		t.Fatal("bridge schema missing x-redevplugin-render-policy")
	}
	for _, key := range []string{
		"max_message_bytes",
		"max_render_depth",
		"max_render_nodes",
		"max_attributes_per_element",
		"max_text_length",
		"max_attribute_value_length",
		"max_form_fields",
		"max_canvas_count",
		"max_canvas_dimension",
		"max_canvas_total_pixels",
		"max_canvas_pointer_events_per_second",
		"max_image_count",
		"max_image_dimension",
		"max_image_total_pixels",
		"worker_heartbeat_interval_ms",
		"worker_heartbeat_timeout_ms",
		"global_attributes",
		"tag_attributes",
		"safe_input_types",
	} {
		if _, ok := policy[key]; !ok {
			t.Fatalf("render policy missing %q", key)
		}
	}

	defs := schema["$defs"].(map[string]any)
	vnode := requireDef(t, defs, "vnode")
	variants, ok := vnode["oneOf"].([]any)
	if !ok || len(variants) != 2 {
		t.Fatalf("vnode oneOf = %#v, want text and element variants", vnode["oneOf"])
	}
	element := requireDef(t, defs, "element_vnode")
	if ref := variants[1].(map[string]any)["$ref"]; ref != "#/$defs/element_vnode" {
		t.Fatalf("element vnode ref = %#v", ref)
	}
	tags := requireStringSlice(t, requireNestedObject(t, element, "properties", "tag")["enum"], "render tag enum")
	wantTags := map[string]bool{"main": false, "button": false, "input": false, "table": false, "img": false, "video": false, "canvas": false}
	for _, tag := range tags {
		if _, ok := wantTags[tag]; ok {
			wantTags[tag] = true
		}
	}
	for tag, found := range wantTags {
		if !found {
			t.Fatalf("render tag enum missing %q", tag)
		}
	}

	globalAttributes := requireStringSlice(t, policy["global_attributes"], "global attributes")
	for _, required := range []string{"id", "class", "role", "data-redevplugin-action", "data-redevplugin-asset-binding", "data-redevplugin-asset-attr"} {
		if !containsStringValue(globalAttributes, required) {
			t.Fatalf("global attributes missing %q", required)
		}
	}
	tagAttributes, ok := policy["tag_attributes"].(map[string]any)
	if !ok {
		t.Fatal("render policy tag_attributes must be an object")
	}
	for tag := range tagAttributes {
		if !containsStringValue(tags, tag) {
			t.Fatalf("tag_attributes defines unsupported tag %q", tag)
		}
	}
}

func readBridgeSchema(t *testing.T) map[string]any {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "bridge-v4.schema.json"))
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

func containsStringValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
