package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestOpaqueSurfaceDocumentSchemaIsClosedAndDigestBound(t *testing.T) {
	schema := readPluginSchema(t, "opaque-surface-document-v3.schema.json")
	if schema["additionalProperties"] != false {
		t.Fatalf("opaque document additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, schema["required"], "opaque document required"), []string{
		"schema_version",
		"entry_path",
		"entry_sha256",
		"body_html",
		"styles",
		"worker",
		"assets",
		"critical_bytes",
	}, "opaque document required fields")
	props := requireNestedObject(t, schema, "properties")
	if got := requireNestedObject(t, props, "schema_version")["const"]; got != "redevplugin.opaque_surface_document.v3" {
		t.Fatalf("opaque document schema_version = %#v", got)
	}
	if got := requireNestedObject(t, props, "entry_sha256")["$ref"]; got != "#/$defs/sha256" {
		t.Fatalf("opaque document entry_sha256 ref = %#v", got)
	}
	worker := requireNestedObject(t, schema, "$defs", "worker")
	if worker["additionalProperties"] != false {
		t.Fatalf("opaque worker additionalProperties = %#v, want false", worker["additionalProperties"])
	}
	workerProps := requireNestedObject(t, worker, "properties")
	if got := requireNestedObject(t, workerProps, "type")["const"]; got != "classic" {
		t.Fatalf("opaque worker type = %#v, want classic", got)
	}
	asset := requireNestedObject(t, schema, "$defs", "asset")
	if asset["additionalProperties"] != false {
		t.Fatalf("opaque asset additionalProperties = %#v, want false", asset["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, asset["required"], "opaque asset required"), []string{
		"binding_id",
		"logical_ids",
		"path",
		"sha256",
		"size",
		"content_type",
	}, "opaque asset required fields")
	logicalIDs := requireNestedObject(t, asset, "properties", "logical_ids")
	if logicalIDs["uniqueItems"] != true || logicalIDs["minItems"] != float64(1) || logicalIDs["maxItems"] != float64(16) {
		t.Fatalf("opaque asset logical id bounds = %#v", logicalIDs)
	}
	assets := requireNestedObject(t, props, "assets")
	if assets["maxItems"] != float64(128) {
		t.Fatalf("opaque document assets maxItems = %#v, want 128", assets["maxItems"])
	}
	size := requireNestedObject(t, asset, "properties", "size")
	if size["minimum"] != float64(0) || size["maximum"] != float64(32<<20) {
		t.Fatalf("opaque asset size bounds = %#v, want 0..%d", size, 32<<20)
	}
	if _, ok := requireNestedObject(t, asset, "properties")["content"]; ok {
		t.Fatal("lazy opaque assets must not embed content in the critical document")
	}
}

func TestOpaqueSurfaceTransportExposesOnlyOpaqueHandles(t *testing.T) {
	schema := readPluginSchema(t, "opaque-surface-transport-v4.schema.json")
	refs := requireObjectArray(t, schema["oneOf"], "opaque transport oneOf")
	wantRefs := map[string]bool{
		"#/$defs/port_envelope":     false,
		"#/$defs/port_ack":          false,
		"#/$defs/initialize":        false,
		"#/$defs/first_paint":       false,
		"#/$defs/first_commit":      false,
		"#/$defs/worker_ready":      false,
		"#/$defs/surface_error":     false,
		"#/$defs/asset_read":        false,
		"#/$defs/asset_response":    false,
		"#/$defs/worker_initialize": false,
	}
	for _, ref := range refs {
		value, ok := ref["$ref"].(string)
		if !ok {
			t.Fatalf("opaque transport oneOf entry = %#v, want $ref", ref)
		}
		if _, ok := wantRefs[value]; !ok {
			t.Fatalf("unexpected opaque transport ref %q", value)
		}
		wantRefs[value] = true
	}
	for ref, found := range wantRefs {
		if !found {
			t.Fatalf("opaque transport missing %q", ref)
		}
	}

	defs := requireNestedObject(t, schema, "$defs")
	for _, name := range []string{
		"port_envelope",
		"port_ack",
		"initialize",
		"first_paint",
		"worker_ready",
		"surface_error",
		"asset_read",
		"asset_response",
		"worker_initialize",
	} {
		if got := requireNestedObject(t, defs, name)["additionalProperties"]; got != false {
			t.Fatalf("opaque transport %s additionalProperties = %#v, want false", name, got)
		}
	}
	initialize := requireNestedObject(t, defs, "initialize")
	if got := requireNestedObject(t, initialize, "properties", "document")["$ref"]; got != "https://schemas.redevplugin.dev/plugin/opaque-surface-document-v3.schema.json" {
		t.Fatalf("opaque initialize document ref = %#v", got)
	}
	assetResponse := requireNestedObject(t, defs, "asset_response")
	if got := requireNestedObject(t, assetResponse, "properties", "content_base64")["contentEncoding"]; got != "base64" {
		t.Fatalf("opaque asset response content encoding = %#v", got)
	}
	workerInitialize := requireNestedObject(t, defs, "worker_initialize")
	portRoles := requireNestedObject(t, workerInitialize, "properties", "port_roles")
	prefixItems := requireObjectArray(t, portRoles["prefixItems"], "opaque worker port roles")
	if len(prefixItems) != 2 || prefixItems[0]["const"] != "runtime_control" || prefixItems[1]["const"] != "plugin_bridge" {
		t.Fatalf("opaque worker port roles = %#v, want runtime_control then plugin_bridge", prefixItems)
	}
	if portRoles["minItems"] != float64(2) || portRoles["maxItems"] != float64(2) {
		t.Fatalf("opaque worker port role cardinality = %#v", portRoles)
	}

	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"asset_ticket",
		"asset_session",
		"bridge_token",
		"plugin_gateway_token",
		"stream_ticket",
		"runtime_lease",
		"owner_session_hash",
		"session_channel_id_hash",
		"sandbox_origin",
		"http://",
		"https://localhost",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("opaque transport must not expose %q", forbidden)
		}
	}
}

func TestOpaqueSurfaceSchemasCompileAndRejectUnsafePackagePaths(t *testing.T) {
	root := repoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for resource, path := range map[string]string{
		"https://schemas.redevplugin.dev/plugin/opaque-surface-document-v3.schema.json": "opaque-surface-document-v3.schema.json",
		"urn:redevplugin:opaque-surface-transport-v4":                                   "opaque-surface-transport-v4.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", path))
		if err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	compiled, err := compiler.Compile("urn:redevplugin:opaque-surface-transport-v4")
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"schema_version": "redevplugin.opaque_surface_document.v3",
		"entry_path":     "ui/index.html",
		"entry_sha256":   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"body_html":      "<main></main>",
		"styles":         []any{},
		"worker": map[string]any{
			"path":    "ui/worker.js",
			"sha256":  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"type":    "classic",
			"content": "self.onmessage = () => {};",
		},
		"assets":         []any{},
		"critical_bytes": 128,
	}
	initialize := map[string]any{
		"type":                "redevplugin.surface.initialize",
		"frame_generation_id": "frame_12345678",
		"surface_handle":      "surface_12345678",
		"document":            document,
	}
	if err := compiled.Validate(initialize); err != nil {
		t.Fatalf("valid initialize frame: %v", err)
	}
	for _, path := range []string{"/ui/index.html", `ui\index.html`, "../index.html", "ui/../index.html", "ui/./index.html"} {
		invalidDocument := cloneOpaqueObject(document)
		invalidDocument["entry_path"] = path
		invalid := cloneOpaqueObject(initialize)
		invalid["document"] = invalidDocument
		if err := compiled.Validate(invalid); err == nil {
			t.Errorf("unsafe package path %q must be rejected", path)
		}
	}
}

func cloneOpaqueObject(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func readPluginSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}
