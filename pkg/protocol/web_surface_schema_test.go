package protocol

import (
	"bytes"
	"encoding/json"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebSurfaceDocumentIsOneClosedOriginBinding(t *testing.T) {
	schema := readPluginSchema(t, "web-surface-document.schema.json")
	if schema["additionalProperties"] != false {
		t.Fatal("document must be closed")
	}
	assertStringSet(t, requireStringSlice(t, schema["required"], "document required"), []string{"schema_version", "origin", "parent_origin", "bootstrap_url", "entry_url"}, "document fields")
	if requireNestedObject(t, schema, "properties", "schema_version")["const"] != "redevplugin.web_surface.v1" {
		t.Fatal("wrong document identity")
	}
}

func TestWebSurfaceTransportIsClosedAndSecretFree(t *testing.T) {
	schema := readPluginSchema(t, "web-surface-transport.schema.json")
	names := []string{"port_envelope", "port_ack", "initialize", "context", "surface_error", "interaction", "entry_ready", "entry_error", "app_ready", "navigation", "quiesce_ack", "file_export", "close_request", "close_response"}
	refs := requireObjectArray(t, schema["oneOf"], "transport variants")
	var got []string
	for _, ref := range refs {
		got = append(got, ref["$ref"].(string))
	}
	var want []string
	for _, name := range names {
		want = append(want, "#/$defs/"+name)
		if requireNestedObject(t, schema, "$defs", name)["additionalProperties"] != false {
			t.Fatalf("open frame %s", name)
		}
	}
	assertStringSet(t, got, want, "Web transport messages")
	raw, _ := json.Marshal(schema)
	for _, secret := range []string{"asset_ticket", "asset_session", "plugin_gateway_token", "stream_ticket", "runtime_lease", "owner_session_hash"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("transport exposes %s", secret)
		}
	}
}

func TestWebSurfaceTransportRejectsRetiredAndAuthorityBearingMessages(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec/plugin/web-surface-transport.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:web", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:web")
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []map[string]any{
		{"type": "redevplugin.surface.entry_ready", "entry_path": "/index.html", "document_id": "document_12345678"},
		{"type": "redevplugin.surface.app_ready", "frame_generation_id": "frame_12345678"},
		{"type": "redevplugin.surface.initialize", "frame_generation_id": "frame_12345678", "surface_handle": "surface_12345678", "entry_path": "/index.html"},
	} {
		if err := schema.Validate(message); err != nil {
			t.Fatal(err)
		}
	}
	for _, message := range []map[string]any{
		{"type": "redevplugin.surface.renderer_ready"},
		{"type": "redevplugin.surface.first_commit"},
		{"type": "redevplugin.surface.entry_ready", "asset_ticket": "secret"},
		{"type": "redevplugin.surface.app_ready"},
		{"type": "redevplugin.surface.initialize", "frame_generation_id": "frame_12345678", "surface_handle": "surface_12345678", "entry_path": "https://remote.example/"},
	} {
		if err := schema.Validate(message); err == nil {
			t.Fatalf("accepted invalid message %#v", message)
		}
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot(t), "testdata/contracts/web-surface-interaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var interaction map[string]any
	if err = json.Unmarshal(raw, &interaction); err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(interaction); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"unexpected": true, "action": ":open", "selection_active": true} {
		invalid := cloneWebObject(interaction)
		invalid[key] = value
		if err = schema.Validate(invalid); err == nil {
			t.Fatalf("accepted invalid interaction %s", key)
		}
	}
}

func cloneWebObject(source map[string]any) map[string]any {
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

func TestWebSurfaceOpeningDiagnostics(t *testing.T) {
	root := repoRoot(t)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "web-surface-transport.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("urn:opening", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "web-surface-document.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("https://schemas.redevplugin.dev/plugin/web-surface-document.schema.json", bytes.NewReader(document)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:opening#/$defs/opening_progress")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "testdata", "contracts", "web-surface-opening.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatal(err)
	}
	for key, invalid := range map[string]any{
		"elapsedMs": -1, "stageElapsedMs": 1.5, "stage": "paint", "phase": "ready",
		"pendingMilestones": []any{"token", "token"}, "asset_ticket": "secret",
	} {
		t.Run(key, func(t *testing.T) {
			changed := make(map[string]any)
			for k, v := range value {
				changed[k] = v
			}
			changed[key] = invalid
			if err := schema.Validate(changed); err == nil {
				t.Fatalf("accepted invalid %s", key)
			}
		})
	}
}
