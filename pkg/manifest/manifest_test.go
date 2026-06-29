package manifest

import (
	"strings"
	"testing"
)

func TestDecodeValidManifest(t *testing.T) {
	raw := `{
		"plugin_id": "com.example.containers",
		"publisher": {"id": "example"},
		"version": "1.0.0",
		"display_name": "Containers",
		"redeven": {"api_version": "plugin-v1", "min_runtime_version": "0.1.0"},
		"ui": {"entrypoint": "ui/index.html", "sandbox": {"tokens": ["allow-scripts"]}},
		"backend": {"kind": "none"},
		"capabilities": [{"binding_id": "container_resources", "capability_id": "redeven.container_resources", "min_capability_version": "1.0.0"}],
		"methods": [{"name": "containers.list", "effect": "read", "execution_mode": "sync", "route": {"kind": "capability", "binding_id": "container_resources"}}],
		"surfaces": [{"surface_id": "containers", "kind": "activity", "label": "Containers", "method": "containers.list"}],
		"intents": [{"intent_id": "open-container-list", "method": "containers.list"}]
	}`

	manifest, err := Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if manifest.PluginID != "com.example.containers" {
		t.Fatalf("PluginID = %q", manifest.PluginID)
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	raw := `{
		"plugin_id": "com.example.bad",
		"publisher": {"id": "example"},
		"version": "1.0.0",
		"display_name": "Bad",
		"redeven": {"api_version": "plugin-v1", "min_runtime_version": "0.1.0"},
		"ui": {"entrypoint": "ui/index.html", "sandbox": {"tokens": ["allow-scripts"]}},
		"backend": {"kind": "none"},
		"native_backend": true
	}`

	if _, err := Decode(strings.NewReader(raw)); err == nil {
		t.Fatal("Decode() expected error for unknown field")
	}
}

func TestValidateRejectsIntentMissingMethod(t *testing.T) {
	m := Manifest{
		PluginID:    "com.example.bad",
		Publisher:   Publisher{ID: "example"},
		Version:     "1.0.0",
		DisplayName: "Bad",
		Redeven:     RuntimeConstraint{APIVersion: "plugin-v1", MinRuntimeVersion: "0.1.0"},
		UI:          UISpec{Entrypoint: "ui/index.html", Sandbox: SandboxSpec{Tokens: []string{"allow-scripts"}}},
		Backend:     BackendSpec{Kind: BackendNone},
		Intents:     []IntentSpec{{IntentID: "missing", Method: "containers.inspect"}},
	}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected missing method error")
	}
}

func TestValidateAllowsSameSurfaceIDAcrossKinds(t *testing.T) {
	m := Manifest{
		PluginID:    "com.example.surfaces",
		Publisher:   Publisher{ID: "example"},
		Version:     "1.0.0",
		DisplayName: "Surfaces",
		Redeven:     RuntimeConstraint{APIVersion: "plugin-v1", MinRuntimeVersion: "0.1.0"},
		UI:          UISpec{Entrypoint: "ui/index.html", Sandbox: SandboxSpec{Tokens: []string{"allow-scripts"}}},
		Backend:     BackendSpec{Kind: BackendNone},
		Surfaces: []SurfaceSpec{
			{SurfaceID: "containers", Kind: SurfaceActivity, Label: "Containers"},
			{SurfaceID: "containers", Kind: SurfaceWorkbench, Label: "Containers"},
		},
	}

	if err := Validate(m); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
