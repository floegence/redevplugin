package manifest

import (
	"strings"
	"testing"
)

func TestDecodeValidManifest(t *testing.T) {
	raw := validManifestJSON()

	manifest, err := Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if manifest.PluginID() != "com.example.containers" {
		t.Fatalf("PluginID() = %q", manifest.PluginID())
	}
	if manifest.Version() != "1.0.0" {
		t.Fatalf("Version() = %q", manifest.Version())
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	raw := strings.Replace(validManifestJSON(), `"intents": [`, `"native_backend": true, "intents": [`, 1)

	if _, err := Decode(strings.NewReader(raw)); err == nil {
		t.Fatal("Decode() expected error for unknown field")
	}
}

func TestDecodeRejectsTrailingJSONValue(t *testing.T) {
	raw := validManifestJSON() + `{}`

	if _, err := Decode(strings.NewReader(raw)); err == nil {
		t.Fatal("Decode() expected trailing JSON error")
	}
}

func TestValidateRejectsIntentMissingMethod(t *testing.T) {
	m := validManifest()
	m.Intents = []IntentSpec{{IntentID: "missing", Method: "containers.inspect"}}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected missing method error")
	}
}

func TestValidateRejectsSameSurfaceIDAcrossKinds(t *testing.T) {
	m := validManifest()
	m.Surfaces = []SurfaceSpec{
		{SurfaceID: "containers", Kind: SurfaceActivity, Label: "Containers", Entry: "ui/index.html"},
		{SurfaceID: "containers", Kind: SurfaceWorkbench, Label: "Containers", Entry: "ui/index.html"},
	}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected duplicate surface_id error")
	}
}

func TestValidateRequiresCancelPolicyForSubscription(t *testing.T) {
	m := validManifest()
	m.Methods = append(m.Methods, MethodSpec{
		Method:    "containers.logs.tail",
		Effect:    MethodEffectRead,
		Execution: MethodExecutionSubscription,
		Route:     MethodRouteSpec{Kind: MethodRouteCapability, BindingID: "container_runtime", TargetMethod: "containers.logs.tail"},
	})

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected cancel_policy error")
	}
}

func validManifest() Manifest {
	return Manifest{
		SchemaVersion: "redeven.plugin.manifest.v1",
		Publisher:     Publisher{PublisherID: "example", DisplayName: "Example"},
		Plugin: Plugin{
			PluginID:          "com.example.containers",
			DisplayName:       "Containers",
			Version:           "1.0.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.1.0",
			UIProtocolVersion: "plugin-ui-v1",
		},
		Surfaces: []SurfaceSpec{
			{SurfaceID: "containers.activity", Kind: SurfaceActivity, Label: "Containers", Entry: "ui/index.html", Method: "containers.list"},
		},
		CapabilityBindings: []CapabilityBinding{
			{BindingID: "container_runtime", CapabilityID: "redeven.capability.container_resources", MinCapabilityVersion: "1.0.0", RequiredPermissions: []string{"read"}},
		},
		Methods: []MethodSpec{
			{
				Method:         "containers.list",
				Effect:         MethodEffectRead,
				Execution:      MethodExecutionSync,
				Route:          MethodRouteSpec{Kind: MethodRouteCapability, BindingID: "container_runtime", TargetMethod: "containers.list"},
				RequestSchema:  map[string]any{"type": "object", "additionalProperties": false},
				ResponseSchema: map[string]any{"type": "object"},
			},
		},
		Settings: &SettingsSpec{
			SchemaVersion: 1,
			Migration:     noopMigration(),
			Fields: []SettingFieldSpec{
				{Key: "default_engine", Type: "select", Scope: "user", Label: "Default engine", Default: "docker", Options: []string{"docker", "podman"}},
			},
		},
		Intents: []IntentSpec{{IntentID: "open-container-list", Method: "containers.list"}},
	}
}

func noopMigration() MigrationSpec {
	return MigrationSpec{
		FromVersion:    1,
		ToVersion:      1,
		Reversible:     true,
		RequiresWorker: false,
		StepsHash:      "sha256:empty",
	}
}

func validManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.containers",
			"display_name": "Containers",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "containers.activity", "kind": "activity", "label": "Containers", "entry": "ui/index.html", "method": "containers.list"}
		],
		"capability_bindings": [
			{"binding_id": "container_runtime", "capability_id": "redeven.capability.container_resources", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "containers.list",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "capability", "binding_id": "container_runtime", "target_method": "containers.list"},
				"request_schema": {"type": "object", "additionalProperties": false},
				"response_schema": {"type": "object"}
			}
		],
		"settings": {
			"schema_version": 1,
			"migration": {
				"from_version": 1,
				"to_version": 1,
				"reversible": true,
				"requires_worker": false,
				"estimated_bytes": 0,
				"max_duration_ms": 1000,
				"data_loss_risk": false,
				"steps_hash": "sha256:empty"
			},
			"fields": [
				{"key": "default_engine", "type": "select", "scope": "user", "label": "Default engine", "default": "docker", "options": ["docker", "podman"]}
			]
		},
		"intents": [
			{"intent_id": "open-container-list", "method": "containers.list"}
		]
	}`
}
