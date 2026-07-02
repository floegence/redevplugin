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
	if manifest.PluginID() != "com.example.resources" {
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
	m.Intents = []IntentSpec{{IntentID: "missing", Method: "resources.inspect"}}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected missing method error")
	}
}

func TestValidateRejectsSameSurfaceIDAcrossKinds(t *testing.T) {
	m := validManifest()
	m.Surfaces = []SurfaceSpec{
		{SurfaceID: "resources", Kind: SurfaceActivity, Label: "Resources", Entry: "ui/index.html"},
		{SurfaceID: "resources", Kind: SurfaceWorkbench, Label: "Resources", Entry: "ui/index.html"},
	}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected duplicate surface_id error")
	}
}

func TestValidateRequiresCancelPolicyForSubscription(t *testing.T) {
	m := validManifest()
	m.Methods = append(m.Methods, MethodSpec{
		Method:    "resources.logs.tail",
		Effect:    MethodEffectRead,
		Execution: MethodExecutionSubscription,
		Route:     MethodRouteSpec{Kind: MethodRouteCapability, BindingID: "resource_provider", TargetMethod: "resources.logs.tail"},
	})

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected cancel_policy error")
	}
}

func TestValidateNetworkConnectors(t *testing.T) {
	m := validManifest()
	m.NetworkAccess = &NetworkAccessSpec{Connectors: []NetworkConnectorSpec{{
		ConnectorID:  "api",
		Transport:    "http",
		Scope:        "user",
		Destinations: []string{"api.example.com"},
	}}}
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	m.NetworkAccess.Connectors = append(m.NetworkAccess.Connectors, NetworkConnectorSpec{
		ConnectorID:  "api",
		Transport:    "tcp",
		Scope:        "environment",
		Destinations: []string{"db.example.com:3306"},
	})
	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected duplicate connector error")
	}

	m.NetworkAccess.Connectors[1].ConnectorID = "db"
	m.NetworkAccess.Connectors[1].Transport = "icmp"
	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected transport error")
	}

	m.NetworkAccess.Connectors[1].Transport = "tcp"
	m.NetworkAccess.Connectors[1].Scope = "global"
	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected scope error")
	}
}

func TestValidateStorageQuotaFiles(t *testing.T) {
	m := validManifest()
	m.Storage = &StorageSpec{Stores: []StoreSpec{{
		StoreID:       "cache",
		Kind:          "kv",
		Scope:         "user",
		QuotaBytes:    1024,
		SchemaVersion: 1,
		Migration:     noopMigration(),
	}}}
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() without quota_files error = %v", err)
	}

	quotaFiles := int64(1)
	m.Storage.Stores[0].QuotaFiles = &quotaFiles
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() with quota_files error = %v", err)
	}

	for _, value := range []int64{0, -1} {
		m.Storage.Stores[0].QuotaFiles = &value
		if err := Validate(m); err == nil {
			t.Fatalf("Validate() with quota_files=%d expected error", value)
		}
	}
}

func TestValidateWorkers(t *testing.T) {
	m := validManifest()
	m.Workers = []WorkerSpec{{
		WorkerID:         "echo_worker",
		Artifact:         "workers/echo.wasm",
		ABI:              "redevplugin-wasm-worker-v1",
		Mode:             WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	}}
	m.Methods = append(m.Methods, MethodSpec{
		Method:    "worker.echo",
		Effect:    MethodEffectRead,
		Execution: MethodExecutionSync,
		Route:     MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "echo_worker", Export: "redevplugin_worker_invoke"},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() worker manifest error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Manifest)
		field  string
	}{
		{
			name: "duplicate worker id",
			mutate: func(m *Manifest) {
				m.Workers = append(m.Workers, m.Workers[0])
			},
			field: "workers[1].worker_id",
		},
		{
			name: "missing artifact",
			mutate: func(m *Manifest) {
				m.Workers[0].Artifact = ""
			},
			field: "workers[0].artifact",
		},
		{
			name: "invalid abi",
			mutate: func(m *Manifest) {
				m.Workers[0].ABI = "other-abi"
			},
			field: "workers[0].abi",
		},
		{
			name: "invalid mode",
			mutate: func(m *Manifest) {
				m.Workers[0].Mode = WorkerMode("daemon")
			},
			field: "workers[0].mode",
		},
		{
			name: "invalid scope",
			mutate: func(m *Manifest) {
				m.Workers[0].Scope = "global"
			},
			field: "workers[0].scope",
		},
		{
			name: "invalid memory",
			mutate: func(m *Manifest) {
				m.Workers[0].MemoryLimitBytes = 0
			},
			field: "workers[0].memory_limit_bytes",
		},
		{
			name: "route references missing worker",
			mutate: func(m *Manifest) {
				m.Methods[1].Route.WorkerID = "missing_worker"
			},
			field: "methods[1].route.worker_id",
		},
		{
			name: "worker route requires export",
			mutate: func(m *Manifest) {
				m.Methods[1].Route.Export = ""
			},
			field: "methods[1].route.export",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := m
			candidate.Workers = append([]WorkerSpec(nil), m.Workers...)
			candidate.Methods = append([]MethodSpec(nil), m.Methods...)
			tc.mutate(&candidate)
			err := Validate(candidate)
			if err == nil {
				t.Fatal("Validate() expected worker validation error")
			}
			if validationErr, ok := err.(ValidationError); !ok || validationErr.Field != tc.field {
				t.Fatalf("Validate() error = %v, want field %s", err, tc.field)
			}
		})
	}
}

func TestValidateCoreActionRouteRequiresActionID(t *testing.T) {
	m := validManifest()
	m.Methods = append(m.Methods, MethodSpec{
		Method:    "core.open",
		Effect:    MethodEffectRead,
		Execution: MethodExecutionSync,
		Route:     MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "example.open_settings"},
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() core_action manifest error = %v", err)
	}

	m.Methods[len(m.Methods)-1].Route.ActionID = ""
	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected missing action_id error")
	}
}

func validManifest() Manifest {
	return Manifest{
		SchemaVersion: "redevplugin.manifest.v1",
		Publisher:     Publisher{PublisherID: "example", DisplayName: "Example"},
		Plugin: Plugin{
			PluginID:          "com.example.resources",
			DisplayName:       "Resources",
			Version:           "1.0.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.1.0",
			UIProtocolVersion: "plugin-ui-v1",
		},
		Surfaces: []SurfaceSpec{
			{SurfaceID: "resources.activity", Kind: SurfaceActivity, Label: "Resources", Entry: "ui/index.html", Method: "resources.list"},
		},
		CapabilityBindings: []CapabilityBinding{
			{BindingID: "resource_provider", CapabilityID: "example.capability.resources", MinCapabilityVersion: "1.0.0", RequiredPermissions: []string{"read"}},
		},
		Methods: []MethodSpec{
			{
				Method:         "resources.list",
				Effect:         MethodEffectRead,
				Execution:      MethodExecutionSync,
				Route:          MethodRouteSpec{Kind: MethodRouteCapability, BindingID: "resource_provider", TargetMethod: "resources.list"},
				RequestSchema:  map[string]any{"type": "object", "additionalProperties": false},
				ResponseSchema: map[string]any{"type": "object"},
			},
		},
		Settings: &SettingsSpec{
			SchemaVersion: 1,
			Migration:     noopMigration(),
			Fields: []SettingFieldSpec{
				{Key: "default_source", Type: "select", Scope: "user", Label: "Default source", Default: "primary", Options: []string{"primary", "secondary"}},
			},
		},
		Intents: []IntentSpec{{IntentID: "open-resource-list", Method: "resources.list"}},
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
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.resources",
			"display_name": "Resources",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "resources.activity", "kind": "activity", "label": "Resources", "entry": "ui/index.html", "method": "resources.list"}
		],
		"capability_bindings": [
			{"binding_id": "resource_provider", "capability_id": "example.capability.resources", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "resources.list",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "capability", "binding_id": "resource_provider", "target_method": "resources.list"},
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
				{"key": "default_source", "type": "select", "scope": "user", "label": "Default source", "default": "primary", "options": ["primary", "secondary"]}
			]
		},
		"intents": [
			{"intent_id": "open-resource-list", "method": "resources.list"}
		]
	}`
}
