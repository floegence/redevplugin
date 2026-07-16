package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
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

func TestValidateMatchesCurrentManifestRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*Manifest)
	}{
		{
			name:  "plugin display name",
			field: "plugin.display_name",
			mutate: func(m *Manifest) {
				m.Plugin.DisplayName = " "
			},
		},
		{
			name:  "minimum runtime version",
			field: "plugin.min_runtime_version",
			mutate: func(m *Manifest) {
				m.Plugin.MinRuntimeVersion = ""
			},
		},
		{
			name:  "surfaces field",
			field: "surfaces",
			mutate: func(m *Manifest) {
				m.Surfaces = nil
			},
		},
		{
			name:  "negative worker idle timeout",
			field: "workers[0].idle_timeout_ms",
			mutate: func(m *Manifest) {
				m.Workers = []WorkerSpec{{
					WorkerID: "worker", Artifact: "workers/worker.wasm", ABI: "redevplugin-wasm-worker-v2",
					Mode: WorkerModeJob, Scope: "user", MemoryLimitBytes: 1 << 20, IdleTimeoutMS: -1,
				}}
			},
		},
		{
			name:  "empty network destination",
			field: "network_access.connectors[0].destinations[0]",
			mutate: func(m *Manifest) {
				m.NetworkAccess = &NetworkAccessSpec{Connectors: []NetworkConnectorSpec{{
					ConnectorID: "api", Transport: "http", Scope: "user", Destinations: []string{" "},
				}}}
			},
		},
		{
			name:  "setting label",
			field: "settings.fields[0].label",
			mutate: func(m *Manifest) {
				m.Settings.Fields[0].Label = ""
			},
		},
		{
			name:  "intent id",
			field: "intents[0].intent_id",
			mutate: func(m *Manifest) {
				m.Intents[0].IntentID = " "
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := validManifest()
			tt.mutate(&candidate)
			var validationErr ValidationError
			if err := Validate(candidate); !errors.As(err, &validationErr) {
				t.Fatalf("Validate() error = %v, want ValidationError", err)
			}
			if validationErr.Field != tt.field {
				t.Fatalf("Validate() field = %q, want %q", validationErr.Field, tt.field)
			}
		})
	}
}

func TestValidateRequiresClosedMethodSchemas(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*MethodSpec)
	}{
		{
			name:  "request schema is required",
			field: "methods[0].request_schema",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = nil
			},
		},
		{
			name:  "response schema is required",
			field: "methods[0].response_schema",
			mutate: func(method *MethodSpec) {
				method.ResponseSchema = nil
			},
		},
		{
			name:  "request schema must describe an object",
			field: "methods[0].request_schema.type",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
			},
		},
		{
			name:  "response schema must reject unknown fields",
			field: "methods[0].response_schema.additionalProperties",
			mutate: func(method *MethodSpec) {
				method.ResponseSchema = map[string]any{"type": "object", "additionalProperties": true}
			},
		},
		{
			name:  "nested objects must reject unknown fields",
			field: "methods[0].request_schema.properties.filter.additionalProperties",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"type": "object"},
					},
				}
			},
		},
		{
			name:  "nullable nested objects must reject unknown fields",
			field: "methods[0].request_schema.properties.filter.additionalProperties",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"type": []any{"object", "null"}},
					},
				}
			},
		},
		{
			name:  "implicit object schemas must reject unknown fields",
			field: "methods[0].request_schema.properties.filter.additionalProperties",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"properties": map[string]any{"name": map[string]any{"type": "string"}}},
					},
				}
			},
		},
		{
			name:  "unconstrained nested schemas must be rejected",
			field: "methods[0].request_schema.properties.filter",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{},
					},
				}
			},
		},
		{
			name:  "negative composition cannot imply an open object domain",
			field: "methods[0].request_schema.properties.filter",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"not": map[string]any{"type": "string"}},
					},
				}
			},
		},
		{
			name:  "true nested schemas must be rejected",
			field: "methods[0].request_schema.properties.filter",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": true,
					},
				}
			},
		},
		{
			name:  "external references are forbidden",
			field: "methods[0].request_schema.$ref",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"$ref":                 "https://schemas.example.test/request.json",
				}
			},
		},
		{
			name:  "invalid schema keywords are rejected",
			field: "methods[0].request_schema",
			mutate: func(method *MethodSpec) {
				method.RequestSchema = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"minProperties":        "invalid",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.mutate(&m.Methods[0])
			expectValidationField(t, m, tt.field)
		})
	}
}

func TestCompileMethodSchemasValidatesInstances(t *testing.T) {
	method := validManifest().Methods[0]
	compiled, err := CompileMethodSchemas(method)
	if err != nil {
		t.Fatalf("CompileMethodSchemas() error = %v", err)
	}
	if err := compiled.ValidateRequest(map[string]any{}); err != nil {
		t.Fatalf("ValidateRequest(valid) error = %v", err)
	}
	if err := compiled.ValidateRequest(map[string]any{"unknown": true}); err == nil {
		t.Fatal("ValidateRequest(unknown field) expected error")
	}
	if err := compiled.ValidateResponse(map[string]any{}); err != nil {
		t.Fatalf("ValidateResponse(valid) error = %v", err)
	}
	if err := compiled.ValidateResponse(map[string]any{"unknown": true}); err == nil {
		t.Fatal("ValidateResponse(unknown field) expected error")
	}
}

func TestCompileMethodSchemasTraversesOnlySubschemaKeywords(t *testing.T) {
	method := validManifest().Methods[0]
	method.RequestSchema = map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"properties": map[string]any{"type": "string"},
			"settings": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"mode": map[string]any{"type": "string"},
				},
				"default":  map[string]any{"properties": "literal default data"},
				"const":    map[string]any{"properties": "literal const data"},
				"examples": []any{map[string]any{"properties": "literal example data"}},
			},
		},
	}
	if _, err := CompileMethodSchemas(method); err != nil {
		t.Fatalf("CompileMethodSchemas() annotation data error = %v", err)
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
		{SurfaceID: "resources", Kind: SurfaceView, Label: "Resources", Entry: "ui/index.html"},
		{SurfaceID: "resources", Kind: SurfaceCommand, Label: "Resources", Entry: "ui/index.html"},
	}

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected duplicate surface_id error")
	}
}

func TestValidateRejectsInvalidHostNeutralSurfaceContract(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*SurfaceSpec)
	}{
		{name: "missing id", field: "surfaces[0].surface_id", mutate: func(surface *SurfaceSpec) { surface.SurfaceID = " " }},
		{name: "product placement kind", field: "surfaces[0].kind", mutate: func(surface *SurfaceSpec) { surface.Kind = SurfaceKind("activity") }},
		{name: "invalid intent", field: "surfaces[0].intent", mutate: func(surface *SurfaceSpec) { surface.Intent = SurfaceIntent("modal") }},
		{name: "missing label", field: "surfaces[0].label", mutate: func(surface *SurfaceSpec) { surface.Label = " " }},
		{name: "invalid width", field: "surfaces[0].default_size.width", mutate: func(surface *SurfaceSpec) { surface.DefaultSize = &WidgetSizeSpec{Width: 0, Height: 400} }},
		{name: "invalid height", field: "surfaces[0].default_size.height", mutate: func(surface *SurfaceSpec) { surface.DefaultSize = &WidgetSizeSpec{Width: 600, Height: -1} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.mutate(&m.Surfaces[0])
			expectValidationField(t, m, tt.field)
		})
	}
}

func TestValidateRequiresCancelPolicyForSubscription(t *testing.T) {
	m := validManifest()
	m.Methods = append(m.Methods, MethodSpec{
		Method:    "resources.logs.tail",
		Effect:    MethodEffectRead,
		Execution: MethodExecutionSubscription,
		Route:     MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "resources.logs.tail"},
	})

	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected cancel_policy error")
	}
}

func TestValidateMethodRouteDiscriminatedUnion(t *testing.T) {
	t.Run("capability route requires target method", func(t *testing.T) {
		m := validCapabilityManifest()
		m.Methods[0].Route.TargetMethod = ""

		expectValidationField(t, m, "methods[0].route.target_method")
	})

	t.Run("capability route rejects worker fields", func(t *testing.T) {
		m := validCapabilityManifest()
		m.Methods[0].Route.WorkerID = "echo_worker"

		expectValidationField(t, m, "methods[0].route.worker_id")
	})

	t.Run("worker route rejects capability fields", func(t *testing.T) {
		m := validManifestWithWorkerMethod()
		m.Methods[1].Route.BindingID = "resource_provider"

		expectValidationField(t, m, "methods[1].route.binding_id")
	})

	t.Run("core action route rejects capability fields", func(t *testing.T) {
		m := validManifest()
		m.Methods = append(m.Methods, MethodSpec{
			Method:    "core.open",
			Effect:    MethodEffectRead,
			Execution: MethodExecutionSync,
			Route:     MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "example.open_settings", BindingID: "resource_provider"},
		})

		expectValidationField(t, m, "methods[1].route.binding_id")
	})
}

func TestValidateMethodConfirmationContract(t *testing.T) {
	t.Run("allows dangerous operation with risk preflight", func(t *testing.T) {
		m := validManifestWithRiskPreflightOperation()

		if err := Validate(m); err != nil {
			t.Fatalf("Validate() risk preflight operation error = %v", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(*Manifest)
		field  string
	}{
		{
			name: "dangerous method requires explicit confirmation",
			mutate: func(m *Manifest) {
				m.Methods[0].Dangerous = true
			},
			field: "methods[0].confirmation",
		},
		{
			name: "dangerous method rejects none confirmation",
			mutate: func(m *Manifest) {
				m.Methods[0].Dangerous = true
				m.Methods[0].Confirmation = &ConfirmationSpec{Mode: ConfirmationNone}
			},
			field: "methods[0].confirmation.mode",
		},
		{
			name: "rejects invalid confirmation mode",
			mutate: func(m *Manifest) {
				m.Methods[0].Confirmation = &ConfirmationSpec{Mode: ConfirmationMode("prompt")}
			},
			field: "methods[0].confirmation.mode",
		},
		{
			name: "preflight method must not be empty",
			mutate: func(m *Manifest) {
				m.Methods[0].Confirmation = &ConfirmationSpec{
					Mode:             ConfirmationRiskBased,
					PreflightMethod:  stringPtr(" "),
					PlanHashRequired: true,
				}
			},
			field: "methods[0].confirmation.preflight_method",
		},
		{
			name: "preflight method requires plan hash",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod())
				m.Methods[0].Confirmation = &ConfirmationSpec{
					Mode:            ConfirmationRiskBased,
					PreflightMethod: stringPtr("resources.start.preflight"),
				}
			},
			field: "methods[0].confirmation.plan_hash_required",
		},
		{
			name: "preflight method must reference declared method",
			mutate: func(m *Manifest) {
				m.Methods[0].Confirmation = &ConfirmationSpec{
					Mode:             ConfirmationRiskBased,
					PreflightMethod:  stringPtr("missing.preflight"),
					PlanHashRequired: true,
				}
			},
			field: "methods[0].confirmation.preflight_method",
		},
		{
			name: "preflight method must not reference same method",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod(), riskyOperationMethod())
				m.Methods[2].Confirmation.PreflightMethod = stringPtr("resources.start")
			},
			field: "methods[2].confirmation.preflight_method",
		},
		{
			name: "preflight method must reference preflight-only method",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskyOperationMethod())
				m.Methods[1].Confirmation.PreflightMethod = stringPtr("resources.list")
			},
			field: "methods[1].confirmation.preflight_method",
		},
		{
			name: "preflight-only method must be read",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod())
				m.Methods[1].Effect = MethodEffectWrite
			},
			field: "methods[1].effect",
		},
		{
			name: "preflight-only method must be sync",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod())
				m.Methods[1].Execution = MethodExecutionOperation
			},
			field: "methods[1].execution",
		},
		{
			name: "preflight-only method must not be dangerous",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod())
				m.Methods[1].Dangerous = true
				m.Methods[1].Confirmation = &ConfirmationSpec{Mode: ConfirmationRequired}
			},
			field: "methods[1].dangerous",
		},
		{
			name: "preflight-only method must not require confirmation",
			mutate: func(m *Manifest) {
				m.Methods = append(m.Methods, riskPreflightMethod())
				m.Methods[1].Confirmation = &ConfirmationSpec{Mode: ConfirmationRequired}
			},
			field: "methods[1].confirmation.mode",
		},
		{
			name: "request hash fields must not be empty",
			mutate: func(m *Manifest) {
				m.Methods[0].Confirmation = &ConfirmationSpec{
					Mode:              ConfirmationRequired,
					RequestHashFields: []string{"resource_id", " "},
				}
			},
			field: "methods[0].confirmation.request_hash_fields[1]",
		},
		{
			name: "request hash fields must be unique",
			mutate: func(m *Manifest) {
				m.Methods[0].Confirmation = &ConfirmationSpec{
					Mode:              ConfirmationRequired,
					RequestHashFields: []string{"resource_id", "resource_id"},
				}
			},
			field: "methods[0].confirmation.request_hash_fields[1]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := validManifest()
			tc.mutate(&candidate)

			expectValidationField(t, candidate, tc.field)
		})
	}
}

func TestValidateMethodCancelPolicyContract(t *testing.T) {
	t.Run("operation requires cancel policy", func(t *testing.T) {
		m := validManifest()
		m.Methods = append(m.Methods, riskyOperationMethod())
		m.Methods[1].Dangerous = false
		m.Methods[1].Confirmation = nil
		m.Methods[1].CancelPolicy = nil

		expectValidationField(t, m, "methods[1].cancel_policy")
	})

	cases := []struct {
		name   string
		mutate func(*Manifest)
		field  string
	}{
		{
			name: "rejects invalid disable behavior",
			mutate: func(m *Manifest) {
				m.Methods[2].CancelPolicy.DisableBehavior = "detach"
			},
			field: "methods[2].cancel_policy.disable_behavior",
		},
		{
			name: "rejects invalid uninstall behavior",
			mutate: func(m *Manifest) {
				m.Methods[2].CancelPolicy.UninstallBehavior = "delete_now"
			},
			field: "methods[2].cancel_policy.uninstall_behavior",
		},
		{
			name: "rejects negative ack timeout",
			mutate: func(m *Manifest) {
				m.Methods[2].CancelPolicy.AckTimeoutMS = -1
			},
			field: "methods[2].cancel_policy.ack_timeout_ms",
		},
		{
			name: "sync method cannot be cancelable",
			mutate: func(m *Manifest) {
				m.Methods[0].CancelPolicy = &CancelPolicySpec{Cancelable: true}
			},
			field: "methods[0].cancel_policy.cancelable",
		},
		{
			name: "sync method cannot declare disable behavior",
			mutate: func(m *Manifest) {
				m.Methods[0].CancelPolicy = &CancelPolicySpec{DisableBehavior: CancelDisableBehaviorCancel}
			},
			field: "methods[0].cancel_policy.disable_behavior",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := validManifestWithRiskPreflightOperation()
			tc.mutate(&candidate)

			expectValidationField(t, candidate, tc.field)
		})
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
	}}}
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() without quota_files error = %v", err)
	}

	quotaFiles := int64(1)
	m.Storage.Stores[0].QuotaFiles = &quotaFiles
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() with quota_files error = %v", err)
	}

	for _, value := range []int64{0, -1, MaxStoreQuotaFiles + 1} {
		m.Storage.Stores[0].QuotaFiles = &value
		if err := Validate(m); err == nil {
			t.Fatalf("Validate() with quota_files=%d expected error", value)
		}
	}
}

func TestValidateStorageResourceLimits(t *testing.T) {
	t.Run("store count", func(t *testing.T) {
		m := validManifest()
		m.Storage = &StorageSpec{Stores: make([]StoreSpec, MaxStorageStores+1)}
		for i := range m.Storage.Stores {
			m.Storage.Stores[i] = StoreSpec{
				StoreID:       fmt.Sprintf("store-%d", i),
				Kind:          "kv",
				Scope:         "user",
				QuotaBytes:    1024,
				SchemaVersion: 1,
			}
		}
		expectValidationField(t, m, "storage.stores")
	})

	t.Run("quota bytes", func(t *testing.T) {
		m := validManifest()
		m.Storage = &StorageSpec{Stores: []StoreSpec{{
			StoreID:       "cache",
			Kind:          "kv",
			Scope:         "user",
			QuotaBytes:    MaxStoreQuotaBytes + 1,
			SchemaVersion: 1,
		}}}
		expectValidationField(t, m, "storage.stores[0].quota_bytes")
	})
}

func TestValidateReadMethodRejectsMutatingStorageBrokerOperations(t *testing.T) {
	for _, operation := range []string{"write", "delete", "put", "exec"} {
		t.Run(operation, func(t *testing.T) {
			m := validManifestWithWorkerMethod()
			m.Storage = &StorageSpec{Stores: []StoreSpec{{
				StoreID:       "store",
				Kind:          storageKindForOperation(operation),
				Scope:         "user",
				QuotaBytes:    1024,
				SchemaVersion: 1,
			}}}
			m.Methods[1].Effect = MethodEffectRead
			m.Methods[1].BrokerAccess = &MethodBrokerAccessSpec{Storage: []StorageBrokerAccessSpec{{
				StoreID:    "store",
				Operations: []string{operation},
			}}}

			expectValidationField(t, m, "methods[1].broker_access.storage[0].operations[0]")
		})
	}
}

func storageKindForOperation(operation string) string {
	switch operation {
	case "write", "delete":
		return "files"
	case "put":
		return "kv"
	default:
		return "sqlite"
	}
}

func TestValidateWorkers(t *testing.T) {
	m := validManifest()
	m.Workers = []WorkerSpec{{
		WorkerID:         "echo_worker",
		Artifact:         "workers/echo.wasm",
		ABI:              "redevplugin-wasm-worker-v2",
		Mode:             WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	}}
	m.Methods = append(m.Methods, MethodSpec{
		Method:         "worker.echo",
		Effect:         MethodEffectRead,
		Execution:      MethodExecutionSync,
		Route:          MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "echo_worker"},
		RequestSchema:  closedObjectSchema(),
		ResponseSchema: closedObjectSchema(),
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
			name: "memory exceeds platform maximum",
			mutate: func(m *Manifest) {
				m.Workers[0].MemoryLimitBytes = MaxWorkerMemoryLimitBytes + 1
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
		Method:         "core.open",
		Effect:         MethodEffectRead,
		Execution:      MethodExecutionSync,
		Route:          MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "example.open_settings"},
		RequestSchema:  closedObjectSchema(),
		ResponseSchema: closedObjectSchema(),
	})
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() core_action manifest error = %v", err)
	}

	m.Methods[len(m.Methods)-1].Route.ActionID = ""
	if err := Validate(m); err == nil {
		t.Fatal("Validate() expected missing action_id error")
	}
}

func expectValidationField(t *testing.T, m Manifest, field string) {
	t.Helper()
	err := Validate(m)
	if err == nil {
		t.Fatalf("Validate() expected validation error for %s", field)
	}
	if validationErr, ok := err.(ValidationError); !ok || validationErr.Field != field {
		t.Fatalf("Validate() error = %v, want field %s", err, field)
	}
}

func validManifestWithWorkerMethod() Manifest {
	m := validManifest()
	m.Workers = []WorkerSpec{{
		WorkerID:         "echo_worker",
		Artifact:         "workers/echo.wasm",
		ABI:              "redevplugin-wasm-worker-v2",
		Mode:             WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	}}
	m.Methods = append(m.Methods, MethodSpec{
		Method:         "worker.echo",
		Effect:         MethodEffectRead,
		Execution:      MethodExecutionSync,
		Route:          MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "echo_worker"},
		RequestSchema:  closedObjectSchema(),
		ResponseSchema: closedObjectSchema(),
	})
	return m
}

func TestValidateAcceptsMethodScopedBrokerAccess(t *testing.T) {
	m := validManifestWithBrokerAccess()
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidMethodScopedBrokerAccess(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*Manifest)
	}{
		{
			name:  "broker access is worker-only",
			field: "methods[0].broker_access",
			mutate: func(m *Manifest) {
				m.Methods[0].BrokerAccess = m.Methods[len(m.Methods)-1].BrokerAccess
			},
		},
		{
			name:  "storage store must be declared",
			field: "methods[1].broker_access.storage[0].store_id",
			mutate: func(m *Manifest) {
				m.Methods[1].BrokerAccess.Storage[0].StoreID = "missing"
			},
		},
		{
			name:  "storage operation must match kind",
			field: "methods[1].broker_access.storage[0].operations[0]",
			mutate: func(m *Manifest) {
				m.Methods[1].BrokerAccess.Storage[0].Operations = []string{"drop"}
			},
		},
		{
			name:  "connector transport must match declaration",
			field: "methods[1].broker_access.network[0].transport",
			mutate: func(m *Manifest) {
				m.Methods[1].BrokerAccess.Network[0].Transport = "tcp"
			},
		},
		{
			name:  "http methods must be canonical",
			field: "methods[1].broker_access.network[0].http_methods[0]",
			mutate: func(m *Manifest) {
				m.Methods[1].BrokerAccess.Network[0].HTTPMethods = []string{"get"}
			},
		},
		{
			name:  "read effect cannot authorize an http write",
			field: "methods[1].broker_access.network[0].http_methods[0]",
			mutate: func(m *Manifest) {
				m.Methods[1].BrokerAccess.Network[0].HTTPMethods = []string{"POST"}
			},
		},
		{
			name:  "read effect cannot authorize a bidirectional transport",
			field: "methods[1].broker_access.network[0].operations[0]",
			mutate: func(m *Manifest) {
				m.NetworkAccess.Connectors[0].Transport = "websocket"
				m.Methods[1].BrokerAccess.Network[0] = NetworkBrokerAccessSpec{
					ConnectorID: "forecast", Transport: "websocket", Operations: []string{"websocket_round_trip"},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifestWithBrokerAccess()
			tt.mutate(&m)
			err := Validate(m)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Validate() error = %v, want field %q", err, tt.field)
			}
		})
	}
}

func validManifestWithBrokerAccess() Manifest {
	m := validManifestWithWorkerMethod()
	m.Storage = &StorageSpec{Stores: []StoreSpec{{
		StoreID:       "notes",
		Kind:          "sqlite",
		Scope:         "user",
		QuotaBytes:    1 << 20,
		SchemaVersion: 1,
	}}}
	m.NetworkAccess = &NetworkAccessSpec{Connectors: []NetworkConnectorSpec{{
		ConnectorID: "forecast", Transport: "http", Scope: "user", Destinations: []string{"https://api.example.com"},
	}}}
	m.Methods[len(m.Methods)-1].BrokerAccess = &MethodBrokerAccessSpec{
		Storage: []StorageBrokerAccessSpec{{StoreID: "notes", Operations: []string{"query"}}},
		Network: []NetworkBrokerAccessSpec{{ConnectorID: "forecast", Transport: "http", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}},
	}
	return m
}

func validManifestWithRiskPreflightOperation() Manifest {
	m := validManifest()
	m.Methods = append(m.Methods, riskPreflightMethod(), riskyOperationMethod())
	return m
}

func riskPreflightMethod() MethodSpec {
	return MethodSpec{
		Method:         "resources.start.preflight",
		Effect:         MethodEffectRead,
		Execution:      MethodExecutionSync,
		PreflightOnly:  true,
		Route:          MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "resources.start.preflight"},
		RequestSchema:  closedObjectSchema(),
		ResponseSchema: closedObjectSchema(),
	}
}

func riskyOperationMethod() MethodSpec {
	return MethodSpec{
		Method:       "resources.start",
		Effect:       MethodEffectExecute,
		Execution:    MethodExecutionOperation,
		Dangerous:    true,
		Confirmation: &ConfirmationSpec{Mode: ConfirmationRiskBased, PreflightMethod: stringPtr("resources.start.preflight"), RequestHashFields: []string{"resource_id"}, PlanHashRequired: true},
		CancelPolicy: &CancelPolicySpec{Cancelable: true, DisableBehavior: CancelDisableBehaviorCancel, UninstallBehavior: CancelUninstallBehaviorCancelThenBlockDelete, AckTimeoutMS: 2000},
		Route:        MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "resources.start"},
		RequestSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"resource_id"},
			"properties":           map[string]any{"resource_id": map[string]any{"type": "string"}},
		},
		ResponseSchema: closedObjectSchema(),
	}
}

func closedObjectSchema() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false}
}

func stringPtr(value string) *string {
	return &value
}

func validManifest() Manifest {
	return Manifest{
		SchemaVersion: "redevplugin.manifest.v5",
		Publisher:     Publisher{PublisherID: "example", DisplayName: "Example"},
		Plugin: Plugin{
			PluginID:          "com.example.resources",
			DisplayName:       "Resources",
			Version:           "1.0.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.1.0",
			UIProtocolVersion: "plugin-ui-v5",
		},
		Surfaces: []SurfaceSpec{
			{SurfaceID: "resources.view", Kind: SurfaceView, Intent: SurfaceIntentPrimary, Label: "Resources", Entry: "ui/index.html"},
		},
		CapabilityBindings: []CapabilityBinding{
			{BindingID: "resource_provider", Contract: validCapabilityPin()},
		},
		Methods: []MethodSpec{
			{
				Method:         "resources.list",
				Effect:         MethodEffectRead,
				Execution:      MethodExecutionSync,
				Route:          MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "resources.list"},
				RequestSchema:  closedObjectSchema(),
				ResponseSchema: closedObjectSchema(),
			},
		},
		Settings: &SettingsSpec{
			SchemaVersion: 1,
			Fields: []SettingFieldSpec{
				{Key: "default_source", Type: "select", Scope: "user", Label: "Default source", Default: "primary", Options: []string{"primary", "secondary"}},
			},
		},
		Intents: []IntentSpec{{IntentID: "open-resource-list", Method: "resources.list"}},
	}
}

func validCapabilityManifest() Manifest {
	m := validManifest()
	m.Methods[0] = MethodSpec{
		Method: "resources.list",
		Route:  MethodRouteSpec{Kind: MethodRouteCapability, BindingID: "resource_provider", TargetMethod: "resources.list"},
	}
	return m
}

func validManifestJSON() string {
	return fmt.Sprintf(`{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.resources",
			"display_name": "Resources",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "resources.view", "kind": "view", "label": "Resources", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "resource_provider", "contract": %s}
		],
		"methods": [
			{
				"method": "resources.list",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "core_action", "action_id": "resources.list"},
				"request_schema": {"type": "object", "additionalProperties": false},
				"response_schema": {"type": "object", "additionalProperties": false}
			}
		],
		"settings": {
			"schema_version": 1,
			"fields": [
				{"key": "default_source", "type": "select", "scope": "user", "label": "Default source", "default": "primary", "options": ["primary", "secondary"]}
			]
		},
		"intents": [
			{"intent_id": "open-resource-list", "method": "resources.list"}
		]
	}`, validCapabilityPinJSON())
}

func validCapabilityPin() capabilitycontract.Pin {
	return capabilitycontract.Pin{
		PublisherID:              "example.publisher",
		ContractID:               "example.resources.v1",
		ContractVersion:          "1.0.0",
		ArtifactRef:              "capabilities/example.resources/v1.0.0/contract.json",
		ArtifactSHA256:           strings.Repeat("1", 64),
		ManifestRef:              "capabilities/example.resources/v1.0.0/manifest.json",
		ManifestSHA256:           strings.Repeat("2", 64),
		SignatureRef:             "capabilities/example.resources/v1.0.0/manifest.sig",
		SignatureSHA256:          strings.Repeat("3", 64),
		SignatureKeyID:           "example-key",
		SignaturePolicyEpoch:     "1",
		SignatureRevocationEpoch: "1",
		CompatibilityRef:         "capabilities/example.resources/v1.0.0/compatibility.json",
		CompatibilitySHA256:      strings.Repeat("4", 64),
		GeneratedClientRef:       "capabilities/example.resources/v1.0.0/client.ts",
		GeneratedClientSHA256:    strings.Repeat("5", 64),
		NoticesRef:               "capabilities/example.resources/v1.0.0/notices.json",
		NoticesSHA256:            strings.Repeat("6", 64),
	}
}

func validCapabilityPinJSON() string {
	raw, err := json.Marshal(validCapabilityPin())
	if err != nil {
		panic(fmt.Sprintf("marshal valid capability pin: %v", err))
	}
	return string(raw)
}
