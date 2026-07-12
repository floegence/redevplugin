package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/version"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestManifestSchemaMatchesGoManifestContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "manifest-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	if schema["additionalProperties"] != false {
		t.Fatalf("manifest schema additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	required := requireStringSlice(t, schema["required"], "manifest required")
	if !stringSetEqual(required, []string{"schema_version", "publisher", "plugin", "surfaces"}) {
		t.Fatalf("manifest required = %#v", required)
	}

	props := requireNestedObject(t, schema, "properties")
	if got := requireNestedObject(t, props, "schema_version")["const"]; got != "redevplugin.manifest.v2" {
		t.Fatalf("schema_version const = %#v", got)
	}
	pluginProps := requireNestedObject(t, props, "plugin", "properties")
	if got := requireNestedObject(t, pluginProps, "api_version")["const"]; got != "plugin-v1" {
		t.Fatalf("plugin.api_version const = %#v", got)
	}
	if got := requireNestedObject(t, pluginProps, "ui_protocol_version")["const"]; got != "plugin-ui-v2" {
		t.Fatalf("plugin.ui_protocol_version const = %#v", got)
	}

	surfaceProps := requireNestedObject(t, props, "surfaces", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, surfaceProps, "kind")["enum"], "surface kind", []string{
		string(manifest.SurfaceView),
		string(manifest.SurfaceCommand),
		string(manifest.SurfaceBackground),
	})
	assertStringEnum(t, requireNestedObject(t, surfaceProps, "intent")["enum"], "surface intent", []string{
		string(manifest.SurfaceIntentPrimary),
		string(manifest.SurfaceIntentSecondary),
		string(manifest.SurfaceIntentUtility),
	})
	if _, ok := surfaceProps["method"]; ok {
		t.Fatal("surface schema must not bind product methods or placement behavior")
	}
	defaultSize := requireNestedObject(t, surfaceProps, "default_size")
	if defaultSize["additionalProperties"] != false {
		t.Fatalf("surface default_size additionalProperties = %#v, want false", defaultSize["additionalProperties"])
	}

	methodProps := requireNestedObject(t, props, "methods", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, methodProps, "effect")["enum"], "method effect", []string{
		string(manifest.MethodEffectRead),
		string(manifest.MethodEffectWrite),
		string(manifest.MethodEffectDelete),
		string(manifest.MethodEffectExecute),
		string(manifest.MethodEffectAdmin),
	})
	assertStringEnum(t, requireNestedObject(t, methodProps, "execution")["enum"], "method execution", []string{
		string(manifest.MethodExecutionSync),
		string(manifest.MethodExecutionOperation),
		string(manifest.MethodExecutionSubscription),
	})
	route := requireNestedObject(t, methodProps, "route")
	if route["additionalProperties"] != false {
		t.Fatalf("method route additionalProperties = %#v, want false", route["additionalProperties"])
	}
	assertStringEnum(t, requireNestedObject(t, route, "properties", "kind")["enum"], "method route kind", []string{
		string(manifest.MethodRouteCapability),
		string(manifest.MethodRouteWorker),
		string(manifest.MethodRouteCoreAction),
	})
	routeConditions := requireObjectArray(t, route["allOf"], "method route allOf")
	capabilityRoute := requireConstCondition(t, routeConditions, "kind", string(manifest.MethodRouteCapability), "capability route")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, capabilityRoute, "then")["required"], "capability route required"), []string{"binding_id", "target_method"}, "capability route required")
	assertForbiddenRequiredFields(t, requireNestedObject(t, capabilityRoute, "then"), []string{"worker_id", "export", "action_id"}, "capability route forbidden fields")
	workerRoute := requireConstCondition(t, routeConditions, "kind", string(manifest.MethodRouteWorker), "worker route")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, workerRoute, "then")["required"], "worker route required"), []string{"worker_id", "export"}, "worker route required")
	assertForbiddenRequiredFields(t, requireNestedObject(t, workerRoute, "then"), []string{"binding_id", "target_method", "action_id"}, "worker route forbidden fields")
	coreActionRoute := requireConstCondition(t, routeConditions, "kind", string(manifest.MethodRouteCoreAction), "core action route")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, coreActionRoute, "then")["required"], "core action route required"), []string{"action_id"}, "core action route required")
	assertForbiddenRequiredFields(t, requireNestedObject(t, coreActionRoute, "then"), []string{"binding_id", "target_method", "worker_id", "export"}, "core action route forbidden fields")

	methodConditions := requireObjectArray(t, requireNestedObject(t, props, "methods", "items")["allOf"], "method allOf")
	dangerousMethod := requireConstCondition(t, methodConditions, "dangerous", true, "dangerous method")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, dangerousMethod, "then")["required"], "dangerous method required"), []string{"confirmation"}, "dangerous method required")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, dangerousMethod, "then", "properties", "confirmation", "properties", "mode")["enum"], "dangerous confirmation modes"), []string{string(manifest.ConfirmationRequired), string(manifest.ConfirmationRiskBased)}, "dangerous confirmation modes")
	preflightOnlyMethod := requireConstCondition(t, methodConditions, "preflight_only", true, "preflight-only method")
	if got := requireNestedObject(t, preflightOnlyMethod, "then", "properties", "effect")["const"]; got != string(manifest.MethodEffectRead) {
		t.Fatalf("preflight_only effect const = %#v, want %q", got, manifest.MethodEffectRead)
	}
	if got := requireNestedObject(t, preflightOnlyMethod, "then", "properties", "execution")["const"]; got != string(manifest.MethodExecutionSync) {
		t.Fatalf("preflight_only execution const = %#v, want %q", got, manifest.MethodExecutionSync)
	}
	if got := requireNestedObject(t, preflightOnlyMethod, "then", "properties", "dangerous")["const"]; got != false {
		t.Fatalf("preflight_only dangerous const = %#v, want false", got)
	}
	asyncMethod := requireEnumCondition(t, methodConditions, "execution", []string{string(manifest.MethodExecutionOperation), string(manifest.MethodExecutionSubscription)}, "async method")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, asyncMethod, "then")["required"], "async method required"), []string{"cancel_policy"}, "async method required")

	workerProps := requireNestedObject(t, props, "workers", "items", "properties")
	if got := requireNestedObject(t, workerProps, "abi")["const"]; got != version.WASMABIVersion {
		t.Fatalf("worker abi const = %#v, want %q", got, version.WASMABIVersion)
	}
	assertStringEnum(t, requireNestedObject(t, workerProps, "mode")["enum"], "worker mode", []string{
		string(manifest.WorkerModeJob),
		string(manifest.WorkerModeActor),
	})
	assertStringEnum(t, requireNestedObject(t, workerProps, "scope")["enum"], "worker scope", []string{"user", "environment"})

	storageProps := requireNestedObject(t, props, "storage", "properties", "stores", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, storageProps, "kind")["enum"], "storage kind", []string{"kv", "files", "sqlite"})
	assertStringEnum(t, requireNestedObject(t, storageProps, "scope")["enum"], "storage scope", []string{"user", "environment"})
	if _, ok := storageProps["quota_files"].(map[string]any); !ok {
		t.Fatal("storage store schema missing quota_files")
	}
	migration := requireNestedObject(t, schema, "$defs", "migration")
	if migration["additionalProperties"] != false {
		t.Fatalf("migration additionalProperties = %#v, want false", migration["additionalProperties"])
	}
	migrationRequired := requireStringSlice(t, migration["required"], "migration required")
	assertStringSet(t, migrationRequired, []string{"from_version", "to_version", "reversible", "requires_worker", "estimated_bytes", "max_duration_ms", "data_loss_risk", "steps_hash"}, "migration required")
	if got := requireNestedObject(t, migration, "properties", "from_version")["minimum"]; got != float64(0) {
		t.Fatalf("migration.from_version minimum = %#v, want 0", got)
	}
	if got := requireNestedObject(t, migration, "properties", "to_version")["minimum"]; got != float64(1) {
		t.Fatalf("migration.to_version minimum = %#v, want 1", got)
	}

	networkProps := requireNestedObject(t, props, "network_access", "properties", "connectors", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, networkProps, "transport")["enum"], "network connector transport", []string{
		string(connectivity.TransportHTTP),
		string(connectivity.TransportWebSocket),
		string(connectivity.TransportTCP),
		string(connectivity.TransportUDP),
	})
	assertStringEnum(t, requireNestedObject(t, networkProps, "scope")["enum"], "network connector scope", []string{"user", "environment"})

	settingsProps := requireNestedObject(t, props, "settings", "properties", "fields", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, settingsProps, "scope")["enum"], "settings field scope", []string{"user", "environment"})
}

func TestManifestMethodSchemaMachineContractMatchesGoValidation(t *testing.T) {
	root := repoRoot(t)
	schemaRaw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "manifest-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:manifest-v2", bytes.NewReader(schemaRaw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:redevplugin:manifest-v2")
	if err != nil {
		t.Fatal(err)
	}
	fixtureRaw, err := os.ReadFile(filepath.Join(root, "testdata", "generated_plugins", "method-contract", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{name: "closed composition fixture", valid: true},
		{
			name: "nested open object",
			mutate: func(document map[string]any) {
				method := firstManifestMethod(t, document)
				method["request_schema"] = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"type": "object"},
					},
				}
			},
			valid: false,
		},
		{
			name: "negative composition open object",
			mutate: func(document map[string]any) {
				method := firstManifestMethod(t, document)
				method["request_schema"] = map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"filter": map[string]any{"not": map[string]any{"type": "string"}},
					},
				}
			},
			valid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(fixtureRaw, &document); err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				tc.mutate(document)
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			machineErr := compiled.Validate(document)
			_, goErr := manifest.Decode(bytes.NewReader(raw))
			if (machineErr == nil) != tc.valid {
				t.Fatalf("machine schema valid = %t, want %t: %v", machineErr == nil, tc.valid, machineErr)
			}
			if (goErr == nil) != tc.valid {
				t.Fatalf("Go manifest valid = %t, want %t: %v", goErr == nil, tc.valid, goErr)
			}
		})
	}
}

func firstManifestMethod(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	methods, ok := document["methods"].([]any)
	if !ok || len(methods) == 0 {
		t.Fatal("fixture methods are missing")
	}
	method, ok := methods[0].(map[string]any)
	if !ok {
		t.Fatal("fixture method is not an object")
	}
	return method
}

func assertStringEnum(t *testing.T, value any, label string, want []string) {
	t.Helper()
	got := requireStringSlice(t, value, label+" enum")
	if !stringSetEqual(got, want) {
		t.Fatalf("%s enum = %#v, want %#v", label, got, want)
	}
}

func requireObjectArray(t *testing.T, value any, label string) []map[string]any {
	t.Helper()
	rawItems, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array", label, value)
	}
	items := make([]map[string]any, 0, len(rawItems))
	for i, rawItem := range rawItems {
		item, ok := rawItem.(map[string]any)
		if !ok {
			t.Fatalf("%s[%d] = %#v, want object", label, i, rawItem)
		}
		items = append(items, item)
	}
	return items
}

func requireConstCondition(t *testing.T, conditions []map[string]any, field string, value any, label string) map[string]any {
	t.Helper()
	for _, condition := range conditions {
		fieldSchema, ok := nestedObject(condition, "if", "properties", field)
		if !ok {
			continue
		}
		if got := fieldSchema["const"]; got == value {
			return condition
		}
	}
	t.Fatalf("%s condition for %s const %#v not found", label, field, value)
	return nil
}

func requireEnumCondition(t *testing.T, conditions []map[string]any, field string, values []string, label string) map[string]any {
	t.Helper()
	for _, condition := range conditions {
		fieldSchema, ok := nestedObject(condition, "if", "properties", field)
		if !ok {
			continue
		}
		if got := requireStringSlice(t, fieldSchema["enum"], label+" enum"); stringSetEqual(got, values) {
			return condition
		}
	}
	t.Fatalf("%s condition for %s enum %#v not found", label, field, values)
	return nil
}

func nestedObject(from map[string]any, path ...string) (map[string]any, bool) {
	current := from
	for _, key := range path {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func assertForbiddenRequiredFields(t *testing.T, schema map[string]any, want []string, label string) {
	t.Helper()
	forbidden := requireObjectArray(t, requireNestedObject(t, schema, "not")["anyOf"], label)
	got := make([]string, 0, len(forbidden))
	for _, condition := range forbidden {
		required := requireStringSlice(t, condition["required"], label+" required")
		if len(required) != 1 {
			t.Fatalf("%s condition required = %#v, want one field", label, required)
		}
		got = append(got, required[0])
	}
	assertStringSet(t, got, want, label)
}
