package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestManifestSchemaMatchesGoManifestContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "manifest-v1.schema.json"))
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
	if got := requireNestedObject(t, props, "schema_version")["const"]; got != "redevplugin.manifest.v1" {
		t.Fatalf("schema_version const = %#v", got)
	}
	pluginProps := requireNestedObject(t, props, "plugin", "properties")
	if got := requireNestedObject(t, pluginProps, "api_version")["const"]; got != "plugin-v1" {
		t.Fatalf("plugin.api_version const = %#v", got)
	}
	if got := requireNestedObject(t, pluginProps, "ui_protocol_version")["const"]; got != "plugin-ui-v1" {
		t.Fatalf("plugin.ui_protocol_version const = %#v", got)
	}

	surfaceProps := requireNestedObject(t, props, "surfaces", "items", "properties")
	assertStringEnum(t, requireNestedObject(t, surfaceProps, "kind")["enum"], "surface kind", []string{
		string(manifest.SurfaceActivity),
		string(manifest.SurfaceWorkbench),
		string(manifest.SurfaceSettings),
	})
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

func assertStringEnum(t *testing.T, value any, label string, want []string) {
	t.Helper()
	got := requireStringSlice(t, value, label+" enum")
	if !stringSetEqual(got, want) {
		t.Fatalf("%s enum = %#v, want %#v", label, got, want)
	}
}
