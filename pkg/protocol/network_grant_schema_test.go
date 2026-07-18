package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestNetworkGrantSchemaMatchesConnectivityContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "network-grant-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	if schema["additionalProperties"] != false {
		t.Fatalf("network grant schema additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	required := requireStringSlice(t, schema["required"], "network grant required")
	if !stringSetEqual(required, []string{
		"grant_id",
		"plugin_instance_id",
		"active_fingerprint",
		"resource_scope",
		"policy_revision",
		"management_revision",
		"revoke_epoch",
		"connector_id",
		"transport",
		"destination",
		"target_classifier_version",
		"expires_at",
	}) {
		t.Fatalf("network grant required = %#v", required)
	}

	props := requireNestedObject(t, schema, "properties")
	grantID := requireNestedObject(t, props, "grant_id")
	if grantID["pattern"] != "^netgrant_[0-9a-f]{32}$" {
		t.Fatalf("grant_id pattern = %#v", grantID["pattern"])
	}
	assertTransportEnum(t, requireNestedObject(t, props, "transport")["enum"], "network grant transport")
	classifier := requireNestedObject(t, props, "target_classifier_version")
	if classifier["const"] != version.TargetClassifierVersion {
		t.Fatalf("target_classifier_version const = %#v, want %q", classifier["const"], version.TargetClassifierVersion)
	}
	if props["runtime_generation_id"] == nil {
		t.Fatal("network grant schema missing optional runtime_generation_id")
	}
	resourceScope := requireNestedObject(t, schema, "$defs", "resource_scope")
	if resourceScope["additionalProperties"] != false {
		t.Fatalf("resource_scope additionalProperties = %#v, want false", resourceScope["additionalProperties"])
	}
	assertRequiredFields(t, resourceScope, "resource scope", []string{"kind", "owner_env_hash"})
	scopeKinds := requireStringSlice(t, requireNestedObject(t, resourceScope, "properties", "kind")["enum"], "resource scope kind")
	if !stringSetEqual(scopeKinds, []string{"user", "environment"}) {
		t.Fatalf("resource scope kinds = %#v", scopeKinds)
	}

	destination := requireNestedObject(t, schema, "$defs", "destination")
	if destination["additionalProperties"] != false {
		t.Fatalf("destination additionalProperties = %#v, want false", destination["additionalProperties"])
	}
	destinationRequired := requireStringSlice(t, destination["required"], "destination required")
	if !stringSetEqual(destinationRequired, []string{"transport", "host", "port"}) {
		t.Fatalf("destination required = %#v", destinationRequired)
	}
	destinationProps := requireNestedObject(t, destination, "properties")
	assertTransportEnum(t, requireNestedObject(t, destinationProps, "transport")["enum"], "destination transport")
	scheme := requireStringSlice(t, requireNestedObject(t, destinationProps, "scheme")["enum"], "destination scheme")
	if !stringSetEqual(scheme, []string{"http", "https", "ws", "wss"}) {
		t.Fatalf("destination scheme enum = %#v", scheme)
	}
	port := requireNestedObject(t, destinationProps, "port")
	if port["minimum"] != float64(1) || port["maximum"] != float64(65535) {
		t.Fatalf("destination port bounds = min %#v max %#v, want 1..65535", port["minimum"], port["maximum"])
	}
}

func assertTransportEnum(t *testing.T, value any, label string) {
	t.Helper()
	got := requireStringSlice(t, value, label+" enum")
	want := []string{
		string(connectivity.TransportHTTP),
		string(connectivity.TransportWebSocket),
		string(connectivity.TransportTCP),
		string(connectivity.TransportUDP),
	}
	if !stringSetEqual(got, want) {
		t.Fatalf("%s enum = %#v, want %#v", label, got, want)
	}
}
