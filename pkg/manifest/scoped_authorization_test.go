package manifest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestScopedAuthorizationValidation(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Manifest)
		invalid bool
	}{
		{name: "valid"},
		{name: "empty ceiling", change: func(m *Manifest) { v := []PermissionID{}; m.Methods[0].Permissions = v }},
		{name: "feature required", invalid: true, change: func(m *Manifest) { m.API.RequiredFeatures = nil }},
		{name: "optional feature insufficient", invalid: true, change: func(m *Manifest) { m.API.OptionalFeatures = m.API.RequiredFeatures; m.API.RequiredFeatures = nil }},
		{name: "undeclared permission", invalid: true, change: func(m *Manifest) { v := []PermissionID{PermissionFSHomeWrite}; m.Methods[0].Permissions = v }},
		{name: "duplicate permission", invalid: true, change: func(m *Manifest) {
			v := []PermissionID{PermissionFSEnvironmentRead, PermissionFSEnvironmentRead}
			m.Methods[0].Permissions = v
		}},
		{name: "unknown permission", invalid: true, change: func(m *Manifest) { v := []PermissionID{"unknown"}; m.Methods[0].Permissions = v }},
		{name: "core action cannot override permissions", invalid: true, change: func(m *Manifest) {
			m.Methods[0].Route = MethodRouteSpec{Kind: MethodRouteCoreAction, ActionID: "resources.list"}
		}},
		{name: "capability cannot override permissions", invalid: true, change: func(m *Manifest) {
			m.Methods[0] = validCapabilityManifest().Methods[0]
			v := []PermissionID{}
			m.Methods[0].Permissions = v
		}},
		{name: "undeclared method", invalid: true, change: func(m *Manifest) { v := []string{"unknown"}; m.Surfaces[0].RequiredMethods = v }},
		{name: "duplicate method", invalid: true, change: func(m *Manifest) {
			v := []string{"resources.list", "resources.list"}
			m.Surfaces[0].RequiredMethods = v
		}},
		{name: "network ceiling required", invalid: true, change: func(m *Manifest) {
			m.Methods[0].BrokerAccess = &MethodBrokerAccessSpec{Network: []NetworkBrokerAccessSpec{{ConnectorID: "missing"}}}
		}},
		{name: "process ceiling required", invalid: true, change: func(m *Manifest) {
			m.Methods[0].BrokerAccess = &MethodBrokerAccessSpec{Process: []ProcessBrokerAccessSpec{{Operations: []string{"start"}}}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.API.RequiredFeatures = []FeatureID{FeatureScopedAuthorization}
			m.Permissions = []PermissionID{PermissionFSEnvironmentRead, PermissionFSEnvironmentWrite}
			m.Workers = []WorkerSpec{{WorkerID: "worker", Artifact: "workers/main.wasm", Mode: WorkerModeJob, Scope: "user", MemoryLimitBytes: 16777216}}
			m.Methods[0].Route = MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "worker"}
			perms := []PermissionID{PermissionFSEnvironmentRead}
			m.Methods[0].Permissions = perms
			methods := []string{"resources.list"}
			m.Surfaces[0].RequiredMethods = methods
			if tc.change != nil {
				tc.change(&m)
			}
			if err := Validate(m); (err != nil) != tc.invalid {
				t.Fatalf("Validate()=%v, invalid=%v", err, tc.invalid)
			}
		})
	}
}

func TestScopedAuthorizationRejectsNullDeclarations(t *testing.T) {
	for _, key := range []string{"permissions", "required_methods"} {
		var target any
		if key == "permissions" {
			target = &MethodSpec{}
		} else {
			target = &SurfaceSpec{}
		}
		if err := json.Unmarshal([]byte(`{"`+key+`":null}`), target); err == nil {
			t.Fatalf("%s accepted null", key)
		}
	}
	raw := strings.Replace(validManifestJSON(), `"kind": "view"`, `"kind": "view", "required_methods": null`, 1)
	if _, err := Decode(strings.NewReader(raw)); err == nil {
		t.Fatal("decoder accepted null surface requirements")
	}
}

func TestScopedAuthorizationPreservesAbsentAndEmptyDeclarations(t *testing.T) {
	raw := []byte(validManifestJSON())
	m, canonical, err := DecodeCanonical(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, expected) {
		t.Fatal("original signed canonical bytes changed")
	}
	encoded, err := json.Marshal(m.Methods)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"permissions"`)) {
		t.Fatal("absent method permissions were added")
	}
	empty := []PermissionID{}
	m.Methods[0].Permissions = empty
	encoded, err = json.Marshal(m.Methods)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"permissions":[]`)) {
		t.Fatal("explicit empty ceiling was lost")
	}
	m.Permissions = []PermissionID{PermissionFSEnvironmentWrite}
	if len(m.WorkerPermissionIDs(m.Methods[0])) != 0 {
		t.Fatal("empty ceiling inherited package permissions")
	}
	m.Methods[0].Permissions = nil
	if len(m.WorkerPermissionIDs(m.Methods[0])) != 1 {
		t.Fatal("absent ceiling changed existing behavior")
	}
}
