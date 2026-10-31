package manifest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func validDataUpgradeManifest() Manifest {
	m := validManifestWithWorkerMethod()
	m.API.RequiredFeatures = append(m.API.RequiredFeatures, FeatureDataUpgrade)
	m.Workers[0].Scope = "environment"
	method := &m.Methods[len(m.Methods)-1]
	method.Effect = MethodEffectWrite
	method.RequestSchema = map[string]any{"type": "object", "properties": map[string]any{"from_version": map[string]any{"type": "string"}, "to_version": map[string]any{"type": "string"}, "scope": map[string]any{"enum": []any{"user", "environment"}}}, "required": []any{"from_version", "to_version", "scope"}, "additionalProperties": false}
	m.DataUpgrade = &DataUpgradeSpec{From: []DataUpgradePredecessor{{Version: "0.9.0", ShapeSHA256: strings.Repeat("a", 64)}}, Method: method.Method, MaxBytes: 1 << 20, MaxRuntimeMS: 1000}
	return m
}

func TestDataUpgradeManifestAdmission(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*Manifest)
		invalid bool
	}{
		{name: "valid"},
		{name: "missing feature", invalid: true, change: func(m *Manifest) { m.API.RequiredFeatures = nil }},
		{name: "missing predecessor", invalid: true, change: func(m *Manifest) { m.DataUpgrade.From = nil }},
		{name: "same version", invalid: true, change: func(m *Manifest) { m.DataUpgrade.From[0].Version = m.Version() }},
		{name: "duplicate version", invalid: true, change: func(m *Manifest) { m.DataUpgrade.From = append(m.DataUpgrade.From, m.DataUpgrade.From[0]) }},
		{name: "invalid digest", invalid: true, change: func(m *Manifest) { m.DataUpgrade.From[0].ShapeSHA256 = strings.Repeat("A", 64) }},
		{name: "missing method", invalid: true, change: func(m *Manifest) { m.DataUpgrade.Method = "missing" }},
		{name: "read method", invalid: true, change: func(m *Manifest) { m.Methods[len(m.Methods)-1].Effect = MethodEffectRead }},
		{name: "user worker", invalid: true, change: func(m *Manifest) { m.Workers[0].Scope = "user" }},
		{name: "confirmation", invalid: true, change: func(m *Manifest) {
			m.Methods[len(m.Methods)-1].Confirmation = &ConfirmationSpec{Mode: ConfirmationRequired}
		}},
		{name: "preflight", invalid: true, change: func(m *Manifest) { m.Methods[len(m.Methods)-1].PreflightOnly = true }},
		{name: "invalid request", invalid: true, change: func(m *Manifest) { m.Methods[len(m.Methods)-1].RequestSchema = closedObjectSchema() }},
		{name: "runtime limit", invalid: true, change: func(m *Manifest) { m.DataUpgrade.MaxRuntimeMS = 300001 }},
		{name: "byte limit", invalid: true, change: func(m *Manifest) { m.DataUpgrade.MaxBytes = 4<<30 + 1 }},
		{name: "surface requirement", invalid: true, change: func(m *Manifest) {
			m.API.RequiredFeatures = append(m.API.RequiredFeatures, FeatureScopedAuthorization)
			m.Surfaces[0].RequiredMethods = MethodNames{m.DataUpgrade.Method}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validDataUpgradeManifest()
			if tc.change != nil {
				tc.change(&m)
			}
			if err := Validate(m); (err != nil) != tc.invalid {
				t.Fatalf("Validate()=%v invalid=%v", err, tc.invalid)
			}
		})
	}
}

func TestDataUpgradeCanonicalRoundTrip(t *testing.T) {
	m := validDataUpgradeManifest()
	raw, err := MarshalCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(decoded.DataUpgrade)
	want, _ := json.Marshal(m.DataUpgrade)
	if !bytes.Equal(got, want) {
		t.Fatalf("upgrade declaration lost: %s != %s", got, want)
	}
	for _, replacement := range []string{`"data_upgrade":null,`, `"data_upgrade":{"unknown":true},`} {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		delete(object, "data_upgrade")
		base, _ := json.Marshal(object)
		candidate := append([]byte("{"+replacement), base[1:]...)
		if _, err := Decode(bytes.NewReader(candidate)); err == nil {
			t.Fatalf("accepted invalid declaration: %s", candidate)
		}
	}
}
