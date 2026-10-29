package manifest

import (
	"encoding/json"
	"testing"
)

func TestBackgroundDeclarationRejectsAmbiguousFields(t *testing.T) {
	for _, raw := range []string{
		`{"strategy":"on_demand","worker_id":"worker","method":null}`,
		`{"strategy":"on_demand","worker_id":"worker","method":""}`,
		`{"strategy":"on_demand","worker_id":"worker","params":null}`,
		`{"strategy":"on_demand","worker_id":"worker","unexpected":true}`,
	} {
		var entry BackgroundSpec
		if err := json.Unmarshal([]byte(raw), &entry); err == nil {
			t.Errorf("accepted ambiguous background: %s", raw)
		}
	}
}

func TestExplicitBackgroundMethodValidation(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Manifest)
		invalid bool
	}{
		{name: "valid"},
		{name: "missing feature", invalid: true, change: func(m *Manifest) { m.API.RequiredFeatures = nil }},
		{name: "unknown method", invalid: true, change: func(m *Manifest) { m.Background.Method = "missing" }},
		{name: "wrong worker", invalid: true, change: func(m *Manifest) { m.Methods[0].Route.WorkerID = "other" }},
		{name: "user scope", invalid: true, change: func(m *Manifest) { m.Workers[0].Scope = "user" }},
		{name: "interactive confirmation", invalid: true, change: func(m *Manifest) { m.Methods[0].Confirmation = &ConfirmationSpec{Mode: ConfirmationRequired} }},
		{name: "preflight", invalid: true, change: func(m *Manifest) { m.Methods[0].PreflightOnly = true }},
		{name: "invalid arguments", invalid: true, change: func(m *Manifest) { m.Background.Params = map[string]any{"unexpected": true} }},
		{name: "arguments without entry", invalid: true, change: func(m *Manifest) { m.Background.Method = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.API.RequiredFeatures = []FeatureID{FeatureBackgroundMethod}
			m.Workers = []WorkerSpec{{WorkerID: "worker", Artifact: "workers/main.wasm", Mode: WorkerModeJob, Scope: "environment", MemoryLimitBytes: 16777216}}
			m.Methods[0].Route = MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "worker"}
			m.Background = &BackgroundSpec{Strategy: BackgroundOnDemand, WorkerID: "worker", Method: m.Methods[0].Method, Params: map[string]any{}}
			if tc.change != nil {
				tc.change(&m)
			}
			if err := Validate(m); (err != nil) != tc.invalid {
				t.Fatalf("Validate()=%v invalid=%v", err, tc.invalid)
			}
		})
	}
}
