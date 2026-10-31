package manifest

import (
	"encoding/json"
	"testing"
)

func TestBackgroundIntervalDeclaration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(map[string]any)
		invalid bool
	}{
		{name: "bounded interval"},
		{name: "missing interval", invalid: true, change: func(b map[string]any) { delete(b, "interval_ms") }},
		{name: "missing budget", invalid: true, change: func(b map[string]any) { delete(b, "max_runtime_ms") }},
		{name: "too frequent", invalid: true, change: func(b map[string]any) { b["interval_ms"] = 999 }},
		{name: "budget exceeds period", invalid: true, change: func(b map[string]any) { b["max_runtime_ms"] = 60001 }},
		{name: "implicit method", invalid: true, change: func(b map[string]any) { delete(b, "method") }},
		{name: "irrelevant interval", invalid: true, change: func(b map[string]any) { b["strategy"] = "on_demand" }},
		{name: "null interval", invalid: true, change: func(b map[string]any) { b["interval_ms"] = nil }},
		{name: "period exceeds one day", invalid: true, change: func(b map[string]any) { b["interval_ms"] = 86400001 }},
		{name: "budget exceeds five minutes", invalid: true, change: func(b map[string]any) { b["interval_ms"] = 86400000; b["max_runtime_ms"] = 300001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.API.RequiredFeatures = []FeatureID{FeatureBackgroundMethod, "background.interval.v1"}
			m.Workers = []WorkerSpec{{WorkerID: "worker", Artifact: "workers/main.wasm", Mode: WorkerModeJob, Scope: "environment", MemoryLimitBytes: 16777216}}
			m.Methods[0].Method = "refresh"
			m.Intents[0].Method = "refresh"
			m.Methods[0].Route = MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "worker"}
			b := map[string]any{"strategy": "interval", "worker_id": "worker", "method": "refresh", "interval_ms": 60000, "max_runtime_ms": 10000}
			if tc.change != nil {
				tc.change(b)
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			err = json.Unmarshal(raw, &m.Background)
			if err == nil {
				err = Validate(m)
			}
			if (err != nil) != tc.invalid {
				t.Fatalf("Validate()=%v invalid=%v", err, tc.invalid)
			}
		})
	}
}

func TestIntervalRejectsActorSubscriptionAndMissingFeature(t *testing.T) {
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Workers[0].Mode = WorkerMode("actor") },
		func(m *Manifest) { m.Methods[0].Execution = MethodExecutionSubscription },
		func(m *Manifest) { m.API.RequiredFeatures = []FeatureID{FeatureBackgroundMethod} },
	} {
		m := validManifest()
		m.API.RequiredFeatures = []FeatureID{FeatureBackgroundMethod, FeatureBackgroundInterval}
		m.Workers = []WorkerSpec{{WorkerID: "worker", Artifact: "workers/main.wasm", Mode: WorkerModeJob, Scope: "environment", MemoryLimitBytes: 16777216}}
		m.Methods[0].Route = MethodRouteSpec{Kind: MethodRouteWorker, WorkerID: "worker"}
		m.Background = &BackgroundSpec{Strategy: BackgroundInterval, WorkerID: "worker", Method: m.Methods[0].Method, IntervalMS: 60000, MaxRuntimeMS: 1000}
		change(&m)
		if err := Validate(m); err == nil {
			t.Fatal("unsupported interval declaration accepted")
		}
	}
}
