package capability

import (
	"errors"
	"testing"
)

func TestNormalizeRiskPlanDataNormalizesTypedPlanAndPropagatesFlagRisk(t *testing.T) {
	got, err := NormalizeRiskPlanData(RiskPlan{
		SchemaVersion: RiskPlanSchemaVersion,
		Summary:       "Start container",
		Effect:        EffectExecute,
		RiskFlags: []RiskFlag{
			{
				ID:            "container.host_namespace",
				Severity:      "HIGH",
				Summary:       "Uses host namespace",
				RequiresAdmin: true,
			},
			{
				ID:           "container.volume_delete",
				Severity:     RiskSeverityCritical,
				Summary:      "May remove data",
				DataLossRisk: true,
				Destructive:  true,
			},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeRiskPlanData() error = %v", err)
	}
	plan, ok := got.(RiskPlan)
	if !ok {
		t.Fatalf("NormalizeRiskPlanData() = %#v, want RiskPlan", got)
	}
	if plan.SchemaVersion != RiskPlanSchemaVersion || plan.RiskFlags[0].Severity != RiskSeverityHigh {
		t.Fatalf("normalized plan mismatch: %#v", plan)
	}
	if !plan.RequiresAdmin || !plan.RequiresConfirmation || !plan.DataLossRisk || !plan.Destructive {
		t.Fatalf("risk flags did not propagate summary booleans: %#v", plan)
	}
}

func TestNormalizeRiskPlanDataAcceptsClosedCurrentMap(t *testing.T) {
	got, err := NormalizeRiskPlanData(map[string]any{
		"schema_version": RiskPlanSchemaVersion,
		"summary":        "Start container",
		"risk_flags": []any{
			map[string]any{"id": "container.write", "severity": "medium", "summary": "Writes container state"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeRiskPlanData() error = %v", err)
	}
	plan, ok := got.(RiskPlan)
	if !ok || plan.SchemaVersion != RiskPlanSchemaVersion || len(plan.RiskFlags) != 1 {
		t.Fatalf("NormalizeRiskPlanData() = %#v, want current RiskPlan", got)
	}
}

func TestNormalizeRiskPlanDataRejectsInvalidRiskPlan(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan any
	}{
		{
			name: "missing plan",
			plan: nil,
		},
		{
			name: "nil typed plan",
			plan: (*RiskPlan)(nil),
		},
		{
			name: "missing schema version on typed plan",
			plan: RiskPlan{Summary: "Start", RiskFlags: []RiskFlag{
				{ID: "x", Severity: RiskSeverityLow, Summary: "x"},
			}},
		},
		{
			name: "missing schema version on generic object",
			plan: map[string]any{"summary": "Start", "risk_flags": []any{}},
		},
		{
			name: "generic scalar",
			plan: "start",
		},
		{
			name: "unsupported schema version",
			plan: RiskPlan{SchemaVersion: "wrong", Summary: "Start", RiskFlags: []RiskFlag{
				{ID: "x", Severity: RiskSeverityLow, Summary: "x"},
			}},
		},
		{
			name: "missing summary",
			plan: RiskPlan{SchemaVersion: RiskPlanSchemaVersion, RiskFlags: []RiskFlag{
				{ID: "x", Severity: RiskSeverityLow, Summary: "x"},
			}},
		},
		{
			name: "unknown map field",
			plan: map[string]any{
				"schema_version": RiskPlanSchemaVersion,
				"summary":        "Start",
				"risk_flags": []any{
					map[string]any{"id": "x", "severity": "low", "summary": "x"},
				},
				"raw_inspect_json": map[string]any{},
			},
		},
		{
			name: "invalid flag severity",
			plan: map[string]any{
				"schema_version": RiskPlanSchemaVersion,
				"summary":        "Start",
				"risk_flags": []any{
					map[string]any{"id": "x", "severity": "urgent", "summary": "x"},
				},
			},
		},
		{
			name: "unknown flag field",
			plan: map[string]any{
				"schema_version": RiskPlanSchemaVersion,
				"summary":        "Start",
				"risk_flags": []map[string]any{
					{"id": "x", "severity": "low", "summary": "x", "raw": true},
				},
			},
		},
		{
			name: "duplicate flag id",
			plan: RiskPlan{SchemaVersion: RiskPlanSchemaVersion, Summary: "Start", RiskFlags: []RiskFlag{
				{ID: "x", Severity: RiskSeverityLow, Summary: "x"},
				{ID: "x", Severity: RiskSeverityHigh, Summary: "x again"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NormalizeRiskPlanData(tc.plan); !errors.Is(err, ErrInvalidRiskPlan) {
				t.Fatalf("NormalizeRiskPlanData() error = %v, want ErrInvalidRiskPlan", err)
			}
		})
	}
}
