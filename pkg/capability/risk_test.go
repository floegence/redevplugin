package capability

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeRiskPlanDataDefaultsTypedPlanAndPropagatesFlagRisk(t *testing.T) {
	got, err := NormalizeRiskPlanData(RiskPlan{
		Summary: "Start container",
		Effect:  EffectExecute,
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

func TestNormalizeRiskPlanDataLeavesLegacyGenericPlanUntouched(t *testing.T) {
	legacy := map[string]any{"summary": "Legacy preflight", "anything": true}
	got, err := NormalizeRiskPlanData(legacy)
	if err != nil {
		t.Fatalf("NormalizeRiskPlanData() legacy error = %v", err)
	}
	if !reflect.DeepEqual(got, legacy) {
		t.Fatalf("legacy plan was changed: %#v", got)
	}
}

func TestNormalizeRiskPlanDataRejectsInvalidRiskPlan(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan any
	}{
		{
			name: "unsupported schema version",
			plan: RiskPlan{SchemaVersion: "wrong", Summary: "Start", RiskFlags: []RiskFlag{
				{ID: "x", Severity: RiskSeverityLow, Summary: "x"},
			}},
		},
		{
			name: "missing summary",
			plan: RiskPlan{RiskFlags: []RiskFlag{
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
			name: "duplicate flag id",
			plan: RiskPlan{Summary: "Start", RiskFlags: []RiskFlag{
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
