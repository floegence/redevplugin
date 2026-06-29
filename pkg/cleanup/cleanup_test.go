package cleanup

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestMemoryOrchestratorPlansRetainAndDeleteUninstall(t *testing.T) {
	ctx := context.Background()
	orchestrator := NewMemoryOrchestrator()

	retainPlan, err := orchestrator.PlanUninstall(ctx, "plugini_retain", false)
	if err != nil {
		t.Fatalf("PlanUninstall(retain) error = %v", err)
	}
	if retainPlan.DeleteData {
		t.Fatal("retain plan unexpectedly deletes data")
	}
	if !reflect.DeepEqual(retainPlan.Phases, []Phase{PhaseTombstone, PhaseRevoke, PhaseDeletePackage, PhaseComplete}) {
		t.Fatalf("retain phases = %#v", retainPlan.Phases)
	}

	deletePlan, err := orchestrator.PlanUninstall(ctx, "plugini_delete", true)
	if err != nil {
		t.Fatalf("PlanUninstall(delete) error = %v", err)
	}
	if !deletePlan.DeleteData {
		t.Fatal("delete plan did not mark DeleteData")
	}
	if !reflect.DeepEqual(deletePlan.Phases, []Phase{PhaseTombstone, PhaseRevoke, PhaseDeleteData, PhaseDeletePackage, PhaseComplete}) {
		t.Fatalf("delete phases = %#v", deletePlan.Phases)
	}
}

func TestMemoryOrchestratorExecutesPlan(t *testing.T) {
	ctx := context.Background()
	orchestrator := NewMemoryOrchestrator()
	plan, err := orchestrator.PlanUninstall(ctx, "plugini_delete", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.Execute(ctx, plan); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	records, err := orchestrator.ListExecutions(ctx, "plugini_delete")
	if err != nil {
		t.Fatalf("ListExecutions() error = %v", err)
	}
	if len(records) != len(plan.Phases) {
		t.Fatalf("execution count = %d, want %d", len(records), len(plan.Phases))
	}
	for i, record := range records {
		if record.PluginInstanceID != "plugini_delete" || record.Phase != plan.Phases[i] || !record.DeleteData {
			t.Fatalf("execution[%d] mismatch: %#v", i, record)
		}
	}
}

func TestMemoryOrchestratorRejectsInvalidPlans(t *testing.T) {
	ctx := context.Background()
	orchestrator := NewMemoryOrchestrator()
	tests := []Plan{
		{},
		{PluginInstanceID: "plugini_bad"},
		{PluginInstanceID: "plugini_bad", Phases: []Phase{PhaseTombstone, PhaseTombstone, PhaseRevoke, PhaseDeletePackage, PhaseComplete}},
		{PluginInstanceID: "plugini_bad", DeleteData: true, Phases: []Phase{PhaseTombstone, PhaseRevoke, PhaseDeletePackage, PhaseComplete}},
		{PluginInstanceID: "plugini_bad", Phases: []Phase{PhaseTombstone, PhaseRevoke, PhaseDeleteData, PhaseDeletePackage, PhaseComplete}},
		{PluginInstanceID: "plugini_bad", Phases: []Phase{PhaseTombstone, "unknown", PhaseRevoke, PhaseDeletePackage, PhaseComplete}},
	}
	for _, plan := range tests {
		if err := orchestrator.Execute(ctx, plan); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("Execute(%#v) error = %v, want ErrInvalidPlan", plan, err)
		}
	}
}
