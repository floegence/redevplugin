package cleanup

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestOrchestratorPlansRetainAndDeleteUninstall(t *testing.T) {
	for _, tc := range cleanupOrchestratorCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			orchestrator := tc.open(t)

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
		})
	}
}

func TestOrchestratorExecutesPlan(t *testing.T) {
	for _, tc := range cleanupOrchestratorCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			orchestrator := tc.open(t)
			inspector := tc.inspect(t, orchestrator)
			plan, err := orchestrator.PlanUninstall(ctx, "plugini_delete", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := orchestrator.Execute(ctx, plan); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			records, err := inspector.ListExecutions(ctx, "plugini_delete")
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
		})
	}
}

func TestOrchestratorForceCleanup(t *testing.T) {
	for _, tc := range cleanupOrchestratorCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			orchestrator := tc.open(t)
			inspector := tc.inspect(t, orchestrator)
			if err := orchestrator.ForceCleanup(ctx, "plugini_force"); err != nil {
				t.Fatalf("ForceCleanup() error = %v", err)
			}
			records, err := inspector.ListExecutions(ctx, "plugini_force")
			if err != nil {
				t.Fatalf("ListExecutions() error = %v", err)
			}
			if len(records) != 5 || records[2].Phase != PhaseDeleteData {
				t.Fatalf("force cleanup records mismatch: %#v", records)
			}
		})
	}
}

func TestOrchestratorRejectsInvalidPlans(t *testing.T) {
	for _, tc := range cleanupOrchestratorCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			orchestrator := tc.open(t)
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
		})
	}
}

func TestSQLiteOrchestratorPersistsExecutionsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cleanup.sqlite")
	orchestrator, err := NewSQLiteOrchestrator(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator.now = func() time.Time {
		return time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)
	}
	plan, err := orchestrator.PlanUninstall(ctx, "plugini_persist", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.Execute(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteOrchestrator(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	records, err := reopened.ListExecutions(ctx, "plugini_persist")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(plan.Phases) {
		t.Fatalf("persisted execution count = %d, want %d", len(records), len(plan.Phases))
	}
	for i, record := range records {
		if record.Phase != plan.Phases[i] || !record.DeleteData || !record.ExecutedAt.Equal(time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)) {
			t.Fatalf("persisted execution[%d] mismatch: %#v", i, record)
		}
	}
}

func TestSQLiteOrchestratorRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cleanup.sqlite")
	orchestrator, err := NewSQLiteOrchestrator(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orchestrator.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_cleanup_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteOrchestrator(ctx, path); err == nil {
		t.Fatal("NewSQLiteOrchestrator() accepted newer schema version")
	}
}

type cleanupOrchestratorCase struct {
	name    string
	open    func(t *testing.T) Orchestrator
	inspect func(t *testing.T, orchestrator Orchestrator) Inspector
}

func cleanupOrchestratorCases() []cleanupOrchestratorCase {
	return []cleanupOrchestratorCase{
		{
			name: "memory",
			open: func(t *testing.T) Orchestrator {
				t.Helper()
				return NewMemoryOrchestrator()
			},
			inspect: func(t *testing.T, orchestrator Orchestrator) Inspector {
				t.Helper()
				inspector, ok := orchestrator.(Inspector)
				if !ok {
					t.Fatal("memory orchestrator does not implement Inspector")
				}
				return inspector
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Orchestrator {
				t.Helper()
				orchestrator, err := NewSQLiteOrchestrator(context.Background(), filepath.Join(t.TempDir(), "cleanup.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = orchestrator.Close()
				})
				return orchestrator
			},
			inspect: func(t *testing.T, orchestrator Orchestrator) Inspector {
				t.Helper()
				inspector, ok := orchestrator.(Inspector)
				if !ok {
					t.Fatal("sqlite orchestrator does not implement Inspector")
				}
				return inspector
			},
		},
	}
}
