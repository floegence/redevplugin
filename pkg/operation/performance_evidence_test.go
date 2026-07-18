package operation

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/capability"
)

var operationPerformanceRecordSink Record

func TestPerformanceOperationMemoryStoreSnapshotAllocations(t *testing.T) {
	const samples = 1_000
	const operationID = "op_performance_snapshot"
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	if _, err := store.Register(context.Background(), RegisterRequest{
		OperationID: operationID,
		ExecutionBinding: operationTestBinding("com.example.performance", "plugini_performance", "documents.update", func(binding *capability.ExecutionBinding) {
			binding.Permissions.Required = []string{"documents.read", "documents.write"}
			binding.Permissions.Granted = []string{"documents.read", "documents.write"}
			binding.Target.Fields = map[string]any{
				"document_id": "doc-1",
				"selectors":   []any{"title", map[string]any{"kind": "section", "indexes": []any{1.0, 2.0, 3.0}}},
			}
		}),
		Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var snapshotErr error
	typedAllocs := testing.AllocsPerRun(samples, func() {
		operationPerformanceRecordSink, snapshotErr = store.Get(ctx, operationID)
	})
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	jsonAllocs := testing.AllocsPerRun(samples, func() {
		operationPerformanceRecordSink, snapshotErr = jsonSnapshotOperationMemoryStoreForPerformance(store, operationID)
	})
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	relative, err := performanceevidence.RelativeBasisPoints(typedAllocs, jsonAllocs)
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 2_000 {
		t.Fatalf("operation memory store snapshot allocations %.2f versus JSON baseline %.2f = %.2f basis points, want <= 2000", typedAllocs, jsonAllocs, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "operation.memory-store-snapshot",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "relative_allocations", Unit: "basis_points", Observed: relative, Limit: 2_000, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func jsonSnapshotOperationMemoryStoreForPerformance(store *MemoryStore, operationID string) (Record, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	record, ok := store.records[operationID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return jsonCloneOperationRecordForPerformance(record)
}

func jsonCloneOperationRecordForPerformance(record Record) (Record, error) {
	raw, err := json.Marshal(record.ExecutionBinding)
	if err != nil {
		return Record{}, err
	}
	var binding capability.ExecutionBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		return Record{}, err
	}
	record.ExecutionBinding = binding
	if record.CancelRequestedAt != nil {
		value := *record.CancelRequestedAt
		record.CancelRequestedAt = &value
	}
	if record.OrphanedAt != nil {
		value := *record.OrphanedAt
		record.OrphanedAt = &value
	}
	if record.TerminalAt != nil {
		value := *record.TerminalAt
		record.TerminalAt = &value
	}
	return record, nil
}
