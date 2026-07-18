package stream

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/capability"
)

var streamPerformanceRecordSink Record

func TestPerformanceStreamMemoryStoreSnapshotAllocations(t *testing.T) {
	const samples = 1_000
	const streamID = "stream_performance_snapshot"
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID: streamID,
		ExecutionBinding: streamTestBindingWith("plugini_performance", func(binding *capability.ExecutionBinding) {
			binding.Permissions.Required = []string{"documents.read", "documents.watch"}
			binding.Permissions.Granted = []string{"documents.read", "documents.watch"}
			binding.Target.Fields = map[string]any{
				"workspace_id": "workspace-1",
				"filters":      []any{"active", map[string]any{"labels": []any{"release", "review"}}},
			}
		}),
		Direction:        DirectionRead,
		ContentType:      "application/json",
		MaxBufferedBytes: 1 << 20,
		Now:              now,
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var snapshotErr error
	typedAllocs := testing.AllocsPerRun(samples, func() {
		streamPerformanceRecordSink, snapshotErr = store.Get(ctx, streamID)
	})
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	jsonAllocs := testing.AllocsPerRun(samples, func() {
		streamPerformanceRecordSink, snapshotErr = jsonSnapshotStreamMemoryStoreForPerformance(store, streamID)
	})
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	relative, err := performanceevidence.RelativeBasisPoints(typedAllocs, jsonAllocs)
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 2_000 {
		t.Fatalf("stream memory store snapshot allocations %.2f versus JSON baseline %.2f = %.2f basis points, want <= 2000", typedAllocs, jsonAllocs, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "stream.memory-store-snapshot",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "relative_allocations", Unit: "basis_points", Observed: relative, Limit: 2_000, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func jsonSnapshotStreamMemoryStoreForPerformance(store *MemoryStore, streamID string) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[streamID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return jsonCloneStreamRecordForPerformance(record)
}

func jsonCloneStreamRecordForPerformance(record Record) (Record, error) {
	raw, err := json.Marshal(record.ExecutionBinding)
	if err != nil {
		return Record{}, err
	}
	var binding capability.ExecutionBinding
	if err := json.Unmarshal(raw, &binding); err != nil {
		return Record{}, err
	}
	record.ExecutionBinding = binding
	if record.ClosedAt != nil {
		value := *record.ClosedAt
		record.ClosedAt = &value
	}
	return record, nil
}
