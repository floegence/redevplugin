package pluginpkg

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/floegence/redevplugin/internal/performanceevidence"
)

func TestPerformanceWASMInspectionCache(t *testing.T) {
	const samples = 1_000
	module := minimalWorkerWASMForTest("redevplugin_worker_invoke")
	var inspectorCalls atomic.Int64
	cache := newWASMInspectionCache(wasmInspectionCacheCapacity, func(module []byte) (wasmModuleContract, error) {
		inspectorCalls.Add(1)
		return inspectWASMModule(module)
	})
	if _, err := cache.inspect(context.Background(), module, testWASMABI); err != nil {
		t.Fatal(err)
	}
	warmAllocs := testing.AllocsPerRun(samples, func() {
		if _, err := cache.inspect(context.Background(), module, testWASMABI); err != nil {
			t.Fatal(err)
		}
	})
	rawAllocs := testing.AllocsPerRun(samples, func() {
		if _, err := inspectWASMModule(module); err != nil {
			t.Fatal(err)
		}
	})
	relative, err := performanceevidence.RelativeBasisPoints(warmAllocs, rawAllocs)
	if err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	capacity := cache.capacity
	cache.mu.Unlock()
	calls := inspectorCalls.Load()
	if calls != 1 || entries != 1 || capacity != wasmInspectionCacheCapacity {
		t.Fatalf("WASM inspection cache calls=%d entries=%d capacity=%d", calls, entries, capacity)
	}
	if performanceevidence.EnforceThresholds() && relative > 5_000 {
		t.Fatalf("warm WASM inspection allocations %.2f versus raw %.2f = %.2f basis points, want <= 5000", warmAllocs, rawAllocs, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "pluginpkg.wasm-inspection-cache",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "inspector_calls", Unit: "count", Observed: float64(calls), Limit: 1, Comparator: "eq"},
			{Name: "cache_entries", Unit: "count", Observed: float64(entries), Limit: 1, Comparator: "eq"},
			{Name: "cache_capacity", Unit: "count", Observed: float64(capacity), Limit: wasmInspectionCacheCapacity, Comparator: "eq"},
			{Name: "warm_relative_allocations", Unit: "basis_points", Observed: relative, Limit: 5_000, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}
