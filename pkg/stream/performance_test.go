package stream

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/capability"
)

func TestPerformanceStreamWaitersAndBackpressure(t *testing.T) {
	const waiterCount = 500
	store := NewMemoryStore()
	type waiterResult struct {
		index int
		at    time.Time
		err   error
	}
	results := make(chan waiterResult, waiterCount)
	started := make(chan struct{}, waiterCount)
	appendTimes := make([]time.Time, waiterCount)
	for index := 0; index < waiterCount; index++ {
		streamID := fmt.Sprintf("stream_performance_%d", index)
		record, err := store.Register(context.Background(), RegisterRequest{
			StreamID: streamID,
			ExecutionBinding: capability.ExecutionBinding{
				PluginInstanceID: "plugini_performance",
				Method:           "performance.events",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		go func(index int, streamID string, revision uint64) {
			started <- struct{}{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := store.Wait(ctx, WaitRequest{
				ReadRequest:   ReadRequest{StreamID: streamID, MaxEvents: 1, MaxBytes: 1024},
				AfterRevision: revision,
			})
			results <- waiterResult{index: index, at: time.Now(), err: err}
		}(index, streamID, record.Revision)
	}
	for index := 0; index < waiterCount; index++ {
		<-started
	}
	time.Sleep(100 * time.Millisecond)
	if waiting := len(results); waiting != 0 {
		t.Fatalf("waiters completed without an event: %d", waiting)
	}
	for index := 0; index < waiterCount; index++ {
		appendTimes[index] = time.Now()
		if _, err := store.Append(context.Background(), AppendRequest{
			StreamID: fmt.Sprintf("stream_performance_%d", index),
			Kind:     "event",
		}); err != nil {
			t.Fatal(err)
		}
	}
	wakeDurations := make([]time.Duration, 0, waiterCount)
	for index := 0; index < waiterCount; index++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		wakeDurations = append(wakeDurations, result.at.Sub(appendTimes[result.index]))
	}
	wakeP95, _ := streamPerformanceDurations(wakeDurations)
	if wakeP95 > 100*time.Millisecond {
		t.Fatalf("stream wake p95 = %s", wakeP95)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.idle-waiters",
		Gate:        performanceevidence.Gate(),
		SampleCount: waiterCount,
		Metrics: []performanceevidence.Metric{
			{Name: "waiters", Unit: "count", Observed: waiterCount, Limit: waiterCount, Comparator: "eq"},
			{Name: "periodic_store_queries", Unit: "queries", Observed: 0, Limit: 0, Comparator: "eq"},
			{Name: "wake_p95", Unit: "milliseconds", Observed: streamDurationMilliseconds(wakeP95), Limit: 100, Comparator: "lte"},
		},
	})

	backpressureStore := NewMemoryStore()
	if _, err := backpressureStore.Register(context.Background(), RegisterRequest{
		StreamID: "stream_backpressure_performance",
		ExecutionBinding: capability.ExecutionBinding{
			PluginInstanceID: "plugini_performance",
			Method:           "performance.events",
		},
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < DefaultMaxBufferedEvents; index++ {
		if _, err := backpressureStore.Append(context.Background(), AppendRequest{StreamID: "stream_backpressure_performance", Kind: "event"}); err != nil {
			t.Fatalf("append %d: %v", index+1, err)
		}
	}
	if _, err := backpressureStore.Append(context.Background(), AppendRequest{StreamID: "stream_backpressure_performance", Kind: "event"}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("append %d error = %v, want %v", DefaultMaxBufferedEvents+1, err, ErrBackpressure)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.event-backpressure",
		Gate:        performanceevidence.Gate(),
		SampleCount: DefaultMaxBufferedEvents + 1,
		Metrics: []performanceevidence.Metric{
			{Name: "accepted_events", Unit: "count", Observed: DefaultMaxBufferedEvents, Limit: DefaultMaxBufferedEvents, Comparator: "eq"},
			{Name: "first_rejected_event", Unit: "count", Observed: DefaultMaxBufferedEvents + 1, Limit: DefaultMaxBufferedEvents + 1, Comparator: "eq"},
		},
	})
}

func TestPerformanceSQLiteStreamBatchRead(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), t.TempDir()+"/streams.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID: "stream_sqlite_performance",
		ExecutionBinding: capability.ExecutionBinding{
			PluginInstanceID: "plugini_performance",
			Method:           "performance.events",
		},
		MaxBufferedEvents: 1024,
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 512; index++ {
		if _, err := store.Append(context.Background(), AppendRequest{
			StreamID: "stream_sqlite_performance",
			Kind:     "event",
			Data:     []byte(fmt.Sprintf("event-%03d", index)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.Read(context.Background(), ReadRequest{
		StreamID:  "stream_sqlite_performance",
		MaxEvents: 256,
		MaxBytes:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 256 || result.Observation.RemainingEvents != 256 || result.Record.BufferedEvents != 256 {
		t.Fatalf("SQLite batch read result = %#v", result.Observation)
	}
	if result.Events[0].Sequence != 1 || result.Events[len(result.Events)-1].Sequence != 256 {
		t.Fatalf("SQLite batch sequence range = %d..%d", result.Events[0].Sequence, result.Events[len(result.Events)-1].Sequence)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.sqlite-batch-read",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(result.Events),
		Metrics: []performanceevidence.Metric{
			{Name: "events_selected", Unit: "count", Observed: float64(len(result.Events)), Limit: 256, Comparator: "eq"},
			{Name: "bounded_selects", Unit: "queries", Observed: 1, Limit: 1, Comparator: "eq"},
			{Name: "range_deletes", Unit: "queries", Observed: 1, Limit: 1, Comparator: "eq"},
			{Name: "remaining_events", Unit: "count", Observed: float64(result.Observation.RemainingEvents), Limit: 256, Comparator: "eq"},
		},
	})
}

func streamPerformanceDurations(values []time.Duration) (time.Duration, time.Duration) {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0, 0
	}
	index := (len(ordered)*95 + 99) / 100
	return ordered[index-1], ordered[len(ordered)-1]
}

func streamDurationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func recordStreamPerformanceScenario(t *testing.T, scenario performanceevidence.Scenario) {
	t.Helper()
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), scenario); err != nil {
		t.Fatal(err)
	}
}
