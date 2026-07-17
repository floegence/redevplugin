package stream

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/capability"
)

func TestPerformanceStreamWaitersAndBackpressure(t *testing.T) {
	const waiterCount = 500
	store, err := NewSQLiteStore(context.Background(), t.TempDir()+"/streams.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	var waitObservationQueries atomic.Int64
	initialObservationsComplete := make(chan struct{})
	store.queryObserver = func(kind sqliteQueryKind) {
		if kind == sqliteQueryWaitObservation && waitObservationQueries.Add(1) == 3*waiterCount {
			close(initialObservationsComplete)
		}
	}
	type waiterResult struct {
		index int
		at    time.Time
		err   error
	}
	results := make(chan waiterResult, waiterCount)
	appendTimes := make([]time.Time, waiterCount)
	for index := 0; index < waiterCount; index++ {
		streamID := fmt.Sprintf("stream_performance_%d", index)
		if _, err := store.Register(context.Background(), RegisterRequest{
			StreamID: streamID,
			ExecutionBinding: capability.ExecutionBinding{
				PluginInstanceID: "plugini_performance",
				Method:           "performance.events",
			},
		}); err != nil {
			t.Fatal(err)
		}
		go func(index int, streamID string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := store.Wait(ctx, streamID)
			results <- waiterResult{index: index, at: time.Now(), err: err}
		}(index, streamID)
	}
	<-initialObservationsComplete
	observedWaitQueries := waitObservationQueries.Load()
	if want := int64(3 * waiterCount); observedWaitQueries != want {
		t.Fatalf("initial SQLite wait observations = %d, want %d", observedWaitQueries, want)
	}
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
	if got := waitObservationQueries.Load(); got != observedWaitQueries {
		t.Fatalf("notifier wake executed additional wait observations: got %d want %d", got, observedWaitQueries)
	}
	periodicQueries := waitObservationQueries.Load() - observedWaitQueries
	wakeP95, _ := streamPerformanceDurations(wakeDurations)
	if gate := performanceevidence.Gate(); (gate == "full" || gate == "release") && wakeP95 > 100*time.Millisecond {
		t.Fatalf("stream wake p95 = %s", wakeP95)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.idle-waiters",
		Gate:        performanceevidence.Gate(),
		SampleCount: waiterCount,
		Metrics: []performanceevidence.Metric{
			{Name: "waiters", Unit: "count", Observed: waiterCount, Limit: waiterCount, Comparator: "eq"},
			{Name: "periodic_store_queries", Unit: "queries", Observed: float64(periodicQueries), Limit: 0, Comparator: "eq"},
			{Name: "wake_p95", Unit: "milliseconds", Observed: streamDurationMilliseconds(wakeP95), Limit: 100, Comparator: "lte"},
		},
	})

	const acceptedEvents = 256
	eventBytes := streamEventOverheadBytes + int64(len("event"))
	backpressureStore := NewMemoryStore()
	if _, err := backpressureStore.Register(context.Background(), RegisterRequest{
		StreamID: "stream_backpressure_performance",
		ExecutionBinding: capability.ExecutionBinding{
			PluginInstanceID: "plugini_performance",
			Method:           "performance.events",
		},
		MaxBufferedBytes: acceptedEvents * eventBytes,
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < acceptedEvents; index++ {
		if _, err := backpressureStore.Append(context.Background(), AppendRequest{StreamID: "stream_backpressure_performance", Kind: "event"}); err != nil {
			t.Fatalf("append %d: %v", index+1, err)
		}
	}
	if _, err := backpressureStore.Append(context.Background(), AppendRequest{StreamID: "stream_backpressure_performance", Kind: "event"}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("append %d error = %v, want %v", acceptedEvents+1, err, ErrBackpressure)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.event-backpressure",
		Gate:        performanceevidence.Gate(),
		SampleCount: acceptedEvents + 1,
		Metrics: []performanceevidence.Metric{
			{Name: "accepted_events", Unit: "count", Observed: acceptedEvents, Limit: acceptedEvents, Comparator: "eq"},
			{Name: "first_rejected_event", Unit: "count", Observed: acceptedEvents + 1, Limit: acceptedEvents + 1, Comparator: "eq"},
		},
	})
}

func TestSQLiteEmptyObservationDoesNotAcquireWriteGate(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), t.TempDir()+"/streams.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID: "stream_read_only",
		ExecutionBinding: capability.ExecutionBinding{
			PluginInstanceID: "plugini_performance",
			Method:           "performance.events",
		},
	}); err != nil {
		t.Fatal(err)
	}

	<-store.writeGate
	t.Cleanup(func() { store.writeGate <- struct{}{} })
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: "stream_read_only", ReadID: "read_readonly1"}); err != nil {
		t.Fatalf("empty delivery acquired write gate: %v", err)
	} else if delivery.DeliveryID != "" || len(delivery.Events) != 0 {
		t.Fatalf("empty delivery = %#v", delivery)
	}

	waitDone := make(chan error, 1)
	waitCtx, waitCancel := context.WithCancel(context.Background())
	waitObservationStarted := make(chan struct{})
	var waitObservationOnce sync.Once
	store.queryObserver = func(kind sqliteQueryKind) {
		if kind == sqliteQueryWaitObservation {
			waitObservationOnce.Do(func() { close(waitObservationStarted) })
		}
	}
	go func() { waitDone <- store.Wait(waitCtx, "stream_read_only") }()
	<-waitObservationStarted
	waitCancel()
	if err := <-waitDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context canceled", err)
	}
}

func TestPerformanceSQLiteStreamBatchDelivery(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), t.TempDir()+"/streams.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	var boundedSelects atomic.Int64
	var rangeDeletes atomic.Int64
	store.queryObserver = func(kind sqliteQueryKind) {
		switch kind {
		case sqliteQueryBoundedEvents:
			boundedSelects.Add(1)
		case sqliteQueryRangeDelete:
			rangeDeletes.Add(1)
		}
	}
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID: "stream_sqlite_performance",
		ExecutionBinding: capability.ExecutionBinding{
			PluginInstanceID: "plugini_performance",
			Method:           "performance.events",
		},
		MaxBufferedBytes: 1 << 20,
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
	_, delivery, err := store.Deliver(context.Background(), DeliverRequest{
		StreamID:  "stream_sqlite_performance",
		ReadID:    "read_batch0001",
		MaxEvents: 256,
		MaxBytes:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Events) != 256 || delivery.ThroughSequence != 256 {
		t.Fatalf("SQLite batch delivery = %#v", delivery)
	}
	if _, err := store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: delivery.StreamID, DeliveryID: delivery.DeliveryID}); err != nil {
		t.Fatal(err)
	}
	observedSelects := boundedSelects.Load()
	observedDeletes := rangeDeletes.Load()
	if observedSelects != 1 || observedDeletes != 1 {
		t.Fatalf("SQLite batch query counts selects=%d deletes=%d, want 1 and 1", observedSelects, observedDeletes)
	}
	_, remaining, err := store.Deliver(context.Background(), DeliverRequest{
		StreamID:  "stream_sqlite_performance",
		ReadID:    "read_batch0002",
		MaxEvents: 256,
		MaxBytes:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Events) != 256 || remaining.Events[0].Sequence != 257 || remaining.Events[255].Sequence != 512 {
		t.Fatalf("remaining SQLite delivery = %#v", remaining)
	}
	recordStreamPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "stream.sqlite-batch-delivery",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(delivery.Events),
		Metrics: []performanceevidence.Metric{
			{Name: "events_selected", Unit: "count", Observed: float64(len(delivery.Events)), Limit: 256, Comparator: "eq"},
			{Name: "bounded_selects", Unit: "queries", Observed: float64(observedSelects), Limit: 1, Comparator: "eq"},
			{Name: "range_deletes", Unit: "queries", Observed: float64(observedDeletes), Limit: 1, Comparator: "eq"},
			{Name: "remaining_events", Unit: "count", Observed: float64(len(remaining.Events)), Limit: 256, Comparator: "eq"},
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
