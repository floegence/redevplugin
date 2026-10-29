package performanceevidence

import (
	"errors"
	"testing"
	"time"
)

func TestRouteSampleCollectorDoesNotGrowDuringMeasurement(t *testing.T) {
	const concurrency, batches = 100, 64
	batch := make([]time.Duration, concurrency*RouteAuthorizationRequestsPerSample)
	for i := range batch {
		batch[i] = time.Duration(i + 1)
	}
	var durations []time.Duration
	var costs []float64
	var err error
	allocations := testing.AllocsPerRun(1, func() {
		durations, costs, err = collectRouteAuthorizationSamples(concurrency, batches, func() ([]time.Duration, time.Duration, error) { return batch, 3200 * time.Nanosecond, nil })
	})
	if err != nil || len(durations) != batches*len(batch) || len(costs) != batches {
		t.Fatalf("samples=%d costs=%d error=%v", len(durations), len(costs), err)
	}
	for i, sample := range durations {
		if sample != batch[i%len(batch)] {
			t.Fatalf("sample %d=%s", i, sample)
		}
	}
	for _, cost := range costs {
		if cost != 1 {
			t.Fatalf("batch cost=%v", cost)
		}
	}
	// The observer owns two buffers. Growing either during collection perturbs
	// subsequent handler batches through allocation and garbage collection.
	if allocations != 2 {
		t.Fatalf("collector allocated %.0f buffers; want exactly 2 before measuring", allocations)
	}
}

func TestRouteSampleCollectorStopsAtFirstFailedBatch(t *testing.T) {
	expected := errors.New("handler failed")
	calls := 0
	samples, batches, err := collectRouteAuthorizationSamples(1, 8, func() ([]time.Duration, time.Duration, error) {
		calls++
		if calls == 2 {
			return nil, 0, expected
		}
		return make([]time.Duration, RouteAuthorizationRequestsPerSample), time.Second, nil
	})
	if !errors.Is(err, expected) || calls != 2 || samples != nil || batches != nil {
		t.Fatalf("calls=%d samples=%v batches=%v err=%v", calls, samples, batches, err)
	}
}
