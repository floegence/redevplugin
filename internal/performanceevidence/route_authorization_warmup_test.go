package performanceevidence

import (
	"errors"
	"testing"
	"time"
)

func TestRouteAuthorizationWarmupRequiresDurationAndMinimumBatches(t *testing.T) {
	for _, step := range []time.Duration{10 * time.Millisecond, 100 * time.Millisecond} {
		t.Run(step.String(), func(t *testing.T) {
			elapsed := time.Duration(0)
			calls := 0
			count, duration, err := warmRouteAuthorization(func() error { calls++; elapsed += step; return nil }, func() time.Time { return time.Unix(0, 0).Add(elapsed) })
			if err != nil || count != calls || count < 32 || duration < time.Second {
				t.Fatalf("warmup=(%d,%s,%v), calls=%d", count, duration, err, calls)
			}
			if count > 32 && duration-step >= time.Second {
				t.Fatal("warmup continued beyond both minimums")
			}
		})
	}
}

func TestRouteAuthorizationWarmupStopsOnFailure(t *testing.T) {
	expected := errors.New("probe failed")
	calls := 0
	_, _, err := warmRouteAuthorization(func() error { calls++; return expected }, time.Now)
	if !errors.Is(err, expected) || calls != 1 {
		t.Fatalf("warmup error=%v calls=%d", err, calls)
	}
}

func TestRouteAuthorizationBatchCountsCoverShortConcurrencyWindow(t *testing.T) {
	for _, test := range []struct{ concurrency, want int }{{1, 1000}, {100, 1024}, {1000, 256}} {
		if got := routeAuthorizationBatchCount(test.concurrency); got != test.want {
			t.Fatalf("c%d batch count=%d, want %d", test.concurrency, got, test.want)
		}
	}
}
