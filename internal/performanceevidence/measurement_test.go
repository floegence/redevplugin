package performanceevidence

import (
	"math"
	"testing"
	"time"
)

func TestRelativeBasisPoints(t *testing.T) {
	got, err := RelativeBasisPoints(3, 10)
	if err != nil || got != 3_000 {
		t.Fatalf("RelativeBasisPoints() = %v, %v", got, err)
	}
	for _, values := range [][2]float64{{1, 0}, {-1, 1}, {1, math.Inf(1)}, {math.NaN(), 1}} {
		if _, err := RelativeBasisPoints(values[0], values[1]); err == nil {
			t.Fatalf("RelativeBasisPoints(%v, %v) succeeded", values[0], values[1])
		}
	}
}

func TestP95(t *testing.T) {
	values := make([]time.Duration, 100)
	for index := range values {
		values[index] = time.Duration(100-index) * time.Millisecond
	}
	if got := P95(values); got != 95*time.Millisecond {
		t.Fatalf("P95() = %s, want 95ms", got)
	}
	if got := P95(nil); got != 0 {
		t.Fatalf("P95(nil) = %s, want 0", got)
	}
}
