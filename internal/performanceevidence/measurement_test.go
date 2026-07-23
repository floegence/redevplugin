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

func TestMedianDurationUsesTheMiddleIndependentRepetition(t *testing.T) {
	values := []time.Duration{90 * time.Microsecond, 10 * time.Microsecond, 30 * time.Microsecond, 20 * time.Microsecond, 80 * time.Microsecond}
	if got := MedianDuration(values); got != 30*time.Microsecond {
		t.Fatalf("MedianDuration() = %s, want 30us", got)
	}
	if got := MedianDuration(nil); got != 0 {
		t.Fatalf("MedianDuration(nil) = %s, want 0", got)
	}
}

func TestEnforceThresholdsRequiresExplicitEvidenceRun(t *testing.T) {
	t.Setenv("REDEVPLUGIN_PERFORMANCE_GATE", "full")
	t.Setenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS", "")
	if EnforceThresholds() {
		t.Fatal("normal test run enforced environment-sensitive performance thresholds")
	}
	t.Setenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS", "/tmp/measurements.ndjson")
	if !EnforceThresholds() {
		t.Fatal("explicit full evidence run did not enforce performance thresholds")
	}
	t.Setenv("REDEVPLUGIN_PERFORMANCE_GATE", "release")
	if !EnforceThresholds() {
		t.Fatal("explicit release evidence run did not enforce performance thresholds")
	}
	t.Setenv("REDEVPLUGIN_PERFORMANCE_GATE", "fast")
	if EnforceThresholds() {
		t.Fatal("fast evidence run enforced release performance thresholds")
	}
}

func TestRouteAuthorizationProfileRequiresStableRequestSamples(t *testing.T) {
	profile := RouteAuthorizationProfile{
		SchemaVersion: "redevplugin.route_authorization_performance.v1",
		Variant:       "v0.6.0",
		Commit:        "0123456789abcdef0123456789abcdef01234567",
		Environment: RouteAuthorizationEnvironment{
			OS:          "linux",
			Arch:        "amd64",
			LogicalCPUs: 8,
			GOMAXPROCS:  8,
			GoVersion:   "go1.26.0",
		},
		WarmupCount:       RouteAuthorizationWarmupCount,
		RequestsPerSample: RouteAuthorizationRequestsPerSample,
		Measurements: []RouteAuthorizationMeasurement{
			{Concurrency: 1, BatchCount: 1000, SampleCount: 32000, MedianNanoseconds: 10, P95Nanoseconds: 12, P99Nanoseconds: 14},
			{Concurrency: 100, BatchCount: 64, SampleCount: 204800, MedianNanoseconds: 10, P95Nanoseconds: 12, P99Nanoseconds: 14},
			{Concurrency: 1000, BatchCount: 64, SampleCount: 2048000, MedianNanoseconds: 10, P95Nanoseconds: 12, P99Nanoseconds: 14},
		},
	}
	if err := ValidateRouteAuthorizationProfile(profile); err != nil {
		t.Fatalf("valid route authorization profile was rejected: %v", err)
	}
	profile.Measurements[0].BatchCount = RouteAuthorizationMinBatchCount
	if err := ValidateRouteAuthorizationProfile(profile); err == nil {
		t.Fatal("route authorization profile accepted an unstable c1 sample count")
	}
}

func TestRouteAuthorizationPercentileUsesRequestSamples(t *testing.T) {
	values := make([]time.Duration, 1000)
	for index := range values {
		values[index] = time.Duration(index+1) * time.Nanosecond
	}
	if got := routeAuthorizationPercentile(values, 99); got != 990*time.Nanosecond {
		t.Fatalf("routeAuthorizationPercentile(..., 99) = %s, want 990ns", got)
	}
}
