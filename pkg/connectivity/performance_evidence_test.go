package connectivity

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
)

func TestPerformanceHTTPKeepAliveRelativeP95(t *testing.T) {
	const (
		samples           = 64
		requestsPerSample = 4
	)
	serverAddress := startHTTPPoolTestServer(t)
	pooled, pooledDials := newHTTPPoolPerformanceExecutor(serverAddress)
	t.Cleanup(func() { closeExecutor(t, pooled) })
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Hour)
	if _, err := pooled.DoHTTP(context.Background(), HTTPRequest{Grant: grant}); err != nil {
		t.Fatal(err)
	}
	pooledDurations := make([]time.Duration, 0, samples)
	connectDurations := make([]time.Duration, 0, samples)
	for sample := range samples {
		connectExecutors := make([]*Executor, requestsPerSample)
		connectDials := make([]*atomic.Int64, requestsPerSample)
		for index := range requestsPerSample {
			connectExecutors[index], connectDials[index] = newHTTPPoolPerformanceExecutor(serverAddress)
		}

		measurePooled := func() time.Duration {
			return measureHTTPPerformanceBatch(t, requestsPerSample, func() error {
				_, err := pooled.DoHTTP(context.Background(), HTTPRequest{Grant: grant})
				return err
			})
		}
		measureConnect := func() time.Duration {
			index := 0
			return measureHTTPPerformanceBatch(t, requestsPerSample, func() error {
				_, err := connectExecutors[index].DoHTTP(context.Background(), HTTPRequest{Grant: grant})
				index++
				return err
			})
		}
		// Alternate paired batches so scheduler and server load affect both paths evenly.
		if sample%2 == 0 {
			pooledDurations = append(pooledDurations, measurePooled())
			connectDurations = append(connectDurations, measureConnect())
		} else {
			connectDurations = append(connectDurations, measureConnect())
			pooledDurations = append(pooledDurations, measurePooled())
		}

		for index, executor := range connectExecutors {
			closeExecutor(t, executor)
			if got := connectDials[index].Load(); got != 1 {
				t.Fatalf("connect baseline sample %d request %d dials = %d, want 1", sample, index, got)
			}
		}
	}
	if got := pooledDials.Load(); got != 1 {
		t.Fatalf("pooled HTTP dials = %d, want 1", got)
	}
	pooledP95 := performanceevidence.P95(pooledDurations)
	connectP95 := performanceevidence.P95(connectDurations)
	relative, err := performanceevidence.RelativeBasisPoints(float64(pooledP95), float64(connectP95))
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 7_000 {
		t.Fatalf("keep-alive p95 %s versus connect p95 %s = %.2f basis points, want <= 7000", pooledP95, connectP95, relative)
	}
	recordConnectivityPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "connectivity.http-keepalive",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "p95_relative_to_connect", Unit: "basis_points", Observed: relative, Limit: 7_000, Comparator: "lte"},
			{Name: "reused_connection_dials", Unit: "count", Observed: float64(pooledDials.Load()), Limit: 1, Comparator: "eq"},
		},
	})
}

func TestPerformanceUDPLimiterHighCardinalityScaling(t *testing.T) {
	const (
		repetitions   = 9
		samples       = 1_000
		operations    = 64
		maxRoundTrips = 10_000_000
	)
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	small := NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: maxRoundTrips, Window: time.Hour})
	smallKey := udpLimiterTestKey("small.example")
	if !small.AllowUDPRoundTrip(now, smallKey) {
		t.Fatal("small UDP limiter rejected initial bucket")
	}
	large := NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: maxRoundTrips, Window: time.Hour})
	for index := 0; index < maxMemoryUDPRateLimitBuckets; index++ {
		if !large.AllowUDPRoundTrip(now, udpLimiterTestKey(performanceUDPHost(index))) {
			t.Fatalf("large UDP limiter rejected bucket %d", index)
		}
	}
	overflowDenied := !large.AllowUDPRoundTrip(now, udpLimiterTestKey("overflow.example"))
	if !overflowDenied {
		t.Fatal("UDP limiter accepted a bucket beyond fixed capacity")
	}
	largeKey := udpLimiterTestKey(performanceUDPHost(maxMemoryUDPRateLimitBuckets / 2))
	smallP95s := make([]time.Duration, 0, repetitions)
	largeP95s := make([]time.Duration, 0, repetitions)
	for repetition := 0; repetition < repetitions; repetition++ {
		smallDurations, largeDurations := measurePairedUDPLimiterBatches(
			small,
			smallKey,
			large,
			largeKey,
			now,
			repetition*samples,
			samples,
			operations,
		)
		smallP95s = append(smallP95s, performanceevidence.P95(smallDurations))
		largeP95s = append(largeP95s, performanceevidence.P95(largeDurations))
	}
	smallP95 := performanceevidence.MedianDuration(smallP95s)
	largeP95 := performanceevidence.MedianDuration(largeP95s)
	relative, err := performanceevidence.RelativeBasisPoints(float64(largeP95), float64(smallP95))
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 20_000 {
		t.Fatalf("large UDP limiter p95 %s versus small p95 %s = %.2f basis points, want <= 20000", largeP95, smallP95, relative)
	}
	recordConnectivityPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "connectivity.udp-limiter-scaling",
		Gate:        performanceevidence.Gate(),
		SampleCount: repetitions * samples,
		Metrics: []performanceevidence.Metric{
			{Name: "p95_large_relative_to_small", Unit: "basis_points", Observed: relative, Limit: 20_000, Comparator: "lte"},
			{Name: "bucket_capacity", Unit: "count", Observed: maxMemoryUDPRateLimitBuckets, Limit: maxMemoryUDPRateLimitBuckets, Comparator: "eq"},
			{Name: "overflow_denied", Unit: "count", Observed: boolCount(overflowDenied), Limit: 1, Comparator: "eq"},
		},
	})
}

func newHTTPPoolPerformanceExecutor(target string) (*Executor, *atomic.Int64) {
	dials := &atomic.Int64{}
	dial := mapDialer(target)
	return newExecutor(ExecutorOptions{}, executorNetworkOptions{
		resolveAddresses: guardedResolveAddresses(func(context.Context, string) ([]net.IPAddr, error) {
			return publicIPAddresses("93.184.216.34"), nil
		}),
		dialResolved: func(ctx context.Context, network, address string, _ []netip.Addr) (net.Conn, error) {
			dials.Add(1)
			return dial(ctx, network, address)
		},
	}), dials
}

func measureHTTPPerformanceBatch(t *testing.T, operations int, operation func() error) time.Duration {
	t.Helper()
	started := time.Now()
	for range operations {
		if err := operation(); err != nil {
			t.Fatal(err)
		}
	}
	return time.Since(started)
}

func measurePairedUDPLimiterBatches(
	small *MemoryUDPRateLimiter,
	smallKey UDPRateLimitKey,
	large *MemoryUDPRateLimiter,
	largeKey UDPRateLimitKey,
	now time.Time,
	sampleOffset int,
	samples int,
	operations int,
) ([]time.Duration, []time.Duration) {
	smallDurations := make([]time.Duration, 0, samples)
	largeDurations := make([]time.Duration, 0, samples)
	for sample := 0; sample < samples; sample++ {
		absoluteSample := sampleOffset + sample
		measureSmall := func() {
			smallDurations = append(smallDurations, measureUDPLimiterBatch(small, smallKey, now, absoluteSample, operations))
		}
		measureLarge := func() {
			largeDurations = append(largeDurations, measureUDPLimiterBatch(large, largeKey, now, absoluteSample, operations))
		}
		// Keep each comparison local and balance which path sees the first scheduler slot.
		if absoluteSample%2 == 0 {
			measureSmall()
			measureLarge()
		} else {
			measureLarge()
			measureSmall()
		}
	}
	return smallDurations, largeDurations
}

func measureUDPLimiterBatch(limiter *MemoryUDPRateLimiter, key UDPRateLimitKey, now time.Time, sample, operations int) time.Duration {
	started := time.Now()
	for operation := 0; operation < operations; operation++ {
		if !limiter.AllowUDPRoundTrip(now.Add(time.Duration(sample*operations+operation+1)), key) {
			panic("performance UDP limiter unexpectedly rejected an existing bucket")
		}
	}
	return time.Since(started)
}

func performanceUDPHost(index int) string {
	return fmt.Sprintf("endpoint-%05d.example", index)
}

func boolCount(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func recordConnectivityPerformanceScenario(t *testing.T, scenario performanceevidence.Scenario) {
	t.Helper()
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), scenario); err != nil {
		t.Fatal(err)
	}
}
