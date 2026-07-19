package performanceevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	RouteAuthorizationWarmupCount       = 8
	RouteAuthorizationMinBatchCount     = 64
	RouteAuthorizationMinSampleCount    = 1000
	RouteAuthorizationRequestsPerSample = 32
)

var routeAuthorizationConcurrencies = [...]int{1, 100, 1000}

type RouteAuthorizationEnvironment struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	LogicalCPUs int    `json:"logical_cpus"`
	GOMAXPROCS  int    `json:"gomaxprocs"`
	GoVersion   string `json:"go_version"`
}

type RouteAuthorizationMeasurement struct {
	Concurrency           int     `json:"concurrency"`
	BatchCount            int     `json:"batch_count"`
	SampleCount           int     `json:"sample_count"`
	MedianNanoseconds     int64   `json:"median_nanoseconds"`
	P95Nanoseconds        int64   `json:"p95_nanoseconds"`
	P99Nanoseconds        int64   `json:"p99_nanoseconds"`
	AllocationsPerRequest float64 `json:"allocations_per_request"`
	BytesPerRequest       float64 `json:"bytes_per_request"`
}

type RouteAuthorizationProfile struct {
	SchemaVersion     string                          `json:"schema_version"`
	Variant           string                          `json:"variant"`
	Commit            string                          `json:"commit"`
	Environment       RouteAuthorizationEnvironment   `json:"environment"`
	WarmupCount       int                             `json:"warmup_count"`
	RequestsPerSample int                             `json:"requests_per_sample"`
	Measurements      []RouteAuthorizationMeasurement `json:"measurements"`
}

func MeasureRouteAuthorization(variant, commit string, invoke func() error) (RouteAuthorizationProfile, error) {
	variant = strings.TrimSpace(variant)
	commit = strings.TrimSpace(commit)
	if variant == "" || commit == "" || invoke == nil {
		return RouteAuthorizationProfile{}, errors.New("route authorization performance measurement is incomplete")
	}
	profile := RouteAuthorizationProfile{
		SchemaVersion: "redevplugin.route_authorization_performance.v1",
		Variant:       variant,
		Commit:        commit,
		Environment: RouteAuthorizationEnvironment{
			OS:          runtime.GOOS,
			Arch:        runtime.GOARCH,
			LogicalCPUs: runtime.NumCPU(),
			GOMAXPROCS:  runtime.GOMAXPROCS(0),
			GoVersion:   runtime.Version(),
		},
		WarmupCount:       RouteAuthorizationWarmupCount,
		RequestsPerSample: RouteAuthorizationRequestsPerSample,
		Measurements:      make([]RouteAuthorizationMeasurement, 0, len(routeAuthorizationConcurrencies)),
	}
	for _, concurrency := range routeAuthorizationConcurrencies {
		batchCount := RouteAuthorizationMinBatchCount
		if minimumBatches := (RouteAuthorizationMinSampleCount + concurrency - 1) / concurrency; minimumBatches > batchCount {
			batchCount = minimumBatches
		}
		for range RouteAuthorizationWarmupCount {
			if _, err := measureRouteAuthorizationBatch(concurrency, invoke); err != nil {
				return RouteAuthorizationProfile{}, err
			}
		}
		durations := make([]time.Duration, 0, batchCount*concurrency)
		for range batchCount {
			batchDurations, err := measureRouteAuthorizationBatch(concurrency, invoke)
			if err != nil {
				return RouteAuthorizationProfile{}, err
			}
			durations = append(durations, batchDurations...)
		}
		allocations, bytes, err := measureRouteAuthorizationMemory(concurrency, batchCount, invoke)
		if err != nil {
			return RouteAuthorizationProfile{}, err
		}
		profile.Measurements = append(profile.Measurements, RouteAuthorizationMeasurement{
			Concurrency:           concurrency,
			BatchCount:            batchCount,
			SampleCount:           len(durations),
			MedianNanoseconds:     routeAuthorizationPercentile(durations, 50).Nanoseconds(),
			P95Nanoseconds:        routeAuthorizationPercentile(durations, 95).Nanoseconds(),
			P99Nanoseconds:        routeAuthorizationPercentile(durations, 99).Nanoseconds(),
			AllocationsPerRequest: allocations,
			BytesPerRequest:       bytes,
		})
	}
	return profile, nil
}

func WriteRouteAuthorizationProfile(path string, profile RouteAuthorizationProfile) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("route authorization performance output path is required")
	}
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func measureRouteAuthorizationBatch(concurrency int, invoke func() error) ([]time.Duration, error) {
	if concurrency < 1 {
		return nil, errors.New("route authorization concurrency must be positive")
	}
	if concurrency == 1 {
		durations := make([]time.Duration, RouteAuthorizationRequestsPerSample)
		for index := range RouteAuthorizationRequestsPerSample {
			started := time.Now()
			if err := invoke(); err != nil {
				return nil, err
			}
			durations[index] = time.Since(started)
		}
		return durations, nil
	}
	ready := sync.WaitGroup{}
	done := sync.WaitGroup{}
	start := make(chan struct{})
	errorsFound := make(chan error, 1)
	durations := make([]time.Duration, concurrency*RouteAuthorizationRequestsPerSample)
	ready.Add(concurrency)
	done.Add(concurrency)
	for index := range concurrency {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			base := index * RouteAuthorizationRequestsPerSample
			for sample := range RouteAuthorizationRequestsPerSample {
				started := time.Now()
				if err := invoke(); err != nil {
					select {
					case errorsFound <- err:
					default:
					}
					break
				}
				durations[base+sample] = time.Since(started)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	select {
	case err := <-errorsFound:
		return nil, err
	default:
		return durations, nil
	}
}

func measureRouteAuthorizationMemory(concurrency, batchCount int, invoke func() error) (float64, float64, error) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for range batchCount {
		if err := runRouteAuthorizationMemoryBatch(concurrency, invoke); err != nil {
			return 0, 0, err
		}
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	requests := float64(batchCount * concurrency)
	if requests == 0 || after.Mallocs < before.Mallocs || after.TotalAlloc < before.TotalAlloc {
		return 0, 0, errors.New("route authorization memory counters are invalid")
	}
	return float64(after.Mallocs-before.Mallocs) / requests,
		float64(after.TotalAlloc-before.TotalAlloc) / requests, nil
}

func runRouteAuthorizationMemoryBatch(concurrency int, invoke func() error) error {
	if concurrency == 1 {
		return invoke()
	}
	ready := sync.WaitGroup{}
	done := sync.WaitGroup{}
	start := make(chan struct{})
	errorsFound := make(chan error, 1)
	ready.Add(concurrency)
	done.Add(concurrency)
	for range concurrency {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			if err := invoke(); err != nil {
				select {
				case errorsFound <- err:
				default:
				}
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	select {
	case err := <-errorsFound:
		return err
	default:
		return nil
	}
}

func routeAuthorizationPercentile(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 || percentile < 1 || percentile > 100 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*percentile + 99) / 100
	return ordered[index-1]
}

func ValidateRouteAuthorizationProfile(profile RouteAuthorizationProfile) error {
	if profile.SchemaVersion != "redevplugin.route_authorization_performance.v1" ||
		strings.TrimSpace(profile.Variant) == "" || strings.TrimSpace(profile.Commit) == "" ||
		profile.WarmupCount != RouteAuthorizationWarmupCount || profile.RequestsPerSample != RouteAuthorizationRequestsPerSample ||
		profile.Environment.OS == "" || profile.Environment.Arch == "" || profile.Environment.LogicalCPUs < 1 ||
		profile.Environment.GOMAXPROCS < 1 || profile.Environment.GoVersion == "" ||
		len(profile.Measurements) != len(routeAuthorizationConcurrencies) {
		return errors.New("route authorization performance profile is invalid")
	}
	for index, concurrency := range routeAuthorizationConcurrencies {
		measurement := profile.Measurements[index]
		minimumBatches := (RouteAuthorizationMinSampleCount + concurrency - 1) / concurrency
		if minimumBatches < RouteAuthorizationMinBatchCount {
			minimumBatches = RouteAuthorizationMinBatchCount
		}
		if measurement.Concurrency != concurrency || measurement.BatchCount != minimumBatches ||
			measurement.SampleCount != minimumBatches*concurrency*RouteAuthorizationRequestsPerSample || measurement.MedianNanoseconds < 1 ||
			measurement.P95Nanoseconds < measurement.MedianNanoseconds ||
			measurement.P99Nanoseconds < measurement.P95Nanoseconds ||
			measurement.AllocationsPerRequest < 0 || measurement.BytesPerRequest < 0 {
			return fmt.Errorf("route authorization performance measurement for concurrency %d is invalid", concurrency)
		}
	}
	return nil
}
