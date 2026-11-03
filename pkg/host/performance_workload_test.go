package host

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestPerformanceRuntimeProductionWorkload(t *testing.T) {
	path := requirePerformanceRuntime(t)
	limits := runtimeclient.RuntimeLimits{WorkerCount: 8, QueueCapacity: 32, PerPluginConcurrency: 4, ModuleCacheEntries: 64, ModuleCacheSourceBytes: 128 << 20}
	h, _, _, _ := newPerformanceRuntimeHost(t, path, limits)
	workerPath := os.Getenv("REDEVPLUGIN_MEASURED_WORKER")
	if workerPath == "" {
		workerPath = "../../crates/redevplugin-runtime/testdata/workload-backend.wasm"
	}
	wasm, err := os.ReadFile(workerPath)
	if err != nil {
		t.Fatalf("%v; structured=%#v", err, err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), strings.Replace(workerFixtureManifestJSON(), "16777216", "268435456", 1))
	writeSurfaceFixture(t, dir, "Assessment")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), wasm)
	var pkg bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &pkg, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	installed := installAndEnablePlugin(t, h, pkg.Bytes())
	grantDeclaredPermissions(t, h, installed)
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "worker.view")
	cases := []string{"noop", "mix", "sort", "json", "json_1m", "json_10m", "json_deep", "noop"}
	if selected := os.Getenv("REDEVPLUGIN_MEASURED_CASES"); selected != "" {
		cases = strings.Split(selected, ",")
	}
	for _, kind := range cases {
		expected := strconv.FormatInt(expectedWorkloadResult(t, kind), 10)
		values := []float64{}
		var failure string
		for i := 0; i < 100; i++ {
			start := time.Now()
			result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "worker.echo", Params: map[string]any{"message": kind}})
			values = append(values, float64(time.Since(start))/float64(time.Millisecond))
			if err != nil {
				failure = err.Error()
				if detail, ok := AsValidatedWorkerExecutionError(err); ok {
					raw, _ := json.Marshal(detail)
					failure = string(raw)
				}
				t.Fatalf("%v; worker=%s; detail=%#v", err, failure, err)
			}
			encoded, err := json.Marshal(result.Data)
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			if actual["from_worker"] != true || actual["backend"] != expected {
				t.Fatalf("incorrect %s result: %s", kind, encoded)
			}
		}
		sort.Float64s(values)
		row := map[string]any{"workload": kind, "median_ms": values[len(values)/2], "p95_ms": values[(len(values)-1)*95/100], "samples_ms": values, "failed": 0, "error": failure, "worker_bytes": len(wasm)}
		b, _ := json.Marshal(row)
		if output := os.Getenv("REDEVPLUGIN_MEASURED_WORKLOAD_OUTPUT"); output != "" {
			f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write(append(b, '\n'))
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s: 100 successful invocations, median %.3f ms, p95 %.3f ms", kind, values[len(values)/2], values[(len(values)-1)*95/100])
	}
}

// Compute an independent native reference outside the timed invocation.
func expectedWorkloadResult(t *testing.T, kind string) int64 {
	t.Helper()
	switch kind {
	case "noop":
		return 2
	case "mix":
		x := uint32(17)
		for i := uint32(0); i < 500000; i++ {
			x = (x^i)*1664525 + 1013904223
		}
		return int64(x)
	case "sort":
		x := uint32(17)
		values := make([]uint32, 20000)
		for i := range values {
			x = x*1664525 + 1013904223
			values[i] = x
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		var sum uint64
		for i, x := range values {
			sum += uint64(x) * uint64(i+1)
		}
		return int64(sum)
	case "json":
		return 2000 * 1999 / 2
	case "json_1m", "json_10m", "json_deep":
		size, depth := 1<<20, 0
		if kind == "json_10m" {
			size = 10 << 20
		}
		if kind == "json_deep" {
			depth = 16
		}
		row := "{\"id\":1,\"label\":\"bounded workload fixture\",\"values\":[1,2,3,4]}"
		return int64(size / (len(row) + depth*2 + 1))
	default:
		t.Fatalf("unknown measured workload %q", kind)
		return 0
	}
}

func TestPerformanceMeasuredRuntimeLatency(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_MEASURED_RUNTIME_OUTPUT") == "" {
		t.Skip("set measurement output for paired latency runs")
	}
	path := requirePerformanceRuntime(t)
	limits := runtimeclient.RuntimeLimits{WorkerCount: 8, QueueCapacity: 32, PerPluginConcurrency: 4, ModuleCacheEntries: 64, ModuleCacheSourceBytes: 128 << 20}
	h, _, _, _ := newPerformanceRuntimeHost(t, path, limits)
	installed := installAndEnablePlugin(t, h, buildWorkerFixturePackage(t))
	grantDeclaredPermissions(t, h, installed)
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "worker.view")
	call := func() error {
		_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "worker.echo", Params: map[string]any{"message": "fixed assessment payload"}})
		return err
	}
	for i := 0; i < 10; i++ {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	for _, concurrency := range []int{1, 4, 8, 32} {
		t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
			const requests = 128
			var mu sync.Mutex
			var wg sync.WaitGroup
			durations := make([]float64, 0, requests)
			errs := []error{}
			jobs := make(chan int, requests)
			for i := 0; i < requests; i++ {
				jobs <- i
			}
			close(jobs)
			start := make(chan struct{})
			started := time.Now()
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for range jobs {
						begin := time.Now()
						err := call()
						ms := float64(time.Since(begin)) / float64(time.Millisecond)
						mu.Lock()
						durations = append(durations, ms)
						if err != nil {
							errs = append(errs, err)
						}
						mu.Unlock()
					}
				}()
			}
			close(start)
			wg.Wait()
			elapsed := time.Since(started).Seconds()
			if len(errs) > 0 {
				t.Fatalf("%d errors: %v", len(errs), errs[0])
			}
			sort.Float64s(durations)
			row := map[string]any{"concurrency": concurrency, "requests": requests, "median_ms": durations[requests/2], "p95_ms": durations[(requests*95+99)/100-1], "p99_ms": durations[(requests*99+99)/100-1], "throughput_rps": float64(requests) / elapsed, "samples_ms": durations, "timing": "starts immediately before Host.CallPluginMethod, excludes client queue"}
			b, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(os.Getenv("REDEVPLUGIN_MEASURED_RUNTIME_OUTPUT"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write(append(b, '\n'))
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(b))
		})
	}
}
