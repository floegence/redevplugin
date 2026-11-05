package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"
)

type measuredStreamReader struct {
	remaining int64
	maximum   int
	digest    io.Writer
}

func (r *measuredStreamReader) Read(p []byte) (int, error) {
	if len(p) > r.maximum {
		r.maximum = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := int64(0); i < n; i++ {
		p[i] = byte((r.remaining - i) % 251)
	}
	r.remaining -= n
	if _, err := r.digest.Write(p[:n]); err != nil {
		return 0, err
	}
	return int(n), nil
}

type measuredStreamWriter struct {
	maximum int
	size    int64
	digest  io.Writer
}

func (w *measuredStreamWriter) Write(p []byte) (int, error) {
	if len(p) > w.maximum {
		w.maximum = len(p)
	}
	w.size += int64(len(p))
	return w.digest.Write(p)
}

func TestPerformanceSurfaceFileStreamBounds(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{productionStateOwners: true})
	var manifest map[string]any
	if err := json.Unmarshal([]byte(workerStorageKVFixtureManifestJSON()), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["workers"] = []any{}
	manifest["methods"] = []any{}
	manifest["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1"}
	namespace := manifest["storage"].(map[string]any)["stores"].([]any)[0].(map[string]any)
	namespace["kind"] = "files"
	namespace["quota_bytes"] = 64 << 20
	surface := manifest["surfaces"].([]any)[0].(map[string]any)
	surface["surface_id"] = "lifecycle.view"
	surface["web"].(map[string]any)["storage"] = []any{map[string]any{"store_id": "cache", "operations": []string{"read", "write", "list"}}}
	raw, _ := json.Marshal(manifest)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	session, _ := openTestWebSurface(t, h, record.PluginInstanceID, "stream_acceptance", hostRuntimeWritableTestContext())
	for _, size := range []int64{1 << 20, 32 << 20} {
		request := WebPrivateFileRequest{WebSurfaceRequest: session, StoreID: "cache", Path: "stream.bin"}
		expected, actual := sha256.New(), sha256.New()
		reader := &measuredStreamReader{remaining: size, digest: expected}
		if n, err := h.TransferWebPrivateFile(context.Background(), request, reader, nil); err != nil || n != size {
			t.Fatalf("write %d: %v", n, err)
		}
		writer := &measuredStreamWriter{digest: actual}
		if n, err := h.TransferWebPrivateFile(context.Background(), request, nil, writer); err != nil || n != size {
			t.Fatalf("read %d: %v", n, err)
		}
		if string(expected.Sum(nil)) != string(actual.Sum(nil)) || writer.size != size {
			t.Fatal("stream content mismatch")
		}
		if reader.maximum > 64<<10 || writer.maximum > 64<<10 {
			t.Fatalf("unbounded transfer buffers read=%d write=%d", reader.maximum, writer.maximum)
		}
		h.webSurfaces.mu.Lock()
		active := h.webSurfaces.activeResources
		h.webSurfaces.mu.Unlock()
		if active != 0 {
			t.Fatalf("stream reservations leaked: %d", active)
		}
		t.Logf("%d bytes verified; upload buffer=%d, download buffer=%d, active resources=%d", size, reader.maximum, writer.maximum, active)
	}
}

// This exercises Surface authorization, audit and durable storage together.
// It measures the public Host boundary, not browser transport latency.
func TestPerformanceSurfaceKVBatch(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{productionStateOwners: true})
	var manifest map[string]any
	if err := json.Unmarshal([]byte(workerStorageKVFixtureManifestJSON()), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["workers"] = []any{}
	manifest["methods"] = []any{}
	manifest["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1", "storage.transactions.v1"}
	surface := manifest["surfaces"].([]any)[0].(map[string]any)
	surface["surface_id"] = "lifecycle.view"
	surface["web"].(map[string]any)["storage"] = []any{map[string]any{"store_id": "cache", "operations": []string{"get", "put", "delete", "list"}}}
	raw, _ := json.Marshal(manifest)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	session, _ := openTestWebSurface(t, h, record.PluginInstanceID, "batch_acceptance", hostRuntimeWritableTestContext())
	calls := 0
	call := func(args map[string]any) (any, error) {
		calls++
		args["store_id"] = "cache"
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		return h.WebResource(context.Background(), WebResourceRequest{WebSurfaceRequest: session, Resource: "storage.kv", Arguments: raw})
	}
	mutations := make([]map[string]any, 64)
	for i := range mutations {
		mutations[i] = map[string]any{"key": fmt.Sprintf("item-%02d", i), "value_base64": "YQ=="}
	}
	singleTimes, batchTimes := []time.Duration{}, []time.Duration{}
	run := func(batch bool) {
		calls = 0
		start := time.Now()
		if batch {
			if _, err := call(map[string]any{"operation": "batch", "mutations": mutations}); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, m := range mutations {
				if _, err := call(map[string]any{"operation": "put", "key": m["key"], "value_base64": m["value_base64"]}); err != nil {
					t.Fatal(err)
				}
			}
		}
		elapsed := time.Since(start)
		if batch {
			if calls != 1 {
				t.Fatal(calls)
			}
			batchTimes = append(batchTimes, elapsed)
		} else {
			if calls != 64 {
				t.Fatal(calls)
			}
			singleTimes = append(singleTimes, elapsed)
		}
	}
	for round := 0; round < 10; round++ {
		if round%2 == 0 {
			run(false)
			run(true)
		} else {
			run(true)
			run(false)
		}
	}
	for _, m := range mutations {
		result, err := call(map[string]any{"operation": "get", "key": m["key"]})
		if err != nil || result.(map[string]any)["value_base64"] != "YQ==" {
			t.Fatalf("incorrect stored value: %v %v", result, err)
		}
	}
	rollback := []map[string]any{{"key": "item-00", "value_base64": "Yg=="}, {"key": "item-01", "value_base64": "Yg==", "expected_etag": "stale"}}
	if _, err := call(map[string]any{"operation": "batch", "mutations": rollback}); err == nil {
		t.Fatal("stale batch succeeded")
	}
	result, err := call(map[string]any{"operation": "get", "key": "item-00"})
	if err != nil || result.(map[string]any)["value_base64"] != "YQ==" {
		t.Fatalf("partial batch committed: %v %v", result, err)
	}
	sort.Slice(singleTimes, func(i, j int) bool { return singleTimes[i] < singleTimes[j] })
	sort.Slice(batchTimes, func(i, j int) bool { return batchTimes[i] < batchTimes[j] })
	speedup := float64(singleTimes[5]) / float64(batchTimes[5])
	t.Logf("64 durable writes: sequential=%s batch=%s speedup=%.2fx; ten alternating rounds, exact results and rollback verified", singleTimes[5], batchTimes[5], speedup)
	if enforcePerformanceLatencyThresholds() && speedup < 5 {
		t.Fatalf("batch speedup %.2fx below 5x", speedup)
	}
}
