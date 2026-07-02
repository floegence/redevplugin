package stress_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

type stressSummary struct {
	Category string         `json:"category"`
	Counters map[string]int `json:"counters"`
}

var stressEvidenceMu sync.Mutex

func TestMain(m *testing.M) {
	if os.Getenv("REDEVPLUGIN_STRESS_RUNTIME_HELPER") == "1" {
		runStressRuntimeHelper()
		return
	}
	os.Exit(m.Run())
}

func TestStressGateStreamBackpressureKeepsOperationStoreResponsive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streams := stream.NewMemoryStore()
	operations := operation.NewMemoryStore()
	payload := make([]byte, 64)
	var backpressure atomic.Int64

	const workerCount = 24
	var wg sync.WaitGroup
	errs := make(chan error, workerCount+1)
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			streamID := fmt.Sprintf("stream_%02d", worker)
			if _, err := streams.Register(ctx, stream.RegisterRequest{
				StreamID:         streamID,
				PluginInstanceID: "plugini_stress_stream",
				Method:           "stress.logs.tail",
				Execution:        "stream",
				Direction:        stream.DirectionRead,
				MaxBufferedBytes: 256,
			}); err != nil {
				errs <- err
				return
			}
			for {
				if err := ctx.Err(); err != nil {
					errs <- err
					return
				}
				_, err := streams.Append(ctx, stream.AppendRequest{StreamID: streamID, Data: payload})
				if errors.Is(err, stream.ErrBackpressure) {
					backpressure.Add(1)
					return
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(worker)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 96; i++ {
			if err := ctx.Err(); err != nil {
				errs <- err
				return
			}
			operationID := fmt.Sprintf("core_operation_%03d", i)
			if _, err := operations.Register(ctx, operation.RegisterRequest{
				OperationID:       operationID,
				PluginInstanceID:  "plugini_core_control",
				Method:            "core.diagnostics.ping",
				Execution:         "sync",
				DisableBehavior:   operation.DisableBehaviorCancel,
				UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
			}); err != nil {
				errs <- err
				return
			}
			if _, err := operations.Get(ctx, operationID); err != nil {
				errs <- err
				return
			}
			if _, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control"}); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := backpressure.Load(); got != workerCount {
		t.Fatalf("backpressure count = %d, want %d", got, workerCount)
	}
	records, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 96 {
		t.Fatalf("operation records = %d, want 96", len(records))
	}
	logStressSummary(t, stressSummary{
		Category: "stream_backpressure",
		Counters: map[string]int{
			"workers":               workerCount,
			"backpressure_denials":  int(backpressure.Load()),
			"core_operation_checks": len(records),
		},
	})
}

func TestStressGateConnectivityGrantClassifierFlood(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	policy, err := connectivity.CompilePolicy(connectivity.CompileRequest{
		PluginInstanceID:   "plugini_stress_net",
		PluginID:           "com.example.stress.net",
		ActiveFingerprint:  "sha256:stress",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		Manifest: manifest.Manifest{
			NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{
				{ConnectorID: "api", Transport: "http", Scope: "user", Destinations: []string{"https://api.example.com"}},
				{ConnectorID: "stream", Transport: "websocket", Scope: "user", Destinations: []string{"wss://stream.example.com"}},
				{ConnectorID: "mysql", Transport: "tcp", Scope: "environment", Destinations: []string{"db.example.com:3306"}},
				{ConnectorID: "metrics", Transport: "udp", Scope: "environment", Destinations: []string{"metrics.example.com:8125"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := connectivity.NewMemoryBroker()
	if err := broker.InstallPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	requests := []connectivity.GrantRequest{
		grantRequest("api", connectivity.TransportHTTP, "https://api.example.com"),
		grantRequest("stream", connectivity.TransportWebSocket, "wss://stream.example.com"),
		grantRequest("mysql", connectivity.TransportTCP, "db.example.com:3306"),
		grantRequest("metrics", connectivity.TransportUDP, "metrics.example.com:8125"),
	}

	var minted atomic.Int64
	var denied atomic.Int64
	errs := make(chan error, len(requests)*64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		for _, req := range requests {
			wg.Add(1)
			go func(i int, req connectivity.GrantRequest) {
				defer wg.Done()
				req.Now = time.Date(2026, 6, 30, 12, 0, i%60, 0, time.UTC)
				if i%5 == 0 {
					req.RevokeEpoch = 4
				}
				_, err := broker.MintConnectionGrant(ctx, req)
				if err == nil {
					minted.Add(1)
					return
				}
				if errors.Is(err, connectivity.ErrConnectorDenied) {
					denied.Add(1)
					return
				}
				errs <- err
			}(i, req)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	classifier := connectivity.DefaultClassifier()
	var blocked atomic.Int64
	for i := 0; i < 128; i++ {
		addr := netip.MustParseAddr("10.0.0.1")
		if i%2 == 1 {
			addr = netip.MustParseAddr("169.254.169.254")
		}
		err := classifier.EvaluateResolvedAddress(connectivity.Destination{Transport: connectivity.TransportTCP, Host: "db.example.com", Port: 3306}, addr)
		if !errors.Is(err, connectivity.ErrTargetDenied) {
			t.Fatalf("EvaluateResolvedAddress(%s) error = %v, want ErrTargetDenied", addr, err)
		}
		blocked.Add(1)
	}
	if minted.Load() == 0 || denied.Load() == 0 || blocked.Load() != 128 {
		t.Fatalf("unexpected grant/classifier counters: minted=%d denied=%d blocked=%d", minted.Load(), denied.Load(), blocked.Load())
	}
	logStressSummary(t, stressSummary{
		Category: "connectivity_classifier",
		Counters: map[string]int{
			"minted_grants":          int(minted.Load()),
			"stale_grant_denials":    int(denied.Load()),
			"blocked_resolved_ips":   int(blocked.Load()),
			"connector_policy_count": len(policy.Connectors),
		},
	})
}

func TestStressGateRuntimeRevokeACKP95(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_STRESS_RUNTIME_HELPER=1"),
		HeartbeatInterval:     250 * time.Millisecond,
		MaxHeartbeatStaleness: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: "stress-os", Arch: "stress-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	}()

	const iterations = 64
	const p95Threshold = 500 * time.Millisecond
	const hardTimeout = 2 * time.Second
	durations := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		revokeCtx, revokeCancel := context.WithTimeout(ctx, hardTimeout)
		start := time.Now()
		result, err := supervisor.Revoke(revokeCtx, "plugini_stress_runtime", uint64(i+1))
		elapsed := time.Since(start)
		revokeCancel()
		if err != nil {
			t.Fatalf("Revoke(%d) error = %v", i+1, err)
		}
		if result.PluginInstanceID != "plugini_stress_runtime" ||
			result.RevokeEpoch != uint64(i+1) ||
			result.ClosedActorCount != 1 ||
			result.ClosedSocketCount != 2 ||
			result.ClosedStreamCount != 3 ||
			result.ClosedStorageHandleCount != 4 {
			t.Fatalf("Revoke(%d) result mismatch: %#v", i+1, result)
		}
		if elapsed >= hardTimeout {
			t.Fatalf("Revoke(%d) elapsed = %s, exceeded hard timeout %s", i+1, elapsed, hardTimeout)
		}
		durations = append(durations, elapsed)
	}
	sort.Slice(durations, func(i int, j int) bool { return durations[i] < durations[j] })
	p95 := percentileDuration(durations, 95)
	if p95 > p95Threshold {
		t.Fatalf("runtime revoke ACK p95 = %s, want <= %s", p95, p95Threshold)
	}
	logStressSummary(t, stressSummary{
		Category: "runtime_revoke_ack",
		Counters: map[string]int{
			"attempts":        iterations,
			"p95_ms":          durationMillisCeil(p95),
			"max_ms":          durationMillisCeil(durations[len(durations)-1]),
			"threshold_ms":    durationMillisCeil(p95Threshold),
			"hard_timeout_ms": durationMillisCeil(hardTimeout),
			"closed_actor":    1,
			"closed_socket":   2,
			"closed_stream":   3,
			"closed_storage":  4,
		},
	})
}

func TestStressGateStorageQuotaExportImportUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := storage.NewMemoryBroker()
	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_storage",
		StoreID:          "settings",
		Kind:             storage.StoreKV,
		QuotaBytes:       4096,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}

	value := make([]byte, 128)
	var writes atomic.Int64
	var quotaDenials atomic.Int64
	errs := make(chan error, 128)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				_, err := broker.PutKV(ctx, storage.KVPutRequest{
					PluginInstanceID: ns.PluginInstanceID,
					StoreID:          ns.StoreID,
					Key:              fmt.Sprintf("worker/%02d/%02d", worker, i),
					Value:            value,
				})
				if err == nil {
					writes.Add(1)
					continue
				}
				if errors.Is(err, storage.ErrQuotaExceeded) {
					quotaDenials.Add(1)
					continue
				}
				errs <- err
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes > ns.QuotaBytes {
		t.Fatalf("usage = %d, exceeds quota %d", usage.UsageBytes, ns.QuotaBytes)
	}
	if writes.Load() == 0 || quotaDenials.Load() == 0 {
		t.Fatalf("unexpected storage counters: writes=%d quota_denials=%d", writes.Load(), quotaDenials.Load())
	}
	archiveRef, err := broker.ExportData(ctx, storage.ExportRequest{PluginInstanceID: ns.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.ImportData(ctx, storage.ImportRequest{
		PluginInstanceID: "plugini_stress_storage_imported",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		TargetNamespaces: []storage.Namespace{{
			StoreID:    ns.StoreID,
			Kind:       ns.Kind,
			QuotaBytes: ns.QuotaBytes,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	imported, err := broker.ListKV(ctx, storage.KVListRequest{
		PluginInstanceID: "plugini_stress_storage_imported",
		StoreID:          ns.StoreID,
		MaxEntries:       1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Entries) != int(writes.Load()) {
		t.Fatalf("imported entries = %d, want %d", len(imported.Entries), writes.Load())
	}
	logStressSummary(t, stressSummary{
		Category: "storage_quota",
		Counters: map[string]int{
			"writes":        int(writes.Load()),
			"quota_denials": int(quotaDenials.Load()),
			"imported":      len(imported.Entries),
			"usage_bytes":   int(usage.UsageBytes),
		},
	})
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func durationMillisCeil(duration time.Duration) int {
	if duration <= 0 {
		return 0
	}
	return int((duration + time.Millisecond - 1) / time.Millisecond)
}

func grantRequest(connectorID string, transport connectivity.Transport, destination string) connectivity.GrantRequest {
	return connectivity.GrantRequest{
		PluginInstanceID:    "plugini_stress_net",
		ActiveFingerprint:   "sha256:stress",
		PolicyRevision:      7,
		ManagementRevision:  11,
		RevokeEpoch:         3,
		ConnectorID:         connectorID,
		Transport:           transport,
		Destination:         destination,
		RuntimeGenerationID: "runtime_gen_stress",
		TTL:                 30 * time.Second,
	}
}

type stressIPCFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type stressHelloPayload struct {
	ChannelNonce string `json:"channel_nonce"`
}

type stressHeartbeatPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type stressRevokePayload struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	RevokeEpoch      uint64 `json:"revoke_epoch"`
}

type stressRuntimeResponsePayload struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func runStressRuntimeHelper() {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(2)
	}
	var frame stressIPCFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		os.Exit(3)
	}
	if frame.IPCVersion != version.RustIPCVersion ||
		frame.FrameType != "hello" ||
		strings.TrimSpace(frame.RequestID) == "" ||
		strings.TrimSpace(frame.RuntimeGenerationID) == "" {
		os.Exit(4)
	}
	var hello stressHelloPayload
	if err := json.Unmarshal(frame.Payload, &hello); err != nil || strings.TrimSpace(hello.ChannelNonce) == "" {
		os.Exit(5)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(stressIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           "hello_ack",
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload: stressRawJSON(map[string]any{
			"runtime_version":  version.RuntimeVersion,
			"rust_ipc_version": version.RustIPCVersion,
			"wasm_abi_version": version.WASMABIVersion,
			"channel_nonce":    hello.ChannelNonce,
		}),
	}); err != nil {
		os.Exit(6)
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request stressIPCFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(7)
		}
		switch request.FrameType {
		case "heartbeat":
			var heartbeat stressHeartbeatPayload
			_ = json.Unmarshal(request.Payload, &heartbeat)
			respondStressRuntime(encoder, request, "heartbeat", stressRawJSON(stressRuntimeResponsePayload{
				OK: true,
				Result: stressRawJSON(map[string]any{
					"runtime_generation_id": request.RuntimeGenerationID,
					"runtime_unix_nano":     time.Now().UnixNano(),
					"max_staleness_ms":      heartbeat.MaxStalenessMillis,
					"host_sent_unix_nano":   heartbeat.SentUnixNano,
				}),
			}))
		case "revoke_epoch":
			var revoke stressRevokePayload
			_ = json.Unmarshal(request.Payload, &revoke)
			respondStressRuntime(encoder, request, "revoke_epoch_ack", stressRawJSON(stressRuntimeResponsePayload{
				OK: true,
				Result: stressRawJSON(map[string]any{
					"plugin_instance_id":          revoke.PluginInstanceID,
					"revoke_epoch":                revoke.RevokeEpoch,
					"closed_actor_count":          1,
					"closed_socket_count":         2,
					"closed_stream_count":         3,
					"closed_storage_handle_count": 4,
				}),
			}))
		default:
			respondStressRuntime(encoder, request, "diagnostic", stressRawJSON(stressRuntimeResponsePayload{
				OK:    false,
				Code:  "UNSUPPORTED_FRAME",
				Error: "unsupported stress runtime frame",
			}))
		}
	}
}

func respondStressRuntime(encoder *json.Encoder, request stressIPCFrame, frameType string, payload json.RawMessage) {
	if err := encoder.Encode(stressIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             payload,
	}); err != nil {
		os.Exit(8)
	}
}

func stressRawJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		os.Exit(9)
	}
	return raw
}

func logStressSummary(t *testing.T, summary stressSummary) {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if evidencePath := os.Getenv("REDEVPLUGIN_STRESS_EVIDENCE_PATH"); evidencePath != "" {
		stressEvidenceMu.Lock()
		defer stressEvidenceMu.Unlock()
		file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open stress evidence file: %v", err)
		}
		if _, err := file.Write(append(data, '\n')); err != nil {
			_ = file.Close()
			t.Fatalf("write stress evidence file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close stress evidence file: %v", err)
		}
	}
}
