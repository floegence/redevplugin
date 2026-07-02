package stress_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
)

type stressSummary struct {
	Category string         `json:"category"`
	Counters map[string]int `json:"counters"`
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

func logStressSummary(t *testing.T, summary stressSummary) {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}
