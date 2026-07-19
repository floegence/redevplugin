package stress_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
	"github.com/floegence/redevplugin/pkg/websecurity"
	_ "modernc.org/sqlite"
)

type stressSummary struct {
	Category string         `json:"category"`
	Counters map[string]int `json:"counters"`
}

type stressAuditSink struct {
	mu     sync.Mutex
	events []observability.AuditEvent
}

func (s *stressAuditSink) AppendPluginAudit(_ context.Context, event observability.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *stressAuditSink) count(pluginInstanceID string, eventType string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, event := range s.events {
		if event.PluginInstanceID == pluginInstanceID && event.Type == eventType {
			count++
		}
	}
	return count
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
	ctx, cancel := context.WithTimeout(stressTestContext(), 5*time.Second)
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
				StreamID: streamID,
				ExecutionBinding: capability.ExecutionBinding{
					PluginID:             "com.example.stress.logs",
					PluginInstanceID:     "plugini_stress_stream",
					Method:               "stress.logs.tail",
					Execution:            "subscription",
					OwnerSessionHash:     "stress_session",
					OwnerUserHash:        "stress_user",
					OwnerEnvHash:         "stress_env",
					SessionChannelIDHash: "stress_channel",
				},
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
				OperationID: operationID,
				ExecutionBinding: capability.ExecutionBinding{
					PluginInstanceID:     "plugini_core_control",
					Method:               "core.diagnostics.ping",
					Execution:            "operation",
					OwnerSessionHash:     "stress_session",
					OwnerUserHash:        "stress_user",
					OwnerEnvHash:         "stress_env",
					SessionChannelIDHash: "stress_channel",
				},
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
			if _, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control", AllOwners: true}); err != nil {
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
	page, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control", AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	records := page.Records
	if len(records) != 96 {
		t.Fatalf("operation records = %d, want 96", len(records))
	}
	var closedStreams int
	var postCloseAppendDenials int
	for worker := 0; worker < workerCount; worker++ {
		streamID := fmt.Sprintf("stream_%02d", worker)
		closed, err := streams.Close(ctx, stream.CloseRequest{
			StreamID: streamID,
			Status:   stream.StatusCanceled,
			Reason:   "stress shutdown",
		})
		if err != nil {
			t.Fatalf("Streams.Close(%s) error = %v", streamID, err)
		}
		if closed.Status != stream.StatusCanceled || closed.ClosedAt == nil {
			t.Fatalf("closed stream mismatch: %#v", closed)
		}
		closedStreams++
		if _, err := streams.Append(ctx, stream.AppendRequest{StreamID: streamID, Data: payload}); errors.Is(err, stream.ErrStreamClosed) {
			postCloseAppendDenials++
		} else {
			t.Fatalf("Append(%s) after close error = %v, want ErrStreamClosed", streamID, err)
		}
	}
	logStressSummary(t, stressSummary{
		Category: "stream_backpressure",
		Counters: map[string]int{
			"workers":                     workerCount,
			"backpressure_denials":        int(backpressure.Load()),
			"core_operation_checks":       len(records),
			"stream_close_requests":       closedStreams,
			"closed_streams":              closedStreams,
			"post_close_append_denials":   postCloseAppendDenials,
			"stream_close_status_checked": 1,
		},
	})
}

func TestStressGateOperationCancelOwnershipEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(stressTestContext(), 5*time.Second)
	defer cancel()

	audit := &stressAuditSink{}
	diagnostics := observability.NewMemoryStore()
	operations := operation.NewMemoryStore()
	operationAdapter := &stressOperationAdapter{}
	verified := stressVerifiedCapabilityContract(t)
	capabilities := capability.NewRegistry()
	if err := capabilities.Register(capability.Registration{Contract: verified, TargetProjector: operationAdapter, Adapter: operationAdapter}); err != nil {
		t.Fatal(err)
	}
	connectivityBroker := connectivity.NewMemoryBroker()
	platformAdapter := stressPlatformAdapter{}
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, filepath.Join(t.TempDir(), "plugin-data"), registryStore)
	if err != nil {
		t.Fatal(err)
	}
	securityJournal := observability.NewMemorySecurityAuditJournal()
	pluginHost, err := host.Open(ctx, host.Config{
		Core: host.CoreAdapters{
			Policy:               stressPolicy{},
			Authorization:        stressAuthorization{},
			PackageTrustVerifier: platformAdapter,
			Registry:             registryStore,
			Audit:                audit,
			SecurityAudit:        securityJournal,
			Diagnostics:          diagnostics,
			SurfaceCatalog:       platformAdapter,
			Assets:               pluginpkg.NewMemoryAssetStore(),
			InstallStages:        installstage.NewMemoryStore(),
			SurfaceTokens:        bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{}),
			PluginData:           pluginData,
			Operations:           operations,
			ConfirmationIntents:  security.NewMemoryConfirmationIntentStore(),
			Streams:              stream.NewMemoryStore(),
		},
		Release: &host.ReleaseModule{
			ReleaseMetadataVerifier:     platformAdapter,
			RevocationVerifier:          platformAdapter,
			ReleaseSourcePolicy:         platformAdapter,
			ReleaseArtifactResolver:     platformAdapter,
			HostRequirements:            platformAdapter,
			CapabilityContractArtifacts: platformAdapter,
			CapabilityContractKeys:      platformAdapter,
		},
		Capability:   &host.CapabilityModule{Registry: capabilities},
		Connectivity: &host.ConnectivityModule{Broker: connectivityBroker, NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})},
		Secrets:      &host.SecretsModule{Store: secrets.NewMemoryStore()},
		CoreAction:   &host.CoreActionModule{Adapter: platformAdapter},
	})
	if err != nil {
		_ = pluginData.Close()
		t.Fatal(err)
	}
	defer pluginHost.Close()

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	for _, operationID := range []string{"op_stress_cancel_success", "op_stress_cancel_fail"} {
		ownerSessionHash := "stress_session"
		ownerUserHash := "stress_user"
		ownerEnvHash := "stress_env"
		sessionChannelIDHash := "stress_channel"
		if operationID == "op_stress_cancel_fail" {
			ownerSessionHash = "session_hash_stress"
			ownerUserHash = "user_hash_stress"
			ownerEnvHash = "environment_hash_stress"
			sessionChannelIDHash = "channel_hash_stress"
		}
		if _, err := operations.Register(ctx, operation.RegisterRequest{
			OperationID: operationID,
			ExecutionBinding: capability.ExecutionBinding{
				PluginID:             "com.example.stress.documents",
				PluginInstanceID:     "plugini_stress_documents",
				RouteKind:            capability.RouteCapability,
				CapabilityID:         verified.Contract.CapabilityID,
				CapabilityVersion:    verified.Contract.CapabilityVersion,
				Contract:             &verified.Pin,
				Method:               "documents.archive",
				Effect:               capability.EffectExecute,
				Execution:            "operation",
				SurfaceInstanceID:    "surface_stress_operation",
				OwnerSessionHash:     ownerSessionHash,
				OwnerUserHash:        ownerUserHash,
				OwnerEnvHash:         ownerEnvHash,
				SessionChannelIDHash: sessionChannelIDHash,
				BridgeChannelID:      "bridge_stress_operation",
				Permissions:          capability.PermissionEvidence{Required: []string{}, Granted: []string{}},
			},
			DisableBehavior:   operation.DisableBehaviorCancel,
			UninstallBehavior: operation.UninstallBehaviorCancelThenBlockDelete,
			Now:               now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	canceled, err := pluginHost.CancelOperation(ctx, host.CancelOperationRequest{
		OperationID: "op_stress_cancel_success",
		Reason:      "user",
		Now:         now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("CancelOperation(success) error = %v", err)
	}
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("CancelOperation(success) mismatch: %#v", canceled)
	}
	if len(operationAdapter.requests) != 0 {
		t.Fatalf("inactive persisted operation unexpectedly dispatched through capability registry: %#v", operationAdapter.requests)
	}

	handler, err := httpadapter.NewHandler(httpadapter.Dependencies{Host: pluginHost, Guard: stressWebSecurityGuard{}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/operations/op_stress_cancel_fail/cancel", strings.NewReader(`{"reason":"user"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("durable cancel status = %d body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK    bool `json:"ok"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Error != nil {
		t.Fatalf("durable cancel response mismatch: %#v", response)
	}

	page, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_stress_documents", AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	records := page.Records
	var cancelRequested int
	for _, record := range records {
		if record.Status == operation.StatusCancelRequested {
			cancelRequested++
		}
	}
	if cancelRequested != 2 {
		t.Fatalf("cancel_requested records = %d, want 2: %#v", cancelRequested, records)
	}
	if len(operationAdapter.requests) != 0 {
		t.Fatalf("persisted operations must not rediscover an execution adapter by contract id: %#v", operationAdapter.requests)
	}

	auditCount := audit.count("plugini_stress_documents", "plugin.operation.cancel_requested")
	if auditCount != 2 {
		t.Fatalf("cancel audit events = %d, want 2", auditCount)
	}

	logStressSummary(t, stressSummary{
		Category: "operation_cancel_ownership",
		Counters: map[string]int{
			"operations_registered":                 len(records),
			"cancel_requested_records":              cancelRequested,
			"durable_requests_without_active_lease": 2,
			"http_accepted_requests":                1,
			"audit_cancel_requested_events":         auditCount,
			"registry_redispatches":                 len(operationAdapter.requests),
		},
	})
}

func TestStressGateRuntimeRevokeACKP95(t *testing.T) {
	ctx, cancel := context.WithTimeout(stressTestContext(), 15*time.Second)
	defer cancel()

	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HandshakeTimeout:      15 * time.Second,
		RuntimePath:           os.Args[0],
		Descriptor:            stressRuntimeDescriptor(t, os.Args[0], target),
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_STRESS_RUNTIME_HELPER=1"),
		HeartbeatInterval:     250 * time.Millisecond,
		MaxHeartbeatStaleness: time.Second,
		StreamSink:            stressRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, target); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(stressTestContext(), time.Second)
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
		result, err := supervisor.Revoke(revokeCtx, runtimeclient.RevokeRequest{
			ResourceScope:    sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
			PluginInstanceID: "plugini_stress_runtime",
			RevokeEpoch:      uint64(i + 1),
		})
		elapsed := time.Since(start)
		revokeCancel()
		if err != nil {
			t.Fatalf("Revoke(%d) error = %v", i+1, err)
		}
		if result.PluginInstanceID != "plugini_stress_runtime" ||
			result.RevokeEpoch != uint64(i+1) ||
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
			"closed_socket":   2,
			"closed_stream":   3,
			"closed_storage":  4,
		},
	})
}

type stressRuntimeStreamSink struct{}

func (stressRuntimeStreamSink) AppendRuntimeStream(context.Context, string, string, []byte) error {
	return nil
}

func (stressRuntimeStreamSink) CloseRuntimeStream(context.Context, string) error {
	return nil
}

func (stressRuntimeStreamSink) FailRuntimeStream(context.Context, string, capability.ExecutionFailureCode, error) error {
	return nil
}

func TestStressGateStorageQuotaExportImportUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(stressTestContext(), 5*time.Second)
	defer cancel()

	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_storage",
		StoreID:          "settings",
		Kind:             storage.StoreKV,
		Scope:            "user",
		QuotaBytes:       4096,
		SchemaVersion:    1,
	}
	resourceScope := stressResourceScope(t, ctx, sessionctx.ScopeKind(ns.Scope))
	const importedPluginInstanceID = "plugini_stress_storage_imported"
	fixture := newStressPluginData(t, ctx, []string{ns.PluginInstanceID, importedPluginInstanceID}, ns)
	broker := fixture.broker
	registryStore := fixture.registryStore
	records := fixture.records
	shape := fixture.shape
	defer broker.Close()

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
					ResourceScope:    resourceScope,
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
	exported, err := broker.Export(ctx, plugindata.ExportRequest{PluginInstanceID: ns.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Import(ctx, plugindata.ImportRequest{
		PluginInstanceID:           importedPluginInstanceID,
		ObjectID:                   exported.ObjectID,
		ExpectedShape:              shape,
		ExpectedManagementRevision: records[importedPluginInstanceID].ManagementRevision,
	}); !errors.Is(err, plugindata.ErrExportNotFound) {
		t.Fatalf("cross-plugin import error = %v, want ErrExportNotFound", err)
	}
	disabled, err := registryStore.SetEnableState(ctx, ns.PluginInstanceID, registry.EnableDisabled, "stress import", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Import(ctx, plugindata.ImportRequest{
		PluginInstanceID:           ns.PluginInstanceID,
		ObjectID:                   exported.ObjectID,
		ExpectedShape:              shape,
		ExpectedManagementRevision: disabled.ManagementRevision,
	}); err != nil {
		t.Fatal(err)
	}
	imported, err := broker.ListKV(ctx, storage.KVListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		MaxEntries:       1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Entries) != int(writes.Load()) {
		t.Fatalf("imported entries = %d, want %d", len(imported.Entries), writes.Load())
	}
	fileCounters := stressFileCountQuotaCounters(t, ctx)
	sqliteCounters := stressSQLiteQuotaBypassCounters(t, ctx)
	logStressSummary(t, stressSummary{
		Category: "storage_quota",
		Counters: map[string]int{
			"writes":                      int(writes.Load()),
			"quota_denials":               int(quotaDenials.Load()),
			"imported":                    len(imported.Entries),
			"usage_bytes":                 int(usage.UsageBytes),
			"file_quota_denials":          fileCounters.quotaDenials,
			"file_usage_files":            fileCounters.usageFiles,
			"file_quota_files":            fileCounters.quotaFiles,
			"sqlite_quota_denials":        sqliteCounters.quotaDenials,
			"sqlite_rollback_checks":      sqliteCounters.rollbackChecks,
			"sqlite_usage_bytes":          sqliteCounters.usageBytes,
			"sqlite_page_count":           sqliteCounters.pageCount,
			"sqlite_sidecar_files":        sqliteCounters.sidecarFiles,
			"sqlite_sidecar_bytes":        sqliteCounters.sidecarBytes,
			"sqlite_sparse_logical_bytes": sqliteCounters.sparseLogicalBytes,
		},
	})
}

type fileCountQuotaCounters struct {
	quotaDenials int
	usageFiles   int
	quotaFiles   int
}

func stressFileCountQuotaCounters(t *testing.T, ctx context.Context) fileCountQuotaCounters {
	t.Helper()

	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_files",
		StoreID:          "workspace",
		Kind:             storage.StoreFiles,
		Scope:            "user",
		QuotaBytes:       1024,
		QuotaFiles:       1,
		SchemaVersion:    1,
	}
	resourceScope := stressResourceScope(t, ctx, sessionctx.ScopeKind(ns.Scope))
	fixture := newStressPluginData(t, ctx, []string{ns.PluginInstanceID}, ns)
	broker := fixture.broker
	defer broker.Close()
	if _, err := broker.WriteFile(ctx, storage.FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		Path:             "one.txt",
		Data:             []byte("one"),
	}); err != nil {
		t.Fatal(err)
	}
	quotaDenials := 0
	if _, err := broker.WriteFile(ctx, storage.FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		Path:             "two.txt",
		Data:             []byte("two"),
	}); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("WriteFile(file count quota) error = %v, want ErrQuotaExceeded", err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageFiles != ns.QuotaFiles {
		t.Fatalf("file quota usage = %#v, want usage_files=%d", usage, ns.QuotaFiles)
	}
	return fileCountQuotaCounters{
		quotaDenials: quotaDenials,
		usageFiles:   int(usage.UsageFiles),
		quotaFiles:   int(usage.QuotaFiles),
	}
}

type sqliteQuotaBypassCounters struct {
	quotaDenials       int
	rollbackChecks     int
	usageBytes         int
	pageCount          int
	sidecarFiles       int
	sidecarBytes       int
	sparseLogicalBytes int
}

func stressSQLiteQuotaBypassCounters(t *testing.T, ctx context.Context) sqliteQuotaBypassCounters {
	t.Helper()

	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_sqlite",
		StoreID:          "db",
		Kind:             storage.StoreSQLite,
		Scope:            "user",
		QuotaBytes:       16 * 1024,
		SchemaVersion:    1,
	}
	resourceScope := stressResourceScope(t, ctx, sessionctx.ScopeKind(ns.Scope))
	fixture := newStressPluginData(t, ctx, []string{ns.PluginInstanceID}, ns)
	broker := fixture.broker
	defer broker.Close()
	if _, err := broker.ExecSQLite(ctx, storage.SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE items (body TEXT)",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 128*1024)
	quotaDenials := 0
	if _, err := broker.ExecSQLite(ctx, storage.SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		SQL:              "INSERT INTO items (body) VALUES (?)",
		Args:             []storage.SQLiteValue{{Text: &body}},
	}); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("ExecSQLite(quota body) error = %v, want ErrQuotaExceeded", err)
	}
	after, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	rollbackChecks := 0
	if after.UsageBytes == before.UsageBytes && sqliteSingleInt(t, broker, ctx, storage.SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		ResourceScope:    resourceScope,
		StoreID:          ns.StoreID,
		SQL:              "SELECT COUNT(*) FROM items",
	}) == 0 {
		rollbackChecks = 1
	}
	if rollbackChecks != 1 {
		t.Fatalf("sqlite quota rollback mismatch: before=%#v after=%#v", before, after)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}

	dataRoot := filepath.Join(
		fixture.root,
		"workspaces", "environment", resourceScope.OwnerEnvHash, fixture.binding.GenerationID,
		"scopes", "users", resourceScope.OwnerUserHash,
		"namespaces", ns.StoreID, "data",
	)
	pageCount := stressSQLitePageCount(t, filepath.Join(dataRoot, "plugin.sqlite"))
	sidecarFiles := 0
	sidecarBytes := int64(0)
	for _, name := range []string{"plugin.sqlite-wal", "plugin.sqlite-shm", "plugin.sqlite-tmp"} {
		path := filepath.Join(dataRoot, name)
		if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != 512 {
			t.Fatalf("sqlite sidecar %s = %#v, err = %v", name, info, err)
		}
		sidecarFiles++
		sidecarBytes += info.Size()
	}
	sparseLogicalBytes := ns.QuotaBytes - before.UsageBytes + 1
	if sparseLogicalBytes <= 0 {
		t.Fatalf("sqlite sparse logical bytes = %d", sparseLogicalBytes)
	}
	sparsePath := filepath.Join(dataRoot, "plugin.sqlite-hole")
	sparseFile, err := os.OpenFile(sparsePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := sparseFile.Truncate(sparseLogicalBytes); err != nil {
		_ = sparseFile.Close()
		t.Fatal(err)
	}
	if err := sparseFile.Close(); err != nil {
		t.Fatal(err)
	}
	sparseInfo, err := os.Lstat(sparsePath)
	if err != nil || !sparseInfo.Mode().IsRegular() || sparseInfo.Size() != sparseLogicalBytes {
		t.Fatalf("sqlite sparse sidecar = %#v, err = %v", sparseInfo, err)
	}
	sidecarFiles++
	sidecarBytes += sparseInfo.Size()

	reopened, err := plugindata.Open(ctx, fixture.root, fixture.registryStore)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Usage(ctx, ns.PluginInstanceID, ns.StoreID); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("Usage(sqlite sidecars) error = %v, want ErrQuotaExceeded", err)
	}

	return sqliteQuotaBypassCounters{
		quotaDenials:       quotaDenials,
		rollbackChecks:     rollbackChecks,
		usageBytes:         int(before.UsageBytes),
		pageCount:          pageCount,
		sidecarFiles:       sidecarFiles,
		sidecarBytes:       int(sidecarBytes),
		sparseLogicalBytes: int(sparseLogicalBytes),
	}
}

func stressSQLitePageCount(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var pageCount int
	queryErr := db.QueryRow(`PRAGMA page_count`).Scan(&pageCount)
	closeErr := db.Close()
	if queryErr != nil {
		t.Fatal(queryErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if pageCount <= 0 {
		t.Fatalf("sqlite page count = %d", pageCount)
	}
	return pageCount
}

type stressPluginData struct {
	broker        *plugindata.FileStore
	registryStore registry.Store
	records       map[string]registry.PluginRecord
	shape         plugindata.Shape
	root          string
	binding       plugindata.Binding
}

func newStressPluginData(t *testing.T, ctx context.Context, pluginInstanceIDs []string, namespace storage.Namespace) stressPluginData {
	t.Helper()
	if len(pluginInstanceIDs) == 0 {
		t.Fatal("at least one plugin instance is required")
	}
	quotaFiles := namespace.QuotaFiles
	storeSpec := manifest.StoreSpec{
		StoreID:       namespace.StoreID,
		Kind:          string(namespace.Kind),
		Scope:         namespace.Scope,
		QuotaBytes:    namespace.QuotaBytes,
		SchemaVersion: namespace.SchemaVersion,
	}
	if quotaFiles > 0 {
		storeSpec.QuotaFiles = &quotaFiles
	}
	pluginManifest := manifest.Manifest{
		Publisher: manifest.Publisher{PublisherID: "dev.redevplugin.stress", DisplayName: "Stress"},
		Plugin: manifest.Plugin{
			PluginID:          "dev.redevplugin.stress.data",
			DisplayName:       "Stress Data",
			Version:           "1.0.0",
			APIVersion:        "plugin-v1",
			MinRuntimeVersion: "0.5.0",
			UIProtocolVersion: version.PluginUIProtocolVersion,
		},
		Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{storeSpec}},
	}
	shape, err := plugindata.ShapeFromManifest(pluginManifest)
	if err != nil {
		t.Fatal(err)
	}
	registryStore := registry.NewMemoryStore()
	records := make(map[string]registry.PluginRecord, len(pluginInstanceIDs))
	for _, pluginInstanceID := range pluginInstanceIDs {
		record, err := registryStore.PutPlugin(ctx, registry.PluginRecord{
			PluginInstanceID: pluginInstanceID,
			PublisherID:      pluginManifest.Publisher.PublisherID,
			PluginID:         pluginManifest.Plugin.PluginID,
			Version:          pluginManifest.Plugin.Version,
			EnableState:      registry.EnableDisabled,
			Manifest:         pluginManifest,
		}, registry.PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		records[pluginInstanceID] = record
	}
	root := filepath.Join(t.TempDir(), "plugin-data")
	pluginData, err := plugindata.Open(ctx, root, registryStore)
	if err != nil {
		t.Fatal(err)
	}
	source := records[pluginInstanceIDs[0]]
	dataset, err := pluginData.CommitEnable(ctx, plugindata.CommitEnableRequest{
		PluginInstanceID:           source.PluginInstanceID,
		Shape:                      shape,
		InitialSettings:            map[string]json.RawMessage{},
		ExpectedManagementRevision: source.ManagementRevision,
	})
	if err != nil {
		_ = pluginData.Close()
		t.Fatal(err)
	}
	return stressPluginData{
		broker:        pluginData,
		registryStore: registryStore,
		records:       records,
		shape:         shape,
		root:          root,
		binding:       dataset.Binding,
	}
}

func sqliteSingleInt(t *testing.T, broker storage.SQLiteBroker, ctx context.Context, req storage.SQLiteQueryRequest) int64 {
	t.Helper()

	result, err := broker.QuerySQLite(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0].Int == nil {
		t.Fatalf("sqlite single int result mismatch: %#v", result.Rows)
	}
	return *result.Rows[0][0].Int
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

type stressWebSecurityGuard struct{}

func (stressWebSecurityGuard) Authenticate(*http.Request) (sessionctx.Context, error) {
	return sessionctx.Context{
		OwnerSessionHash:     "session_hash_stress",
		OwnerUserHash:        "user_hash_stress",
		OwnerEnvHash:         "environment_hash_stress",
		SessionChannelIDHash: "channel_hash_stress",
	}, nil
}

func (stressWebSecurityGuard) ValidateOrigin(_ *http.Request, _ sessionctx.Context, policy websecurity.OriginPolicy) error {
	if !policy.Valid() {
		return websecurity.ErrOriginPolicyInvalid
	}
	return nil
}

func (stressWebSecurityGuard) ValidateCSRF(_ *http.Request, _ sessionctx.Context, policy websecurity.CSRFPolicy) error {
	if !policy.Valid() {
		return websecurity.ErrCSRFPolicyInvalid
	}
	return nil
}

func (stressWebSecurityGuard) AuthorizeRoute(_ *http.Request, _ sessionctx.Context, action websecurity.RouteAction) error {
	if !action.Valid() {
		return websecurity.ErrRouteActionInvalid
	}
	return nil
}

func stressTestContext() context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "stress_session",
		OwnerUserHash:        "stress_user",
		OwnerEnvHash:         "stress_env",
		SessionChannelIDHash: "stress_channel",
	})
}

func stressResourceScope(t testing.TB, ctx context.Context, kind sessionctx.ScopeKind) sessionctx.ResourceScope {
	t.Helper()
	session, err := sessionctx.Require(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.ResourceScope(kind)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

type stressOperationAdapter struct {
	requests []capability.OperationCancellation
}

func (c *stressOperationAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{Kind: "stress", Fields: req.TargetInput}, nil
}

func (c *stressOperationAdapter) Invoke(_ context.Context, _ capability.Invocation) (capability.Result, error) {
	return capability.Result{}, nil
}

func (c *stressOperationAdapter) CancelOperation(_ context.Context, req capability.OperationCancellation) error {
	c.requests = append(c.requests, req)
	return nil
}

func stressVerifiedCapabilityContract(t *testing.T) capabilitycontract.VerifiedContract {
	t.Helper()
	emptyObject := map[string]any{"type": "object", "additionalProperties": false}
	contract := capabilitycontract.Contract{
		SchemaVersion:     capabilitycontract.SchemaVersion,
		ContractID:        "example.stress.documents.v1",
		ContractVersion:   "1.0.0",
		PublisherID:       "example.stress",
		CapabilityID:      "example.capability.stress.documents",
		CapabilityVersion: "1.0.0",
		ClientName:        "StressDocumentsClient",
		Methods: []capabilitycontract.Method{{
			Name:             "documents.archive",
			ClientMethod:     "archiveDocument",
			Effect:           "execute",
			Execution:        "operation",
			TargetFields:     []string{},
			TargetSchema:     emptyObject,
			RequestTypeName:  "StressArchiveRequest",
			ResponseTypeName: "StressArchiveResponse",
			RequestSchema:    emptyObject,
			ResponseSchema:   emptyObject,
			CancelPolicy: &capabilitycontract.CancelPolicy{
				Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel_then_block_delete", AckTimeoutMS: 1000,
			},
		}},
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/stress/1.0.0",
		GeneratedAt:     time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC), SourceCommit: strings.Repeat("f", 40),
		MinReDevPluginVersion: "0.3.0", SignatureKeyID: "stress-key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle: bundle, ExpectedPin: bundle.Pin,
		TrustedKey: capabilitycontract.TrustedKey{
			PublisherID: contract.PublisherID, KeyID: "stress-key", PublicKey: publicKey, PolicyEpoch: "1", RevocationEpoch: "1",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type stressPlatformAdapter struct{}

func (stressPlatformAdapter) VerifyPackageTrust(context.Context, host.PackageTrustVerificationRequest) (host.PackageTrustVerificationResult, error) {
	return host.PackageTrustVerificationResult{TrustState: registry.TrustUnsignedLocal}, nil
}

func (stressPlatformAdapter) VerifyReleaseMetadata(context.Context, host.ReleaseMetadataVerificationRequest) (host.ReleaseMetadataVerificationResult, error) {
	return host.ReleaseMetadataVerificationResult{}, errors.New("stress host does not configure release metadata verification")
}

func (stressPlatformAdapter) VerifySourceRevocationEvidence(context.Context, host.SourceRevocationEvidenceVerificationRequest) (host.SourceRevocationEvidenceVerificationResult, error) {
	return host.SourceRevocationEvidenceVerificationResult{}, errors.New("stress host does not configure release revocation verification")
}

func (stressPlatformAdapter) ResolveReleaseSourcePolicy(context.Context, host.ReleaseSourcePolicyRequest) (host.SourcePolicySnapshot, error) {
	return host.SourcePolicySnapshot{}, errors.New("stress host does not configure release sources")
}

func (stressPlatformAdapter) ResolveReleaseArtifact(context.Context, host.ReleaseArtifactResolveRequest) (host.ResolvedPackageArtifact, error) {
	return host.ResolvedPackageArtifact{}, errors.New("stress host does not configure release artifacts")
}

func (stressPlatformAdapter) SelectHostRequirement(_ context.Context, req host.HostRequirementSelectionRequest) (host.HostRequirementSelection, error) {
	if len(req.Requirements) == 0 {
		return host.HostRequirementSelection{}, errors.New("stress host requirement is missing")
	}
	return host.HostRequirementSelection{HostID: req.Requirements[0].HostID}, nil
}

func (stressPlatformAdapter) ResolveCapabilityContract(context.Context, host.CapabilityContractResolveRequest) (host.ResolvedCapabilityContractArtifact, error) {
	return host.ResolvedCapabilityContractArtifact{}, errors.New("stress host does not configure capability artifacts")
}

func (stressPlatformAdapter) ResolveCapabilityContractKey(context.Context, host.CapabilityContractKeyRequest) ([]byte, error) {
	return nil, errors.New("stress host does not configure capability keys")
}

func (stressPlatformAdapter) PublishSurfaces(context.Context, host.SurfaceSnapshot) error {
	return nil
}

func (stressPlatformAdapter) ResolveCoreActionTarget(context.Context, capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{}, errors.New("stress host does not configure core actions")
}

func (stressPlatformAdapter) InvokeCoreAction(context.Context, capability.Invocation) (capability.Result, error) {
	return capability.Result{}, errors.New("stress host does not configure core actions")
}

type stressPolicy struct{}

type stressAuthorization struct{}

func (stressAuthorization) Authorize(_ context.Context, req host.AuthorizationRequest) error {
	if !req.Session.Valid() || !req.Action.Valid() || !req.Target.Kind.Valid() || req.Target.Kind != req.Action.Resource() {
		return host.ErrActionDenied
	}
	return nil
}

func (stressPolicy) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (stressPolicy) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

func (stressPolicy) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

type stressIPCFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type stressHelloPayload struct {
	Target       stressRuntimeTargetWire     `json:"target"`
	ChannelNonce string                      `json:"channel_nonce"`
	Limits       runtimeclient.RuntimeLimits `json:"limits"`
}

type stressRuntimeTargetWire struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type stressHeartbeatPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type stressRevokePayload struct {
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	PluginInstanceID string                   `json:"plugin_instance_id"`
	RevokeEpoch      uint64                   `json:"revoke_epoch"`
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
			"actual_target":    hello.Target,
			"rust_ipc_version": version.RustIPCVersion,
			"wasm_abi_version": version.WASMABIVersion,
			"channel_nonce":    hello.ChannelNonce,
			"limits":           hello.Limits,
		}),
	}); err != nil {
		os.Exit(6)
	}
	controlRead := stressRuntimeControlFile("REDEVPLUGIN_CONTROL_READ_FD", "stress-runtime-control-read")
	controlWrite := stressRuntimeControlFile("REDEVPLUGIN_CONTROL_WRITE_FD", "stress-runtime-control-write")
	if controlRead == nil || controlWrite == nil {
		os.Exit(7)
	}
	defer controlRead.Close()
	defer controlWrite.Close()
	reader = bufio.NewReader(controlRead)
	encoder = json.NewEncoder(controlWrite)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request stressIPCFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(8)
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
					"active_invocations":    0,
					"queued_invocations":    0,
					"limits":                hello.Limits,
					"module_cache":          runtimeclient.ModuleCacheMetrics{},
				}),
			}))
		case "revoke_epoch":
			var revoke stressRevokePayload
			_ = json.Unmarshal(request.Payload, &revoke)
			respondStressRuntime(encoder, request, "revoke_epoch_ack", stressRawJSON(stressRuntimeResponsePayload{
				OK: true,
				Result: stressRawJSON(map[string]any{
					"resource_scope":              revoke.ResourceScope,
					"plugin_instance_id":          revoke.PluginInstanceID,
					"revoke_epoch":                revoke.RevokeEpoch,
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

func stressRuntimeControlFile(environmentVariable string, name string) *os.File {
	fileDescriptor, err := strconv.Atoi(os.Getenv(environmentVariable))
	if err != nil || fileDescriptor < 0 {
		return nil
	}
	return os.NewFile(uintptr(fileDescriptor), name)
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

func stressRuntimeDescriptor(t *testing.T, path string, target runtimetarget.Target) runtimeclient.RuntimeDescriptor {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatal(err)
	}
	runtimeVersion, err := version.ParseSemVer(version.RuntimeVersion)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := runtimeclient.NewRuntimeDescriptor(
		runtimeVersion,
		target,
		version.RustIPCVersion,
		version.WASMABIVersion,
		hex.EncodeToString(hasher.Sum(nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
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
