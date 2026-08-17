package stress_test

import (
	"context"
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
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/httpadapter"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"github.com/floegence/redevplugin/v3/pkg/version"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
	_ "modernc.org/sqlite"
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

func TestStressGateExecutionCancelOwnershipEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(stressTestContext(), 5*time.Second)
	defer cancel()

	diagnostics := observability.NewMemoryStore()
	connectivityBroker := connectivity.NewMemoryBroker()
	platformAdapter := stressPlatformAdapter{}
	securityJournal := observability.NewMemorySecurityAuditJournal()
	pluginHost, err := host.Open(ctx, host.Config{
		StateRoot: filepath.Join(t.TempDir(), "control-state"),
		Core: host.CoreAdapters{
			Policy:               stressPolicy{},
			Authorization:        stressAuthorization{},
			PackageTrustVerifier: platformAdapter,
			Audit:                diagnostics,
			SecurityAudit:        securityJournal,
			Diagnostics:          diagnostics,
			SurfaceCatalog:       platformAdapter,
			Assets:               pluginpkg.NewMemoryAssetStore(),
		},
		Connectivity: &host.ConnectivityModule{Broker: connectivityBroker, NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})},
		Secrets:      &host.SecretsModule{Store: secrets.NewMemoryStore()},
		CoreAction:   &host.CoreActionModule{Adapter: platformAdapter},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pluginHost.Close()

	if _, err := pluginHost.CancelExecution(ctx, "execution_stress_missing_direct", "user"); err == nil {
		t.Fatal("CancelExecution(missing) succeeded")
	}

	handler, err := httpadapter.NewHandler(httpadapter.Dependencies{Host: pluginHost, Guard: stressWebSecurityGuard{}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/executions/execution_stress_missing_http/cancel", strings.NewReader(`{"reason":"user"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("owner-scoped cancel status = %d body = %s", rec.Code, rec.Body.String())
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
	if response.OK || response.Error == nil {
		t.Fatalf("missing execution cancel response mismatch: %#v", response)
	}

	records, nextCursor, err := pluginHost.ListExecutions(ctx, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || nextCursor != 0 {
		t.Fatalf("unexpected executions after rejected cancellation: records=%#v next_cursor=%d", records, nextCursor)
	}

	logStressSummary(t, stressSummary{
		Category: "execution_cancel_ownership",
		Counters: map[string]int{
			"owner_scoped_cancel_requests": 2,
			"missing_executions_rejected":  2,
			"parallel_store_records":       len(records),
		},
	})
}

func TestStressGateRuntimeRevokeACKP95(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the runtime admission stress target requires Linux")
	}
	ctx, cancel := context.WithTimeout(stressTestContext(), 15*time.Second)
	defer cancel()

	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatal(err)
	}
	options := runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HandshakeTimeout:      15 * time.Second,
		RuntimePath:           os.Args[0],
		ArtifactIdentity:      stressRuntimeArtifactIdentity(t, os.Args[0], target),
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_STRESS_RUNTIME_HELPER=1"),
		HeartbeatInterval:     250 * time.Millisecond,
		MaxHeartbeatStaleness: time.Second,
		StreamSink:            stressRuntimeStreamSink{},
		IOBroker:              stressRuntimeIOBroker{},
	}
	var supervisor *runtimeclient.ProcessSupervisor
	for attempt := 1; attempt <= 3; attempt++ {
		supervisor, err = runtimeclient.NewProcessSupervisor(options)
		if err != nil {
			t.Fatal(err)
		}
		err = supervisor.Start(ctx, target)
		if err == nil {
			break
		}
		if !errors.Is(err, runtimeclient.ErrRuntimeHandshake) || attempt == 3 {
			t.Fatalf("Start() error = %v", err)
		}
		stopCtx, stopCancel := context.WithTimeout(stressTestContext(), time.Second)
		_ = supervisor.Stop(stopCtx)
		stopCancel()
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

type stressRuntimeIOBroker struct{}

func (stressRuntimeIOBroker) Control(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("stress revoke fixture does not expose resource I/O")
}

func (stressRuntimeIOBroker) Read(context.Context, string, uint64, []byte) (int, uint32, error) {
	return 0, 0, errors.New("stress revoke fixture does not expose resource I/O")
}

func (stressRuntimeIOBroker) Write(context.Context, string, uint64, []byte, uint32) (int, error) {
	return 0, errors.New("stress revoke fixture does not expose resource I/O")
}

func (stressRuntimeIOBroker) Seek(context.Context, string, uint64, int64, int) (int64, error) {
	return 0, errors.New("stress revoke fixture does not expose resource I/O")
}

func (stressRuntimeIOBroker) Close(context.Context, string, uint64) error {
	return errors.New("stress revoke fixture does not expose resource I/O")
}

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
	disabled, err := registryStore.SetEnableState(ctx, ns.PluginInstanceID, registry.EnableDisabledByUser, "stress import", time.Now())
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
		SchemaVersion: manifest.SchemaVersionV9,
		Publisher:     manifest.Publisher{PublisherID: "dev.redevplugin.stress", DisplayName: "Stress"},
		Plugin: manifest.Plugin{
			PluginID:    "dev.redevplugin.stress.data",
			DisplayName: "Stress Data",
			Version:     "1.0.0",
		},
		API:         manifest.PublicAPIRequirement{Major: 1},
		Permissions: []manifest.PermissionID{},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: "main",
			Kind:      manifest.SurfaceView,
			Label:     "Stress data",
			Entry:     "ui/index.html",
		}},
		Presentation: manifest.PresentationSpec{
			DefaultLocale: "en-US",
			Summary:       "Stress data fixture",
			Description:   []string{"Stress data fixture"},
			Highlights:    []string{},
			Keywords:      []string{"stress"},
			Localizations: []manifest.PresentationLocalizationSpec{},
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
			PackageSourceProvenance: registry.PackageSourceProvenance{
				Kind: registry.PackageSourceLocalGenerated,
			},
			EnableState: registry.EnableDisabledByUser,
			Manifest:    pluginManifest,
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
	dataset, err := pluginData.InstallCommit(ctx, plugindata.InstallCommitRequest{
		PluginInstanceID: source.PluginInstanceID,
		Shape:            shape,
	}, func(commitCtx context.Context, _ *plugindata.Binding, binding plugindata.Binding, committedShape plugindata.Shape, commitTime time.Time) error {
		return registryStore.SwapImport(
			commitCtx,
			source.ManagementRevision,
			nil,
			binding,
			committedShape,
			commitTime,
		)
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

func (stressWebSecurityGuard) AuthorizeRoute(_ *http.Request, _ sessionctx.Context, action websecurity.RouteAction, _ websecurity.RouteEffect) error {
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

type stressPlatformAdapter struct{}

func (stressPlatformAdapter) VerifyPackageTrust(context.Context, host.PackageTrustVerificationRequest) (host.PackageTrustVerificationResult, error) {
	return host.PackageTrustVerificationResult{TrustState: registry.TrustUnsignedLocal}, nil
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
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type stressHelloPayload struct {
	InternalWire          uint16                      `json:"internal_wire"`
	PlatformVersion       string                      `json:"platform_version"`
	RuntimeArtifactSHA256 string                      `json:"runtime_artifact_sha256"`
	ConnectionNonce       string                      `json:"connection_nonce"`
	Target                string                      `json:"target"`
	Limits                runtimeclient.RuntimeLimits `json:"limits"`
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
	ipcRead := os.NewFile(3, "stress-runtime-ipc-read")
	ipcWrite := os.NewFile(4, "stress-runtime-ipc-write")
	controlRead := os.NewFile(5, "stress-runtime-control-read")
	controlWrite := os.NewFile(6, "stress-runtime-control-write")
	if ipcRead == nil || ipcWrite == nil || controlRead == nil || controlWrite == nil {
		os.Exit(7)
	}
	defer ipcRead.Close()
	defer ipcWrite.Close()
	defer controlRead.Close()
	defer controlWrite.Close()
	wireFrame, frame, err := readStressRuntimeFrame(ipcRead)
	if err != nil {
		os.Exit(2)
	}
	if wireFrame.Type != runtimeclient.IPCFrameHello ||
		frame.FrameType != "hello" ||
		strings.TrimSpace(frame.RequestID) == "" ||
		strings.TrimSpace(frame.RuntimeGenerationID) == "" {
		os.Exit(4)
	}
	var hello stressHelloPayload
	if err := json.Unmarshal(frame.Payload, &hello); err != nil || hello.InternalWire != runtimeclient.InternalWire ||
		hello.PlatformVersion != version.CurrentPlatformVersion() ||
		strings.TrimSpace(hello.RuntimeArtifactSHA256) == "" || strings.TrimSpace(hello.ConnectionNonce) == "" {
		os.Exit(5)
	}
	if err := writeStressRuntimeFrame(ipcWrite, runtimeclient.IPCFrameHelloAck, wireFrame.RequestID, stressIPCFrame{
		FrameType:           "hello_ack",
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload: stressRawJSON(map[string]any{
			"internal_wire":           runtimeclient.InternalWire,
			"platform_version":        hello.PlatformVersion,
			"runtime_artifact_sha256": hello.RuntimeArtifactSHA256,
			"connection_nonce":        hello.ConnectionNonce,
			"actual_target":           hello.Target,
			"limits":                  hello.Limits,
		}),
	}); err != nil {
		os.Exit(6)
	}
	for {
		wireRequest, request, err := readStressRuntimeFrame(controlRead)
		if err != nil {
			return
		}
		switch request.FrameType {
		case "heartbeat":
			if wireRequest.Type != runtimeclient.IPCFrameHeartbeat {
				os.Exit(8)
			}
			var heartbeat stressHeartbeatPayload
			_ = json.Unmarshal(request.Payload, &heartbeat)
			respondStressRuntime(controlWrite, wireRequest.RequestID, runtimeclient.IPCFrameHeartbeat, request, "heartbeat", stressRawJSON(stressRuntimeResponsePayload{
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
			if wireRequest.Type != runtimeclient.IPCFrameRevokePlugin {
				os.Exit(8)
			}
			var revoke stressRevokePayload
			_ = json.Unmarshal(request.Payload, &revoke)
			respondStressRuntime(controlWrite, wireRequest.RequestID, runtimeclient.IPCFrameRevokePlugin, request, "revoke_epoch_ack", stressRawJSON(stressRuntimeResponsePayload{
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
			respondStressRuntime(controlWrite, wireRequest.RequestID, runtimeclient.IPCFrameDiagnostic, request, "diagnostic", stressRawJSON(stressRuntimeResponsePayload{
				OK:    false,
				Code:  "UNSUPPORTED_FRAME",
				Error: "unsupported stress runtime frame",
			}))
		}
	}
}

func readStressRuntimeFrame(reader io.Reader) (runtimeclient.IPCFrame, stressIPCFrame, error) {
	wireFrame, err := runtimeclient.ReadIPCFrame(reader)
	if err != nil {
		return runtimeclient.IPCFrame{}, stressIPCFrame{}, err
	}
	if wireFrame.Flags != 0 || len(wireFrame.Metadata) == 0 || len(wireFrame.Body) != 0 {
		return runtimeclient.IPCFrame{}, stressIPCFrame{}, errors.New("invalid stress runtime semantic frame placement")
	}
	var frame stressIPCFrame
	if err := json.Unmarshal(wireFrame.Metadata, &frame); err != nil {
		return runtimeclient.IPCFrame{}, stressIPCFrame{}, err
	}
	return wireFrame, frame, nil
}

func writeStressRuntimeFrame(writer io.Writer, wireType runtimeclient.IPCFrameType, requestID uint64, frame stressIPCFrame) error {
	metadata, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return runtimeclient.WriteIPCFrame(writer, runtimeclient.IPCFrame{
		Type:      wireType,
		RequestID: requestID,
		Metadata:  metadata,
	})
}

func respondStressRuntime(writer io.Writer, requestID uint64, wireType runtimeclient.IPCFrameType, request stressIPCFrame, frameType string, payload json.RawMessage) {
	if err := writeStressRuntimeFrame(writer, wireType, requestID, stressIPCFrame{
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

func stressRuntimeArtifactIdentity(t *testing.T, path string, target runtimetarget.Target) runtimeclient.RuntimeArtifactIdentity {
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
	runtimeVersion, err := version.ParseSemVer(version.CurrentPlatformVersion())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := runtimeclient.NewRuntimeArtifactIdentity(runtimeclient.RuntimeArtifactIdentityOptions{
		PlatformVersion: runtimeVersion,
		Target:          target,
		BinarySHA256:    hex.EncodeToString(hasher.Sum(nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
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
