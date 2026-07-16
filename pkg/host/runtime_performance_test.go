package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/version"
)

const performanceRuntimePathEnv = "REDEVPLUGIN_PERFORMANCE_RUNTIME"
const performanceMeasurementsPathEnv = "REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"

func TestPerformanceRuntimeWarmConcurrencyAndCache(t *testing.T) {
	runtimePath := requirePerformanceRuntime(t)
	limits := runtimeclient.RuntimeLimits{
		WorkerCount:            8,
		QueueCapacity:          32,
		PerPluginConcurrency:   4,
		ModuleCacheEntries:     64,
		ModuleCacheSourceBytes: 128 << 20,
	}
	h, supervisor, assets := newPerformanceRuntimeHost(t, runtimePath, limits, connectivity.NewMemoryBroker(), connectivity.NewExecutor(connectivity.ExecutorOptions{}))
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	assets.reads.Store(0)

	coldErrors, _ := callWorkerConcurrently(h, installed.PluginInstanceID, gateway.GatewayToken, 32)
	if len(coldErrors) > 0 {
		t.Fatalf("cold concurrent invocations failed: %v", coldErrors[0])
	}
	if reads := assets.reads.Load(); reads != 1 {
		t.Fatalf("artifact reads after concurrent first invocation = %d, want 1", reads)
	}
	heartbeat, err := supervisor.Heartbeat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.ModuleCache.Compiles != 1 || heartbeat.ModuleCache.Entries != 1 {
		t.Fatalf("module cache after cold concurrency = %#v", heartbeat.ModuleCache)
	}

	warmErrors, durations := callWorkerConcurrently(h, installed.PluginInstanceID, gateway.GatewayToken, 32)
	if len(warmErrors) > 0 {
		t.Fatalf("warm concurrent invocations failed: %v", warmErrors[0])
	}
	p95, maximum := performanceDurations(durations)
	if p95 > 100*time.Millisecond || maximum > 500*time.Millisecond {
		t.Fatalf("warm invocation latency p95=%s max=%s", p95, maximum)
	}
	if reads := assets.reads.Load(); reads != 1 {
		t.Fatalf("artifact reads after warm invocations = %d, want 1", reads)
	}
	heartbeat, err = supervisor.Heartbeat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.ModuleCache.Hits < 32 || heartbeat.ModuleCache.Compiles != 1 {
		t.Fatalf("module cache after warm concurrency = %#v", heartbeat.ModuleCache)
	}
	recordPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "runtime.cache-single-flight",
		Gate:        performanceevidence.Gate(),
		SampleCount: 32,
		Metrics: []performanceevidence.Metric{
			{Name: "artifact_reads", Unit: "count", Observed: float64(assets.reads.Load()), Limit: 1, Comparator: "eq"},
			{Name: "module_compiles", Unit: "count", Observed: float64(heartbeat.ModuleCache.Compiles), Limit: 1, Comparator: "eq"},
			{Name: "cache_entries", Unit: "count", Observed: float64(heartbeat.ModuleCache.Entries), Limit: 1, Comparator: "eq"},
		},
	})
	recordPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "runtime.warm-invocations",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(durations),
		Metrics: []performanceevidence.Metric{
			{Name: "completed", Unit: "count", Observed: float64(len(durations)), Limit: 32, Comparator: "eq"},
			{Name: "p95", Unit: "milliseconds", Observed: durationMilliseconds(p95), Limit: 100, Comparator: "lte"},
			{Name: "max", Unit: "milliseconds", Observed: durationMilliseconds(maximum), Limit: 500, Comparator: "lte"},
		},
	})
}

func TestPerformanceRuntimeIsolationAndCancellation(t *testing.T) {
	runtimePath := requirePerformanceRuntime(t)
	limits := runtimeclient.RuntimeLimits{
		WorkerCount:            8,
		QueueCapacity:          32,
		PerPluginConcurrency:   4,
		ModuleCacheEntries:     64,
		ModuleCacheSourceBytes: 128 << 20,
	}
	broker := connectivity.NewMemoryBroker()
	executor := newPerformanceBlockingNetworkExecutor()
	h, supervisor, assets := newPerformanceRuntimeHost(t, runtimePath, limits, broker, executor)
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	if errors, _ := callWorkerConcurrently(h, installed.PluginInstanceID, gateway.GatewayToken, 1); len(errors) > 0 {
		t.Fatalf("warm echo invocation failed: %v", errors[0])
	}
	blocking := installPerformanceBlockingArtifact(t, assets, broker)

	blockedDone := invokePerformanceBlockingWorker(supervisor, blocking, context.Background(), "isolation")
	blockedRequest := <-executor.started
	errs, durations := callWorkerConcurrently(h, installed.PluginInstanceID, gateway.GatewayToken, 16)
	if len(errs) > 0 {
		t.Fatalf("isolated invocations failed: %v", errs[0])
	}
	p95, _ := performanceDurations(durations)
	if p95 > 250*time.Millisecond {
		t.Fatalf("blocked hostcall isolation p95 = %s", p95)
	}
	close(blockedRequest.release)
	if err := <-blockedDone; err != nil {
		t.Fatalf("blocking isolation invocation failed: %v", err)
	}
	recordPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "runtime.blocked-hostcall-isolation",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(durations),
		Metrics: []performanceevidence.Metric{
			{Name: "completed", Unit: "count", Observed: float64(len(durations)), Limit: 16, Comparator: "eq"},
			{Name: "p95", Unit: "milliseconds", Observed: durationMilliseconds(p95), Limit: 250, Comparator: "lte"},
		},
	})

	blockers := make([]<-chan error, 0, limits.PerPluginConcurrency)
	requests := make([]*performanceBlockingRequest, 0, limits.PerPluginConcurrency)
	for index := 0; index < limits.PerPluginConcurrency; index++ {
		blockers = append(blockers, invokePerformanceBlockingWorker(supervisor, blocking, context.Background(), fmt.Sprintf("queue-blocker-%d", index)))
		requests = append(requests, <-executor.started)
	}
	queuedDurations := make([]time.Duration, 0, 20)
	for index := 0; index < 20; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := invokePerformanceBlockingWorker(supervisor, blocking, ctx, fmt.Sprintf("queued-%d", index))
		waitForRuntimeQueue(t, supervisor, 1)
		started := time.Now()
		cancel()
		err := <-done
		queuedDurations = append(queuedDurations, time.Since(started))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued cancellation error = %v", err)
		}
	}
	for _, request := range requests {
		close(request.release)
	}
	for _, done := range blockers {
		if err := <-done; err != nil {
			t.Fatalf("queue blocker failed: %v", err)
		}
	}
	queuedP95, _ := performanceDurations(queuedDurations)
	if queuedP95 > 50*time.Millisecond {
		t.Fatalf("queued cancellation p95 = %s", queuedP95)
	}
	recordPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "runtime.cancel-queued",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(queuedDurations),
		Metrics: []performanceevidence.Metric{
			{Name: "p95", Unit: "milliseconds", Observed: durationMilliseconds(queuedP95), Limit: 50, Comparator: "lte"},
		},
	})

	runningDurations := make([]time.Duration, 0, 20)
	for index := 0; index < 20; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := invokePerformanceBlockingWorker(supervisor, blocking, ctx, fmt.Sprintf("running-%d", index))
		<-executor.started
		started := time.Now()
		cancel()
		err := <-done
		runningDurations = append(runningDurations, time.Since(started))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("running cancellation error = %v", err)
		}
	}
	runningP95, _ := performanceDurations(runningDurations)
	if runningP95 > 100*time.Millisecond {
		t.Fatalf("running cancellation p95 = %s", runningP95)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil || !health.Ready {
		t.Fatalf("runtime health after cancellation = %#v, %v", health, err)
	}
	recordPerformanceScenario(t, performanceevidence.Scenario{
		ID:          "runtime.cancel-running",
		Gate:        performanceevidence.Gate(),
		SampleCount: len(runningDurations),
		Metrics: []performanceevidence.Metric{
			{Name: "ack_p95", Unit: "milliseconds", Observed: durationMilliseconds(runningP95), Limit: 100, Comparator: "lte"},
			{Name: "runtime_ready", Unit: "count", Observed: 1, Limit: 1, Comparator: "eq"},
		},
	})
}

type performanceCountingAssetStore struct {
	pluginpkg.AssetStore
	reads atomic.Int64
}

func (s *performanceCountingAssetStore) ReadAsset(ctx context.Context, packageHash string, assetPath string) (pluginpkg.Asset, error) {
	s.reads.Add(1)
	return s.AssetStore.ReadAsset(ctx, packageHash, assetPath)
}

func newPerformanceRuntimeHost(
	t *testing.T,
	runtimePath string,
	limits runtimeclient.RuntimeLimits,
	broker connectivity.Broker,
	executor connectivity.NetworkExecutor,
) (*Host, *runtimeclient.ProcessSupervisor, *performanceCountingAssetStore) {
	t.Helper()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: broker,
		networkExecutor:    executor,
		runtimeLimits:      limits,
	})
	observabilityStore := observability.NewMemoryStore()
	h.adapters.Audit = observabilityStore
	h.adapters.Diagnostics = observabilityStore
	assets := &performanceCountingAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:     runtimePath,
		Diagnostics:     observabilityStore,
		Artifacts:       runtimeArtifactProvider{assets: assets},
		HandleGrants:    runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:    storageFilesBroker(h.adapters.Storage),
		StorageKV:       storageKVBroker(h.adapters.Storage),
		StorageSQLite:   storageSQLiteBroker(h.adapters.Storage),
		Connectivity:    broker,
		NetworkExecutor: executor,
		Limits:          limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	if err := supervisor.Start(context.Background(), runtimeclient.Target{OS: "performance", Arch: "native"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := supervisor.Stop(ctx); err != nil {
			t.Errorf("stop runtime: %v", err)
		}
	})
	return h, supervisor, assets
}

func callWorkerConcurrently(h *Host, pluginInstanceID string, gatewayToken string, count int) ([]error, []time.Duration) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := make([]error, 0)
	durations := make([]time.Duration, 0, count)
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			started := time.Now()
			_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID:     pluginInstanceID,
				SurfaceInstanceID:    "surface_rpc",
				SessionChannelIDHash: "channel_hash",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				BridgeChannelID:      "bridge_rpc",
				GatewayToken:         gatewayToken,
				Method:               "worker.echo",
				Params:               map[string]any{"message": fmt.Sprintf("performance-%d", index)},
			})
			elapsed := time.Since(started)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			durations = append(durations, elapsed)
		}(index)
	}
	wg.Wait()
	return errs, durations
}

type performanceBlockingRequest struct {
	release chan struct{}
}

type performanceBlockingNetworkExecutor struct {
	started chan *performanceBlockingRequest
}

func newPerformanceBlockingNetworkExecutor() *performanceBlockingNetworkExecutor {
	return &performanceBlockingNetworkExecutor{started: make(chan *performanceBlockingRequest, 64)}
}

func (e *performanceBlockingNetworkExecutor) DoHTTP(ctx context.Context, _ connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	request := &performanceBlockingRequest{release: make(chan struct{})}
	e.started <- request
	select {
	case <-ctx.Done():
		return connectivity.HTTPResponse{}, ctx.Err()
	case <-request.release:
		return connectivity.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ok":true}`)}, nil
	}
}

func (e *performanceBlockingNetworkExecutor) StreamHTTP(context.Context, connectivity.HTTPRequest, func(connectivity.HTTPResponseChunk) error) (connectivity.HTTPStreamResponse, error) {
	return connectivity.HTTPStreamResponse{}, errors.New("unexpected stream request")
}

func (e *performanceBlockingNetworkExecutor) WebSocketRoundTrip(context.Context, connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	return connectivity.WebSocketRoundTripResponse{}, errors.New("unexpected websocket request")
}

func (e *performanceBlockingNetworkExecutor) TCPRoundTrip(context.Context, connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	return connectivity.TCPRoundTripResponse{}, errors.New("unexpected tcp request")
}

func (e *performanceBlockingNetworkExecutor) UDPRoundTrip(context.Context, connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	return connectivity.UDPRoundTripResponse{}, errors.New("unexpected udp request")
}

type performanceBlockingArtifact struct {
	packageHash       string
	artifactSHA256    string
	pluginID          string
	pluginInstanceID  string
	activeFingerprint string
}

func installPerformanceBlockingArtifact(t *testing.T, assets pluginpkg.AssetStore, broker connectivity.Broker) performanceBlockingArtifact {
	t.Helper()
	request := []byte(`{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"GET","path":"/performance","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":5000}`)
	module := importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", "network_execute", "redevplugin_worker_invoke", request)
	artifactSHA256 := performanceSHA256(module)
	packageHash := performanceSHA256([]byte("redevplugin-performance-blocking-worker-v1"))
	entry := pluginpkg.Entry{Path: "workers/blocking.wasm", Size: int64(len(module)), SHA256: artifactSHA256, Mode: "0644", ContentType: "application/wasm"}
	if err := assets.PutPackage(context.Background(), pluginpkg.Package{
		PackageHash: packageHash,
		Entries:     []pluginpkg.Entry{entry},
		Files:       map[string][]byte{entry.Path: module},
	}); err != nil {
		t.Fatal(err)
	}
	destination, err := connectivity.ParseDestination(connectivity.TransportHTTP, "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	artifact := performanceBlockingArtifact{
		packageHash:       packageHash,
		artifactSHA256:    artifactSHA256,
		pluginID:          "com.example.performance.blocking",
		pluginInstanceID:  "plugini_performance_blocking",
		activeFingerprint: performanceSHA256([]byte("redevplugin-performance-active-v1")),
	}
	if err := broker.InstallPolicy(context.Background(), connectivity.PolicySet{
		PluginInstanceID:        artifact.pluginInstanceID,
		PluginID:                artifact.pluginID,
		ActiveFingerprint:       artifact.activeFingerprint,
		PolicyRevision:          1,
		ManagementRevision:      1,
		RevokeEpoch:             1,
		TargetClassifierVersion: version.TargetClassifierVersion,
		Connectors: []connectivity.ConnectorPolicy{{
			ConnectorID:  "api",
			Transport:    connectivity.TransportHTTP,
			Scope:        connectivity.ScopeUser,
			Destinations: []connectivity.Destination{destination},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func invokePerformanceBlockingWorker(supervisor *runtimeclient.ProcessSupervisor, artifact performanceBlockingArtifact, ctx context.Context, suffix string) <-chan error {
	done := make(chan error, 1)
	go func() {
		health, err := supervisor.Health(context.Background())
		if err != nil {
			done <- err
			return
		}
		access := manifest.MethodBrokerAccessSpec{Network: []manifest.NetworkBrokerAccessSpec{{
			ConnectorID: "api", Transport: "http", Operations: []string{"http"}, HTTPMethods: []string{"GET"},
		}}}
		accessHash, err := workerBrokerAccessHash(access)
		if err != nil {
			done <- err
			return
		}
		params := map[string]any{}
		paramsRaw, _ := json.Marshal(params)
		paramsHash := performanceSHA256(paramsRaw)
		payload := workerInvocationPayload{
			PluginID: artifact.pluginID, PluginInstanceID: artifact.pluginInstanceID,
			ActiveFingerprint: artifact.activeFingerprint, RuntimeInstanceID: health.RuntimeInstanceID,
			RuntimeGenerationID: health.RuntimeGenerationID, PackageHash: artifact.packageHash,
			WorkerID: "blocking_worker", WorkerMode: "job", WorkerScope: "user",
			Artifact: "workers/blocking.wasm", ArtifactSHA256: artifact.artifactSHA256,
			ABI: version.WASMABIVersion, Method: "worker.block", Export: "redevplugin_worker_invoke",
			Effect: "read", Execution: "sync", SurfaceInstanceID: "surface_performance",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", SessionChannelIDHash: "channel_hash",
			BridgeChannelID: "bridge_performance", AuditCorrelationID: "audit_" + suffix,
			ParamsSHA256: paramsHash, Params: params, BrokerAccess: access, BrokerAccessSHA256: accessHash,
		}
		invocationHash, err := workerInvocationTargetHash(payload)
		if err != nil {
			done <- err
			return
		}
		rawPayload, err := json.Marshal(payload)
		if err != nil {
			done <- err
			return
		}
		now := time.Now().UTC()
		_, err = supervisor.InvokeWorker(ctx, runtimeclient.Lease{
			LeaseID: "lease_" + suffix, LeaseToken: "runtime_execution_lease.lease_" + suffix + ".secret",
			LeaseNonce: "nonce_" + suffix + "_1234567890", PluginID: artifact.pluginID,
			PluginVersion: "1.0.0", ActiveFingerprint: artifact.activeFingerprint,
			PluginInstanceID: artifact.pluginInstanceID, SurfaceInstanceID: payload.SurfaceInstanceID,
			OwnerSessionHash: payload.OwnerSessionHash, OwnerUserHash: payload.OwnerUserHash,
			SessionChannelIDHash: payload.SessionChannelIDHash, BridgeChannelID: payload.BridgeChannelID,
			Method: payload.Method, Effect: payload.Effect, Execution: payload.Execution,
			AuditCorrelationID: payload.AuditCorrelationID, TargetDescriptorHashes: []string{invocationHash},
			Limits:         runtimeclient.LeaseLimits{TimeoutMillis: 10_000, MemoryBytes: 16 << 20, MaxPayloadBytes: 1 << 20},
			PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1,
			IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
		}, payload.Method, rawPayload)
		done <- err
	}()
	return done
}

func waitForRuntimeQueue(t *testing.T, supervisor *runtimeclient.ProcessSupervisor, minimum int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		heartbeat, err := supervisor.Heartbeat(ctx)
		cancel()
		if err == nil && heartbeat.QueuedInvocations >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runtime invocation did not enter the queue")
}

func performanceDurations(values []time.Duration) (time.Duration, time.Duration) {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0, 0
	}
	index := (len(ordered)*95 + 99) / 100
	if index < 1 {
		index = 1
	}
	return ordered[index-1], ordered[len(ordered)-1]
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func performanceSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requirePerformanceRuntime(t *testing.T) string {
	t.Helper()
	path := os.Getenv(performanceRuntimePathEnv)
	if path == "" {
		t.Skipf("%s is not set", performanceRuntimePathEnv)
	}
	return path
}

func recordPerformanceScenario(t *testing.T, scenario performanceevidence.Scenario) {
	t.Helper()
	if err := performanceevidence.Record(os.Getenv(performanceMeasurementsPathEnv), scenario); err != nil {
		t.Fatal(err)
	}
}
