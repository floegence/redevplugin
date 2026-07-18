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
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
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

	coldErrors, _ := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 32, performanceRuntimeAdmissionCapacity(limits))
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

	warmErrors, durations := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 32, performanceRuntimeAdmissionCapacity(limits))
	if len(warmErrors) > 0 {
		t.Fatalf("warm concurrent invocations failed: %v", warmErrors[0])
	}
	p95, maximum := performanceDurations(durations)
	if enforcePerformanceLatencyThresholds() && (p95 > 100*time.Millisecond || maximum > 500*time.Millisecond) {
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

func TestPerformanceRuntimeCanceledColdLoadDoesNotFailWaiter(t *testing.T) {
	runtimePath := requirePerformanceRuntime(t)
	limits := runtimeclient.RuntimeLimits{
		WorkerCount:            2,
		QueueCapacity:          4,
		PerPluginConcurrency:   2,
		ModuleCacheEntries:     8,
		ModuleCacheSourceBytes: 16 << 20,
	}
	broker := connectivity.NewMemoryBroker()
	executor := newPerformanceBlockingNetworkExecutor()
	_, supervisor, assets := newPerformanceRuntimeHost(t, runtimePath, limits, broker, executor)
	artifact := installPerformanceBlockingArtifact(t, assets, broker)
	artifactReadStarted, releaseArtifactRead := assets.blockNextRead()

	leaderCtx, cancelLeader := context.WithCancel(hostTestContext())
	leaderDone := invokePerformanceBlockingWorker(supervisor, artifact, leaderCtx, "cold-load-leader")
	select {
	case <-artifactReadStarted:
	case err := <-leaderDone:
		t.Fatalf("cold-load leader failed before artifact read: %v", err)
	case <-time.After(time.Second):
		t.Fatal("cold artifact read did not start")
	}
	waiterDone := invokePerformanceBlockingWorker(supervisor, artifact, hostTestContext(), "cold-load-waiter")
	waitForModuleCacheMisses(t, supervisor, 2)

	cancelStarted := time.Now()
	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled cold-load leader error = %v, want %v", err, context.Canceled)
		}
		if elapsed := time.Since(cancelStarted); elapsed > 250*time.Millisecond {
			t.Fatalf("canceled cold-load leader returned after %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled cold-load leader did not return promptly")
	}

	close(releaseArtifactRead)
	select {
	case request := <-executor.started:
		close(request.release)
	case <-time.After(time.Second):
		t.Fatal("cold-load waiter did not reach network execution")
	}
	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("cold-load waiter failed after leader cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cold-load waiter did not complete after artifact release")
	}
	if reads := assets.reads.Load(); reads != 1 {
		t.Fatalf("artifact reads after shared canceled cold load = %d, want 1", reads)
	}
	heartbeat, err := supervisor.Heartbeat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.ModuleCache.Compiles != 1 || heartbeat.ModuleCache.Entries != 1 {
		t.Fatalf("module cache after shared canceled cold load = %#v", heartbeat.ModuleCache)
	}
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
	if errors, _ := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 1, 1); len(errors) > 0 {
		t.Fatalf("warm echo invocation failed: %v", errors[0])
	}
	blocking := installPerformanceBlockingArtifact(t, assets, broker)

	blockedDone := invokePerformanceBlockingWorker(supervisor, blocking, context.Background(), "isolation")
	blockedRequest := <-executor.started
	errs, durations := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 16, performanceRuntimeAdmissionCapacity(limits))
	if len(errs) > 0 {
		t.Fatalf("isolated invocations failed: %v", errs[0])
	}
	p95, _ := performanceDurations(durations)
	if enforcePerformanceLatencyThresholds() && p95 > 250*time.Millisecond {
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
	if enforcePerformanceLatencyThresholds() && queuedP95 > 50*time.Millisecond {
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
	if enforcePerformanceLatencyThresholds() && runningP95 > 100*time.Millisecond {
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

func TestPerformanceRuntimeSaturatedPluginPreservesOtherPluginCapacity(t *testing.T) {
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
	if errors, _ := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 1, 1); len(errors) > 0 {
		t.Fatalf("warm invocation failed: %v", errors[0])
	}
	blocking := installPerformanceBlockingArtifact(t, assets, broker)

	active := make([]<-chan error, 0, limits.PerPluginConcurrency)
	activeRequests := make([]*performanceBlockingRequest, 0, limits.PerPluginConcurrency)
	for index := 0; index < limits.PerPluginConcurrency; index++ {
		active = append(active, invokePerformanceBlockingWorker(supervisor, blocking, context.Background(), fmt.Sprintf("saturation-active-%d", index)))
		activeRequests = append(activeRequests, <-executor.started)
	}
	queued := make([]<-chan error, 0, limits.PerPluginConcurrency)
	queuedCancels := make([]context.CancelFunc, 0, limits.PerPluginConcurrency)
	for index := 0; index < limits.PerPluginConcurrency; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		queuedCancels = append(queuedCancels, cancel)
		queued = append(queued, invokePerformanceBlockingWorker(supervisor, blocking, ctx, fmt.Sprintf("saturation-queued-%d", index)))
	}
	waitForRuntimeQueue(t, supervisor, limits.PerPluginConcurrency)

	errs, durations := callWorkerConcurrentlyBounded(h, installed.PluginInstanceID, gateway.GatewayToken, 8, performanceRuntimeAdmissionCapacity(limits))
	if len(errs) > 0 {
		t.Fatalf("other plugin invocation failed while saturated plugin owned its queue: %v", errs[0])
	}
	p95, _ := performanceDurations(durations)
	if enforcePerformanceLatencyThresholds() && p95 > 250*time.Millisecond {
		t.Fatalf("saturated plugin isolation p95 = %s", p95)
	}

	for _, cancel := range queuedCancels {
		cancel()
	}
	for index, done := range queued {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("queued invocation %d cancellation error = %v", index, err)
		}
	}
	for _, request := range activeRequests {
		close(request.release)
	}
	for index, done := range active {
		if err := <-done; err != nil {
			t.Fatalf("active invocation %d error = %v", index, err)
		}
	}
}

type performanceCountingAssetStore struct {
	pluginpkg.AssetStore
	reads        atomic.Int64
	blockMu      sync.Mutex
	blockNext    bool
	blockStart   chan struct{}
	blockRelease chan struct{}
}

func (s *performanceCountingAssetStore) ReadAsset(ctx context.Context, packageHash string, assetPath string) (pluginpkg.Asset, error) {
	s.reads.Add(1)
	s.blockMu.Lock()
	block := s.blockNext
	started := s.blockStart
	release := s.blockRelease
	if block {
		s.blockNext = false
	}
	s.blockMu.Unlock()
	if block {
		close(started)
		select {
		case <-ctx.Done():
			return pluginpkg.Asset{}, ctx.Err()
		case <-release:
		}
	}
	return s.AssetStore.ReadAsset(ctx, packageHash, assetPath)
}

func (s *performanceCountingAssetStore) blockNextRead() (<-chan struct{}, chan struct{}) {
	s.blockMu.Lock()
	defer s.blockMu.Unlock()
	s.blockNext = true
	s.blockStart = make(chan struct{})
	s.blockRelease = make(chan struct{})
	return s.blockStart, s.blockRelease
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
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	observabilityStore := observability.NewMemoryStore()
	h.adapters.Audit = observabilityStore
	h.adapters.Diagnostics = observabilityStore
	assets := &performanceCountingAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:           runtimePath,
		Descriptor:            hostRuntimeTestDescriptor(t, runtimePath),
		Diagnostics:           observabilityStore,
		Artifacts:             runtimeArtifactProvider{assets: assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		StorageSQLite:         h.adapters.PluginData,
		Connectivity:          broker,
		NetworkExecutor:       executor,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
		Limits:                limits,
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = performanceRuntimeManager{supervisor: supervisor}
	if err := supervisor.Start(context.Background(), hostRuntimeTestTarget(t)); err != nil {
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

type performanceRuntimeManager struct {
	supervisor *runtimeclient.ProcessSupervisor
}

func (performanceRuntimeManager) BindHostServices(services runtimeclient.RuntimeHostServices) error {
	if services.StreamSink == nil {
		return runtimeclient.ErrRuntimeHostServicesInvalid
	}
	return nil
}

func (m performanceRuntimeManager) Preflight(ctx context.Context, target runtimeclient.Target) (runtimeclient.RuntimeDescriptor, error) {
	return m.supervisor.Preflight(ctx, target)
}

func (m performanceRuntimeManager) Start(ctx context.Context, target runtimeclient.Target) (runtimeclient.ManagerHealth, error) {
	if err := m.supervisor.Start(ctx, target); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	return m.Health(ctx)
}

func (m performanceRuntimeManager) Stop(ctx context.Context) error {
	return m.supervisor.Stop(ctx)
}

func (m performanceRuntimeManager) Health(ctx context.Context) (runtimeclient.ManagerHealth, error) {
	health, err := m.supervisor.Health(ctx)
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	return runtimeclient.ManagerHealth{
		Ready:      health.Ready,
		Descriptor: health.Descriptor,
		Shards:     []runtimeclient.ShardHealth{{RuntimeShardID: "runtime_shard_performance", Health: health}},
	}, nil
}

func (m performanceRuntimeManager) BindPlugin(ctx context.Context, pluginInstanceID string) (runtimeclient.RuntimeBinding, error) {
	health, err := m.supervisor.Health(ctx)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if !health.Ready || pluginInstanceID == "" {
		return runtimeclient.RuntimeBinding{}, runtimeclient.ErrRuntimeNotReady
	}
	return runtimeclient.RuntimeBinding{
		RuntimeShardID:      "runtime_shard_performance",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		IPCChannelID:        health.IPCChannelID,
		ConnectionNonce:     health.ConnectionNonce,
		Descriptor:          health.Descriptor,
	}, nil
}

func (m performanceRuntimeManager) InvokeWorker(ctx context.Context, _ runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	return m.supervisor.InvokeWorker(ctx, lease, method, payload)
}

func (m performanceRuntimeManager) Revoke(ctx context.Context, req runtimeclient.RevokeRequest) (runtimeclient.RevokeResult, error) {
	return m.supervisor.Revoke(ctx, req)
}

func callWorkerConcurrentlyBounded(h *Host, pluginInstanceID string, gatewayToken string, count int, maxInFlight int) ([]error, []time.Duration) {
	if count < 1 {
		panic("performance invocation count must be positive")
	}
	if maxInFlight < 1 || maxInFlight > count {
		panic("performance invocation maxInFlight must be between one and count")
	}
	admission := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := make([]error, 0)
	durations := make([]time.Duration, 0, count)
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			started := time.Now()
			admission <- struct{}{}
			defer func() { <-admission }()
			_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
				PluginInstanceID:  pluginInstanceID,
				SurfaceInstanceID: "surface_rpc",
				BridgeChannelID:   "bridge_rpc",
				GatewayToken:      gatewayToken,
				Method:            "worker.echo",
				Params:            map[string]any{"message": fmt.Sprintf("performance-%d", index)},
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

func performanceRuntimeAdmissionCapacity(limits runtimeclient.RuntimeLimits) int {
	return limits.PerPluginConcurrency + min(limits.QueueCapacity, limits.PerPluginConcurrency)
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
	if err := broker.InstallPolicy(hostTestContext(), connectivity.PolicySet{
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
			ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"},
		}}}
		accessHash, err := workerBrokerAccessHash(access)
		if err != nil {
			done <- err
			return
		}
		params := map[string]any{}
		paramsRaw, _ := marshalWorkerCanonicalJSON(params)
		paramsHash := performanceSHA256(paramsRaw)
		payload := workerInvocationPayload{
			PluginID: artifact.pluginID, PluginInstanceID: artifact.pluginInstanceID,
			ActiveFingerprint: artifact.activeFingerprint, RuntimeInstanceID: health.RuntimeInstanceID,
			RuntimeGenerationID: health.RuntimeGenerationID, PackageHash: artifact.packageHash,
			WorkerID: "blocking_worker", WorkerMode: "job", WorkerScope: "user",
			Artifact: "workers/blocking.wasm", ArtifactSHA256: artifact.artifactSHA256,
			ABI: version.WASMABIVersion, Method: "worker.block",
			Effect: "read", Execution: "sync", SurfaceInstanceID: "surface_performance",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
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
			LeaseID:    "lease_" + suffix,
			TokenID:    "token_" + suffix,
			LeaseNonce: "nonce_" + suffix + "_1234567890", PluginID: artifact.pluginID,
			PluginVersion: "1.0.0", ActiveFingerprint: artifact.activeFingerprint,
			PluginInstanceID: artifact.pluginInstanceID, SurfaceInstanceID: payload.SurfaceInstanceID,
			OwnerSessionHash: payload.OwnerSessionHash, OwnerUserHash: payload.OwnerUserHash, OwnerEnvHash: payload.OwnerEnvHash,
			SessionChannelIDHash: payload.SessionChannelIDHash, BridgeChannelID: payload.BridgeChannelID,
			Method: payload.Method, Effect: payload.Effect, Execution: payload.Execution,
			AuditCorrelationID: payload.AuditCorrelationID, TargetDescriptorHashes: []string{invocationHash},
			Limits:         runtimeclient.LeaseLimits{TimeoutMillis: 10_000, MemoryBytes: 16 << 20, MaxPayloadBytes: 1 << 20},
			PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1,
			RuntimeShardID: "runtime_shard_performance", RuntimeInstanceID: health.RuntimeInstanceID,
			RuntimeGenerationID: health.RuntimeGenerationID, IPCChannelID: health.IPCChannelID,
			ConnectionNonce: health.ConnectionNonce, IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: now.Add(30 * time.Second).UnixMilli(),
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

func waitForModuleCacheMisses(t *testing.T, supervisor *runtimeclient.ProcessSupervisor, minimum uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		heartbeat, err := supervisor.Heartbeat(ctx)
		cancel()
		if err == nil && heartbeat.ModuleCache.Misses >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("runtime module cache did not reach %d misses", minimum)
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

func enforcePerformanceLatencyThresholds() bool {
	gate := performanceevidence.Gate()
	return gate == "full" || gate == "release"
}
