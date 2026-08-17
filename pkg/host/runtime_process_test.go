package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

const hostRuntimeProcessHandshakeTimeout = 15 * time.Second

type testProcessManager struct {
	*runtimeclient.ProcessSupervisor
}

func (m testProcessManager) BindHostServices(services runtimeclient.RuntimeHostServices) error {
	if services.StreamSink == nil {
		return runtimeclient.ErrRuntimeHostServicesInvalid
	}
	return nil
}

func (m testProcessManager) Start(ctx context.Context, target runtimetarget.Target) (runtimeclient.ManagerHealth, error) {
	if err := m.ProcessSupervisor.Start(ctx, target); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	return m.Health(ctx)
}

func (m testProcessManager) Health(ctx context.Context) (runtimeclient.ManagerHealth, error) {
	health, err := m.ProcessSupervisor.Health(ctx)
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	return runtimeclient.ManagerHealth{
		Ready:            health.Ready,
		ArtifactIdentity: health.ArtifactIdentity,
		Shards:           []runtimeclient.ShardHealth{{RuntimeShardID: "runtime_shard_00", Health: health}},
	}, nil
}

func (m testProcessManager) RevokeSession(ctx context.Context, req runtimeclient.SessionRevokeRequest) (runtimeclient.SessionRevokeResult, error) {
	shard, err := m.ProcessSupervisor.RevokeSession(ctx, req)
	if err != nil {
		return runtimeclient.SessionRevokeResult{}, err
	}
	shard.RuntimeShardID = "runtime_shard_00"
	return runtimeclient.SessionRevokeResult{
		SessionScope: req.SessionScope, SessionRevokeSequence: req.SessionRevokeSequence,
		Shards: []runtimeclient.SessionRevokeShardResult{shard}, Counts: shard.Counts,
	}, nil
}

func (m testProcessManager) BindPlugin(ctx context.Context, _ string) (runtimeclient.RuntimeBinding, error) {
	health, err := m.ProcessSupervisor.Health(ctx)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	return runtimeclient.RuntimeBinding{
		RuntimeShardID:      "runtime_shard_00",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		IPCChannelID:        health.IPCChannelID,
		ConnectionNonce:     health.ConnectionNonce,
		ArtifactIdentity:    health.ArtifactIdentity,
	}, nil
}

func (m testProcessManager) InvokeWorker(ctx context.Context, _ runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	return m.ProcessSupervisor.InvokeWorker(ctx, lease, method, payload)
}

func hostRuntimeTestTarget(t *testing.T) runtimetarget.Target {
	t.Helper()
	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatalf("test runtime target: %v", err)
	}
	return target
}

func hostRuntimeWritableTestContext() context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		CanRead:              true,
		CanWrite:             true,
	})
}

func hostRuntimeTestDescriptor(t *testing.T, runtimePath string) runtimeclient.RuntimeArtifactIdentity {
	t.Helper()
	file, err := os.Open(runtimePath)
	if err != nil {
		t.Fatalf("open runtime executable: %v", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatalf("hash runtime executable: %v", err)
	}
	runtimeVersionText := strings.TrimSpace(os.Getenv("REDEVPLUGIN_PERFORMANCE_RUNTIME_VERSION"))
	if runtimeVersionText == "" {
		runtimeVersionText = hostRuntimeExpectedVersion(t, runtimePath)
	}
	runtimeVersion, err := version.ParseSemVer(runtimeVersionText)
	if err != nil {
		t.Fatalf("parse runtime version: %v", err)
	}
	descriptor, err := runtimeclient.NewRuntimeArtifactIdentity(runtimeclient.RuntimeArtifactIdentityOptions{
		PlatformVersion: runtimeVersion, Target: hostRuntimeTestTarget(t),
		BinarySHA256: hex.EncodeToString(hasher.Sum(nil)),
	})
	if err != nil {
		t.Fatalf("construct runtime artifact identity: %v", err)
	}
	return descriptor
}

func hostRuntimeExpectedVersion(t *testing.T, runtimePath string) string {
	t.Helper()
	runtimeName := strings.TrimSuffix(filepath.Base(runtimePath), ".exe")
	if runtimeName != "redevplugin-runtime" {
		return version.CurrentPlatformVersion()
	}
	bytes, err := os.ReadFile(filepath.Join(findRepoRootForHostTest(t), "VERSION"))
	if err != nil {
		t.Fatalf("read platform runtime version: %v", err)
	}
	platformVersion := strings.TrimSpace(string(bytes))
	if platformVersion == "" {
		t.Fatal("platform runtime version is empty")
	}
	return platformVersion
}

func TestProcessManagerRevokesExactSessionAcrossTwoBuiltRustRuntimeShards(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repoRoot := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, withoutRuntimeManager: true})
	manager, err := runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
		ShardCount: 2,
		Supervisor: runtimeclient.ProcessSupervisorOptions{
			Limits: runtimeclient.DefaultRuntimeLimits(), HandshakeTimeout: hostRuntimeProcessHandshakeTimeout,
			HeartbeatInterval: 2 * time.Second, MaxHeartbeatStaleness: 5 * time.Second,
			RuntimePath: runtimePath, ArtifactIdentity: hostRuntimeTestDescriptor(t, runtimePath),
			Diagnostics: h.adapters.Diagnostics, Artifacts: runtimeArtifactProvider{assets: h.adapters.Assets},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BindHostServices(runtimeclient.RuntimeHostServices{StreamSink: hostRuntimeStreamSink{executions: h.executions}, IOBroker: h.runtimeIO}); err != nil {
		t.Fatal(err)
	}
	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	scope := sessionctx.SessionScope{
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}
	result, err := manager.RevokeSession(context.Background(), runtimeclient.SessionRevokeRequest{
		SessionScope: scope, SessionRevokeSequence: 1,
	})
	if err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if len(result.Shards) != 2 || result.SessionScope != scope || result.SessionRevokeSequence != 1 || result.RuntimeStopped {
		t.Fatalf("RevokeSession() result = %#v", result)
	}
	for index, shard := range result.Shards {
		if shard.State != runtimeclient.SessionRevokeStateComplete || shard.RuntimeShardID == "" || shard.RuntimeGenerationID == "" {
			t.Fatalf("RevokeSession() shard %d = %#v", index, shard)
		}
	}
}

func TestCallPluginMethodWorkerThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repoRoot := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}

	ctx := hostTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HandshakeTimeout:      hostRuntimeProcessHandshakeTimeout,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		ArtifactIdentity:      hostRuntimeTestDescriptor(t, runtimePath),
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
		IOBroker:              h.runtimeIO,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	record, err := h.getPluginRecord(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	workerEntry, ok := packageEntryByPath(record.PackageEntries, "workers/echo.wasm")
	if !ok {
		t.Fatal("worker artifact metadata is missing")
	}
	if err := supervisor.PrewarmWorker(ctx, runtimeclient.PrewarmWorkerRequest{
		PluginInstanceID: installed.PluginInstanceID,
		WorkerID:         "echo_worker",
		Artifact: runtimeclient.ArtifactRequest{
			PackageHash: record.PackageHash, Artifact: "workers/echo.wasm", ArtifactSHA256: workerEntry.SHA256,
		},
	}); err != nil {
		t.Fatalf("PrewarmWorker() error = %v", err)
	}
	prewarmHeartbeat, err := supervisor.Heartbeat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prewarmHeartbeat.ModuleCache.Compiles != 1 || prewarmHeartbeat.ModuleCache.Entries != 1 {
		t.Fatalf("module cache after prewarm = %#v", prewarmHeartbeat.ModuleCache)
	}

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello from rust runtime"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with built Rust runtime error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	if data["backend"] != "executed wasm worker scaffold" ||
		data["transport"] != "rust runtime ipc" ||
		data["method"] != "worker.echo" ||
		data["worker_id"] != "echo_worker" {
		t.Fatalf("built Rust runtime result mismatch: %#v", data)
	}
	warm, err := supervisor.Heartbeat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if warm.ModuleCache.Compiles != 1 || warm.ModuleCache.Entries != 1 || warm.ModuleCache.Hits == 0 {
		t.Fatalf("module cache after warm invocation = %#v", warm.ModuleCache)
	}
}

func TestCallPluginMethodWorkerStorageMemoryHostcallThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repoRoot := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}

	ctx := hostRuntimeWritableTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		ArtifactIdentity:      hostRuntimeTestDescriptor(t, runtimePath),
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
		IOBroker:              h.runtimeIO,
		HandshakeTimeout:      hostRuntimeProcessHandshakeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageMemoryHostcallFixturePackage(t), "worker.view")
	body := []byte("hello from memory storage hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with storage memory hostcall error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	storageControl, ok := data["storage"].(map[string]any)
	if !ok {
		t.Fatalf("storage result missing: %#v", data)
	}
	storageFile, ok := storageControl["result"].(map[string]any)
	if !ok {
		t.Fatalf("storage control result missing: %#v", storageControl)
	}
	if storageFile["ok"] != true || storageFile["path"] != "notes/from-memory.txt" || storageFile["size_bytes"] != float64(len(body)) {
		t.Fatalf("storage result mismatch: %#v", storageFile)
	}
	read, err := h.adapters.PluginData.ReadFile(ctx, storage.FileReadRequest{
		PluginInstanceID: installed.PluginInstanceID,
		ResourceScope:    runtimeProcessResourceScope(t, ctx, sessionctx.ScopeUser),
		StoreID:          "workspace",
		Path:             "notes/from-memory.txt",
	})
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(read.Data) != string(body) {
		t.Fatalf("stored file = %q, want %q", read.Data, body)
	}
}

func TestCallPluginMethodWorkerStorageKVMemoryHostcallThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repoRoot := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}

	ctx := hostRuntimeWritableTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		ArtifactIdentity:      hostRuntimeTestDescriptor(t, runtimePath),
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
		IOBroker:              h.runtimeIO,
		HandshakeTimeout:      hostRuntimeProcessHandshakeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageKVMemoryHostcallFixturePackage(t), "worker.view")
	body := []byte("hello from memory kv hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with storage kv memory hostcall error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	storageControl, ok := data["storage"].(map[string]any)
	if !ok {
		t.Fatalf("storage result missing: %#v", data)
	}
	storageKV, ok := storageControl["result"].(map[string]any)
	if !ok {
		t.Fatalf("storage control result missing: %#v", storageControl)
	}
	if storageKV["ok"] != true || storageKV["key"] != "runs/latest" || storageKV["size_bytes"] != float64(len(body)) {
		t.Fatalf("storage result mismatch: %#v", storageKV)
	}
	read, err := h.adapters.PluginData.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: installed.PluginInstanceID,
		ResourceScope:    runtimeProcessResourceScope(t, ctx, sessionctx.ScopeUser),
		StoreID:          "cache",
		Key:              "runs/latest",
	})
	if err != nil {
		t.Fatalf("GetKV() error = %v", err)
	}
	if string(read.Value) != string(body) {
		t.Fatalf("stored kv = %q, want %q", read.Value, body)
	}
}

func TestCallPluginMethodWorkerStorageSQLiteMemoryHostcallThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repoRoot := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}

	ctx := hostRuntimeWritableTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		ArtifactIdentity:      hostRuntimeTestDescriptor(t, runtimePath),
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
		IOBroker:              h.runtimeIO,
		HandshakeTimeout:      hostRuntimeProcessHandshakeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageSQLiteMemoryHostcallFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with storage sqlite memory hostcall error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	storageControl, ok := data["storage"].(map[string]any)
	if !ok {
		t.Fatalf("storage result missing: %#v", data)
	}
	storageSQLite, ok := storageControl["result"].(map[string]any)
	if !ok {
		t.Fatalf("storage control result missing: %#v", storageControl)
	}
	if storageSQLite["ok"] != true || storageSQLite["database"] != "plugin.sqlite" {
		t.Fatalf("storage result mismatch: %#v", storageSQLite)
	}
	if storageSQLite["rows_affected"] != float64(0) {
		t.Fatalf("storage rows_affected = %#v, want 0", storageSQLite["rows_affected"])
	}
	tableName := "worker_runs"
	query, err := h.adapters.PluginData.QuerySQLite(ctx, storage.SQLiteQueryRequest{
		PluginInstanceID: installed.PluginInstanceID,
		ResourceScope:    runtimeProcessResourceScope(t, ctx, sessionctx.ScopeUser),
		StoreID:          "db",
		Database:         "plugin.sqlite",
		SQL:              "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
		Args:             []storage.SQLiteValue{{Text: &tableName}},
		MaxRows:          1,
		MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatalf("QuerySQLite() error = %v", err)
	}
	if len(query.Rows) != 1 || len(query.Rows[0]) != 1 || query.Rows[0][0].Text == nil || *query.Rows[0][0].Text != "worker_runs" {
		t.Fatalf("sqlite table was not created through wasm hostcall: %#v", query.Rows)
	}
	assertRuntimeRevokeCounts(t, supervisor, installed.PluginInstanceID, installed.RevokeEpoch+1, 0, 0, 0)
}

func runtimeProcessResourceScope(t testing.TB, ctx context.Context, kind sessionctx.ScopeKind) sessionctx.ResourceScope {
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

type runtimeRevoker interface {
	Revoke(context.Context, runtimeclient.RevokeRequest) (runtimeclient.RevokeResult, error)
}

func assertRuntimeRevokeCounts(t *testing.T, supervisor runtimeRevoker, pluginInstanceID string, revokeEpoch uint64, socket, stream, storageHandle int) {
	t.Helper()
	revokeCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
	defer cancel()
	result, err := supervisor.Revoke(revokeCtx, runtimeclient.RevokeRequest{
		ResourceScope:    sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	})
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if result.PluginInstanceID != pluginInstanceID ||
		result.RevokeEpoch != revokeEpoch ||
		result.ClosedSocketCount != socket ||
		result.ClosedStreamCount != stream ||
		result.ClosedStorageHandleCount != storageHandle {
		t.Fatalf("Revoke() result mismatch: got %#v, want socket=%d stream=%d storage=%d", result, socket, stream, storageHandle)
	}
}

func findRepoRootForHostTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}
