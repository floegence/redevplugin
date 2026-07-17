package host

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

const (
	hostRuntimeProcessHelperEnv        = "REDEVPLUGIN_HOST_RUNTIME_PROCESS_HELPER"
	hostRuntimeProcessHandshakeTimeout = 15 * time.Second
)

type testProcessManager struct {
	*runtimeclient.ProcessSupervisor
}

func (m testProcessManager) BindHostServices(services runtimeclient.RuntimeHostServices) error {
	if services.StreamSink == nil {
		return runtimeclient.ErrRuntimeHostServicesInvalid
	}
	return nil
}

func (m testProcessManager) Start(ctx context.Context, target runtimeclient.Target) (runtimeclient.ManagerHealth, error) {
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
	return runtimeclient.ManagerHealth{Ready: health.Ready, Shards: []runtimeclient.ShardHealth{{RuntimeShardID: "runtime_shard_00", Health: health}}}, nil
}

func (m testProcessManager) BindPlugin(ctx context.Context, _ string) (runtimeclient.RuntimeBinding, error) {
	health, err := m.ProcessSupervisor.Health(ctx)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	return runtimeclient.RuntimeBinding{
		RuntimeShardID: "runtime_shard_00", RuntimeInstanceID: health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID, IPCChannelID: health.IPCChannelID,
		ConnectionNonce: health.ConnectionNonce,
	}, nil
}

func (m testProcessManager) InvokeWorker(ctx context.Context, _ runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	return m.ProcessSupervisor.InvokeWorker(ctx, lease, method, payload)
}

func TestMain(m *testing.M) {
	if os.Getenv(hostRuntimeProcessHelperEnv) == "1" {
		runHostRuntimeProcessHelper()
		return
	}
	os.Exit(m.Run())
}

func TestCallPluginMethodWorkerNetworkExecuteThroughRuntimeProcess(t *testing.T) {
	ctx := hostTestContext()
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus: http.StatusCreated,
		httpBody:   []byte(`{"ok":true,"source":"network-executor"}`),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		HandshakeTimeout:      5 * time.Second,
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), hostRuntimeProcessHelperEnv+"=1"),
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          broker,
		NetworkExecutor:       executor,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello from host"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	networkExecute, ok := data["network_execute"].(map[string]any)
	if !ok {
		t.Fatalf("network_execute result missing: %#v", data)
	}
	if networkExecute["ok"] != true ||
		networkExecute["status_code"] != float64(http.StatusCreated) ||
		networkExecute["connector_id"] != "api" ||
		networkExecute["runtime_generation_id"] == "" {
		t.Fatalf("network_execute result mismatch: %#v", networkExecute)
	}
	body, err := base64.StdEncoding.DecodeString(networkExecute["body_base64"].(string))
	if err != nil {
		t.Fatalf("decode body_base64: %v", err)
	}
	if string(body) != string(executor.httpBody) {
		t.Fatalf("network body = %s, want %s", body, executor.httpBody)
	}
	if executor.httpCalls != 1 ||
		executor.lastHTTP.Grant.PluginInstanceID != installed.PluginInstanceID ||
		executor.lastHTTP.Grant.ConnectorID != "api" ||
		executor.lastHTTP.Grant.Destination.Host != "api.example.com" ||
		executor.lastHTTP.Grant.RuntimeGenerationID == "" ||
		executor.lastHTTP.Method != http.MethodPost ||
		executor.lastHTTP.Path != "/v1/worker" ||
		string(executor.lastHTTP.Body) != "hello from host" {
		t.Fatalf("network executor call mismatch: calls=%d req=%#v", executor.httpCalls, executor.lastHTTP)
	}
}

func TestCallPluginMethodWorkerHTTPStreamThroughRuntimeProcess(t *testing.T) {
	ctx := hostTestContext()
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus:   http.StatusAccepted,
		streamChunks: [][]byte{[]byte("line 1\n"), []byte("line 2\n")},
	}
	var manager *runtimeclient.ProcessManager
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: broker,
		networkExecutor:    executor,
		runtimeManagerFactory: func(deps testRuntimeManagerDependencies) (runtimeclient.Manager, error) {
			var err error
			manager, err = runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
				ShardCount: 1,
				Supervisor: runtimeclient.ProcessSupervisorOptions{
					Limits:                runtimeclient.DefaultRuntimeLimits(),
					HandshakeTimeout:      5 * time.Second,
					HeartbeatInterval:     2 * time.Second,
					MaxHeartbeatStaleness: 5 * time.Second,
					RuntimePath:           os.Args[0],
					Args:                  []string{"-test.run=TestMain"},
					Env:                   append(os.Environ(), hostRuntimeProcessHelperEnv+"=1", "REDEVPLUGIN_HOST_RUNTIME_HTTP_STREAM=1"),
					Diagnostics:           deps.Diagnostics,
					Artifacts:             runtimeArtifactProvider{assets: deps.Assets},
					HandleGrants:          runtimeHandleGrantValidator{tokens: deps.SurfaceTokens},
					StorageFiles:          deps.PluginData,
					StorageKV:             deps.PluginData,
					Connectivity:          deps.Connectivity,
					NetworkExecutor:       deps.NetworkExecutor,
				},
			})
			return manager, err
		},
	})
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
		defer cancel()
		if err := h.StopRuntime(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if manager == nil {
		t.Fatal("runtime manager factory did not return the process manager")
	}
	if _, err := h.StartRuntime(ctx, StartRuntimeRequest{Target: RuntimeTarget{OS: "test-os", Arch: "test-arch"}}); err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkSubscriptionFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "stream from host"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.StreamID == "" || result.StreamTicket == "" || result.StreamTicketID == "" {
		t.Fatalf("stream result missing ticket/id: %#v", result)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	networkExecute, ok := data["network_execute"].(map[string]any)
	if !ok {
		t.Fatalf("network_execute result missing: %#v", data)
	}
	if networkExecute["ok"] != true ||
		networkExecute["status_code"] != float64(http.StatusAccepted) ||
		networkExecute["stream_id"] != result.StreamID ||
		networkExecute["bytes_read"] != float64(len("line 1\nline 2\n")) ||
		networkExecute["chunk_count"] != float64(2) {
		t.Fatalf("stream network_execute result mismatch: %#v", networkExecute)
	}
	streamResult, err := h.ReadStream(ctx, scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Status != stream.StatusClosed ||
		streamResult.Record.SurfaceInstanceID != "surface_rpc" ||
		streamResult.Record.OwnerSessionHash != "session_hash" ||
		streamResult.Record.OwnerUserHash != "user_hash" ||
		streamResult.Record.OwnerEnvHash != "env_hash" ||
		streamResult.Record.SessionChannelIDHash != "channel_hash" ||
		streamResult.Record.BridgeChannelID != "bridge_rpc" {
		t.Fatalf("stream record mismatch: %#v", streamResult.Record)
	}
	if len(streamResult.Events) != 2 ||
		string(streamResult.Events[0].Data) != "line 1\n" ||
		string(streamResult.Events[1].Data) != "line 2\n" {
		t.Fatalf("stream events mismatch: %#v", streamResult.Events)
	}
	if executor.streamCalls != 1 ||
		executor.lastStreamHTTP.Grant.PluginInstanceID != installed.PluginInstanceID ||
		executor.lastStreamHTTP.Path != "/v1/worker" ||
		executor.lastStreamHTTP.MaxChunkBytes != 4 {
		t.Fatalf("stream executor call mismatch: calls=%d req=%#v", executor.streamCalls, executor.lastStreamHTTP)
	}
}

func TestCallPluginMethodWorkerHTTPStreamMemoryHostcallThroughBuiltRustRuntime(t *testing.T) {
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
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus:   http.StatusAccepted,
		streamChunks: [][]byte{[]byte("line 1\n"), []byte("line 2\n")},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          broker,
		NetworkExecutor:       executor,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkSubscriptionMemoryHostcallFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with stream memory hostcall error = %v", err)
	}
	if result.StreamID == "" || result.StreamTicket == "" || result.StreamTicketID == "" {
		t.Fatalf("stream result missing ticket/id: %#v", result)
	}
	streamResult, err := h.ReadStream(ctx, scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Status != stream.StatusClosed {
		t.Fatalf("stream status = %q, want %q", streamResult.Record.Status, stream.StatusClosed)
	}
	if len(streamResult.Events) != 2 ||
		string(streamResult.Events[0].Data) != "line 1\n" ||
		string(streamResult.Events[1].Data) != "line 2\n" {
		t.Fatalf("stream events mismatch: %#v", streamResult.Events)
	}
	if executor.streamCalls != 1 || executor.lastStreamHTTP.Path != "/v1/worker" {
		t.Fatalf("stream executor call mismatch: calls=%d req=%#v", executor.streamCalls, executor.lastStreamHTTP)
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
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          h.adapters.Connectivity,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

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
}

func TestCallPluginMethodWorkerNetworkMemoryHostcallThroughBuiltRustRuntime(t *testing.T) {
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
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus: http.StatusAccepted,
		httpBody:   []byte(`{"ok":true,"source":"memory-hostcall"}`),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          broker,
		NetworkExecutor:       executor,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkMemoryHostcallFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with network memory hostcall error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	networkExecute, ok := data["network_execute"].(map[string]any)
	if !ok {
		t.Fatalf("network_execute result missing: %#v", data)
	}
	if networkExecute["ok"] != true ||
		networkExecute["status_code"] != float64(http.StatusAccepted) ||
		networkExecute["connector_id"] != "api" ||
		networkExecute["transport"] != "http" {
		t.Fatalf("network_execute result mismatch: %#v", networkExecute)
	}
	if executor.httpCalls != 1 ||
		executor.lastHTTP.Grant.PluginInstanceID != installed.PluginInstanceID ||
		executor.lastHTTP.Grant.ConnectorID != "api" ||
		executor.lastHTTP.Grant.Destination.Host != "api.example.com" ||
		executor.lastHTTP.Grant.RuntimeGenerationID == "" ||
		executor.lastHTTP.Method != http.MethodPost ||
		executor.lastHTTP.Path != "/v1/worker" ||
		string(executor.lastHTTP.Body) != "hello from memory hostcall" {
		t.Fatalf("network memory executor call mismatch: calls=%d req=%#v", executor.httpCalls, executor.lastHTTP)
	}
	assertRuntimeRevokeCounts(t, supervisor, installed.PluginInstanceID, installed.RevokeEpoch+1, 0, 0, 0)
}

func TestCallPluginMethodWorkerNetworkSocketMemoryHostcallsThroughBuiltRustRuntime(t *testing.T) {
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

	cases := []struct {
		name          string
		transport     connectivity.Transport
		response      func(*recordingHostNetworkExecutor)
		assertRequest func(*testing.T, *recordingHostNetworkExecutor, string)
		assertResult  func(*testing.T, map[string]any)
	}{
		{
			name:      "websocket",
			transport: connectivity.TransportWebSocket,
			response: func(executor *recordingHostNetworkExecutor) {
				executor.wsResponse = connectivity.WebSocketRoundTripResponse{MessageType: connectivity.WebSocketMessageText, Payload: []byte("websocket:pong")}
			},
			assertRequest: func(t *testing.T, executor *recordingHostNetworkExecutor, pluginInstanceID string) {
				t.Helper()
				if executor.websocketCalls != 1 ||
					executor.lastWebSocket.Grant.PluginInstanceID != pluginInstanceID ||
					executor.lastWebSocket.Grant.ConnectorID != "stream" ||
					executor.lastWebSocket.Grant.Destination.Host != "stream.example.com" ||
					executor.lastWebSocket.Grant.RuntimeGenerationID == "" ||
					executor.lastWebSocket.MessageType != connectivity.WebSocketMessageText ||
					string(executor.lastWebSocket.Payload) != "hello websocket" ||
					executor.lastWebSocket.MaxRequestBytes != 1024 ||
					executor.lastWebSocket.MaxResponseBytes != 4096 ||
					executor.lastWebSocket.Timeout != time.Second {
					t.Fatalf("websocket executor call mismatch: calls=%d req=%#v", executor.websocketCalls, executor.lastWebSocket)
				}
			},
			assertResult: func(t *testing.T, networkExecute map[string]any) {
				t.Helper()
				if networkExecute["ok"] != true ||
					networkExecute["connector_id"] != "stream" ||
					networkExecute["transport"] != "websocket" ||
					networkExecute["message_type"] != "text" ||
					networkExecute["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("websocket:pong")) {
					t.Fatalf("websocket network_execute result mismatch: %#v", networkExecute)
				}
			},
		},
		{
			name:      "tcp",
			transport: connectivity.TransportTCP,
			response: func(executor *recordingHostNetworkExecutor) {
				executor.tcpResponse = connectivity.TCPRoundTripResponse{Payload: []byte("tcp:pong")}
			},
			assertRequest: func(t *testing.T, executor *recordingHostNetworkExecutor, pluginInstanceID string) {
				t.Helper()
				if executor.tcpCalls != 1 ||
					executor.lastTCP.Grant.PluginInstanceID != pluginInstanceID ||
					executor.lastTCP.Grant.ConnectorID != "mysql" ||
					executor.lastTCP.Grant.Destination.Host != "db.example.com" ||
					executor.lastTCP.Grant.Destination.Port != 3306 ||
					executor.lastTCP.Grant.RuntimeGenerationID == "" ||
					string(executor.lastTCP.Payload) != "hello tcp" ||
					executor.lastTCP.MaxRequestBytes != 1024 ||
					executor.lastTCP.MaxReadBytes != 4096 ||
					executor.lastTCP.Timeout != time.Second {
					t.Fatalf("tcp executor call mismatch: calls=%d req=%#v", executor.tcpCalls, executor.lastTCP)
				}
			},
			assertResult: func(t *testing.T, networkExecute map[string]any) {
				t.Helper()
				if networkExecute["ok"] != true ||
					networkExecute["connector_id"] != "mysql" ||
					networkExecute["transport"] != "tcp" ||
					networkExecute["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("tcp:pong")) {
					t.Fatalf("tcp network_execute result mismatch: %#v", networkExecute)
				}
			},
		},
		{
			name:      "udp",
			transport: connectivity.TransportUDP,
			response: func(executor *recordingHostNetworkExecutor) {
				executor.udpResponse = connectivity.UDPRoundTripResponse{Payload: []byte("udp:pong")}
			},
			assertRequest: func(t *testing.T, executor *recordingHostNetworkExecutor, pluginInstanceID string) {
				t.Helper()
				if executor.udpCalls != 1 ||
					executor.lastUDP.Grant.PluginInstanceID != pluginInstanceID ||
					executor.lastUDP.Grant.ConnectorID != "metrics" ||
					executor.lastUDP.Grant.Destination.Host != "metrics.example.com" ||
					executor.lastUDP.Grant.Destination.Port != 8125 ||
					executor.lastUDP.Grant.RuntimeGenerationID == "" ||
					string(executor.lastUDP.Payload) != "hello udp" ||
					executor.lastUDP.MaxReadBytes != 4096 ||
					executor.lastUDP.Timeout != time.Second {
					t.Fatalf("udp executor call mismatch: calls=%d req=%#v", executor.udpCalls, executor.lastUDP)
				}
			},
			assertResult: func(t *testing.T, networkExecute map[string]any) {
				t.Helper()
				if networkExecute["ok"] != true ||
					networkExecute["connector_id"] != "metrics" ||
					networkExecute["transport"] != "udp" ||
					networkExecute["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("udp:pong")) {
					t.Fatalf("udp network_execute result mismatch: %#v", networkExecute)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := hostTestContext()
			broker := connectivity.NewMemoryBroker()
			executor := &recordingHostNetworkExecutor{}
			tc.response(executor)
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:      true,
				localGenerated:     true,
				connectivityBroker: broker,
				networkExecutor:    executor,
			})
			supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
				Limits:                runtimeclient.DefaultRuntimeLimits(),
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
				RuntimePath:           runtimePath,
				Diagnostics:           h.adapters.Diagnostics,
				Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
				HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
				StorageFiles:          h.adapters.PluginData,
				StorageKV:             h.adapters.PluginData,
				Connectivity:          broker,
				NetworkExecutor:       executor,
				StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
			if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkTransportMemoryHostcallFixturePackage(t, tc.transport), "worker.view")

			result, err := h.CallPluginMethod(ctx, CallMethodRequest{
				PluginInstanceID:  installed.PluginInstanceID,
				SurfaceInstanceID: "surface_rpc",

				BridgeChannelID: "bridge_rpc",
				GatewayToken:    gateway.GatewayToken,
				Method:          "worker.echo",
				Params:          map[string]any{},
			})
			if err != nil {
				t.Fatalf("CallPluginMethod() with %s network memory hostcall error = %v", tc.name, err)
			}
			data, ok := result.Data.(map[string]any)
			if !ok {
				t.Fatalf("worker result data = %#v, want map", result.Data)
			}
			networkExecute, ok := data["network_execute"].(map[string]any)
			if !ok {
				t.Fatalf("network_execute result missing: %#v", data)
			}
			tc.assertResult(t, networkExecute)
			tc.assertRequest(t, executor, installed.PluginInstanceID)
		})
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

	ctx := hostTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          h.adapters.Connectivity,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
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
	storageFile, ok := data["storage_file"].(map[string]any)
	if !ok {
		t.Fatalf("storage_file result missing: %#v", data)
	}
	if storageFile["ok"] != true || storageFile["path"] != "notes/from-memory.txt" || storageFile["size_bytes"] != float64(len(body)) {
		t.Fatalf("storage_file result mismatch: %#v", storageFile)
	}
	read, err := h.adapters.PluginData.ReadFile(ctx, storage.FileReadRequest{
		PluginInstanceID: installed.PluginInstanceID,
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

	ctx := hostTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		Connectivity:          h.adapters.Connectivity,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
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
	storageKV, ok := data["storage_kv"].(map[string]any)
	if !ok {
		t.Fatalf("storage_kv result missing: %#v", data)
	}
	if storageKV["ok"] != true || storageKV["key"] != "runs/latest" || storageKV["size_bytes"] != float64(len(body)) {
		t.Fatalf("storage_kv result mismatch: %#v", storageKV)
	}
	read, err := h.adapters.PluginData.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: installed.PluginInstanceID,
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

	ctx := hostTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits:                runtimeclient.DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           runtimePath,
		Diagnostics:           h.adapters.Diagnostics,
		Artifacts:             runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:          runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:          h.adapters.PluginData,
		StorageKV:             h.adapters.PluginData,
		StorageSQLite:         h.adapters.PluginData,
		Connectivity:          h.adapters.Connectivity,
		StreamSink:            hostRuntimeStreamSink{executions: h.executions},
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
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
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
	storageSQLite, ok := data["storage_sqlite"].(map[string]any)
	if !ok {
		t.Fatalf("storage_sqlite result missing: %#v", data)
	}
	if storageSQLite["ok"] != true || storageSQLite["database"] != "plugin.sqlite" {
		t.Fatalf("storage_sqlite result mismatch: %#v", storageSQLite)
	}
	if storageSQLite["rows_affected"] != float64(0) {
		t.Fatalf("storage_sqlite rows_affected = %#v, want 0", storageSQLite["rows_affected"])
	}
	tableName := "worker_runs"
	query, err := h.adapters.PluginData.QuerySQLite(ctx, storage.SQLiteQueryRequest{
		PluginInstanceID: installed.PluginInstanceID,
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

type runtimeRevoker interface {
	Revoke(context.Context, string, uint64) (runtimeclient.RevokeResult, error)
}

func assertRuntimeRevokeCounts(t *testing.T, supervisor runtimeRevoker, pluginInstanceID string, revokeEpoch uint64, socket, stream, storageHandle int) {
	t.Helper()
	revokeCtx, cancel := context.WithTimeout(hostTestContext(), 3*time.Second)
	defer cancel()
	result, err := supervisor.Revoke(revokeCtx, pluginInstanceID, revokeEpoch)
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

type hostRuntimeIPCFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	ParentRequestID     string          `json:"parent_request_id,omitempty"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type hostRuntimeHelloAckPayload struct {
	RuntimeVersion string                      `json:"runtime_version"`
	RustIPCVersion string                      `json:"rust_ipc_version"`
	WASMABIVersion string                      `json:"wasm_abi_version"`
	ChannelNonce   string                      `json:"channel_nonce"`
	Limits         runtimeclient.RuntimeLimits `json:"limits"`
}

type hostRuntimeHelloPayload struct {
	ChannelNonce string                      `json:"channel_nonce"`
	Limits       runtimeclient.RuntimeLimits `json:"limits"`
}

type hostRuntimeResponsePayload struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Code        string          `json:"code,omitempty"`
	Message     string          `json:"message,omitempty"`
	ErrorOrigin string          `json:"error_origin,omitempty"`
}

type hostRuntimeRevokePayload struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	RevokeEpoch      uint64 `json:"revoke_epoch"`
}

type hostRuntimeHeartbeatPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type hostRuntimeInvokePayload struct {
	Lease      runtimeclient.Lease     `json:"lease"`
	Method     string                  `json:"method"`
	Invocation workerInvocationPayload `json:"invocation"`
}

type hostRuntimeNetworkExecuteRequest struct {
	PluginID             string                 `json:"plugin_id,omitempty"`
	PluginInstanceID     string                 `json:"plugin_instance_id"`
	ActiveFingerprint    string                 `json:"active_fingerprint"`
	RuntimeInstanceID    string                 `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID  string                 `json:"runtime_generation_id"`
	RuntimeShardID       string                 `json:"runtime_shard_id,omitempty"`
	PolicyRevision       uint64                 `json:"policy_revision"`
	ManagementRevision   uint64                 `json:"management_revision"`
	RevokeEpoch          uint64                 `json:"revoke_epoch"`
	ConnectorID          string                 `json:"connector_id"`
	Transport            connectivity.Transport `json:"transport"`
	Destination          string                 `json:"destination"`
	TTLMillis            int64                  `json:"ttl_ms,omitempty"`
	Operation            string                 `json:"operation,omitempty"`
	Method               string                 `json:"method,omitempty"`
	Path                 string                 `json:"path,omitempty"`
	Headers              http.Header            `json:"headers,omitempty"`
	BodyBase64           string                 `json:"body_base64,omitempty"`
	MaxChunkBytes        int64                  `json:"max_chunk_bytes,omitempty"`
	MaxBufferedBytes     int64                  `json:"max_buffered_bytes,omitempty"`
	MaxRequestBytes      int64                  `json:"max_request_bytes,omitempty"`
	MaxResponseBytes     int64                  `json:"max_response_bytes,omitempty"`
	TimeoutMillis        int64                  `json:"timeout_ms,omitempty"`
	StreamID             string                 `json:"stream_id,omitempty"`
	StreamMethod         string                 `json:"stream_method,omitempty"`
	StreamEffect         string                 `json:"stream_effect,omitempty"`
	StreamExecution      string                 `json:"stream_execution,omitempty"`
	SurfaceInstanceID    string                 `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string                 `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string                 `json:"owner_user_hash,omitempty"`
	OwnerEnvHash         string                 `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash string                 `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string                 `json:"bridge_channel_id,omitempty"`
	ContentType          string                 `json:"content_type,omitempty"`
}

type hostRuntimeNetworkExecuteResponse struct {
	OK          bool   `json:"ok"`
	Code        string `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
	ErrorOrigin string `json:"error_origin,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	StreamID    string `json:"stream_id,omitempty"`
}

func runHostRuntimeProcessHelper() {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	var controlStarted bool
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var frame hostRuntimeIPCFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			os.Exit(20)
		}
		switch frame.FrameType {
		case "hello":
			var hello hostRuntimeHelloPayload
			if err := json.Unmarshal(frame.Payload, &hello); err != nil || hello.ChannelNonce == "" {
				os.Exit(21)
			}
			raw, _ := json.Marshal(hostRuntimeHelloAckPayload{
				RuntimeVersion: version.RuntimeVersion,
				RustIPCVersion: version.RustIPCVersion,
				WASMABIVersion: version.WASMABIVersion,
				ChannelNonce:   hello.ChannelNonce,
				Limits:         hello.Limits,
			})
			_ = encoder.Encode(hostRuntimeIPCFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           "hello_ack",
				RequestID:           frame.RequestID,
				RuntimeGenerationID: frame.RuntimeGenerationID,
				Payload:             raw,
			})
			if !controlStarted {
				controlStarted = true
				go runHostRuntimeControlHelper(hello.Limits)
			}
		case "invoke_worker":
			hostRuntimeProcessNetworkExecute(reader, encoder, frame)
		default:
			os.Exit(21)
		}
	}
}

func runHostRuntimeControlHelper(limits runtimeclient.RuntimeLimits) {
	readFD, readErr := strconv.Atoi(os.Getenv("REDEVPLUGIN_CONTROL_READ_FD"))
	writeFD, writeErr := strconv.Atoi(os.Getenv("REDEVPLUGIN_CONTROL_WRITE_FD"))
	if readErr != nil || writeErr != nil || readFD < 3 || writeFD < 3 {
		os.Exit(31)
	}
	readFile := os.NewFile(uintptr(readFD), "redevplugin-control-read")
	writeFile := os.NewFile(uintptr(writeFD), "redevplugin-control-write")
	if readFile == nil || writeFile == nil {
		os.Exit(32)
	}
	reader := bufio.NewReader(readFile)
	encoder := json.NewEncoder(writeFile)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var frame hostRuntimeIPCFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			os.Exit(33)
		}
		switch frame.FrameType {
		case "heartbeat":
			var heartbeat hostRuntimeHeartbeatPayload
			_ = json.Unmarshal(frame.Payload, &heartbeat)
			result, _ := json.Marshal(map[string]any{
				"runtime_generation_id": frame.RuntimeGenerationID,
				"runtime_unix_nano":     time.Now().UnixNano(),
				"max_staleness_ms":      heartbeat.MaxStalenessMillis,
				"host_sent_unix_nano":   heartbeat.SentUnixNano,
				"active_invocations":    0,
				"queued_invocations":    0,
				"limits":                limits,
				"module_cache":          runtimeclient.ModuleCacheMetrics{},
			})
			raw, _ := json.Marshal(hostRuntimeResponsePayload{OK: true, Result: result})
			_ = encoder.Encode(hostRuntimeIPCFrame{IPCVersion: version.RustIPCVersion, FrameType: "heartbeat", RequestID: frame.RequestID, RuntimeGenerationID: frame.RuntimeGenerationID, Payload: raw})
		case "revoke_epoch":
			var revoke hostRuntimeRevokePayload
			_ = json.Unmarshal(frame.Payload, &revoke)
			result, _ := json.Marshal(map[string]any{
				"plugin_instance_id":          revoke.PluginInstanceID,
				"revoke_epoch":                revoke.RevokeEpoch,
				"closed_socket_count":         0,
				"closed_stream_count":         0,
				"closed_storage_handle_count": 0,
			})
			raw, _ := json.Marshal(hostRuntimeResponsePayload{OK: true, Result: result})
			_ = encoder.Encode(hostRuntimeIPCFrame{IPCVersion: version.RustIPCVersion, FrameType: "revoke_epoch_ack", RequestID: frame.RequestID, RuntimeGenerationID: frame.RuntimeGenerationID, Payload: raw})
		default:
			os.Exit(34)
		}
	}
}

func hostRuntimeProcessNetworkExecute(reader *bufio.Reader, encoder *json.Encoder, frame hostRuntimeIPCFrame) {
	var invoke hostRuntimeInvokePayload
	if err := json.Unmarshal(frame.Payload, &invoke); err != nil {
		os.Exit(22)
	}
	message, _ := invoke.Invocation.Params["message"].(string)
	body := base64.StdEncoding.EncodeToString([]byte(message))
	operation := "http"
	if os.Getenv("REDEVPLUGIN_HOST_RUNTIME_HTTP_STREAM") == "1" {
		operation = "http_stream"
	}
	request := hostRuntimeNetworkExecuteRequest{
		PluginID:             invoke.Invocation.PluginID,
		PluginInstanceID:     invoke.Lease.PluginInstanceID,
		ActiveFingerprint:    invoke.Invocation.ActiveFingerprint,
		RuntimeInstanceID:    invoke.Lease.RuntimeInstanceID,
		RuntimeGenerationID:  invoke.Lease.RuntimeGenerationID,
		RuntimeShardID:       invoke.Lease.RuntimeShardID,
		PolicyRevision:       invoke.Lease.PolicyRevision,
		ManagementRevision:   invoke.Lease.ManagementRevision,
		RevokeEpoch:          invoke.Lease.RevokeEpoch,
		OwnerSessionHash:     invoke.Lease.OwnerSessionHash,
		OwnerUserHash:        invoke.Lease.OwnerUserHash,
		OwnerEnvHash:         invoke.Lease.OwnerEnvHash,
		SessionChannelIDHash: invoke.Lease.SessionChannelIDHash,
		ConnectorID:          "api",
		Transport:            connectivity.TransportHTTP,
		Destination:          "https://api.example.com",
		TTLMillis:            int64(time.Minute / time.Millisecond),
		Operation:            operation,
		Method:               http.MethodPost,
		Path:                 "/v1/worker",
		Headers:              http.Header{"Content-Type": []string{"text/plain"}},
		BodyBase64:           body,
		MaxRequestBytes:      1024,
		MaxResponseBytes:     4096,
		TimeoutMillis:        1000,
	}
	if operation == "http_stream" {
		request.StreamID = invoke.Invocation.StreamID
		request.MaxChunkBytes = 4
		request.MaxBufferedBytes = 64 * 1024
		request.StreamMethod = invoke.Invocation.Method
		request.StreamEffect = invoke.Invocation.Effect
		request.StreamExecution = invoke.Invocation.Execution
		request.SurfaceInstanceID = invoke.Invocation.SurfaceInstanceID
		request.OwnerSessionHash = invoke.Invocation.OwnerSessionHash
		request.OwnerUserHash = invoke.Invocation.OwnerUserHash
		request.OwnerEnvHash = invoke.Invocation.OwnerEnvHash
		request.SessionChannelIDHash = invoke.Invocation.SessionChannelIDHash
		request.BridgeChannelID = invoke.Invocation.BridgeChannelID
		request.ContentType = "text/plain"
	}
	rawRequest, _ := json.Marshal(request)
	networkRequestID := frame.RequestID + ":network_execute"
	_ = encoder.Encode(hostRuntimeIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           "network_execute",
		RequestID:           networkRequestID,
		ParentRequestID:     frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload:             rawRequest,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(23)
	}
	var networkResponseFrame hostRuntimeIPCFrame
	if err := json.Unmarshal(line, &networkResponseFrame); err != nil {
		os.Exit(24)
	}
	if networkResponseFrame.FrameType != "network_execute" || networkResponseFrame.RequestID != networkRequestID {
		os.Exit(25)
	}
	var networkResponse hostRuntimeNetworkExecuteResponse
	if err := json.Unmarshal(networkResponseFrame.Payload, &networkResponse); err != nil {
		os.Exit(26)
	}
	if !networkResponse.OK {
		raw, _ := json.Marshal(hostRuntimeResponsePayload{
			OK: false, Code: networkResponse.Code, Message: networkResponse.Message, ErrorOrigin: networkResponse.ErrorOrigin,
		})
		_ = encoder.Encode(hostRuntimeIPCFrame{
			IPCVersion:          version.RustIPCVersion,
			FrameType:           "invoke_worker_result",
			RequestID:           frame.RequestID,
			RuntimeGenerationID: frame.RuntimeGenerationID,
			Payload:             raw,
		})
		return
	}
	result := map[string]any{
		"data": map[string]any{
			"network_execute": mustHostRuntimeMap(networkResponseFrame.Payload),
		},
	}
	if networkResponse.StreamID != "" {
		result["stream_id"] = networkResponse.StreamID
	}
	raw, _ := json.Marshal(hostRuntimeResponsePayload{
		OK:     true,
		Result: mustHostRuntimeRaw(result),
	})
	_ = encoder.Encode(hostRuntimeIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           "invoke_worker_result",
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload:             raw,
	})
}

func mustHostRuntimeMap(raw json.RawMessage) map[string]any {
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		os.Exit(27)
	}
	return decoded
}

func mustHostRuntimeRaw(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		os.Exit(28)
	}
	return raw
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
