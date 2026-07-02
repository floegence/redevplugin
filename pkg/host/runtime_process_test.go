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
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/version"
)

const hostRuntimeProcessHelperEnv = "REDEVPLUGIN_HOST_RUNTIME_PROCESS_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(hostRuntimeProcessHelperEnv) == "1" {
		runHostRuntimeProcessHelper()
		return
	}
	os.Exit(m.Run())
}

func TestCallPluginMethodWorkerNetworkExecuteThroughRuntimeProcess(t *testing.T) {
	ctx := context.Background()
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus: http.StatusCreated,
		httpBody:   []byte(`{"ok":true,"source":"network-executor"}`),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:     os.Args[0],
		Args:            []string{"-test.run=TestMain"},
		Env:             append(os.Environ(), hostRuntimeProcessHelperEnv+"=1"),
		Diagnostics:     h.adapters.Diagnostics,
		Artifacts:       runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:    runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:    storageFilesBroker(h.adapters.Storage),
		StorageKV:       storageKVBroker(h.adapters.Storage),
		Connectivity:    broker,
		NetworkExecutor: executor,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkFixturePackage(t), "worker.activity")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "hello from host"},
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

	ctx := context.Background()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storage.NewMemoryBroker(),
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:  runtimePath,
		Diagnostics:  h.adapters.Diagnostics,
		Artifacts:    runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants: runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles: storageFilesBroker(h.adapters.Storage),
		StorageKV:    storageKVBroker(h.adapters.Storage),
		Connectivity: h.adapters.Connectivity,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "hello from rust runtime"},
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

func TestCallPluginMethodWorkerNetworkHostcallThroughBuiltRustRuntime(t *testing.T) {
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

	ctx := context.Background()
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus: http.StatusAccepted,
		httpBody:   []byte(`{"ok":true,"source":"rust-runtime"}`),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:      runtimePath,
		Diagnostics:      h.adapters.Diagnostics,
		Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:     storageFilesBroker(h.adapters.Storage),
		StorageKV:        storageKVBroker(h.adapters.Storage),
		Connectivity:     broker,
		NetworkExecutor:  executor,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkHostcallFixturePackage(t), "worker.activity")
	body := []byte("hello from wasm network hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params: map[string]any{
			"network_body_base64": base64.StdEncoding.EncodeToString(body),
		},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with network hostcall error = %v", err)
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
		string(executor.lastHTTP.Body) != string(body) {
		t.Fatalf("network executor call mismatch: calls=%d req=%#v", executor.httpCalls, executor.lastHTTP)
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

	ctx := context.Background()
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{
		httpStatus: http.StatusAccepted,
		httpBody:   []byte(`{"ok":true,"source":"memory-hostcall"}`),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: broker,
		networkExecutor:    executor,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:      runtimePath,
		Diagnostics:      h.adapters.Diagnostics,
		Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:     storageFilesBroker(h.adapters.Storage),
		StorageKV:        storageKVBroker(h.adapters.Storage),
		Connectivity:     broker,
		NetworkExecutor:  executor,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkMemoryHostcallFixturePackage(t), "worker.activity")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{},
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
			ctx := context.Background()
			broker := connectivity.NewMemoryBroker()
			executor := &recordingHostNetworkExecutor{}
			tc.response(executor)
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:      true,
				localGenerated:     true,
				storageBroker:      storage.NewMemoryBroker(),
				connectivityBroker: broker,
				networkExecutor:    executor,
			})
			supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
				RuntimePath:      runtimePath,
				Diagnostics:      h.adapters.Diagnostics,
				Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
				HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
				StorageFiles:     storageFilesBroker(h.adapters.Storage),
				StorageKV:        storageKVBroker(h.adapters.Storage),
				Connectivity:     broker,
				NetworkExecutor:  executor,
				HandshakeTimeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			h.adapters.RuntimeSupervisor = supervisor
			t.Cleanup(func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := supervisor.Stop(stopCtx); err != nil {
					t.Errorf("Stop() error = %v", err)
				}
			})
			if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			installed, gateway := installEnableAndMintGateway(t, h, buildWorkerNetworkTransportMemoryHostcallFixturePackage(t, tc.transport), "worker.activity")

			result, err := h.CallPluginMethod(ctx, CallMethodRequest{
				PluginInstanceID:     installed.PluginInstanceID,
				SurfaceInstanceID:    "surface_rpc",
				SessionChannelIDHash: "channel_hash",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				BridgeChannelID:      "bridge_rpc",
				GatewayToken:         gateway.GatewayToken,
				Method:               "worker.echo",
				Params:               map[string]any{},
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

func TestCallPluginMethodWorkerStorageHostcallThroughBuiltRustRuntime(t *testing.T) {
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

	ctx := context.Background()
	storageBroker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storageBroker,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:  runtimePath,
		Diagnostics:  h.adapters.Diagnostics,
		Artifacts:    runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants: runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles: storageFilesBroker(h.adapters.Storage),
		StorageKV:    storageKVBroker(h.adapters.Storage),
		Connectivity: h.adapters.Connectivity,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageFixturePackage(t), "worker.activity")
	storageGrant, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "workspace",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	body := []byte("hello from wasm storage hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params: map[string]any{
			"storage_handle_grant_token": storageGrant.HandleGrant.HandleGrantToken,
			"storage_store_id":           "workspace",
			"storage_path":               "notes/from-wasm.txt",
			"storage_data_base64":        base64.StdEncoding.EncodeToString(body),
		},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with storage hostcall error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	storageFile, ok := data["storage_file"].(map[string]any)
	if !ok {
		t.Fatalf("storage_file result missing: %#v", data)
	}
	if storageFile["ok"] != true || storageFile["path"] != "notes/from-wasm.txt" || storageFile["size_bytes"] != float64(len(body)) {
		t.Fatalf("storage_file result mismatch: %#v", storageFile)
	}
	read, err := storageBroker.ReadFile(ctx, storage.FileReadRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/from-wasm.txt",
	})
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(read.Data) != string(body) {
		t.Fatalf("stored file = %q, want %q", read.Data, body)
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

	ctx := context.Background()
	storageBroker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storageBroker,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:      runtimePath,
		Diagnostics:      h.adapters.Diagnostics,
		Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:     storageFilesBroker(h.adapters.Storage),
		StorageKV:        storageKVBroker(h.adapters.Storage),
		Connectivity:     h.adapters.Connectivity,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageMemoryHostcallFixturePackage(t), "worker.activity")
	storageGrant, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "workspace",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	body := []byte("hello from memory storage hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params: map[string]any{
			"storage_handle_grant_token": storageGrant.HandleGrant.HandleGrantToken,
		},
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
	read, err := storageBroker.ReadFile(ctx, storage.FileReadRequest{
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

	ctx := context.Background()
	storageBroker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storageBroker,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:      runtimePath,
		Diagnostics:      h.adapters.Diagnostics,
		Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:     storageFilesBroker(h.adapters.Storage),
		StorageKV:        storageKVBroker(h.adapters.Storage),
		Connectivity:     h.adapters.Connectivity,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageKVMemoryHostcallFixturePackage(t), "worker.activity")
	storageGrant, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "cache",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	body := []byte("hello from memory kv hostcall")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params: map[string]any{
			"storage_kv_handle_grant_token": storageGrant.HandleGrant.HandleGrantToken,
		},
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
	read, err := storageBroker.GetKV(ctx, storage.KVGetRequest{
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

	ctx := context.Background()
	storageBroker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storageBroker,
	})
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:      runtimePath,
		Diagnostics:      h.adapters.Diagnostics,
		Artifacts:        runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:     runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:     storageFilesBroker(h.adapters.Storage),
		StorageKV:        storageKVBroker(h.adapters.Storage),
		StorageSQLite:    storageSQLiteBroker(h.adapters.Storage),
		Connectivity:     h.adapters.Connectivity,
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeSupervisor = supervisor
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageSQLiteMemoryHostcallFixturePackage(t), "worker.activity")
	storageGrant, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params: map[string]any{
			"storage_sqlite_handle_grant_token": storageGrant.HandleGrant.HandleGrantToken,
		},
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
	tableName := "worker_runs"
	query, err := storageBroker.QuerySQLite(ctx, storage.SQLiteQueryRequest{
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
}

type hostRuntimeIPCFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type hostRuntimeHelloAckPayload struct {
	RuntimeVersion string `json:"runtime_version"`
	RustIPCVersion string `json:"rust_ipc_version"`
	WASMABIVersion string `json:"wasm_abi_version"`
	ChannelNonce   string `json:"channel_nonce"`
}

type hostRuntimeHelloPayload struct {
	ChannelNonce string `json:"channel_nonce"`
}

type hostRuntimeResponsePayload struct {
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Code    string          `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
}

type hostRuntimeInvokePayload struct {
	Lease      runtimeclient.Lease     `json:"lease"`
	Method     string                  `json:"method"`
	Invocation WorkerInvocationPayload `json:"invocation"`
}

type hostRuntimeNetworkExecuteRequest struct {
	PluginInstanceID    string                 `json:"plugin_instance_id"`
	ActiveFingerprint   string                 `json:"active_fingerprint"`
	RuntimeInstanceID   string                 `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string                 `json:"runtime_generation_id"`
	RuntimeShardID      string                 `json:"runtime_shard_id,omitempty"`
	PolicyRevision      uint64                 `json:"policy_revision"`
	ManagementRevision  uint64                 `json:"management_revision"`
	RevokeEpoch         uint64                 `json:"revoke_epoch"`
	ConnectorID         string                 `json:"connector_id"`
	Transport           connectivity.Transport `json:"transport"`
	Destination         string                 `json:"destination"`
	TTLMillis           int64                  `json:"ttl_ms,omitempty"`
	Operation           string                 `json:"operation,omitempty"`
	Method              string                 `json:"method,omitempty"`
	Path                string                 `json:"path,omitempty"`
	Headers             http.Header            `json:"headers,omitempty"`
	BodyBase64          string                 `json:"body_base64,omitempty"`
	MaxRequestBytes     int64                  `json:"max_request_bytes,omitempty"`
	MaxResponseBytes    int64                  `json:"max_response_bytes,omitempty"`
	TimeoutMillis       int64                  `json:"timeout_ms,omitempty"`
}

type hostRuntimeNetworkExecuteResponse struct {
	OK         bool   `json:"ok"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

func runHostRuntimeProcessHelper() {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
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
			})
			_ = encoder.Encode(hostRuntimeIPCFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           "hello_ack",
				RequestID:           frame.RequestID,
				RuntimeGenerationID: frame.RuntimeGenerationID,
				Payload:             raw,
			})
		case "invoke_worker":
			hostRuntimeProcessNetworkExecute(reader, encoder, frame)
		case "revoke_epoch":
			raw, _ := json.Marshal(hostRuntimeResponsePayload{OK: true})
			_ = encoder.Encode(hostRuntimeIPCFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           "revoke_epoch_ack",
				RequestID:           frame.RequestID,
				RuntimeGenerationID: frame.RuntimeGenerationID,
				Payload:             raw,
			})
		default:
			os.Exit(21)
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
	rawRequest, _ := json.Marshal(hostRuntimeNetworkExecuteRequest{
		PluginInstanceID:    invoke.Lease.PluginInstanceID,
		ActiveFingerprint:   invoke.Invocation.ActiveFingerprint,
		RuntimeGenerationID: invoke.Lease.RuntimeGenerationID,
		PolicyRevision:      invoke.Lease.PolicyRevision,
		ManagementRevision:  invoke.Lease.ManagementRevision,
		RevokeEpoch:         invoke.Lease.RevokeEpoch,
		ConnectorID:         "api",
		Transport:           connectivity.TransportHTTP,
		Destination:         "https://api.example.com",
		TTLMillis:           int64(time.Minute / time.Millisecond),
		Operation:           "http",
		Method:              http.MethodPost,
		Path:                "/v1/worker",
		Headers:             http.Header{"Content-Type": []string{"text/plain"}},
		BodyBase64:          body,
		MaxRequestBytes:     1024,
		MaxResponseBytes:    4096,
		TimeoutMillis:       1000,
	})
	networkRequestID := frame.RequestID + ":network_execute"
	_ = encoder.Encode(hostRuntimeIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           "network_execute",
		RequestID:           networkRequestID,
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
		raw, _ := json.Marshal(hostRuntimeResponsePayload{OK: false, Code: networkResponse.Code, Message: networkResponse.Message})
		_ = encoder.Encode(hostRuntimeIPCFrame{
			IPCVersion:          version.RustIPCVersion,
			FrameType:           "invoke_worker_result",
			RequestID:           frame.RequestID,
			RuntimeGenerationID: frame.RuntimeGenerationID,
			Payload:             raw,
		})
		return
	}
	raw, _ := json.Marshal(hostRuntimeResponsePayload{
		OK: true,
		Result: mustHostRuntimeRaw(map[string]any{
			"data": map[string]any{
				"network_execute": mustHostRuntimeMap(networkResponseFrame.Payload),
			},
		}),
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
