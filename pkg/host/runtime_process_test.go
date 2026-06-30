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
	if data["backend"] != "validated wasm worker scaffold" ||
		data["transport"] != "rust runtime ipc" ||
		data["method"] != "worker.echo" ||
		data["worker_id"] != "echo_worker" {
		t.Fatalf("built Rust runtime result mismatch: %#v", data)
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
			raw, _ := json.Marshal(hostRuntimeHelloAckPayload{
				RuntimeVersion: version.RuntimeVersion,
				RustIPCVersion: version.RustIPCVersion,
				WASMABIVersion: version.WASMABIVersion,
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
