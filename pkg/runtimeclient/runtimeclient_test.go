package runtimeclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestMain(m *testing.M) {
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_HELPER") == "1" {
		runRuntimeClientHelper()
		return
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER") == "1" {
		os.Stdout.WriteString("not-json\n")
		time.Sleep(10 * time.Second)
		return
	}
	os.Exit(m.Run())
}

func TestProcessSupervisorLifecycleAndDiagnostics(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		Diagnostics: store,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Ready ||
		health.RuntimeInstanceID == "" ||
		health.RuntimeGenerationID == "" ||
		health.RuntimeVersion != version.RuntimeVersion ||
		health.RustIPCVersion != version.RustIPCVersion ||
		health.WASMABIVersion != version.WASMABIVersion {
		t.Fatalf("health mismatch: %#v", health)
	}
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	if decoded["data"].(map[string]any)["from_runtime"] != true {
		t.Fatalf("worker result mismatch: %#v", decoded)
	}
	if err := supervisor.Revoke(context.Background(), "plugini_1", 3); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	waitForDiagnostic(t, store, "plugin.runtime.process.started")
	waitForDiagnostic(t, store, "plugin.runtime.ipc.handshake")

	stopRuntimeSupervisor(t, supervisor)
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health(after stop) error = %v", err)
	}
	if health.Ready {
		t.Fatalf("health after stop still ready: %#v", health)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{}, "worker.echo", nil); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker(after stop) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestProcessSupervisorMapsRuntimeRequestFailure(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE=1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorServesBoundArtifactHandle(t *testing.T) {
	provider := &recordingArtifactProvider{
		content: []byte("wasm bytes"),
		sha256:  fixtureArtifactSHA,
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1"),
		Artifacts:   provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	artifact, ok := decoded["artifact"].(map[string]any)
	if !ok {
		t.Fatalf("artifact result missing: %#v", decoded)
	}
	if artifact["ok"] != true || artifact["sha256"] != fixtureArtifactSHA || artifact["content_base64"] != base64.StdEncoding.EncodeToString([]byte("wasm bytes")) {
		t.Fatalf("artifact result mismatch: %#v", artifact)
	}
	if provider.calls != 1 || provider.last.PackageHash != fixturePackageHash || provider.last.Artifact != fixtureArtifact || provider.last.ArtifactSHA256 != fixtureArtifactSHA {
		t.Fatalf("artifact provider mismatch: calls=%d last=%#v", provider.calls, provider.last)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorValidatesHandleGrantDuringWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:db",
			Method:              "storage.sqlite",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE=1"),
		HandleGrants: validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	handle, ok := decoded["handle_grant"].(map[string]any)
	if !ok {
		t.Fatalf("handle grant result missing: %#v", decoded)
	}
	if handle["ok"] != true || handle["handle_id"] != "storage:db" || handle["method"] != "storage.sqlite" {
		t.Fatalf("handle grant result mismatch: %#v", handle)
	}
	if validator.calls != 1 || validator.last.RuntimeGenerationID != health.RuntimeGenerationID || validator.last.HandleID != "storage:db" {
		t.Fatalf("validator mismatch: calls=%d last=%#v", validator.calls, validator.last)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesHandleGrantOutsideWorkerInvocation(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE_ON_REVOKE=1"),
		HandleGrants: &recordingHandleGrantValidator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := supervisor.Revoke(context.Background(), "plugini_1", 3); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("Revoke() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsInvalidHandleGrantRequestBeforeValidator(t *testing.T) {
	validator := &recordingHandleGrantValidator{}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE=1", "REDEVPLUGIN_RUNTIMECLIENT_INVALID_HANDLE_REQUEST=1"),
		HandleGrants: validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if validator.calls != 0 {
		t.Fatalf("validator was called for invalid request: %d", validator.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesUnboundArtifactHandle(t *testing.T) {
	provider := &recordingArtifactProvider{
		content: []byte("wasm bytes"),
		sha256:  fixtureArtifactSHA,
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT=1"),
		Artifacts:   provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if provider.calls != 0 {
		t.Fatalf("artifact provider was called for denied request: %d", provider.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRequiresWorkerInvocationArtifactIdentity(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", []byte(`{"message":"hello"}`)); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsNonWorkerArtifactPath(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	payload := []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":"ui/index.html","artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo","export":"redeven_worker_invoke"}`, fixturePackageHash, fixtureArtifactSHA))
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", payload); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsMissingPath(t *testing.T) {
	if _, err := NewProcessSupervisor(ProcessSupervisorOptions{}); !errors.Is(err, ErrRuntimePathRequired) {
		t.Fatalf("NewProcessSupervisor() error = %v, want ErrRuntimePathRequired", err)
	}
}

func TestProcessSupervisorFailsClosedOnBadHandshake(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:      os.Args[0],
		Args:             []string{"-test.run=TestMain"},
		Env:              append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER=1"),
		HandshakeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Start(context.Background(), Target{OS: "test-os", Arch: "test-arch"})
	if !errors.Is(err, ErrRuntimeHandshake) {
		t.Fatalf("Start() error = %v, want ErrRuntimeHandshake", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("bad handshake left runtime ready: %#v", health)
	}
}

func runRuntimeClientHelper() {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(2)
	}
	var frame ipcFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		os.Exit(3)
	}
	if frame.FrameType != ipcFrameTypeHello || frame.IPCVersion != version.RustIPCVersion || strings.TrimSpace(frame.RequestID) == "" {
		os.Exit(4)
	}
	payload, _ := json.Marshal(helloAckPayload{
		RuntimeVersion: version.RuntimeVersion,
		RustIPCVersion: version.RustIPCVersion,
		WASMABIVersion: version.WASMABIVersion,
	})
	_ = json.NewEncoder(os.Stdout).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeHelloAck,
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload:             payload,
	})
	encoder := json.NewEncoder(os.Stdout)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request ipcFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(5)
		}
		switch request.FrameType {
		case ipcFrameTypeInvokeWorker:
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT") == "1" {
				if !requestArtifactFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE") == "1" {
				if !validateHandleGrantFromHelper(reader, encoder, request) {
					continue
				}
			}
			resultPayload := runtimeResponsePayload{OK: true, Result: json.RawMessage(`{"data":{"from_runtime":true}}`)}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE") == "1" {
				resultPayload = runtimeResponsePayload{OK: false, Code: "WASM_NOT_IMPLEMENTED", Message: "runtime worker execution is not implemented"}
			}
			raw, _ := json.Marshal(resultPayload)
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeInvokeWorkerResult,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		case ipcFrameTypeRevokeEpoch:
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE_ON_REVOKE") == "1" {
				if !validateHandleGrantFromHelper(reader, encoder, request) {
					continue
				}
			}
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true})
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeRevokeEpochAck,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		default:
			os.Exit(6)
		}
	}
}

func requestArtifactFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	artifactReq := artifactRequestPayloadFromInvoke(request)
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT") == "1" {
		artifactReq.Artifact = "workers/other.wasm"
	}
	rawArtifactReq, _ := json.Marshal(artifactReq)
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeOpenHandle,
		RequestID:           request.RequestID + ":artifact",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawArtifactReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(7)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(8)
	}
	if response.FrameType != ipcFrameTypeOpenHandle || response.RequestID != request.RequestID+":artifact" {
		os.Exit(9)
	}
	var artifact artifactHandleResultPayload
	if err := json.Unmarshal(response.Payload, &artifact); err != nil {
		os.Exit(10)
	}
	if !artifact.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: artifact.Code, Message: artifact.Message})
		_ = encoder.Encode(ipcFrame{
			IPCVersion:          version.RustIPCVersion,
			FrameType:           ipcFrameTypeInvokeWorkerResult,
			RequestID:           request.RequestID,
			RuntimeGenerationID: request.RuntimeGenerationID,
			Payload:             raw,
		})
		return false
	}
	raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
		"artifact": map[string]any{
			"ok":             artifact.OK,
			"sha256":         artifact.SHA256,
			"content_base64": artifact.ContentBase64,
		},
	})})
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeInvokeWorkerResult,
		RequestID:           request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             raw,
	})
	return false
}

func artifactRequestPayloadFromInvoke(request ipcFrame) artifactHandleRequestPayload {
	var payload invokeWorkerRequestPayload
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		os.Exit(11)
	}
	var invocation ArtifactRequest
	if err := json.Unmarshal(payload.Invocation, &invocation); err != nil {
		os.Exit(12)
	}
	return artifactHandleRequestPayload(invocation)
}

func validateHandleGrantFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawHandleReq, _ := json.Marshal(handleGrantValidationRequestFromInvoke(request))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeValidateHandleGrant,
		RequestID:           request.RequestID + ":handle_grant",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawHandleReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(13)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(14)
	}
	if response.FrameType != ipcFrameTypeValidateHandleGrant || response.RequestID != request.RequestID+":handle_grant" {
		os.Exit(15)
	}
	var grant handleGrantValidationResultPayload
	if err := json.Unmarshal(response.Payload, &grant); err != nil {
		os.Exit(16)
	}
	if !grant.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: grant.Code, Message: grant.Message})
		resultFrameType := ipcFrameTypeInvokeWorkerResult
		if request.FrameType == ipcFrameTypeRevokeEpoch {
			resultFrameType = ipcFrameTypeRevokeEpochAck
		}
		_ = encoder.Encode(ipcFrame{
			IPCVersion:          version.RustIPCVersion,
			FrameType:           resultFrameType,
			RequestID:           request.RequestID,
			RuntimeGenerationID: request.RuntimeGenerationID,
			Payload:             raw,
		})
		return false
	}
	raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
		"handle_grant": map[string]any{
			"ok":                    grant.OK,
			"handle_grant_id":       grant.HandleGrantID,
			"handle_id":             grant.HandleID,
			"method":                grant.Method,
			"runtime_generation_id": grant.RuntimeGenerationID,
			"max_total_bytes":       grant.MaxTotalBytes,
		},
	})})
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeInvokeWorkerResult,
		RequestID:           request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             raw,
	})
	return false
}

func handleGrantValidationRequestFromInvoke(request ipcFrame) HandleGrantValidationRequest {
	req := HandleGrantValidationRequest{
		HandleGrantToken:    "handle_grant_token_1",
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: request.RuntimeGenerationID,
		RuntimeShardID:      "runtime_shard_1",
		HandleID:            "storage:db",
		Method:              "storage.sqlite",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}
	if request.FrameType == ipcFrameTypeInvokeWorker {
		var payload invokeWorkerRequestPayload
		if err := json.Unmarshal(request.Payload, &payload); err == nil {
			req.PluginInstanceID = payload.Lease.PluginInstanceID
			req.PolicyRevision = payload.Lease.PolicyRevision
			req.ManagementRevision = payload.Lease.ManagementRevision
			req.RevokeEpoch = payload.Lease.RevokeEpoch
		}
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_INVALID_HANDLE_REQUEST") == "1" {
		req.HandleGrantToken = ""
	}
	return req
}

func mustMarshalRaw(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func waitForDiagnostic(t *testing.T, store *observability.MemoryStore, eventType string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, err := store.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{Type: eventType, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	events, _ := store.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{Limit: 20})
	t.Fatalf("timed out waiting for diagnostic %q; events=%#v", eventType, events)
}

const (
	fixturePackageHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixtureArtifact    = "workers/echo.wasm"
	fixtureArtifactSHA = "sha256:a81d16f296ff2ebdb2dfe2ee0fbb532ba602da1ef9f797f8b1edb3e987fcf5db"
)

type recordingArtifactProvider struct {
	calls   int
	last    ArtifactRequest
	content []byte
	sha256  string
	err     error
}

type recordingHandleGrantValidator struct {
	calls  int
	last   HandleGrantValidationRequest
	result HandleGrantValidationResult
	err    error
}

func (v *recordingHandleGrantValidator) ValidateHandleGrant(_ context.Context, req HandleGrantValidationRequest) (HandleGrantValidationResult, error) {
	v.calls++
	v.last = req
	if v.err != nil {
		return HandleGrantValidationResult{}, v.err
	}
	return v.result, nil
}

func (p *recordingArtifactProvider) ReadArtifact(_ context.Context, req ArtifactRequest) (ArtifactResult, error) {
	p.calls++
	p.last = req
	if p.err != nil {
		return ArtifactResult{}, p.err
	}
	return ArtifactResult{Content: append([]byte(nil), p.content...), SHA256: p.sha256}, nil
}

func workerInvocationFixture() []byte {
	return []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":%q,"artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo","export":"redeven_worker_invoke","params":{"message":"hello"}}`, fixturePackageHash, fixtureArtifact, fixtureArtifactSHA))
}

func stopRuntimeSupervisor(t *testing.T, supervisor *ProcessSupervisor) {
	t.Helper()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}
