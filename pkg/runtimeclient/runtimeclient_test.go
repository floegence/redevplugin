package runtimeclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", []byte(`{"message":"hello"}`))
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

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
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
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", []byte("{}")); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
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
