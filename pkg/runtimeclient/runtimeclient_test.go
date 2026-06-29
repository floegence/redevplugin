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
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{}, "worker.echo", []byte("{}")); !errors.Is(err, ErrRuntimeIPCUnavailable) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeIPCUnavailable", err)
	}
	if err := supervisor.Revoke(context.Background(), "plugin_a", 3); !errors.Is(err, ErrRuntimeIPCUnavailable) {
		t.Fatalf("Revoke() error = %v, want ErrRuntimeIPCUnavailable", err)
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
	time.Sleep(10 * time.Second)
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
