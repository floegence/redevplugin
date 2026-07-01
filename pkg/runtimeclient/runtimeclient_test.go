package runtimeclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/storage"
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

func TestProcessSupervisorInvalidatesRuntimeOnCanceledIPC(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BLOCK_INVOKE=1"),
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
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := supervisor.InvokeWorker(ctx, Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("InvokeWorker() canceled error = %v, want %v", err, context.DeadlineExceeded)
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime should be marked not ready after canceled IPC: %#v", health)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_2"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker(after canceled IPC) error = %v, want %v", err, ErrRuntimeNotReady)
	}
	waitForDiagnostic(t, store, "plugin.runtime.ipc.invalidated")
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRevokeInvalidatesRuntimeWhenIPCLockIsBusy(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BLOCK_INVOKE=1"),
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
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := supervisor.InvokeWorker(context.Background(), Lease{
			LeaseID:             "lease_busy",
			LeaseToken:          "token_busy",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
		}, "worker.echo", workerInvocationFixture())
		done <- err
	}()
	time.Sleep(25 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := supervisor.Revoke(ctx, "plugini_1", 4); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Revoke(busy IPC) error = %v, want %v", err, context.DeadlineExceeded)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("busy InvokeWorker did not return after runtime invalidation")
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime should be marked not ready after busy revoke timeout: %#v", health)
	}
	waitForDiagnostic(t, store, "plugin.runtime.ipc.invalidated")
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRevokeIsNoopWhenRuntimeIsNotReady(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Revoke(context.Background(), "plugini_1", 1); err != nil {
		t.Fatalf("Revoke(not ready) error = %v", err)
	}
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

func TestProcessSupervisorServesStorageFileRequestDuringWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:workspace",
			Method:              "storage.files",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	files := &recordingStorageFilesBroker{
		readResult: storage.FileReadResult{
			Path:      "notes/today.txt",
			Data:      []byte("hello"),
			SizeBytes: 5,
			Usage:     storage.Usage{PluginInstanceID: "plugini_1", StoreID: "workspace", UsageBytes: 5, QuotaBytes: 4096},
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE=read"),
		HandleGrants: validator,
		StorageFiles: files,
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
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
		LeaseID:             "lease_1",
		LeaseToken:          "token_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	storageFile, ok := decoded["storage_file"].(map[string]any)
	if !ok {
		t.Fatalf("storage file result missing: %#v", decoded)
	}
	if storageFile["ok"] != true || storageFile["path"] != "notes/today.txt" || storageFile["data_base64"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatalf("storage file result mismatch: %#v", storageFile)
	}
	if validator.calls != 1 || validator.last.HandleID != "storage:workspace" || validator.last.Method != "storage.files" {
		t.Fatalf("validator mismatch: calls=%d last=%#v", validator.calls, validator.last)
	}
	if files.readCalls != 1 || files.lastRead.PluginInstanceID != "plugini_1" || files.lastRead.StoreID != "workspace" || files.lastRead.Path != "notes/today.txt" {
		t.Fatalf("storage read mismatch: calls=%d last=%#v", files.readCalls, files.lastRead)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorServesStorageKVRequestDuringWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:settings",
			Method:              "storage.kv",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	kv := &recordingStorageKVBroker{
		putResult: storage.KVPutResult{
			Key:       "demo/last_broker_run",
			SizeBytes: 8,
			Usage:     storage.Usage{PluginInstanceID: "plugini_1", StoreID: "settings", UsageBytes: 8, QuotaBytes: 4096},
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV=put"),
		HandleGrants: validator,
		StorageKV:    kv,
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
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
		LeaseID:             "lease_1",
		LeaseToken:          "token_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	storageKV, ok := decoded["storage_kv"].(map[string]any)
	if !ok {
		t.Fatalf("storage kv result missing: %#v", decoded)
	}
	if storageKV["ok"] != true || storageKV["key"] != "demo/last_broker_run" || storageKV["size_bytes"] != float64(8) {
		t.Fatalf("storage kv result mismatch: %#v", storageKV)
	}
	if validator.calls != 1 || validator.last.HandleID != "storage:settings" || validator.last.Method != "storage.kv" {
		t.Fatalf("validator mismatch: calls=%d last=%#v", validator.calls, validator.last)
	}
	if kv.putCalls != 1 || kv.lastPut.PluginInstanceID != "plugini_1" || kv.lastPut.StoreID != "settings" || kv.lastPut.Key != "demo/last_broker_run" || string(kv.lastPut.Value) != "hello kv" {
		t.Fatalf("storage kv put mismatch: calls=%d last=%#v", kv.putCalls, kv.lastPut)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorServesStorageSQLiteRequestDuringWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:db",
			Method:              "storage.sqlite",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	title := "stored from wasm"
	score := int64(7)
	sqlite := &recordingStorageSQLiteBroker{
		queryResult: storage.SQLiteQueryResult{
			Database: "plugin.sqlite",
			Columns:  []string{"title", "score"},
			Rows: [][]storage.SQLiteValue{{
				{Text: &title},
				{Int: &score},
			}},
			Usage: storage.Usage{PluginInstanceID: "plugini_1", StoreID: "db", UsageBytes: 4096, QuotaBytes: 8192},
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:   os.Args[0],
		Args:          []string{"-test.run=TestMain"},
		Env:           append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_SQLITE=query"),
		HandleGrants:  validator,
		StorageSQLite: sqlite,
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
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
		LeaseID:             "lease_1",
		LeaseToken:          "token_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	storageSQLite, ok := decoded["storage_sqlite"].(map[string]any)
	if !ok {
		t.Fatalf("storage sqlite result missing: %#v", decoded)
	}
	if storageSQLite["ok"] != true || storageSQLite["database"] != "plugin.sqlite" {
		t.Fatalf("storage sqlite result mismatch: %#v", storageSQLite)
	}
	rows, ok := storageSQLite["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("storage sqlite rows mismatch: %#v", storageSQLite["rows"])
	}
	if validator.calls != 1 || validator.last.HandleID != "storage:db" || validator.last.Method != "storage.sqlite" {
		t.Fatalf("validator mismatch: calls=%d last=%#v", validator.calls, validator.last)
	}
	if sqlite.queryCalls != 1 || sqlite.lastQuery.PluginInstanceID != "plugini_1" || sqlite.lastQuery.StoreID != "db" || sqlite.lastQuery.SQL != "SELECT title, score FROM events WHERE score = ?" {
		t.Fatalf("storage sqlite query mismatch: calls=%d last=%#v", sqlite.queryCalls, sqlite.lastQuery)
	}
	if len(sqlite.lastQuery.Args) != 1 || sqlite.lastQuery.Args[0].Int == nil || *sqlite.lastQuery.Args[0].Int != score {
		t.Fatalf("storage sqlite args mismatch: %#v", sqlite.lastQuery.Args)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorMintsNetworkGrantDuringWorkerInvocation(t *testing.T) {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	broker := &recordingConnectivityBroker{
		grant: connectivity.ConnectionGrant{
			GrantID:                 "netgrant_00112233445566778899aabbccddeeff",
			PluginInstanceID:        "plugini_1",
			ActiveFingerprint:       "sha256:active",
			PolicyRevision:          1,
			ManagementRevision:      2,
			RevokeEpoch:             3,
			ConnectorID:             "api",
			Transport:               connectivity.TransportHTTP,
			Destination:             connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "https", Host: "api.example.com", Port: 443},
			RuntimeGenerationID:     "runtime_gen_test",
			TargetClassifierVersion: version.TargetClassifierVersion,
			ExpiresAt:               now.Add(30 * time.Second),
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT=1"),
		Connectivity: broker,
		Now:          func() time.Time { return now },
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
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
		LeaseID:             "lease_1",
		LeaseToken:          "token_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	networkGrant, ok := decoded["network_grant"].(map[string]any)
	if !ok {
		t.Fatalf("network grant result missing: %#v", decoded)
	}
	if networkGrant["ok"] != true || networkGrant["grant_id"] != broker.grant.GrantID || networkGrant["connector_id"] != "api" || networkGrant["transport"] != "http" {
		t.Fatalf("network grant result mismatch: %#v", networkGrant)
	}
	if broker.calls != 1 ||
		broker.last.PluginInstanceID != "plugini_1" ||
		broker.last.RuntimeGenerationID != health.RuntimeGenerationID ||
		broker.last.ConnectorID != "api" ||
		broker.last.Destination != "https://api.example.com" ||
		broker.last.TTL != 30*time.Second {
		t.Fatalf("connectivity broker mismatch: calls=%d last=%#v", broker.calls, broker.last)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorExecutesNetworkDuringWorkerInvocation(t *testing.T) {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	broker := &recordingConnectivityBroker{
		grant: connectivity.ConnectionGrant{
			GrantID:                 "netgrant_00112233445566778899aabbccddeeff",
			PluginInstanceID:        "plugini_1",
			ActiveFingerprint:       "sha256:active",
			PolicyRevision:          1,
			ManagementRevision:      2,
			RevokeEpoch:             3,
			ConnectorID:             "api",
			Transport:               connectivity.TransportHTTP,
			Destination:             connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "https", Host: "api.example.com", Port: 443},
			RuntimeGenerationID:     "runtime_gen_test",
			TargetClassifierVersion: version.TargetClassifierVersion,
			ExpiresAt:               now.Add(30 * time.Second),
		},
	}
	executor := &recordingNetworkExecutor{
		httpResponse: connectivity.HTTPResponse{
			StatusCode: 201,
			Headers:    http.Header{"X-Worker": []string{"ok"}},
			Body:       []byte(`{"ok":true}`),
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:     os.Args[0],
		Args:            []string{"-test.run=TestMain"},
		Env:             append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
		Connectivity:    broker,
		NetworkExecutor: executor,
		Now:             func() time.Time { return now },
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
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
		LeaseID:             "lease_1",
		LeaseToken:          "token_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if err != nil {
		t.Fatalf("InvokeWorker() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawResult, &decoded); err != nil {
		t.Fatalf("decode worker result: %v", err)
	}
	networkExecute, ok := decoded["network_execute"].(map[string]any)
	if !ok {
		t.Fatalf("network execute result missing: %#v", decoded)
	}
	if networkExecute["ok"] != true || networkExecute["status_code"] != float64(201) || networkExecute["body_base64"] != base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)) {
		t.Fatalf("network execute result mismatch: %#v", networkExecute)
	}
	if broker.calls != 1 || broker.last.ConnectorID != "api" || broker.last.Destination != "https://api.example.com" {
		t.Fatalf("connectivity broker mismatch: calls=%d last=%#v", broker.calls, broker.last)
	}
	if executor.httpCalls != 1 ||
		executor.lastHTTP.Grant.GrantID != broker.grant.GrantID ||
		executor.lastHTTP.Method != http.MethodPost ||
		executor.lastHTTP.Path != "/v1/worker" ||
		string(executor.lastHTTP.Body) != `{"hello":"network"}` ||
		executor.lastHTTP.Headers.Get("X-Test") != "ok" ||
		executor.lastHTTP.MaxResponseBytes != 1024 ||
		executor.lastHTTP.Timeout != 2*time.Second {
		t.Fatalf("network executor mismatch: calls=%d last=%#v", executor.httpCalls, executor.lastHTTP)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorExecutesWebSocketAndSocketNetworkDuringWorkerInvocation(t *testing.T) {
	cases := []struct {
		name          string
		operation     string
		transport     connectivity.Transport
		destination   connectivity.Destination
		response      func(*recordingNetworkExecutor)
		assertRequest func(*testing.T, *recordingNetworkExecutor)
		assertResult  func(*testing.T, map[string]any)
	}{
		{
			name:        "websocket",
			operation:   "websocket_round_trip",
			transport:   connectivity.TransportWebSocket,
			destination: connectivity.Destination{Transport: connectivity.TransportWebSocket, Scheme: "wss", Host: "stream.example.com", Port: 443},
			response: func(executor *recordingNetworkExecutor) {
				executor.wsResponse = connectivity.WebSocketRoundTripResponse{MessageType: connectivity.WebSocketMessageText, Payload: []byte("ws:hello")}
			},
			assertRequest: func(t *testing.T, executor *recordingNetworkExecutor) {
				t.Helper()
				if executor.websocketCalls != 1 || executor.lastWebSocket.MessageType != connectivity.WebSocketMessageText || string(executor.lastWebSocket.Payload) != "hello" || executor.lastWebSocket.MaxResponseBytes != 1024 || executor.lastWebSocket.Timeout != 2*time.Second {
					t.Fatalf("websocket executor mismatch: calls=%d last=%#v", executor.websocketCalls, executor.lastWebSocket)
				}
			},
			assertResult: func(t *testing.T, result map[string]any) {
				t.Helper()
				if result["message_type"] != string(connectivity.WebSocketMessageText) || result["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("ws:hello")) {
					t.Fatalf("websocket result mismatch: %#v", result)
				}
			},
		},
		{
			name:        "tcp",
			operation:   "tcp_round_trip",
			transport:   connectivity.TransportTCP,
			destination: connectivity.Destination{Transport: connectivity.TransportTCP, Host: "db.example.com", Port: 5432},
			response: func(executor *recordingNetworkExecutor) {
				executor.tcpResponse = connectivity.TCPRoundTripResponse{Payload: []byte("tcp:hello")}
			},
			assertRequest: func(t *testing.T, executor *recordingNetworkExecutor) {
				t.Helper()
				if executor.tcpCalls != 1 || string(executor.lastTCP.Payload) != "hello" || executor.lastTCP.MaxReadBytes != 1024 || executor.lastTCP.Timeout != 2*time.Second {
					t.Fatalf("tcp executor mismatch: calls=%d last=%#v", executor.tcpCalls, executor.lastTCP)
				}
			},
			assertResult: func(t *testing.T, result map[string]any) {
				t.Helper()
				if result["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("tcp:hello")) {
					t.Fatalf("tcp result mismatch: %#v", result)
				}
			},
		},
		{
			name:        "udp",
			operation:   "udp_round_trip",
			transport:   connectivity.TransportUDP,
			destination: connectivity.Destination{Transport: connectivity.TransportUDP, Host: "metrics.example.com", Port: 8125},
			response: func(executor *recordingNetworkExecutor) {
				executor.udpResponse = connectivity.UDPRoundTripResponse{Payload: []byte("udp:hello")}
			},
			assertRequest: func(t *testing.T, executor *recordingNetworkExecutor) {
				t.Helper()
				if executor.udpCalls != 1 || string(executor.lastUDP.Payload) != "hello" || executor.lastUDP.MaxReadBytes != 1024 || executor.lastUDP.Timeout != 2*time.Second {
					t.Fatalf("udp executor mismatch: calls=%d last=%#v", executor.udpCalls, executor.lastUDP)
				}
			},
			assertResult: func(t *testing.T, result map[string]any) {
				t.Helper()
				if result["payload_base64"] != base64.StdEncoding.EncodeToString([]byte("udp:hello")) {
					t.Fatalf("udp result mismatch: %#v", result)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
			broker := &recordingConnectivityBroker{
				grant: connectivity.ConnectionGrant{
					GrantID:                 "netgrant_00112233445566778899aabbccddeeff",
					PluginInstanceID:        "plugini_1",
					ActiveFingerprint:       "sha256:active",
					PolicyRevision:          1,
					ManagementRevision:      2,
					RevokeEpoch:             3,
					ConnectorID:             "api",
					Transport:               tc.transport,
					Destination:             tc.destination,
					RuntimeGenerationID:     "runtime_gen_test",
					TargetClassifierVersion: version.TargetClassifierVersion,
					ExpiresAt:               now.Add(30 * time.Second),
				},
			}
			executor := &recordingNetworkExecutor{}
			tc.response(executor)
			supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
				RuntimePath:     os.Args[0],
				Args:            []string{"-test.run=TestMain"},
				Env:             append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE="+tc.operation),
				Connectivity:    broker,
				NetworkExecutor: executor,
				Now:             func() time.Time { return now },
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
			broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
			rawResult, err := supervisor.InvokeWorker(context.Background(), Lease{
				LeaseID:             "lease_1",
				LeaseToken:          "token_1",
				RuntimeGenerationID: health.RuntimeGenerationID,
				PluginInstanceID:    "plugini_1",
				PolicyRevision:      1,
				ManagementRevision:  2,
				RevokeEpoch:         3,
			}, "worker.echo", workerInvocationFixture())
			if err != nil {
				t.Fatalf("InvokeWorker() error = %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(rawResult, &decoded); err != nil {
				t.Fatalf("decode worker result: %v", err)
			}
			networkExecute, ok := decoded["network_execute"].(map[string]any)
			if !ok {
				t.Fatalf("network execute result missing: %#v", decoded)
			}
			if broker.calls != 1 || broker.last.Transport != tc.transport {
				t.Fatalf("connectivity broker mismatch: calls=%d last=%#v", broker.calls, broker.last)
			}
			tc.assertRequest(t, executor)
			tc.assertResult(t, networkExecute)
			stopRuntimeSupervisor(t, supervisor)
		})
	}
}

func TestProcessSupervisorDeniesNetworkExecuteWithoutExecutor(t *testing.T) {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	broker := &recordingConnectivityBroker{
		grant: connectivity.ConnectionGrant{
			GrantID:                 "netgrant_00112233445566778899aabbccddeeff",
			PluginInstanceID:        "plugini_1",
			ActiveFingerprint:       "sha256:active",
			PolicyRevision:          1,
			ManagementRevision:      2,
			RevokeEpoch:             3,
			ConnectorID:             "api",
			Transport:               connectivity.TransportHTTP,
			Destination:             connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "https", Host: "api.example.com", Port: 443},
			RuntimeGenerationID:     "runtime_gen_test",
			TargetClassifierVersion: version.TargetClassifierVersion,
			ExpiresAt:               now.Add(30 * time.Second),
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
		Connectivity: broker,
		Now:          func() time.Time { return now },
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
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesNetworkGrantWithoutBroker(t *testing.T) {
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath: os.Args[0],
		Args:        []string{"-test.run=TestMain"},
		Env:         append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT=1"),
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
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesStorageFileWithoutBroker(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:workspace",
			Method:              "storage.files",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE=read"),
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
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if validator.calls != 0 {
		t.Fatalf("validator should not be called when broker is unavailable: %d", validator.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesStorageKVWithoutBroker(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:settings",
			Method:              "storage.kv",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV=put"),
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
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{LeaseID: "lease_1", LeaseToken: "token_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if validator.calls != 0 {
		t.Fatalf("validator should not be called when broker is unavailable: %d", validator.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesStorageFileOutsideWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:workspace",
			Method:              "storage.files",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	files := &recordingStorageFilesBroker{}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE_ON_REVOKE=read"),
		HandleGrants: validator,
		StorageFiles: files,
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
	if validator.calls != 0 || files.readCalls != 0 {
		t.Fatalf("storage outside worker should not touch validator or broker: validator=%d reads=%d", validator.calls, files.readCalls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesStorageKVOutsideWorkerInvocation(t *testing.T) {
	validator := &recordingHandleGrantValidator{
		result: HandleGrantValidationResult{
			HandleGrantID:       "handle_grant_1",
			HandleID:            "storage:settings",
			Method:              "storage.kv",
			RuntimeGenerationID: "runtime_gen_test",
			MaxTotalBytes:       4096,
		},
	}
	kv := &recordingStorageKVBroker{}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV_ON_REVOKE=put"),
		HandleGrants: validator,
		StorageKV:    kv,
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
	if validator.calls != 0 || kv.putCalls != 0 {
		t.Fatalf("storage kv outside worker should not touch validator or broker: validator=%d puts=%d", validator.calls, kv.putCalls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesNetworkGrantOutsideWorkerInvocation(t *testing.T) {
	broker := &recordingConnectivityBroker{}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:  os.Args[0],
		Args:         []string{"-test.run=TestMain"},
		Env:          append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT_ON_REVOKE=1"),
		Connectivity: broker,
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
	if broker.calls != 0 {
		t.Fatalf("network grant outside worker should not touch broker: %d", broker.calls)
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
	payload := []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":"ui/index.html","artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo","export":"redevplugin_worker_invoke"}`, fixturePackageHash, fixtureArtifactSHA))
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
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BLOCK_INVOKE") == "1" {
				time.Sleep(10 * time.Second)
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT") == "1" {
				if !requestArtifactFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT") == "1" {
				if !requestNetworkGrantFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE") != "" {
				if !requestNetworkExecuteFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE") != "" {
				if !requestStorageFileFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV") != "" {
				if !requestStorageKVFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_SQLITE") != "" {
				if !requestStorageSQLiteFromHelper(reader, encoder, request) {
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
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT_ON_REVOKE") == "1" {
				if !requestNetworkGrantFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE_ON_REVOKE") != "" {
				if !requestStorageFileFromHelper(reader, encoder, request) {
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV_ON_REVOKE") != "" {
				if !requestStorageKVFromHelper(reader, encoder, request) {
					continue
				}
			}
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

func requestStorageFileFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawStorageReq, _ := json.Marshal(storageFileRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE")))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageFile,
		RequestID:           request.RequestID + ":storage_file",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawStorageReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(17)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(18)
	}
	if response.FrameType != ipcFrameTypeStorageFile || response.RequestID != request.RequestID+":storage_file" {
		os.Exit(19)
	}
	var storageFile storageFileResponsePayload
	if err := json.Unmarshal(response.Payload, &storageFile); err != nil {
		os.Exit(20)
	}
	if !storageFile.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageFile.Code, Message: storageFile.Message})
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
		"storage_file": storageFile,
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

func requestStorageKVFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawStorageReq, _ := json.Marshal(storageKVRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV")))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageKV,
		RequestID:           request.RequestID + ":storage_kv",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawStorageReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(41)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(42)
	}
	if response.FrameType != ipcFrameTypeStorageKV || response.RequestID != request.RequestID+":storage_kv" {
		os.Exit(43)
	}
	var storageKV storageKVResponsePayload
	if err := json.Unmarshal(response.Payload, &storageKV); err != nil {
		os.Exit(44)
	}
	if !storageKV.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageKV.Code, Message: storageKV.Message})
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
		"storage_kv": storageKV,
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

func requestStorageSQLiteFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawStorageReq, _ := json.Marshal(storageSQLiteRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_SQLITE")))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageSQLite,
		RequestID:           request.RequestID + ":storage_sqlite",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawStorageReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(51)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(52)
	}
	if response.FrameType != ipcFrameTypeStorageSQLite || response.RequestID != request.RequestID+":storage_sqlite" {
		os.Exit(53)
	}
	var storageSQLite storageSQLiteResponsePayload
	if err := json.Unmarshal(response.Payload, &storageSQLite); err != nil {
		os.Exit(54)
	}
	if !storageSQLite.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageSQLite.Code, Message: storageSQLite.Message})
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
		"storage_sqlite": storageSQLite,
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

func requestNetworkGrantFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawNetworkReq, _ := json.Marshal(networkGrantRequestFromInvoke(request))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeNetworkGrant,
		RequestID:           request.RequestID + ":network_grant",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawNetworkReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(21)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(22)
	}
	if response.FrameType != ipcFrameTypeNetworkGrant || response.RequestID != request.RequestID+":network_grant" {
		os.Exit(23)
	}
	var networkGrant networkGrantResponsePayload
	if err := json.Unmarshal(response.Payload, &networkGrant); err != nil {
		os.Exit(24)
	}
	if !networkGrant.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: networkGrant.Code, Message: networkGrant.Message})
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
		"network_grant": networkGrant,
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

func requestNetworkExecuteFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	rawNetworkReq, _ := json.Marshal(networkExecuteRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE")))
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeNetworkExecute,
		RequestID:           request.RequestID + ":network_execute",
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             rawNetworkReq,
	})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(25)
	}
	var response ipcFrame
	if err := json.Unmarshal(line, &response); err != nil {
		os.Exit(26)
	}
	if response.FrameType != ipcFrameTypeNetworkExecute || response.RequestID != request.RequestID+":network_execute" {
		os.Exit(27)
	}
	var networkExecute networkExecuteResponsePayload
	if err := json.Unmarshal(response.Payload, &networkExecute); err != nil {
		os.Exit(28)
	}
	if !networkExecute.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: networkExecute.Code, Message: networkExecute.Message})
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
		"network_execute": networkExecute,
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

func storageFileRequestFromInvoke(request ipcFrame, operation string) storageFileRequestPayload {
	req := storageFileRequestPayload{
		HandleGrantToken:    "handle_grant_token_1",
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: request.RuntimeGenerationID,
		RuntimeShardID:      "runtime_shard_1",
		HandleID:            "storage:workspace",
		Method:              "storage.files",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
		Operation:           operation,
		StoreID:             "workspace",
		Path:                "notes/today.txt",
		DataBase64:          base64.StdEncoding.EncodeToString([]byte("hello")),
		MaxBytes:            1024,
		MaxEntries:          10,
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
	return req
}

func storageKVRequestFromInvoke(request ipcFrame, operation string) storageKVRequestPayload {
	req := storageKVRequestPayload{
		HandleGrantToken:    "handle_grant_token_1",
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: request.RuntimeGenerationID,
		RuntimeShardID:      "runtime_shard_1",
		HandleID:            "storage:settings",
		Method:              "storage.kv",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
		Operation:           operation,
		StoreID:             "settings",
		Key:                 "demo/last_broker_run",
		ValueBase64:         base64.StdEncoding.EncodeToString([]byte("hello kv")),
		Prefix:              "demo/",
		MaxBytes:            1024,
		MaxEntries:          10,
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
	return req
}

func storageSQLiteRequestFromInvoke(request ipcFrame, operation string) storageSQLiteRequestPayload {
	score := int64(7)
	req := storageSQLiteRequestPayload{
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
		Operation:           operation,
		StoreID:             "db",
		Database:            "plugin.sqlite",
		SQL:                 "SELECT title, score FROM events WHERE score = ?",
		Args:                []storageSQLiteValueIPC{{Int: &score}},
		MaxRows:             10,
		MaxResponseBytes:    4096,
		TimeoutMillis:       1000,
	}
	if operation == "exec" {
		req.SQL = "INSERT INTO events (title, score) VALUES ('stored from wasm', 7)"
		req.Args = nil
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
	return req
}

func networkExecuteRequestFromInvoke(request ipcFrame, operation string) networkExecuteRequestPayload {
	grantReq := networkGrantRequestFromInvoke(request)
	req := networkExecuteRequestPayload{
		PluginInstanceID:    grantReq.PluginInstanceID,
		ActiveFingerprint:   grantReq.ActiveFingerprint,
		RuntimeInstanceID:   grantReq.RuntimeInstanceID,
		RuntimeGenerationID: grantReq.RuntimeGenerationID,
		RuntimeShardID:      grantReq.RuntimeShardID,
		PolicyRevision:      grantReq.PolicyRevision,
		ManagementRevision:  grantReq.ManagementRevision,
		RevokeEpoch:         grantReq.RevokeEpoch,
		ConnectorID:         grantReq.ConnectorID,
		Transport:           grantReq.Transport,
		Destination:         grantReq.Destination,
		TTLMillis:           grantReq.TTLMillis,
		Operation:           operation,
		Method:              http.MethodPost,
		Path:                "/v1/worker",
		Headers:             http.Header{"X-Test": []string{"ok"}},
		BodyBase64:          base64.StdEncoding.EncodeToString([]byte(`{"hello":"network"}`)),
		MaxResponseBytes:    1024,
		TimeoutMillis:       2000,
	}
	switch operation {
	case "websocket_round_trip":
		req.Transport = connectivity.TransportWebSocket
		req.Destination = "wss://stream.example.com"
		req.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("hello"))
		req.MessageType = string(connectivity.WebSocketMessageText)
	case "tcp_round_trip":
		req.Transport = connectivity.TransportTCP
		req.Destination = "tcp://db.example.com:5432"
		req.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("hello"))
	case "udp_round_trip":
		req.Transport = connectivity.TransportUDP
		req.Destination = "udp://metrics.example.com:8125"
		req.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte("hello"))
	}
	return req
}

func networkGrantRequestFromInvoke(request ipcFrame) networkGrantRequestPayload {
	req := networkGrantRequestPayload{
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: request.RuntimeGenerationID,
		RuntimeShardID:      "runtime_shard_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
		ConnectorID:         "api",
		Transport:           connectivity.TransportHTTP,
		Destination:         "https://api.example.com",
		TTLMillis:           30000,
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
	return req
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

type recordingStorageFilesBroker struct {
	readCalls   int
	writeCalls  int
	deleteCalls int
	listCalls   int
	lastRead    storage.FileReadRequest
	lastWrite   storage.FileWriteRequest
	lastDelete  storage.FileDeleteRequest
	lastList    storage.FileListRequest
	readResult  storage.FileReadResult
	writeResult storage.FileWriteResult
	listResult  storage.FileListResult
	err         error
}

type recordingStorageKVBroker struct {
	getCalls    int
	putCalls    int
	deleteCalls int
	listCalls   int
	lastGet     storage.KVGetRequest
	lastPut     storage.KVPutRequest
	lastDelete  storage.KVDeleteRequest
	lastList    storage.KVListRequest
	getResult   storage.KVGetResult
	putResult   storage.KVPutResult
	listResult  storage.KVListResult
	err         error
}

type recordingStorageSQLiteBroker struct {
	execCalls   int
	queryCalls  int
	lastExec    storage.SQLiteExecRequest
	lastQuery   storage.SQLiteQueryRequest
	execResult  storage.SQLiteExecResult
	queryResult storage.SQLiteQueryResult
	err         error
}

type recordingConnectivityBroker struct {
	calls       int
	installCall int
	removeCall  int
	last        connectivity.GrantRequest
	grant       connectivity.ConnectionGrant
	err         error
}

type recordingNetworkExecutor struct {
	httpCalls      int
	websocketCalls int
	tcpCalls       int
	udpCalls       int
	lastHTTP       connectivity.HTTPRequest
	lastWebSocket  connectivity.WebSocketRoundTripRequest
	lastTCP        connectivity.TCPRoundTripRequest
	lastUDP        connectivity.UDPRoundTripRequest
	httpResponse   connectivity.HTTPResponse
	wsResponse     connectivity.WebSocketRoundTripResponse
	tcpResponse    connectivity.TCPRoundTripResponse
	udpResponse    connectivity.UDPRoundTripResponse
	err            error
}

func (b *recordingConnectivityBroker) InstallPolicy(context.Context, connectivity.PolicySet) error {
	b.installCall++
	return nil
}

func (b *recordingConnectivityBroker) RemovePolicy(context.Context, string) error {
	b.removeCall++
	return nil
}

func (b *recordingConnectivityBroker) MintConnectionGrant(_ context.Context, req connectivity.GrantRequest) (connectivity.ConnectionGrant, error) {
	b.calls++
	b.last = req
	if b.err != nil {
		return connectivity.ConnectionGrant{}, b.err
	}
	return b.grant, nil
}

func (e *recordingNetworkExecutor) DoHTTP(_ context.Context, req connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	e.httpCalls++
	e.lastHTTP = req
	if e.err != nil {
		return connectivity.HTTPResponse{}, e.err
	}
	return e.httpResponse, nil
}

func (e *recordingNetworkExecutor) WebSocketRoundTrip(_ context.Context, req connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	e.websocketCalls++
	e.lastWebSocket = req
	if e.err != nil {
		return connectivity.WebSocketRoundTripResponse{}, e.err
	}
	return e.wsResponse, nil
}

func (e *recordingNetworkExecutor) TCPRoundTrip(_ context.Context, req connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	e.tcpCalls++
	e.lastTCP = req
	if e.err != nil {
		return connectivity.TCPRoundTripResponse{}, e.err
	}
	return e.tcpResponse, nil
}

func (e *recordingNetworkExecutor) UDPRoundTrip(_ context.Context, req connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	e.udpCalls++
	e.lastUDP = req
	if e.err != nil {
		return connectivity.UDPRoundTripResponse{}, e.err
	}
	return e.udpResponse, nil
}

func (v *recordingHandleGrantValidator) ValidateHandleGrant(_ context.Context, req HandleGrantValidationRequest) (HandleGrantValidationResult, error) {
	v.calls++
	v.last = req
	if v.err != nil {
		return HandleGrantValidationResult{}, v.err
	}
	return v.result, nil
}

func (b *recordingStorageFilesBroker) ReadFile(_ context.Context, req storage.FileReadRequest) (storage.FileReadResult, error) {
	b.readCalls++
	b.lastRead = req
	if b.err != nil {
		return storage.FileReadResult{}, b.err
	}
	return b.readResult, nil
}

func (b *recordingStorageFilesBroker) WriteFile(_ context.Context, req storage.FileWriteRequest) (storage.FileWriteResult, error) {
	b.writeCalls++
	b.lastWrite = req
	if b.err != nil {
		return storage.FileWriteResult{}, b.err
	}
	return b.writeResult, nil
}

func (b *recordingStorageFilesBroker) DeleteFile(_ context.Context, req storage.FileDeleteRequest) error {
	b.deleteCalls++
	b.lastDelete = req
	return b.err
}

func (b *recordingStorageFilesBroker) ListFiles(_ context.Context, req storage.FileListRequest) (storage.FileListResult, error) {
	b.listCalls++
	b.lastList = req
	if b.err != nil {
		return storage.FileListResult{}, b.err
	}
	return b.listResult, nil
}

func (b *recordingStorageKVBroker) GetKV(_ context.Context, req storage.KVGetRequest) (storage.KVGetResult, error) {
	b.getCalls++
	b.lastGet = req
	if b.err != nil {
		return storage.KVGetResult{}, b.err
	}
	return b.getResult, nil
}

func (b *recordingStorageKVBroker) PutKV(_ context.Context, req storage.KVPutRequest) (storage.KVPutResult, error) {
	b.putCalls++
	b.lastPut = req
	if b.err != nil {
		return storage.KVPutResult{}, b.err
	}
	return b.putResult, nil
}

func (b *recordingStorageKVBroker) DeleteKV(_ context.Context, req storage.KVDeleteRequest) error {
	b.deleteCalls++
	b.lastDelete = req
	return b.err
}

func (b *recordingStorageKVBroker) ListKV(_ context.Context, req storage.KVListRequest) (storage.KVListResult, error) {
	b.listCalls++
	b.lastList = req
	if b.err != nil {
		return storage.KVListResult{}, b.err
	}
	return b.listResult, nil
}

func (b *recordingStorageSQLiteBroker) ExecSQLite(_ context.Context, req storage.SQLiteExecRequest) (storage.SQLiteExecResult, error) {
	b.execCalls++
	b.lastExec = req
	if b.err != nil {
		return storage.SQLiteExecResult{}, b.err
	}
	return b.execResult, nil
}

func (b *recordingStorageSQLiteBroker) QuerySQLite(_ context.Context, req storage.SQLiteQueryRequest) (storage.SQLiteQueryResult, error) {
	b.queryCalls++
	b.lastQuery = req
	if b.err != nil {
		return storage.SQLiteQueryResult{}, b.err
	}
	return b.queryResult, nil
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
	return []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":%q,"artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo","export":"redevplugin_worker_invoke","params":{"message":"hello"}}`, fixturePackageHash, fixtureArtifact, fixtureArtifactSHA))
}

func stopRuntimeSupervisor(t *testing.T, supervisor *ProcessSupervisor) {
	t.Helper()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}
