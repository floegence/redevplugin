package runtimeclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestMain(m *testing.M) {
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_HELPER") == "1" {
		writeRuntimeHelperStartMarker()
		runRuntimeClientHelper()
		return
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER") == "1" {
		writeRuntimeHelperStartMarker()
		os.Stdout.WriteString("not-json\n")
		time.Sleep(10 * time.Second)
		return
	}
	os.Exit(m.Run())
}

func writeRuntimeHelperStartMarker() {
	if path := os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_START_MARKER"); path != "" {
		_ = os.WriteFile(path, []byte("started"), 0o600)
	}
}

func TestReadBoundedIPCLineRejectsOversizedFrame(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("123456789\n"))
	_, err := readBoundedIPCLine(reader, 8)
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("readBoundedIPCLine() error = %v, want size limit", err)
	}
}

func TestReadIPCFrameRejectsNonCanonicalJSON(t *testing.T) {
	tests := []struct {
		name  string
		frame string
	}{
		{name: "unknown field", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","request_id":"r1","payload":{},"future":true}`},
		{name: "duplicate frame type", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","frame_type":"heartbeat","request_id":"r1","payload":{}}`},
		{name: "case folded request id", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","request_id":"r1","REQUEST_ID":"r2","payload":{}}`},
		{name: "case alias only", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","REQUEST_ID":"r1","payload":{}}`},
		{name: "duplicate nested payload key", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","request_id":"r1","payload":{"ok":true,"ok":false}}`},
		{name: "trailing JSON", frame: `{"ipc_version":"rust-ipc-v4","frame_type":"diagnostic","request_id":"r1","payload":{}} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readIPCFrame(bufio.NewReader(strings.NewReader(test.frame + "\n"))); err == nil {
				t.Fatal("readIPCFrame() accepted non-canonical JSON")
			}
		})
	}
}

func TestValidateHelloAckRejectsNonCanonicalPayload(t *testing.T) {
	baseFrame := ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeHelloAck,
		RequestID:           "hello_1",
		RuntimeGenerationID: "g1",
	}
	for _, payload := range []string{
		`{"runtime_version":"1.0.0","rust_ipc_version":"rust-ipc-v4","wasm_abi_version":"redevplugin-wasm-worker-v2","channel_nonce":"nonce_1234567890123456","future":true}`,
		`{"runtime_version":"1.0.0","runtime_version":"2.0.0","rust_ipc_version":"rust-ipc-v4","wasm_abi_version":"redevplugin-wasm-worker-v2","channel_nonce":"nonce_1234567890123456"}`,
		`{"runtime_version":"1.0.0","RUNTIME_VERSION":"2.0.0","rust_ipc_version":"rust-ipc-v4","wasm_abi_version":"redevplugin-wasm-worker-v2","channel_nonce":"nonce_1234567890123456"}`,
		`{"RUNTIME_VERSION":"1.0.0","rust_ipc_version":"rust-ipc-v4","wasm_abi_version":"redevplugin-wasm-worker-v2","channel_nonce":"nonce_1234567890123456"}`,
		`{"runtime_version":"1.0.0","rust_ipc_version":"rust-ipc-v4","wasm_abi_version":"redevplugin-wasm-worker-v2","channel_nonce":"nonce_1234567890123456"} {}`,
	} {
		frame := baseFrame
		frame.Payload = json.RawMessage(payload)
		if _, err := validateHelloAck(
			"hello_1",
			"g1",
			"nonce_1234567890123456",
			testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64)),
			DefaultRuntimeLimits(),
			frame,
		); !errors.Is(err, ErrRuntimeHandshake) {
			t.Fatalf("validateHelloAck(%s) error = %v, want ErrRuntimeHandshake", payload, err)
		}
	}
}

func TestStrictJSONAllowsCaseDistinctDynamicMapKeys(t *testing.T) {
	var payload struct {
		Headers map[string]string `json:"headers"`
	}
	if err := decodeStrictJSON([]byte(`{"headers":{"Key":"first","key":"second"}}`), &payload); err != nil {
		t.Fatalf("decodeStrictJSON() error = %v", err)
	}
	if payload.Headers["Key"] != "first" || payload.Headers["key"] != "second" {
		t.Fatalf("headers = %#v", payload.Headers)
	}
}

func TestHostcallHandlersRejectNonCanonicalRequests(t *testing.T) {
	health := Health{RuntimeGenerationID: "g1"}
	allowedArtifact := &ArtifactRequest{}
	allowedInvocation := &workerInvocationContext{}
	tests := []struct {
		name     string
		wantCode string
		knownKey string
		call     func(*ProcessSupervisor, io.Writer, ipcFrame) error
	}{
		{name: "open handle", wantCode: "ARTIFACT_REQUEST_INVALID", knownKey: "package_hash", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToOpenHandle(context.Background(), writer, "g1", frame, allowedArtifact)
		}},
		{name: "validate handle grant", wantCode: "HANDLE_GRANT_REQUEST_INVALID", knownKey: "handle_grant_token", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToValidateHandleGrant(context.Background(), writer, "g1", frame, allowedArtifact)
		}},
		{name: "storage file", wantCode: "STORAGE_FILE_REQUEST_INVALID", knownKey: "handle_grant_token", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToStorageFile(context.Background(), writer, health, frame, allowedInvocation)
		}},
		{name: "storage kv", wantCode: "STORAGE_KV_REQUEST_INVALID", knownKey: "handle_grant_token", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToStorageKV(context.Background(), writer, health, frame, allowedInvocation)
		}},
		{name: "storage sqlite", wantCode: "STORAGE_SQLITE_REQUEST_INVALID", knownKey: "handle_grant_token", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToStorageSQLite(context.Background(), writer, health, frame, allowedInvocation)
		}},
		{name: "network grant", wantCode: "NETWORK_GRANT_REQUEST_INVALID", knownKey: "plugin_instance_id", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToNetworkGrant(context.Background(), writer, health, frame, allowedInvocation)
		}},
		{name: "network execute", wantCode: "NETWORK_EXECUTE_REQUEST_INVALID", knownKey: "plugin_instance_id", call: func(supervisor *ProcessSupervisor, writer io.Writer, frame ipcFrame) error {
			return supervisor.respondToNetworkExecute(context.Background(), writer, health, frame, allowedInvocation)
		}},
	}
	for _, test := range tests {
		for _, request := range []struct {
			name    string
			payload string
		}{
			{name: "unknown field", payload: `{"future":true}`},
			{name: "duplicate field", payload: fmt.Sprintf(`{"%s":"first","%s":"second"}`, test.knownKey, test.knownKey)},
			{name: "case folded field", payload: fmt.Sprintf(`{"%s":"first","%s":"second"}`, test.knownKey, strings.ToUpper(test.knownKey))},
			{name: "case alias only", payload: fmt.Sprintf(`{"%s":"first"}`, strings.ToUpper(test.knownKey))},
			{name: "trailing JSON", payload: `{}` + ` {}`},
		} {
			t.Run(test.name+"/"+request.name, func(t *testing.T) {
				var output bytes.Buffer
				frame := ipcFrame{RequestID: "hostcall_1", Payload: json.RawMessage(request.payload)}
				if err := test.call(&ProcessSupervisor{}, &output, frame); err != nil {
					t.Fatalf("handler error = %v", err)
				}
				response, err := readIPCFrame(bufio.NewReader(&output))
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				var failure struct {
					OK          bool              `json:"ok"`
					Code        string            `json:"code"`
					Message     string            `json:"message"`
					ErrorOrigin WorkerErrorOrigin `json:"error_origin"`
				}
				if err := decodeStrictJSON(response.Payload, &failure); err != nil {
					t.Fatalf("decode response payload: %v", err)
				}
				if failure.OK || failure.Code != test.wantCode || failure.ErrorOrigin != WorkerErrorOriginHostcall {
					t.Fatalf("failure = %#v, want code %s", failure, test.wantCode)
				}
			})
		}
	}
}

func TestBrokerResponsesFailClosedAboveWASMHostcallLimit(t *testing.T) {
	tests := []struct {
		name     string
		wantCode string
		write    func(*bytes.Buffer) error
	}{
		{
			name:     "storage file",
			wantCode: "STORAGE_FILE_TOO_LARGE",
			write: func(buffer *bytes.Buffer) error {
				return (&ProcessSupervisor{}).writeStorageFileResponse(buffer, "g1", ipcFrame{RequestID: "r1", ParentRequestID: "invoke1"}, storageFileResponsePayload{
					Operation: "read", OK: true, DataBase64: strings.Repeat("A", maxWASMHostcallResponseBytes+1),
					Usage: &storage.Usage{PluginInstanceID: "plugini_1", StoreID: "workspace", QuotaBytes: 1, QuotaFiles: 1},
				})
			},
		},
		{
			name:     "storage kv",
			wantCode: "STORAGE_KV_VALUE_TOO_LARGE",
			write: func(buffer *bytes.Buffer) error {
				return (&ProcessSupervisor{}).writeStorageKVResponse(buffer, "g1", ipcFrame{RequestID: "r1", ParentRequestID: "invoke1"}, storageKVResponsePayload{
					Operation: "get", OK: true, ValueBase64: strings.Repeat("A", maxWASMHostcallResponseBytes+1),
					Usage: &storage.Usage{PluginInstanceID: "plugini_1", StoreID: "settings", QuotaBytes: 1, QuotaFiles: 1},
				})
			},
		},
		{
			name:     "storage sqlite",
			wantCode: "STORAGE_SQLITE_RESULT_TOO_LARGE",
			write: func(buffer *bytes.Buffer) error {
				large := strings.Repeat("x", maxWASMHostcallResponseBytes+1)
				rows := [][]storageSQLiteValueIPC{{{Text: &large}}}
				return (&ProcessSupervisor{}).writeStorageSQLiteResponse(buffer, "g1", ipcFrame{RequestID: "r1", ParentRequestID: "invoke1"}, storageSQLiteResponsePayload{
					Operation: "query", OK: true, Rows: &rows, Columns: &[]string{}, Usage: &storage.Usage{PluginInstanceID: "plugini_1", StoreID: "db", QuotaBytes: 1, QuotaFiles: 1},
				})
			},
		},
		{
			name:     "network",
			wantCode: "NETWORK_RESPONSE_TOO_LARGE",
			write: func(buffer *bytes.Buffer) error {
				return (&ProcessSupervisor{}).writeNetworkExecuteResponse(buffer, "g1", ipcFrame{RequestID: "r1", ParentRequestID: "invoke1"}, networkExecuteResponsePayload{
					OK: true, BodyBase64: strings.Repeat("A", maxWASMHostcallResponseBytes+1),
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := tc.write(&output); err != nil {
				t.Fatalf("write response error = %v", err)
			}
			if output.Len() > maxWASMHostcallResponseBytes {
				t.Fatalf("bounded response length = %d, want <= %d", output.Len(), maxWASMHostcallResponseBytes)
			}
			if !strings.Contains(output.String(), tc.wantCode) ||
				!strings.Contains(output.String(), `"error_origin":"hostcall"`) ||
				!strings.Contains(output.String(), `"parent_request_id":"invoke1"`) {
				t.Fatalf("bounded response = %s, want %s hostcall error", output.String(), tc.wantCode)
			}
		})
	}
}

func TestStorageSuccessResponsesUseOperationSpecificClosedWireShapes(t *testing.T) {
	usage := &storage.Usage{
		PluginInstanceID: "plugini_1", StoreID: "workspace",
		UsageBytes: 1, QuotaBytes: 100, UsageFiles: 1, QuotaFiles: 10,
	}
	rowsAffected := int64(1)
	columns := []string{"title"}
	text := "note"
	rows := [][]storageSQLiteValueIPC{{{Text: &text}}}
	tests := []struct {
		name string
		want []string
		raw  func() ([]byte, error)
	}{
		{name: "file read", want: []string{"ok", "path", "data_base64", "size_bytes", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "read", OK: true, Path: "a.txt", DataBase64: "YQ==", SizeBytes: 1, Usage: usage})
		}},
		{name: "file write", want: []string{"ok", "path", "size_bytes", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "write", OK: true, Path: "a.txt", SizeBytes: 1, Usage: usage})
		}},
		{name: "file delete", want: []string{"ok", "path"}, raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "delete", OK: true, Path: "a.txt"})
		}},
		{name: "file list", want: []string{"ok", "path", "entries", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "list", OK: true, Entries: []storage.FileEntry{}, Usage: usage})
		}},
		{name: "kv get", want: []string{"ok", "key", "value_base64", "size_bytes", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "get", OK: true, Key: "theme", ValueBase64: "ZGFyaw==", SizeBytes: 4, Usage: usage})
		}},
		{name: "kv put", want: []string{"ok", "key", "size_bytes", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "put", OK: true, Key: "theme", SizeBytes: 4, Usage: usage})
		}},
		{name: "kv delete", want: []string{"ok", "key"}, raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "delete", OK: true, Key: "theme"})
		}},
		{name: "kv list", want: []string{"ok", "prefix", "entries", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "list", OK: true, Prefix: "settings/", Entries: []storage.KVEntry{}, Usage: usage})
		}},
		{name: "sqlite exec", want: []string{"ok", "database", "rows_affected", "last_insert_id", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageSQLiteHostcallPayload(storageSQLiteResponsePayload{Operation: "exec", OK: true, Database: "plugin.sqlite", RowsAffected: &rowsAffected, LastInsertID: 7, Usage: usage})
		}},
		{name: "sqlite query", want: []string{"ok", "database", "columns", "rows", "usage"}, raw: func() ([]byte, error) {
			return marshalStorageSQLiteHostcallPayload(storageSQLiteResponsePayload{Operation: "query", OK: true, Database: "plugin.sqlite", Columns: &columns, Rows: &rows, Usage: usage})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := test.raw()
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded) != len(test.want) {
				t.Fatalf("response keys = %v, want %v; payload=%s", decoded, test.want, raw)
			}
			for _, key := range test.want {
				if _, ok := decoded[key]; !ok {
					t.Fatalf("response missing %q: %s", key, raw)
				}
			}
		})
	}
}

func TestStorageSuccessResponsesRejectMixedOrIncompleteOperations(t *testing.T) {
	usage := &storage.Usage{PluginInstanceID: "plugini_1", StoreID: "workspace", QuotaBytes: 100, QuotaFiles: 10}
	rowsAffected := int64(1)
	columns := []string{"title"}
	rows := [][]storageSQLiteValueIPC{}
	tests := []struct {
		name string
		raw  func() ([]byte, error)
	}{
		{name: "file read with list fields", raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "read", OK: true, Entries: []storage.FileEntry{}, Usage: usage})
		}},
		{name: "file write with read fields", raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "write", OK: true, DataBase64: "YQ==", Usage: usage})
		}},
		{name: "file list missing usage", raw: func() ([]byte, error) {
			return marshalStorageFileHostcallPayload(storageFileResponsePayload{Operation: "list", OK: true, Entries: []storage.FileEntry{}})
		}},
		{name: "kv get with list fields", raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "get", OK: true, Entries: []storage.KVEntry{}, Usage: usage})
		}},
		{name: "kv put with get fields", raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "put", OK: true, ValueBase64: "YQ==", Usage: usage})
		}},
		{name: "kv list missing usage", raw: func() ([]byte, error) {
			return marshalStorageKVHostcallPayload(storageKVResponsePayload{Operation: "list", OK: true, Entries: []storage.KVEntry{}})
		}},
		{name: "sqlite exec with query fields", raw: func() ([]byte, error) {
			return marshalStorageSQLiteHostcallPayload(storageSQLiteResponsePayload{Operation: "exec", OK: true, RowsAffected: &rowsAffected, Columns: &columns, Rows: &rows, Usage: usage})
		}},
		{name: "sqlite query with exec fields", raw: func() ([]byte, error) {
			return marshalStorageSQLiteHostcallPayload(storageSQLiteResponsePayload{Operation: "query", OK: true, RowsAffected: &rowsAffected, Columns: &columns, Rows: &rows, Usage: usage})
		}},
		{name: "sqlite query missing rows", raw: func() ([]byte, error) {
			return marshalStorageSQLiteHostcallPayload(storageSQLiteResponsePayload{Operation: "query", OK: true, Columns: &columns, Usage: usage})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if raw, err := test.raw(); err == nil {
				t.Fatalf("accepted invalid success response: %s", raw)
			}
		})
	}
}

func TestProcessSupervisorLifecycleAndDiagnostics(t *testing.T) {
	const maxHeartbeatStaleness = 5 * time.Second
	store := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: maxHeartbeatStaleness,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		Diagnostics:           store,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Ready ||
		health.RuntimeInstanceID == "" ||
		health.RuntimeGenerationID == "" ||
		health.Descriptor.Version().String() != version.RuntimeVersion ||
		health.Descriptor.Target() != testRuntimeTarget ||
		health.Descriptor.IPCVersion() != version.RustIPCVersion ||
		health.Descriptor.WASMABIVersion() != version.WASMABIVersion {
		t.Fatalf("health mismatch: %#v", health)
	}
	heartbeat, err := supervisor.Heartbeat(context.Background())
	if err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}
	if heartbeat.RuntimeGenerationID != health.RuntimeGenerationID ||
		heartbeat.RuntimeUnixNano <= 0 ||
		heartbeat.MaxStalenessMillis != int64(maxHeartbeatStaleness/time.Millisecond) ||
		heartbeat.HostSentUnixNanoEcho <= 0 {
		t.Fatalf("heartbeat mismatch: %#v", heartbeat)
	}
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
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
	revokeResult, err := supervisor.Revoke(context.Background(), "plugini_1", 3)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revokeResult.PluginInstanceID != "plugini_1" ||
		revokeResult.RevokeEpoch != 3 ||
		revokeResult.ClosedSocketCount != 2 ||
		revokeResult.ClosedStreamCount != 3 ||
		revokeResult.ClosedStorageHandleCount != 4 {
		t.Fatalf("Revoke() result mismatch: %#v", revokeResult)
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
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{}, "worker.echo", nil); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker(after stop) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestProcessSupervisorRuntimeLeaseReplayStoreRejectsDuplicateBeforeIPC(t *testing.T) {
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		Diagnostics:           diagnostics,
		RuntimeLeaseReplays:   NewMemoryRuntimeLeaseReplayStore(),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{
		LeaseID:             "rel_replay",
		LeaseNonce:          "nonce_replay_1234567890",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		Method:              "worker.echo",
		PolicyRevision:      11,
		ManagementRevision:  12,
		RevokeEpoch:         13,
		ExpiresAtUnixMillis: time.Now().Add(time.Minute).UnixMilli(),
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), lease, "worker.echo", workerInvocationFixture()); err != nil {
		t.Fatalf("InvokeWorker(first) error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), lease, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeLeaseReplay) {
		t.Fatalf("InvokeWorker(replay) error = %v, want %v", err, ErrRuntimeLeaseReplay)
	}
	waitForDiagnostic(t, diagnostics, "plugin.runtime.lease.replayed")
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorMapsRuntimeRequestFailure(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_FAIL_INVOKE=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestWorkerExecutionErrorPreservesStableWorkerFailure(t *testing.T) {
	err := (runtimeResponsePayload{Code: "NOTE_NOT_FOUND", Message: "note was not found", ErrorOrigin: WorkerErrorOriginPlugin}).workerExecutionError()
	var workerErr *WorkerExecutionError
	if !errors.As(err, &workerErr) {
		t.Fatalf("worker execution error type = %T, want *WorkerExecutionError", err)
	}
	if workerErr.Code != "NOTE_NOT_FOUND" || workerErr.Message != "note was not found" || workerErr.Origin != WorkerErrorOriginPlugin {
		t.Fatalf("worker execution error = %#v", workerErr)
	}
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("worker execution error must remain a runtime request failure: %v", err)
	}
}

func TestWorkerExecutionErrorRejectsMissingOrUnknownOrigin(t *testing.T) {
	for _, origin := range []WorkerErrorOrigin{"", "worker"} {
		err := (runtimeResponsePayload{Code: "RUNTIME_CAPABILITY_REVOKED", Message: "spoofed", ErrorOrigin: origin}).workerExecutionError()
		var workerErr *WorkerExecutionError
		if errors.As(err, &workerErr) {
			t.Fatalf("origin %q produced trusted worker error %#v", origin, workerErr)
		}
		if !errors.Is(err, ErrRuntimeIPCUnavailable) {
			t.Fatalf("origin %q error = %v, want ErrRuntimeIPCUnavailable", origin, err)
		}
	}
}

func TestDecodeRuntimeResponseRejectsNonCanonicalPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "removed error field", payload: `{"ok":false,"error":"removed","code":"FAILED","message":"failed","error_origin":"runtime"}`},
		{name: "unknown field", payload: `{"ok":true,"result":{},"future":true}`},
		{name: "duplicate ok", payload: `{"ok":true,"ok":false,"result":{}}`},
		{name: "case folded ok", payload: `{"ok":true,"OK":false,"result":{}}`},
		{name: "case alias only", payload: `{"OK":true,"result":{}}`},
		{name: "duplicate code", payload: `{"ok":false,"code":"FAILED","code":"SPOOFED","message":"failed","error_origin":"runtime"}`},
		{name: "trailing JSON", payload: `{"ok":true,"result":{}} {}`},
		{name: "missing ok", payload: `{"result":{}}`},
		{name: "success missing result", payload: `{"ok":true}`},
		{name: "success with code", payload: `{"ok":true,"result":{},"code":"FAILED"}`},
		{name: "success with message", payload: `{"ok":true,"result":{},"message":"failed"}`},
		{name: "success with origin", payload: `{"ok":true,"result":{},"error_origin":"runtime"}`},
		{name: "failure with result", payload: `{"ok":false,"result":{},"code":"FAILED","message":"failed","error_origin":"runtime"}`},
		{name: "failure missing code", payload: `{"ok":false,"message":"failed","error_origin":"runtime"}`},
		{name: "failure empty code", payload: `{"ok":false,"code":" ","message":"failed","error_origin":"runtime"}`},
		{name: "failure missing message", payload: `{"ok":false,"code":"FAILED","error_origin":"runtime"}`},
		{name: "failure empty message", payload: `{"ok":false,"code":"FAILED","message":" ","error_origin":"runtime"}`},
		{name: "failure missing origin", payload: `{"ok":false,"code":"FAILED","message":"failed"}`},
		{name: "failure invalid origin", payload: `{"ok":false,"code":"FAILED","message":"failed","error_origin":"worker"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(test.payload)})
			if !errors.Is(err, ErrRuntimeIPCUnavailable) {
				t.Fatalf("decodeRuntimeResponse() error = %v, want ErrRuntimeIPCUnavailable", err)
			}
		})
	}
}

func TestDecodeRuntimeResponseAcceptsClosedSuccessAndFailure(t *testing.T) {
	success, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(`{"ok":true,"result":{"data":{"ok":true}}}`)})
	if err != nil || !success.OK || string(success.Result) != `{"data":{"ok":true}}` {
		t.Fatalf("success = %#v, error = %v", success, err)
	}
	failure, err := decodeRuntimeResponse(ipcFrame{Payload: json.RawMessage(`{"ok":false,"code":"FAILED","message":"failed","error_origin":"runtime"}`)})
	if err != nil || failure.OK || failure.Code != "FAILED" || failure.Message != "failed" || failure.ErrorOrigin != WorkerErrorOriginRuntime {
		t.Fatalf("failure = %#v, error = %v", failure, err)
	}
}

func TestRuntimeLimitsMustBeExplicitAndValid(t *testing.T) {
	if _, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{RuntimePath: os.Args[0], StreamSink: &recordingRuntimeStreamSink{}}); err == nil {
		t.Fatal("NewProcessSupervisor() accepted zero runtime limits")
	}
	limits := DefaultRuntimeLimits()
	if err := ValidateRuntimeLimits(limits); err != nil {
		t.Fatalf("DefaultRuntimeLimits() error = %v", err)
	}
	if _, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                limits,
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	}); !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("NewProcessSupervisor(without host services) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                limits,
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if supervisor.limits != limits {
		t.Fatalf("runtime limits = %#v, want %#v", supervisor.limits, limits)
	}
	invalid := []RuntimeLimits{
		{},
		{WorkerCount: 65, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 65, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 2, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1025, ModuleCacheSourceBytes: 1},
		{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 0},
	}
	for _, limits := range invalid {
		if err := ValidateRuntimeLimits(limits); err == nil {
			t.Fatalf("ValidateRuntimeLimits(%#v) accepted invalid limits", limits)
		}
	}
}

func TestProcessSupervisorTimingMustBeExplicitAndValid(t *testing.T) {
	valid := ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*ProcessSupervisorOptions)
	}{
		{name: "zero handshake timeout", mutate: func(options *ProcessSupervisorOptions) { options.HandshakeTimeout = 0 }},
		{name: "negative handshake timeout", mutate: func(options *ProcessSupervisorOptions) { options.HandshakeTimeout = -time.Second }},
		{name: "zero heartbeat interval", mutate: func(options *ProcessSupervisorOptions) { options.HeartbeatInterval = 0 }},
		{name: "negative heartbeat interval", mutate: func(options *ProcessSupervisorOptions) { options.HeartbeatInterval = -time.Second }},
		{name: "zero heartbeat staleness", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = 0 }},
		{name: "negative heartbeat staleness", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = -time.Second }},
		{name: "staleness below interval", mutate: func(options *ProcessSupervisorOptions) { options.MaxHeartbeatStaleness = time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			test.mutate(&options)
			if _, err := newTestProcessSupervisor(t, options); err == nil {
				t.Fatal("NewProcessSupervisor() accepted invalid runtime timing")
			}
		})
	}
}

func TestProcessSupervisorRequiresExplicitDescriptor(t *testing.T) {
	_, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("NewProcessSupervisor() error = %v, want ErrRuntimeDescriptorInvalid", err)
	}
}

func TestProcessSupervisorRejectsDigestMismatchBeforeStartingProcess(t *testing.T) {
	markerPath := filepath.Join(t.TempDir(), "runtime-started")
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Descriptor:            testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("0", 64)),
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_START_MARKER="+markerPath),
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeArtifactDigest) {
		t.Fatalf("Start() error = %v, want ErrRuntimeArtifactDigest", err)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime helper process was started before digest validation: %v", err)
	}
}

func TestProcessSupervisorRejectsHelloDescriptorMismatch(t *testing.T) {
	for _, test := range []struct {
		name string
		env  string
	}{
		{name: "runtime version", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_RUNTIME_VERSION=99.0.0"},
		{name: "build metadata", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_RUNTIME_VERSION=" + version.RuntimeVersion + "+different-build"},
		{name: "target os", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET_OS=linux"},
		{name: "target arch", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET_ARCH=amd64"},
		{name: "ipc", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_IPC_VERSION=rust-ipc-v99"},
		{name: "wasm abi", env: "REDEVPLUGIN_RUNTIMECLIENT_ACK_WASM_ABI_VERSION=redevplugin-wasm-worker-v99"},
	} {
		t.Run(test.name, func(t *testing.T) {
			supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
				RuntimePath:           os.Args[0],
				Args:                  []string{"-test.run=TestMain"},
				Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", test.env),
				Limits:                DefaultRuntimeLimits(),
				StreamSink:            &recordingRuntimeStreamSink{},
				HandshakeTimeout:      5 * time.Second,
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeHandshake) || !errors.Is(err, ErrRuntimeDescriptorMismatch) {
				t.Fatalf("Start() error = %v, want handshake descriptor mismatch", err)
			}
			health, healthErr := supervisor.Health(context.Background())
			if healthErr != nil {
				t.Fatal(healthErr)
			}
			if health.Ready {
				t.Fatalf("mismatched hello left runtime ready: %#v", health)
			}
		})
	}
}

func TestProcessSupervisorRejectsTypedNilHostStreamSink(t *testing.T) {
	var typedNil *recordingRuntimeStreamSink
	_, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		StreamSink:            typedNil,
	})
	if !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("NewProcessSupervisor(typed nil stream sink) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
}

func TestRuntimeAdmissionCancellationDoesNotConsumeCapacity(t *testing.T) {
	controller := newRuntimeAdmissionController(RuntimeLimits{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1})
	releaseFirst, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.acquire(ctx, "plugini_waiting"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire() error = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseFirst()
	releaseSecond()
	release, err := controller.acquire(context.Background(), "plugini_waiting")
	if err != nil {
		t.Fatalf("acquire() after cancellation error = %v", err)
	}
	release()
}

func TestRuntimeAdmissionPreservesQueueCapacityForOtherPlugins(t *testing.T) {
	controller := newRuntimeAdmissionController(RuntimeLimits{WorkerCount: 8, QueueCapacity: 32, PerPluginConcurrency: 4})
	releases := make([]func(), 0, 9)
	for index := 0; index < 8; index++ {
		release, err := controller.acquire(context.Background(), "plugini_saturated")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.acquire(ctx, "plugini_saturated"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ninth saturated-plugin acquire error = %v, want %v", err, context.DeadlineExceeded)
	}
	releaseOther, err := controller.acquire(context.Background(), "plugini_other")
	if err != nil {
		t.Fatalf("other plugin acquire error = %v", err)
	}
	releases = append(releases, releaseOther)
	for _, release := range releases {
		release()
	}
}

func TestProcessSupervisorMultiplexesSameShardInvocations(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                RuntimeLimits{WorkerCount: 2, QueueCapacity: 2, PerPluginConcurrency: 2, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1 << 20},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_MULTIPLEX=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })

	slowDone := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_multiplex_slow"}, "worker.echo", workerInvocationFixture())
		slowDone <- err
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	fastDone := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_multiplex_fast"}, "worker.echo", workerInvocationFixture())
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("fast invocation error = %v", err)
		}
	case err := <-slowDone:
		t.Fatalf("slow invocation completed before fast invocation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("multiplexed invocations did not complete")
	}
	if err := <-slowDone; err != nil {
		t.Fatalf("slow invocation error = %v", err)
	}
}

func TestProcessSupervisorControlIPCRemainsAvailableWhenInvocationAdmissionIsFull(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                RuntimeLimits{WorkerCount: 1, QueueCapacity: 1, PerPluginConcurrency: 1, ModuleCacheEntries: 1, ModuleCacheSourceBytes: 1 << 20},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })

	activeDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_control_active"}, "worker.echo", workerInvocationFixture())
		activeDone <- invokeErr
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	pendingDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_control_pending"}, "worker.echo", workerInvocationFixture())
		pendingDone <- invokeErr
	}()
	waitForInvocationAdmissionCount(t, supervisor, 2)

	controlCtx, cancelControl := context.WithTimeout(context.Background(), time.Second)
	defer cancelControl()
	if _, err := supervisor.Heartbeat(controlCtx); err != nil {
		t.Fatalf("Heartbeat() while invocation admission was full: %v", err)
	}
	if _, err := supervisor.Revoke(controlCtx, "plugini_1", 2); err != nil {
		t.Fatalf("Revoke() while invocation admission was full: %v", err)
	}
	for index, done := range []<-chan error{activeDone, pendingDone} {
		select {
		case invokeErr := <-done:
			if !errors.Is(invokeErr, ErrRuntimeRequestFailed) {
				t.Fatalf("invocation %d error = %v, want %v", index, invokeErr, ErrRuntimeRequestFailed)
			}
		case <-time.After(time.Second):
			t.Fatalf("invocation %d did not exit after revoke", index)
		}
	}
	waitForInvocationAdmissionCount(t, supervisor, 0)
}

func TestProcessSupervisorDrainsCanceledInvocationWithoutInvalidatingRuntime(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS=80"),
		Diagnostics:           store,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := supervisor.invokeWorkerForTest(ctx, Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("InvokeWorker() canceled error = %v, want %v", err, context.DeadlineExceeded)
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready after draining a canceled invocation: %#v", health)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_2",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
	}, "worker.echo", workerInvocationFixture()); err != nil {
		t.Fatalf("InvokeWorker(after canceled invocation) error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRevokeUsesIndependentControlChannelDuringInvocation(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE=1",
		),
		Diagnostics: store,
		StreamSink:  &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_busy",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
		}, "worker.echo", workerInvocationFixture())
		done <- err
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result, err := supervisor.Revoke(ctx, "plugini_1", 4)
	if err != nil {
		t.Fatalf("Revoke(during invocation) error = %v", err)
	}
	if result.PluginInstanceID != "plugini_1" || result.RevokeEpoch != 4 {
		t.Fatalf("Revoke(during invocation) result = %#v", result)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrRuntimeRequestFailed) {
			t.Fatalf("InvokeWorker(after revoke) error = %v, want %v", err, ErrRuntimeRequestFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("InvokeWorker did not observe the concurrent revoke")
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready after a successful concurrent revoke: %#v", health)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorHeartbeatInvalidatesStaleRuntime(t *testing.T) {
	store := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BLOCK_HEARTBEAT=1"),
		Diagnostics:           store,
		HeartbeatInterval:     10 * time.Millisecond,
		MaxHeartbeatStaleness: 30 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForDiagnostic(t, store, "plugin.runtime.ipc.invalidated")
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime should be marked not ready after stale heartbeat: %#v", health)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorStopWaitsForInvalidatedProcessBeforeRestart(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}

	health := Health{RuntimeGenerationID: "generation_invalidated", Ready: true}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.cmd = &exec.Cmd{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = health
	supervisor.mu.Unlock()

	supervisor.invalidateRuntimeAfterIPCFailure(health, "test invalidation", errors.New("ipc failed"))
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("runtime invalidation did not cancel the process context")
	}

	stopDone := make(chan error, 1)
	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopDone <- supervisor.Stop(stopCtx)
	}()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() returned before invalidated process cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	supervisor.mu.Lock()
	supervisor.cmd = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() after invalidated process cleanup error = %v", err)
	}

	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() after invalidated process cleanup error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorConcurrentStopWaitersObserveSameExit(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.cmd = &exec.Cmd{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = Health{RuntimeGenerationID: "generation_concurrent_stop", Ready: true}
	supervisor.mu.Unlock()

	const waiters = 16
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- supervisor.Stop(ctx)
		}()
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("concurrent Stop() calls did not cancel the process")
	}
	select {
	case err := <-results:
		t.Fatalf("Stop() returned before process exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	supervisor.mu.Lock()
	supervisor.cmd = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	for index := 0; index < waiters; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("Stop() waiter %d error = %v", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("Stop() waiter %d did not observe process exit", index)
		}
	}
}

func TestProcessSupervisorStopMakesGenerationUnavailableBeforeExit(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Limits:                DefaultRuntimeLimits(),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	exit := &processExit{done: make(chan struct{})}
	canceled := make(chan struct{})
	var cancelOnce sync.Once
	supervisor.mu.Lock()
	supervisor.cmd = &exec.Cmd{}
	supervisor.cancel = func() { cancelOnce.Do(func() { close(canceled) }) }
	supervisor.exit = exit
	supervisor.health = Health{
		RuntimeInstanceID: "runtime_stopping", RuntimeGenerationID: "generation_stopping",
		IPCChannelID: "ipc_stopping", Ready: true,
	}
	supervisor.mu.Unlock()

	stopDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopDone <- supervisor.Stop(ctx)
	}()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Stop() did not cancel the runtime")
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("Health() remained ready while Stop() waited for process exit: %#v", health)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Start() during Stop() error = %v, want %v", err, ErrRuntimeNotReady)
	}
	if _, err := supervisor.InvokeWorker(context.Background(), Lease{}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker() during Stop() error = %v, want %v", err, ErrRuntimeNotReady)
	}
	supervisor.admission.mu.Lock()
	pending := supervisor.admission.active
	supervisor.admission.mu.Unlock()
	if pending != 0 {
		t.Fatalf("Stop-in-progress invocation admission count = %d, want 0", pending)
	}

	supervisor.mu.Lock()
	supervisor.cmd = nil
	supervisor.cancel = nil
	supervisor.exit = nil
	supervisor.mu.Unlock()
	close(exit.done)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
}

func TestProcessSupervisorHeartbeatContinuesWhileIPCRequestIsInFlight(t *testing.T) {
	store := observability.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:           DefaultRuntimeLimits(),
		HandshakeTimeout: 5 * time.Second,
		RuntimePath:      os.Args[0],
		Args:             []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS=200",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_HEARTBEAT_DURING_INVOKE=1",
		),
		Diagnostics:           store,
		HeartbeatInterval:     10 * time.Millisecond,
		MaxHeartbeatStaleness: 30 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	invokeDone := make(chan error, 1)
	go func() {
		_, invokeErr := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_heartbeat_busy",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
		}, "worker.echo", workerInvocationFixture())
		invokeDone <- invokeErr
	}()
	waitForSustainedIPCLock(t, supervisor, 20*time.Millisecond)
	time.Sleep(3 * supervisor.maxHeartbeatStaleness)
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready {
		t.Fatalf("runtime should remain ready while a valid IPC request is in flight: %#v", health)
	}
	select {
	case err := <-invokeDone:
		if err != nil {
			t.Fatalf("InvokeWorker() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("InvokeWorker() did not finish")
	}
	if _, err := supervisor.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat(after in-flight request) error = %v", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsRevokeWhenRuntimeIsNotReady(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Revoke(context.Background(), "plugini_1", 1); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Revoke(not ready) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestDecodeRevokeResultRequiresStructuredCounters(t *testing.T) {
	_, err := decodeRevokeResult(json.RawMessage(`{"plugin_instance_id":"plugini_1","revoke_epoch":3}`), "plugini_1", 3)
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeRevokeResult(missing counters) error = %v, want ErrRuntimeRequestFailed", err)
	}
	_, err = decodeRevokeResult(json.RawMessage(`{"plugin_instance_id":"other","revoke_epoch":3,"closed_socket_count":0,"closed_stream_count":0,"closed_storage_handle_count":0}`), "plugini_1", 3)
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeRevokeResult(plugin mismatch) error = %v, want ErrRuntimeRequestFailed", err)
	}
	if _, err := decodeRevokeResult(json.RawMessage(`{"plugin_instance_id":"plugini_1","revoke_epoch":3,"closed_socket_count":0,"closed_stream_count":0,"closed_storage_handle_count":0,"extra":true}`), "plugini_1", 3); err == nil {
		t.Fatal("decodeRevokeResult(extra field) expected fail-closed error")
	}
	result, err := decodeRevokeResult(json.RawMessage(`{"plugin_instance_id":"plugini_1","revoke_epoch":3,"closed_socket_count":2,"closed_stream_count":3,"closed_storage_handle_count":4}`), "plugini_1", 3)
	if err != nil {
		t.Fatalf("decodeRevokeResult() error = %v", err)
	}
	if result.ClosedSocketCount != 2 || result.ClosedStreamCount != 3 || result.ClosedStorageHandleCount != 4 {
		t.Fatalf("decodeRevokeResult() result mismatch: %#v", result)
	}
}

func TestDecodeHeartbeatResultRequiresStructuredTiming(t *testing.T) {
	_, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":1}`), "gen_1")
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeHeartbeatResult(missing fields) error = %v, want ErrRuntimeRequestFailed", err)
	}
	_, err = decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"other","runtime_unix_nano":1,"max_staleness_ms":5000,"host_sent_unix_nano":1}`), "gen_1")
	if !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("decodeHeartbeatResult(generation mismatch) error = %v, want ErrRuntimeRequestFailed", err)
	}
	if _, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":1,"max_staleness_ms":5000,"host_sent_unix_nano":1,"extra":true}`), "gen_1"); err == nil {
		t.Fatal("decodeHeartbeatResult(extra field) expected fail-closed error")
	}
	result, err := decodeHeartbeatResult(json.RawMessage(`{"runtime_generation_id":"gen_1","runtime_unix_nano":2,"max_staleness_ms":5000,"host_sent_unix_nano":1}`), "gen_1")
	if err != nil {
		t.Fatalf("decodeHeartbeatResult() error = %v", err)
	}
	if result.RuntimeGenerationID != "gen_1" || result.RuntimeUnixNano != 2 || result.MaxStalenessMillis != 5000 || result.HostSentUnixNanoEcho != 1 {
		t.Fatalf("decodeHeartbeatResult() result mismatch: %#v", result)
	}
}

func TestIPCGoldenFixtures(t *testing.T) {
	expectedFixtureNames := []string{
		"missing_required.json",
		"replay_frame.json",
		"runtime_generation_mismatch.json",
		"unknown_enum.json",
		"valid_hello_ack.json",
		"valid_invoke_worker_result.json",
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "contracts", "ipc", "*.json"))
	if err != nil {
		t.Fatalf("glob ipc fixtures: %v", err)
	}
	sort.Strings(files)
	if len(files) != len(expectedFixtureNames) {
		t.Fatalf("IPC golden fixture count = %d, want exactly %d current-protocol fixtures", len(files), len(expectedFixtureNames))
	}
	for index, file := range files {
		if got := filepath.Base(file); got != expectedFixtureNames[index] {
			t.Fatalf("IPC golden fixture %d = %q, want %q", index, got, expectedFixtureNames[index])
		}
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var fixture ipcGoldenFixture
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if fixture.Name == "" || fixture.Kind == "" {
				t.Fatalf("fixture missing name/kind: %#v", fixture)
			}
			err = validateIPCGoldenFixture(fixture)
			if fixture.WantError {
				if err == nil {
					t.Fatal("fixture unexpectedly passed")
				}
				if fixture.ErrorContains != "" && !strings.Contains(err.Error(), fixture.ErrorContains) {
					t.Fatalf("fixture error = %v, want substring %q", err, fixture.ErrorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("fixture error = %v", err)
			}
		})
	}
}

type ipcGoldenFixture struct {
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	RequestID           string   `json:"request_id"`
	RuntimeGenerationID string   `json:"runtime_generation_id"`
	ResponseFrameType   string   `json:"response_frame_type,omitempty"`
	ChannelNonce        string   `json:"channel_nonce,omitempty"`
	WantError           bool     `json:"want_error"`
	ErrorContains       string   `json:"error_contains,omitempty"`
	Frame               ipcFrame `json:"frame"`
}

func validateIPCGoldenFixture(fixture ipcGoldenFixture) error {
	switch fixture.Kind {
	case "hello_ack":
		var ack helloAckPayload
		if err := json.Unmarshal(fixture.Frame.Payload, &ack); err != nil {
			return err
		}
		runtimeVersion, err := version.ParseSemVer(ack.RuntimeVersion)
		if err != nil {
			return err
		}
		descriptor, err := NewRuntimeDescriptor(runtimeVersion, ack.ActualTarget, ack.RustIPCVersion, ack.WASMABIVersion, strings.Repeat("a", 64))
		if err != nil {
			return err
		}
		_, err = validateHelloAck(fixture.RequestID, fixture.RuntimeGenerationID, fixture.ChannelNonce, descriptor, ack.Limits, fixture.Frame)
		return err
	case "response":
		if err := validateIPCResponse(fixture.RequestID, fixture.RuntimeGenerationID, fixture.ResponseFrameType, fixture.Frame); err != nil {
			return err
		}
		_, err := decodeRuntimeResponse(fixture.Frame)
		return err
	default:
		return fmt.Errorf("unsupported ipc fixture kind %q", fixture.Kind)
	}
}

func TestWorkerInvocationContextBindsBrokerAccessHash(t *testing.T) {
	payload := workerInvocationFixtureWithAccess(workerBrokerAccess{
		Storage: []workerStorageBrokerAccess{{StoreID: "notes", Operations: []string{"query"}}},
		Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}},
	})
	lease := workerInvocationLeaseFixture()
	invocation, err := workerInvocationContextFromInvocation(lease, payload)
	if err != nil {
		t.Fatalf("workerInvocationContextFromInvocation() error = %v", err)
	}
	if !invocation.BrokerAccess.allowsStorage("notes", "query") || invocation.BrokerAccess.allowsStorage("notes", "exec") {
		t.Fatalf("storage broker access mismatch: %#v", invocation.BrokerAccess.Storage)
	}
	if !invocation.BrokerAccess.allowsNetwork("forecast", "http", "http", "GET") || invocation.BrokerAccess.allowsNetwork("forecast", "http", "http", "POST") {
		t.Fatalf("network broker access mismatch: %#v", invocation.BrokerAccess.Network)
	}
	if scope, ok := invocation.BrokerAccess.networkScope("forecast", "http"); !ok || scope != sessionctx.ScopeUser {
		t.Fatalf("network broker scope = %q, %v", scope, ok)
	}
	var tampered map[string]any
	if err := json.Unmarshal(payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["broker_access_sha256"] = "sha256:" + strings.Repeat("0", 64)
	rawTampered, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workerInvocationContextFromInvocation(lease, rawTampered); !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered broker access error = %v", err)
	}
}

func TestWorkerInvocationContextRejectsSignedLeaseAudienceMismatch(t *testing.T) {
	lease := workerInvocationLeaseFixture()
	for _, field := range []string{
		"plugin_id",
		"plugin_instance_id",
		"active_fingerprint",
		"runtime_instance_id",
		"runtime_generation_id",
		"method",
		"effect",
		"execution",
		"surface_instance_id",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"bridge_channel_id",
		"operation_id",
		"stream_id",
		"audit_correlation_id",
	} {
		t.Run(field, func(t *testing.T) {
			var invocation map[string]any
			if err := json.Unmarshal(workerInvocationFixture(), &invocation); err != nil {
				t.Fatal(err)
			}
			invocation[field] = "spoofed"
			raw, err := json.Marshal(invocation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workerInvocationContextFromInvocation(lease, raw); !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), field) {
				t.Fatalf("audience mismatch error = %v, want %s mismatch", err, field)
			}
		})
	}
}

func TestStorageHostcallIdentityMismatchStopsBeforeGrantAndBroker(t *testing.T) {
	lease := workerInvocationLeaseFixture()
	invocation, err := workerInvocationContextFromInvocation(lease, workerInvocationFixture())
	if err != nil {
		t.Fatal(err)
	}
	base := storageFileRequestPayload{
		HandleGrantToken:    "handle_grant_token_1",
		PluginInstanceID:    lease.PluginInstanceID,
		ActiveFingerprint:   lease.ActiveFingerprint,
		RuntimeInstanceID:   lease.RuntimeInstanceID,
		RuntimeGenerationID: lease.RuntimeGenerationID,
		RuntimeShardID:      lease.RuntimeShardID,
		HandleID:            "storage:workspace",
		Method:              "storage.files",
		PolicyRevision:      lease.PolicyRevision,
		ManagementRevision:  lease.ManagementRevision,
		RevokeEpoch:         lease.RevokeEpoch,
		Operation:           "read",
		StoreID:             "workspace",
		Path:                "notes/today.txt",
		MaxBytes:            1024,
	}
	tests := []struct {
		name   string
		mutate func(*storageFileRequestPayload)
	}{
		{name: "plugin_instance_id", mutate: func(req *storageFileRequestPayload) { req.PluginInstanceID = "plugini_spoofed" }},
		{name: "active_fingerprint", mutate: func(req *storageFileRequestPayload) { req.ActiveFingerprint = "sha256:spoofed" }},
		{name: "runtime_instance_id", mutate: func(req *storageFileRequestPayload) { req.RuntimeInstanceID = "runtime_spoofed" }},
		{name: "runtime_generation_id", mutate: func(req *storageFileRequestPayload) { req.RuntimeGenerationID = "runtime_gen_spoofed" }},
		{name: "runtime_shard_id", mutate: func(req *storageFileRequestPayload) { req.RuntimeShardID = "runtime_shard_spoofed" }},
		{name: "policy_revision", mutate: func(req *storageFileRequestPayload) { req.PolicyRevision++ }},
		{name: "management_revision", mutate: func(req *storageFileRequestPayload) { req.ManagementRevision++ }},
		{name: "revoke_epoch", mutate: func(req *storageFileRequestPayload) { req.RevokeEpoch++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := base
			test.mutate(&req)
			validator := &recordingHandleGrantValidator{}
			files := &recordingStorageFilesBroker{}
			supervisor := &ProcessSupervisor{handleGrants: validator, storageFiles: files}
			var output bytes.Buffer
			if err := supervisor.respondToStorageFile(context.Background(), &output, Health{RuntimeGenerationID: lease.RuntimeGenerationID}, ipcFrame{
				RequestID: "storage_identity_1",
				Payload:   mustMarshalRaw(req),
			}, &invocation); err != nil {
				t.Fatal(err)
			}
			if validator.calls != 0 || files.readCalls != 0 || files.writeCalls != 0 || files.deleteCalls != 0 || files.listCalls != 0 {
				t.Fatalf("identity mismatch reached adapters: validator=%d files=%#v", validator.calls, files)
			}
			response, err := readIPCFrame(bufio.NewReader(&output))
			if err != nil {
				t.Fatal(err)
			}
			var failure hostcallFailurePayload
			if err := decodeStrictJSON(response.Payload, &failure); err != nil {
				t.Fatal(err)
			}
			if failure.OK || (failure.Code != "STORAGE_FILE_REQUEST_DENIED" && failure.Code != "STORAGE_FILE_REQUEST_INVALID") {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
}

func TestNetworkHostcallIdentityMismatchStopsBeforeBrokerAndExecutor(t *testing.T) {
	lease := workerInvocationLeaseFixture()
	invocation, err := workerInvocationContextFromInvocation(lease, workerInvocationFixture())
	if err != nil {
		t.Fatal(err)
	}
	base := networkExecuteRequestPayload{
		PluginID:             lease.PluginID,
		PluginInstanceID:     lease.PluginInstanceID,
		ActiveFingerprint:    lease.ActiveFingerprint,
		ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: lease.OwnerEnvHash, OwnerUserHash: lease.OwnerUserHash},
		RuntimeInstanceID:    lease.RuntimeInstanceID,
		RuntimeGenerationID:  lease.RuntimeGenerationID,
		RuntimeShardID:       lease.RuntimeShardID,
		PolicyRevision:       lease.PolicyRevision,
		ManagementRevision:   lease.ManagementRevision,
		RevokeEpoch:          lease.RevokeEpoch,
		ConnectorID:          "api",
		Transport:            connectivity.TransportHTTP,
		Destination:          "https://api.example.com",
		TTLMillis:            1000,
		Operation:            "http",
		Method:               http.MethodPost,
		Path:                 "/v1/worker",
		MaxResponseBytes:     1024,
		TimeoutMillis:        1000,
		OwnerSessionHash:     lease.OwnerSessionHash,
		OwnerUserHash:        lease.OwnerUserHash,
		OwnerEnvHash:         lease.OwnerEnvHash,
		SessionChannelIDHash: lease.SessionChannelIDHash,
	}
	tests := []struct {
		name   string
		mutate func(*networkExecuteRequestPayload)
	}{
		{name: "plugin_id", mutate: func(req *networkExecuteRequestPayload) { req.PluginID = "com.example.spoofed" }},
		{name: "plugin_instance_id", mutate: func(req *networkExecuteRequestPayload) { req.PluginInstanceID = "plugini_spoofed" }},
		{name: "active_fingerprint", mutate: func(req *networkExecuteRequestPayload) { req.ActiveFingerprint = "sha256:spoofed" }},
		{name: "runtime_instance_id", mutate: func(req *networkExecuteRequestPayload) { req.RuntimeInstanceID = "runtime_spoofed" }},
		{name: "runtime_generation_id", mutate: func(req *networkExecuteRequestPayload) { req.RuntimeGenerationID = "runtime_gen_spoofed" }},
		{name: "runtime_shard_id", mutate: func(req *networkExecuteRequestPayload) { req.RuntimeShardID = "runtime_shard_spoofed" }},
		{name: "policy_revision", mutate: func(req *networkExecuteRequestPayload) { req.PolicyRevision++ }},
		{name: "management_revision", mutate: func(req *networkExecuteRequestPayload) { req.ManagementRevision++ }},
		{name: "revoke_epoch", mutate: func(req *networkExecuteRequestPayload) { req.RevokeEpoch++ }},
		{name: "owner_session_hash", mutate: func(req *networkExecuteRequestPayload) { req.OwnerSessionHash = "session_spoofed" }},
		{name: "owner_user_hash", mutate: func(req *networkExecuteRequestPayload) { req.OwnerUserHash = "user_spoofed" }},
		{name: "owner_env_hash", mutate: func(req *networkExecuteRequestPayload) { req.OwnerEnvHash = "env_spoofed" }},
		{name: "resource_scope", mutate: func(req *networkExecuteRequestPayload) { req.ResourceScope.OwnerUserHash = "user_spoofed" }},
		{name: "session_channel_id_hash", mutate: func(req *networkExecuteRequestPayload) { req.SessionChannelIDHash = "channel_spoofed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := base
			test.mutate(&req)
			validator := &recordingHandleGrantValidator{}
			broker := &recordingConnectivityBroker{}
			executor := &recordingNetworkExecutor{}
			supervisor := &ProcessSupervisor{handleGrants: validator, connectivity: broker, networkExecutor: executor}
			var output bytes.Buffer
			if err := supervisor.respondToNetworkExecute(context.Background(), &output, Health{RuntimeGenerationID: lease.RuntimeGenerationID}, ipcFrame{
				RequestID: "network_identity_1",
				Payload:   mustMarshalRaw(req),
			}, &invocation); err != nil {
				t.Fatal(err)
			}
			if validator.calls != 0 || broker.calls != 0 || executor.httpCalls != 0 || executor.streamCalls != 0 || executor.websocketCalls != 0 || executor.tcpCalls != 0 || executor.udpCalls != 0 {
				t.Fatalf("identity mismatch reached adapters: validator=%d broker=%d executor=%#v", validator.calls, broker.calls, executor)
			}
			response, err := readIPCFrame(bufio.NewReader(&output))
			if err != nil {
				t.Fatal(err)
			}
			var failure hostcallFailurePayload
			if err := decodeStrictJSON(response.Payload, &failure); err != nil {
				t.Fatal(err)
			}
			if failure.OK || (failure.Code != "NETWORK_EXECUTE_REQUEST_DENIED" && failure.Code != "NETWORK_EXECUTE_REQUEST_INVALID") {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
}

func TestProcessSupervisorServesBoundArtifactHandle(t *testing.T) {
	provider := &recordingArtifactProvider{
		content: []byte("wasm bytes"),
		sha256:  fixtureArtifactSHA,
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1"),
		Artifacts:             provider,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
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

func TestProcessSupervisorArtifactHostcallIsInvocationIndependentAndGenerationBound(t *testing.T) {
	provider := &cancelAwareArtifactProvider{
		started:  make(chan time.Time, 1),
		canceled: make(chan error, 1),
	}
	oldWriter := &lockedBuffer{}
	newWriter := &lockedBuffer{}
	generationCtx, cancelGeneration := context.WithCancel(context.Background())
	generation := &runtimeGeneration{id: "generation_old", ctx: generationCtx, stdin: oldWriter}
	_, cancelInvocation := context.WithCancel(context.Background())
	supervisor := &ProcessSupervisor{artifacts: provider, ipcIn: &serializedWriteCloser{WriteCloser: nopWriteCloser{Writer: newWriter}}}
	request := ArtifactRequest{PackageHash: fixturePackageHash, Artifact: fixtureArtifact, ArtifactSHA256: fixtureArtifactSHA}
	flight := &pendingCompileFlight{
		generation: generation, parentRequestID: "invoke_old", artifactRequestID: "invoke_old:artifact",
		artifact: request, wasmABIVersion: version.WASMABIVersion, registered: true,
	}
	supervisor.dispatchCompileFlightArtifact(generation, Health{RuntimeGenerationID: generation.id}, ipcFrame{
		IPCVersion: version.RustIPCVersion, FrameType: ipcFrameTypeOpenHandle,
		RequestID: flight.artifactRequestID, ParentRequestID: flight.parentRequestID, RuntimeGenerationID: generation.id,
		Payload: mustMarshalRaw(request),
	}, flight)

	calledAt := <-provider.started
	cancelInvocation()
	select {
	case err := <-provider.canceled:
		t.Fatalf("artifact read inherited invocation cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancelGeneration()
	select {
	case err := <-provider.canceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("artifact generation cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("artifact read did not stop with its runtime generation")
	}
	deadline := time.Now().Add(time.Second)
	for oldWriter.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if oldWriter.Len() == 0 {
		t.Fatal("artifact response was not written to the owning generation")
	}
	if newWriter.Len() != 0 {
		t.Fatal("old generation artifact response was written to the current transport")
	}
	frame, err := readIPCFrame(bufio.NewReader(bytes.NewReader(oldWriter.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	var failure hostcallFailurePayload
	if err := decodeStrictJSON(frame.Payload, &failure); err != nil {
		t.Fatal(err)
	}
	if failure.OK || failure.Code != "ARTIFACT_READ_FAILED" {
		t.Fatalf("artifact cancellation response = %#v", failure)
	}
	if elapsed := time.Since(calledAt); elapsed > time.Second {
		t.Fatalf("artifact generation cancellation took %s", elapsed)
	}
}

func TestProcessSupervisorRoutesLateCompileFlightArtifactAfterInvocationCancellation(t *testing.T) {
	provider := &notifyingArtifactProvider{called: make(chan ArtifactRequest, 1)}
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_LATE_ARTIFACT_AFTER_CANCEL=1",
		),
		Artifacts:   provider,
		Diagnostics: diagnostics,
		StreamSink:  storeRuntimeStreamSink{store: stream.NewMemoryStore()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := supervisor.invokeWorkerForTest(ctx, Lease{
		LeaseID: "lease_late_artifact", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
	}, "worker.echo", workerInvocationFixture()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled InvokeWorker() error = %v, want context deadline", err)
	}
	select {
	case request := <-provider.called:
		if request != (ArtifactRequest{PackageHash: fixturePackageHash, Artifact: fixtureArtifact, ArtifactSHA256: fixtureArtifactSHA}) {
			t.Fatalf("late compile flight artifact request = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("late compile flight artifact request was not routed")
	}

	deadline := time.Now().Add(time.Second)
	for {
		supervisor.pendingMu.Lock()
		compileFlights := len(supervisor.compileFlights)
		supervisor.pendingMu.Unlock()
		if compileFlights == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("completed compile flight route was retained: %d", compileFlights)
		}
		time.Sleep(time.Millisecond)
	}
	for {
		health, err = supervisor.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !health.Ready {
			t.Fatalf("late compile flight invalidated the owning generation: %#v diagnostics=%#v", health, diagnostics.list("plugin.runtime.ipc.invalidated"))
		}
		if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID: "lease_after_late_artifact", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_2",
		}, "worker.echo", workerInvocationFixtureForPlugin("plugini_2")); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("independent invocation after late compile flight failed: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestCancelAcknowledgementRemovesOnlyNeverStartedCompileFlightIntent(t *testing.T) {
	generation := &runtimeGeneration{id: "generation_cancel_cleanup", ctx: context.Background()}
	unregistered := &pendingCompileFlight{generation: generation, parentRequestID: "invoke_queued", artifactRequestID: "invoke_queued:artifact"}
	registered := &pendingCompileFlight{generation: generation, parentRequestID: "invoke_running", artifactRequestID: "invoke_running:artifact", registered: true}
	supervisor := &ProcessSupervisor{compileFlights: map[string]*pendingCompileFlight{
		unregistered.artifactRequestID: unregistered,
		registered.artifactRequestID:   registered,
	}}

	supervisor.reconcileCompileFlightAfterCancelAck(generation, "invoke_queued", "queued")
	supervisor.reconcileCompileFlightAfterCancelAck(generation, "invoke_running", "running")

	supervisor.pendingMu.Lock()
	defer supervisor.pendingMu.Unlock()
	if _, exists := supervisor.compileFlights[unregistered.artifactRequestID]; exists {
		t.Fatal("queued invocation retained an unregistered compile flight intent")
	}
	if supervisor.compileFlights[registered.artifactRequestID] != registered {
		t.Fatal("running registered compile flight was removed by cancellation acknowledgement")
	}
}

func TestProcessSupervisorInvalidatesRuntimeForUnknownCompileFlightLifecycle(t *testing.T) {
	for _, frameType := range []string{ipcFrameTypeCompileFlightRegister, ipcFrameTypeCompileFlightComplete} {
		t.Run(frameType, func(t *testing.T) {
			provider := &recordingArtifactProvider{content: []byte("wasm bytes"), sha256: fixtureArtifactSHA}
			supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
				Limits:                DefaultRuntimeLimits(),
				HandshakeTimeout:      5 * time.Second,
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
				RuntimePath:           os.Args[0],
				Args:                  []string{"-test.run=TestMain"},
				Env: append(os.Environ(),
					"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
					"REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1",
					"REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_COMPILE_FLIGHT="+frameType,
				),
				Artifacts:  provider,
				StreamSink: &recordingRuntimeStreamSink{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
				t.Fatal(err)
			}
			health, err := supervisor.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
				LeaseID: "lease_unknown_flight", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
			}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeIPCUnavailable) {
				t.Fatalf("InvokeWorker() error = %v, want %v", err, ErrRuntimeIPCUnavailable)
			}
			wantProviderCalls := 0
			if frameType == ipcFrameTypeCompileFlightComplete {
				wantProviderCalls = 1
			}
			if provider.calls != wantProviderCalls {
				t.Fatalf("artifact provider calls = %d, want %d", provider.calls, wantProviderCalls)
			}
			health, err = supervisor.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if health.Ready {
				t.Fatalf("runtime remained ready after unknown %s: %#v", frameType, health)
			}
			stopRuntimeSupervisor(t, supervisor)
		})
	}
}

func TestProcessSupervisorFailsOnlyPendingRequestsFromOwningGeneration(t *testing.T) {
	oldGeneration := &runtimeGeneration{id: "generation_old", ctx: context.Background()}
	newGeneration := &runtimeGeneration{id: "generation_new", ctx: context.Background()}
	oldPending := &pendingIPCRequest{generation: oldGeneration, result: make(chan ipcCallResult, 1)}
	newPending := &pendingIPCRequest{generation: newGeneration, result: make(chan ipcCallResult, 1)}
	supervisor := &ProcessSupervisor{pending: map[string]*pendingIPCRequest{
		"old": oldPending,
		"new": newPending,
	}}
	want := errors.New("old generation failed")
	supervisor.failPendingGeneration(oldGeneration, want)
	select {
	case result := <-oldPending.result:
		if !errors.Is(result.err, want) {
			t.Fatalf("old generation pending error = %v", result.err)
		}
	default:
		t.Fatal("old generation pending request was not failed")
	}
	select {
	case result := <-newPending.result:
		t.Fatalf("new generation pending request was failed: %v", result.err)
	default:
	}
	supervisor.pendingMu.Lock()
	defer supervisor.pendingMu.Unlock()
	if len(supervisor.pending) != 1 || supervisor.pending["new"] != newPending {
		t.Fatalf("remaining pending requests = %#v", supervisor.pending)
	}
}

func TestProcessSupervisorInvalidatesRuntimeForUnknownHostcallParent(t *testing.T) {
	provider := &recordingArtifactProvider{content: []byte("wasm bytes"), sha256: fixtureArtifactSHA}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env: append(os.Environ(),
			"REDEVPLUGIN_RUNTIMECLIENT_HELPER=1",
			"REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1",
			"REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_HOSTCALL_PARENT=1",
		),
		Artifacts:  provider,
		StreamSink: &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID: "lease_unknown_parent", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1",
	}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeIPCUnavailable) {
		t.Fatalf("InvokeWorker() error = %v, want %v", err, ErrRuntimeIPCUnavailable)
	}
	if provider.calls != 0 {
		t.Fatalf("unknown parent reached artifact provider: %d", provider.calls)
	}
	health, err = supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("runtime remained ready after unknown hostcall parent: %#v", health)
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE=1"),
		HandleGrants:          validator,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture())
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE=read"),
		HandleGrants:          validator,
		StorageFiles:          files,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
	assertBoundedDeadline(t, "storage file read", files.lastReadCalledAt, files.lastReadDeadline, files.lastReadDeadlineOK, defaultRuntimeHostcallTimeout)
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesStorageOperationOutsideMethodBrokerAccess(t *testing.T) {
	validator := &recordingHandleGrantValidator{}
	files := &recordingStorageFilesBroker{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE=read"),
		HandleGrants:          validator,
		StorageFiles:          files,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixtureWithAccess(workerBrokerAccess{
		Storage: []workerStorageBrokerAccess{{StoreID: "workspace", Operations: []string{"write"}}},
	}))
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "STORAGE_FILE_REQUEST_DENIED") {
		t.Fatalf("InvokeWorker() error = %v, want method-scoped storage denial", err)
	}
	if validator.calls != 0 || files.readCalls != 0 {
		t.Fatalf("denied storage request reached broker: validator=%d reads=%d", validator.calls, files.readCalls)
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV=put"),
		HandleGrants:          validator,
		StorageKV:             kv,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
	assertBoundedDeadline(t, "storage kv put", kv.lastPutCalledAt, kv.lastPutDeadline, kv.lastPutDeadlineOK, defaultRuntimeHostcallTimeout)
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_SQLITE=query"),
		HandleGrants:          validator,
		StorageSQLite:         sqlite,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
	assertBoundedDeadline(t, "storage sqlite query", sqlite.lastQueryCalledAt, sqlite.lastQueryDeadline, sqlite.lastQueryDeadlineOK, time.Second)
	if len(sqlite.lastQuery.Args) != 1 || sqlite.lastQuery.Args[0].Int == nil || *sqlite.lastQuery.Args[0].Int != score {
		t.Fatalf("storage sqlite args mismatch: %#v", sqlite.lastQuery.Args)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestStorageSQLiteQueryResponsePreservesEmptyRows(t *testing.T) {
	broker := &recordingStorageSQLiteBroker{
		queryResult: storage.SQLiteQueryResult{
			Database: "plugin.sqlite",
			Columns:  []string{"id"},
			Rows:     [][]storage.SQLiteValue{},
		},
	}
	payload := dispatchStorageSQLiteRequest(context.Background(), broker, storageSQLiteRequestPayload{
		Operation: "query",
		StoreID:   "db",
		Database:  "plugin.sqlite",
		SQL:       "SELECT id FROM notes WHERE 1 = 0",
	})
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal empty SQLite query response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode empty SQLite query response: %v", err)
	}
	rows, ok := decoded["rows"].([]any)
	if !ok || len(rows) != 0 {
		t.Fatalf("empty SQLite query rows must remain an explicit array: %s", raw)
	}
}

func TestStorageSQLiteValuePreservesEmptyBlobPresence(t *testing.T) {
	emptyBlob := []byte{}
	wire := storageSQLiteValueToIPC(storage.SQLiteValue{Blob: emptyBlob})
	if wire.BlobBase64 == nil || *wire.BlobBase64 != "" || wire.Null != nil || wire.Int != nil || wire.Float != nil || wire.Text != nil {
		t.Fatalf("empty blob wire value = %#v", wire)
	}
	decoded, err := storageSQLiteValueFromIPC(wire)
	if err != nil || decoded.Blob == nil || len(decoded.Blob) != 0 {
		t.Fatalf("empty blob decoded value = %#v, err=%v", decoded, err)
	}
	falseValue := false
	intValue := int64(1)
	textValue := "ambiguous"
	for _, invalid := range []storageSQLiteValueIPC{
		{},
		{Null: &falseValue},
		{Int: &intValue, Text: &textValue},
	} {
		if _, err := storageSQLiteValueFromIPC(invalid); err == nil {
			t.Fatalf("accepted invalid SQLite value %#v", invalid)
		}
	}
}

func TestStorageSQLiteExecResponsePreservesZeroRowsAffected(t *testing.T) {
	broker := &recordingStorageSQLiteBroker{
		execResult: storage.SQLiteExecResult{Database: "plugin.sqlite", RowsAffected: 0},
	}
	payload := dispatchStorageSQLiteRequest(context.Background(), broker, storageSQLiteRequestPayload{
		Operation: "exec",
		StoreID:   "db",
		Database:  "plugin.sqlite",
		SQL:       "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY)",
	})
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal zero-row SQLite exec response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode zero-row SQLite exec response: %v", err)
	}
	if rowsAffected, ok := decoded["rows_affected"].(float64); !ok || rowsAffected != 0 {
		t.Fatalf("zero-row SQLite exec response must preserve rows_affected: %s", raw)
	}
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT=1"),
		Connectivity:          broker,
		Now:                   func() time.Time { return now },
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
		!broker.last.ResourceScope.Matches(sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}) ||
		broker.last.ConnectorID != "api" ||
		broker.last.Destination != "https://api.example.com" ||
		broker.last.TTL != 30*time.Second {
		t.Fatalf("connectivity broker mismatch: calls=%d last=%#v", broker.calls, broker.last)
	}
	if !broker.hasLastSession || broker.lastSession.OwnerEnvHash != "env_hash" || broker.lastSession.OwnerUserHash != "user_hash" {
		t.Fatalf("connectivity broker session = %#v, present=%v", broker.lastSession, broker.hasLastSession)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsNetworkGrantClassifierVersionMismatch(t *testing.T) {
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
			TargetClassifierVersion: "target-classifier-invalid",
			ExpiresAt:               now.Add(30 * time.Second),
		},
	}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT=1"),
		Connectivity:          broker,
		Now:                   func() time.Time { return now },
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	_, err = supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixture())
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "NETWORK_GRANT_VALIDATION_FAILED") {
		t.Fatalf("InvokeWorker() error = %v, want NETWORK_GRANT_VALIDATION_FAILED runtime request", err)
	}
	if broker.calls != 1 {
		t.Fatalf("connectivity broker calls = %d, want 1", broker.calls)
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
		Connectivity:          broker,
		NetworkExecutor:       executor,
		Now:                   func() time.Time { return now },
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
		executor.lastHTTP.Query.Encode() != "lang=en&units=metric" ||
		string(executor.lastHTTP.Body) != `{"hello":"network"}` ||
		executor.lastHTTP.Headers.Get("X-Test") != "ok" ||
		executor.lastHTTP.MaxResponseBytes != 1024 ||
		executor.lastHTTP.Timeout != 2*time.Second {
		t.Fatalf("network executor mismatch: calls=%d last=%#v", executor.httpCalls, executor.lastHTTP)
	}
	assertBoundedDeadline(t, "network grant mint", broker.lastCalledAt, broker.lastDeadline, broker.lastDeadlineOK, 2*time.Second)
	assertBoundedDeadline(t, "network http execute", executor.lastHTTPCalledAt, executor.lastHTTPDeadline, executor.lastHTTPDeadlineOK, 2*time.Second)
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesHTTPMethodOutsideMethodBrokerAccess(t *testing.T) {
	now := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	broker := &recordingConnectivityBroker{}
	executor := &recordingNetworkExecutor{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
		Connectivity:          broker,
		NetworkExecutor:       executor,
		Now:                   func() time.Time { return now },
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
		RuntimeGenerationID: health.RuntimeGenerationID,
		PluginInstanceID:    "plugini_1",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}, "worker.echo", workerInvocationFixtureWithAccess(workerBrokerAccess{
		Network: []workerNetworkBrokerAccess{{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}},
	}))
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "NETWORK_EXECUTE_REQUEST_DENIED") {
		t.Fatalf("InvokeWorker() error = %v, want method-scoped HTTP method denial", err)
	}
	if broker.calls != 0 || executor.httpCalls != 0 {
		t.Fatalf("denied network request reached broker: grants=%d http=%d", broker.calls, executor.httpCalls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorStreamsHTTPNetworkDuringWorkerInvocation(t *testing.T) {
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
		streamResponse: connectivity.HTTPStreamResponse{
			StatusCode: http.StatusAccepted,
			Headers:    http.Header{"Content-Type": []string{"text/plain"}},
		},
		streamChunks: [][]byte{[]byte("alpha\n"), []byte("beta\n")},
	}
	streams := stream.NewMemoryStore()
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http_stream"),
		Connectivity:          broker,
		NetworkExecutor:       executor,
		StreamSink:            storeRuntimeStreamSink{store: streams},
		Now:                   func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	const streamID = "stream_runtime_1"
	if _, err := streams.Register(context.Background(), stream.RegisterRequest{
		StreamID: streamID,
		ExecutionBinding: capability.ExecutionBinding{
			PluginID:             "com.example.worker",
			PluginInstanceID:     "plugini_1",
			Method:               "worker.echo",
			Effect:               capability.EffectRead,
			Execution:            "subscription",
			SurfaceInstanceID:    "surface_runtime",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			SessionChannelIDHash: "channel_hash",
			BridgeChannelID:      "bridge_runtime",
		},
		Direction: stream.DirectionRead,
		Now:       now,
	}); err != nil {
		t.Fatalf("Streams.Register() error = %v", err)
	}
	rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
		LeaseID:             "lease_1",
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
	returnedStreamID, _ := networkExecute["stream_id"].(string)
	if networkExecute["ok"] != true ||
		networkExecute["status_code"] != float64(http.StatusAccepted) ||
		returnedStreamID != streamID ||
		networkExecute["body_base64"] != nil ||
		networkExecute["bytes_read"] != float64(len("alpha\nbeta\n")) ||
		networkExecute["chunk_count"] != float64(2) {
		t.Fatalf("stream network execute result mismatch: %#v", networkExecute)
	}
	record, delivery, err := streams.Deliver(context.Background(), stream.DeliverRequest{StreamID: streamID, ReadID: "read_runtime_1"})
	if err != nil {
		t.Fatalf("Streams.Deliver(%s) error = %v", streamID, err)
	}
	if record.PluginID != "com.example.worker" ||
		record.PluginInstanceID != "plugini_1" ||
		record.Method != "worker.echo" ||
		record.SurfaceInstanceID != "surface_runtime" ||
		record.OwnerSessionHash != "session_hash" ||
		record.OwnerUserHash != "user_hash" ||
		record.SessionChannelIDHash != "channel_hash" ||
		record.BridgeChannelID != "bridge_runtime" ||
		record.Status != stream.StatusClosed {
		t.Fatalf("stream record audience mismatch: %#v", record)
	}
	if len(delivery.Events) != 2 || string(delivery.Events[0].Data) != "alpha\n" || string(delivery.Events[1].Data) != "beta\n" {
		t.Fatalf("stream events mismatch: %#v", delivery.Events)
	}
	if executor.streamCalls != 1 ||
		executor.lastStreamHTTP.MaxChunkBytes != 4 ||
		executor.lastStreamHTTP.MaxResponseBytes != 1024 ||
		executor.lastStreamHTTP.Timeout != 2*time.Second {
		t.Fatalf("stream executor mismatch: calls=%d req=%#v", executor.streamCalls, executor.lastStreamHTTP)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestNetworkExecuteErrorResponseMapsRateLimit(t *testing.T) {
	rawErr := fmt.Errorf("%w: udp endpoint", connectivity.ErrRateLimited)
	response := networkExecuteErrorResponse(rawErr)
	if response.OK || response.Code != "NETWORK_RATE_LIMITED" || response.Message != "network request was rate limited" {
		t.Fatalf("rate-limit response mismatch: %#v", response)
	}
	if strings.Contains(response.Message, "udp endpoint") {
		t.Fatalf("rate-limit response leaked internal error: %#v", response)
	}
	if !errors.Is(response.InternalError, connectivity.ErrRateLimited) {
		t.Fatalf("rate-limit internal error = %v, want ErrRateLimited", response.InternalError)
	}
}

func TestRuntimeHostcallFailuresRedactPublicErrorsAndRetainDiagnostics(t *testing.T) {
	t.Run("storage sqlite", func(t *testing.T) {
		const sensitive = "open /Users/secret/path/plugin.sqlite: vault-token-super-secret"
		diagnostics := &runtimeDiagnosticSink{}
		validator := &recordingHandleGrantValidator{
			result: HandleGrantValidationResult{
				HandleGrantID:       "handle_grant_1",
				HandleID:            "storage:db",
				Method:              "storage.sqlite",
				RuntimeGenerationID: "runtime_gen_test",
			},
		}
		supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
			Limits:                DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
			RuntimePath:           os.Args[0],
			Args:                  []string{"-test.run=TestMain"},
			Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_SQLITE=query"),
			Diagnostics:           diagnostics,
			HandleGrants:          validator,
			StorageSQLite:         &recordingStorageSQLiteBroker{err: errors.New(sensitive)},
			StreamSink:            &recordingRuntimeStreamSink{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })
		health, err := supervisor.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		validator.result.RuntimeGenerationID = health.RuntimeGenerationID
		_, err = supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_redaction_storage",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
			PolicyRevision:      1,
			ManagementRevision:  2,
			RevokeEpoch:         3,
		}, "worker.echo", workerInvocationFixture())
		assertRedactedRuntimeError(t, err, "STORAGE_SQLITE_FAILED", "storage sqlite operation failed", sensitive)
		assertHostcallFailureDiagnostic(t, diagnostics, "storage_sqlite", "STORAGE_SQLITE_FAILED", sensitive)
	})

	t.Run("network execute", func(t *testing.T) {
		const sensitive = "resolver internal: 10.0.0.7 via private-dns at /Users/secret/path"
		now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
		diagnostics := &runtimeDiagnosticSink{}
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
		supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
			Limits:                DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
			RuntimePath:           os.Args[0],
			Args:                  []string{"-test.run=TestMain"},
			Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
			Diagnostics:           diagnostics,
			Connectivity:          broker,
			NetworkExecutor:       &recordingNetworkExecutor{err: errors.New(sensitive)},
			Now:                   func() time.Time { return now },
			StreamSink:            &recordingRuntimeStreamSink{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		t.Cleanup(func() { stopRuntimeSupervisor(t, supervisor) })
		health, err := supervisor.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
		_, err = supervisor.invokeWorkerForTest(context.Background(), Lease{
			LeaseID:             "lease_redaction_network",
			RuntimeGenerationID: health.RuntimeGenerationID,
			PluginInstanceID:    "plugini_1",
			PolicyRevision:      1,
			ManagementRevision:  2,
			RevokeEpoch:         3,
		}, "worker.echo", workerInvocationFixture())
		assertRedactedRuntimeError(t, err, "NETWORK_EXECUTE_FAILED", "network execute operation failed", sensitive)
		assertHostcallFailureDiagnostic(t, diagnostics, "network_execute", "NETWORK_EXECUTE_FAILED", sensitive)
	})
}

func assertRedactedRuntimeError(t *testing.T, err error, code, publicMessage, sensitive string) {
	t.Helper()
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), code) || !strings.Contains(err.Error(), publicMessage) {
		t.Fatalf("runtime error = %v, want %s with fixed public message", err, code)
	}
	for _, secret := range []string{sensitive, "/Users/secret/path", "vault-token-super-secret", "resolver internal", "private-dns"} {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("runtime error leaked %q: %v", secret, err)
		}
	}
}

func assertHostcallFailureDiagnostic(t *testing.T, store *runtimeDiagnosticSink, hostcall, code, rawError string) {
	t.Helper()
	events := store.list("plugin.runtime.hostcall.failed")
	if len(events) != 1 {
		t.Fatalf("hostcall failure diagnostics = %#v, want exactly one event", events)
	}
	event := events[0]
	if event.Message != "runtime hostcall failed" || event.Details["hostcall"] != hostcall || event.Details["code"] != code {
		t.Fatalf("hostcall failure diagnostic mismatch: %#v", event)
	}
	failure, ok := event.InternalDetails["failure"].(observability.Failure)
	if !ok || failure.Code != observability.FailureAction || failure.Action != "runtime.hostcall" || strings.Contains(fmt.Sprint(event.InternalDetails), rawError) {
		t.Fatalf("hostcall failure diagnostic retained raw cause: %#v", event)
	}
}

func TestProcessSupervisorRedactsRuntimeProcessOutput(t *testing.T) {
	const sensitive = "vault token sk-live-secret at /Users/secret/path"
	diagnostics := &runtimeDiagnosticSink{}
	supervisor := &ProcessSupervisor{diagnostics: diagnostics, now: func() time.Time {
		return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	}}

	supervisor.scanPipe(strings.NewReader(sensitive+"\n"), "stderr")
	events := diagnostics.list("plugin.runtime.process.stderr")
	if len(events) != 1 || events[0].Details["stream"] != "stderr" || events[0].InternalDetails != nil {
		t.Fatalf("runtime process stderr diagnostic = %#v", events)
	}
	if strings.Contains(fmt.Sprint(events[0]), sensitive) || strings.Contains(fmt.Sprint(events[0]), "sk-live-secret") || strings.Contains(fmt.Sprint(events[0]), "/Users/secret/path") {
		t.Fatalf("runtime process stderr diagnostic retained output: %#v", events[0])
	}
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
				if executor.tcpCalls != 1 || string(executor.lastTCP.Payload) != "hello" || executor.lastTCP.MaxRequestBytes != 2048 || executor.lastTCP.MaxReadBytes != 1024 || executor.lastTCP.Timeout != 2*time.Second {
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
			supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
				Limits:                DefaultRuntimeLimits(),
				HandshakeTimeout:      5 * time.Second,
				HeartbeatInterval:     2 * time.Second,
				MaxHeartbeatStaleness: 5 * time.Second,
				RuntimePath:           os.Args[0],
				Args:                  []string{"-test.run=TestMain"},
				Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE="+tc.operation),
				Connectivity:          broker,
				NetworkExecutor:       executor,
				Now:                   func() time.Time { return now },
				StreamSink:            &recordingRuntimeStreamSink{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			health, err := supervisor.Health(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
			rawResult, err := supervisor.invokeWorkerForTest(context.Background(), Lease{
				LeaseID:             "lease_1",
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_EXECUTE=http"),
		Connectivity:          broker,
		Now:                   func() time.Time { return now },
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	broker.grant.RuntimeGenerationID = health.RuntimeGenerationID
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesNetworkGrantWithoutBroker(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE=read"),
		HandleGrants:          validator,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV=put"),
		HandleGrants:          validator,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validator.result.RuntimeGenerationID = health.RuntimeGenerationID
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE_ON_REVOKE=read"),
		HandleGrants:          validator,
		StorageFiles:          files,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.Revoke(context.Background(), "plugini_1", 3); !errors.Is(err, ErrRuntimeRequestFailed) {
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV_ON_REVOKE=put"),
		HandleGrants:          validator,
		StorageKV:             kv,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.Revoke(context.Background(), "plugini_1", 3); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("Revoke() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if validator.calls != 0 || kv.putCalls != 0 {
		t.Fatalf("storage kv outside worker should not touch validator or broker: validator=%d puts=%d", validator.calls, kv.putCalls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesNetworkGrantOutsideWorkerInvocation(t *testing.T) {
	broker := &recordingConnectivityBroker{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT_ON_REVOKE=1"),
		Connectivity:          broker,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.Revoke(context.Background(), "plugini_1", 3); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("Revoke() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if broker.calls != 0 {
		t.Fatalf("network grant outside worker should not touch broker: %d", broker.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorDeniesHandleGrantOutsideWorkerInvocation(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE_ON_REVOKE=1"),
		HandleGrants:          &recordingHandleGrantValidator{},
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.Revoke(context.Background(), "plugini_1", 3); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("Revoke() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsInvalidHandleGrantRequestBeforeValidator(t *testing.T) {
	validator := &recordingHandleGrantValidator{}
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE=1", "REDEVPLUGIN_RUNTIMECLIENT_INVALID_HANDLE_REQUEST=1"),
		HandleGrants:          validator,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
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
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_ARTIFACT=1", "REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT=1"),
		Artifacts:             provider,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1", RuntimeGenerationID: health.RuntimeGenerationID, PluginInstanceID: "plugini_1"}, "worker.echo", workerInvocationFixture()); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	if provider.calls != 0 {
		t.Fatalf("artifact provider was called for denied request: %d", provider.calls)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRequiresWorkerInvocationArtifactIdentity(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", []byte(`{"message":"hello"}`)); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsNonWorkerArtifactPath(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HandshakeTimeout:      5 * time.Second,
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1"),
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	payload := []byte(fmt.Sprintf(`{"package_hash":%q,"artifact":"ui/index.html","artifact_sha256":%q,"worker_id":"echo_worker","method":"worker.echo"}`, fixturePackageHash, fixtureArtifactSHA))
	if _, err := supervisor.invokeWorkerForTest(context.Background(), Lease{LeaseID: "lease_1"}, "worker.echo", payload); !errors.Is(err, ErrRuntimeRequestFailed) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeRequestFailed", err)
	}
	stopRuntimeSupervisor(t, supervisor)
}

func TestProcessSupervisorRejectsMissingPath(t *testing.T) {
	if _, err := NewProcessSupervisor(ProcessSupervisorOptions{StreamSink: &recordingRuntimeStreamSink{}}); !errors.Is(err, ErrRuntimePathRequired) {
		t.Fatalf("NewProcessSupervisor() error = %v, want ErrRuntimePathRequired", err)
	}
}

func TestProcessSupervisorFailsClosedOnBadHandshake(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_BAD_HELPER=1"),
		HandshakeTimeout:      200 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Start(context.Background(), testRuntimeTarget)
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

func TestProcessSupervisorFailsClosedOnHandshakeNonceMismatch(t *testing.T) {
	supervisor, err := newTestProcessSupervisor(t, ProcessSupervisorOptions{
		Limits:                DefaultRuntimeLimits(),
		HeartbeatInterval:     2 * time.Second,
		MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_RUNTIMECLIENT_HELPER=1", "REDEVPLUGIN_RUNTIMECLIENT_BAD_NONCE=1"),
		HandshakeTimeout:      200 * time.Millisecond,
		StreamSink:            &recordingRuntimeStreamSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Start(context.Background(), testRuntimeTarget)
	if !errors.Is(err, ErrRuntimeHandshake) {
		t.Fatalf("Start() error = %v, want ErrRuntimeHandshake", err)
	}
	health, err := supervisor.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("nonce mismatch left runtime ready: %#v", health)
	}
}

func TestRuntimeHostcallContextCapsRequestedTimeout(t *testing.T) {
	start := time.Now()
	ctx, cancel := runtimeHostcallContext(context.Background(), 5*time.Minute)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("runtimeHostcallContext() missing deadline")
	}
	if remaining := deadline.Sub(start); remaining <= 0 || remaining > maxRuntimeHostcallTimeout+250*time.Millisecond {
		t.Fatalf("runtimeHostcallContext() remaining deadline = %v, want capped by %v", remaining, maxRuntimeHostcallTimeout)
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
	var hello helloRequestPayload
	if err := json.Unmarshal(frame.Payload, &hello); err != nil {
		os.Exit(5)
	}
	channelNonce := hello.ChannelNonce
	if strings.TrimSpace(channelNonce) == "" {
		os.Exit(6)
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_LEASE_PUBLIC_KEY") == "1" {
		if len(hello.RuntimeLeasePublicKeys) != 1 ||
			hello.RuntimeLeasePublicKeys[0].Algorithm != RuntimeLeaseSignatureAlgorithm ||
			!strings.HasPrefix(hello.RuntimeLeasePublicKeys[0].KeyID, "host_ephemeral_") {
			os.Exit(60)
		}
		rawKey, err := base64.StdEncoding.DecodeString(hello.RuntimeLeasePublicKeys[0].PublicKeyBase64)
		if err != nil || len(rawKey) != ed25519.PublicKeySize {
			os.Exit(61)
		}
	}
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BAD_NONCE") == "1" {
		channelNonce = "wrong_channel_nonce"
	}
	runtimeVersion := envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_RUNTIME_VERSION", version.RuntimeVersion)
	actualTarget := Target{
		OS:   envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET_OS", hello.Target.OS),
		Arch: envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_TARGET_ARCH", hello.Target.Arch),
	}
	payload, _ := json.Marshal(helloAckPayload{
		RuntimeVersion: runtimeVersion,
		ActualTarget:   actualTarget,
		RustIPCVersion: envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_IPC_VERSION", version.RustIPCVersion),
		WASMABIVersion: envOrDefault("REDEVPLUGIN_RUNTIMECLIENT_ACK_WASM_ABI_VERSION", version.WASMABIVersion),
		ChannelNonce:   channelNonce,
		Limits:         hello.Limits,
	})
	_ = json.NewEncoder(os.Stdout).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeHelloAck,
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload:             payload,
	})
	controlReadFD, err := strconv.Atoi(os.Getenv("REDEVPLUGIN_CONTROL_READ_FD"))
	if err != nil || controlReadFD < 3 {
		os.Exit(64)
	}
	controlWriteFD, err := strconv.Atoi(os.Getenv("REDEVPLUGIN_CONTROL_WRITE_FD"))
	if err != nil || controlWriteFD < 3 {
		os.Exit(65)
	}
	controlReadFile := os.NewFile(uintptr(controlReadFD), "redevplugin-control-read")
	controlWriteFile := os.NewFile(uintptr(controlWriteFD), "redevplugin-control-write")
	if controlReadFile == nil || controlWriteFile == nil {
		os.Exit(66)
	}
	revoked := make(chan struct{})
	var revokeOnce sync.Once
	var heartbeatCount atomic.Int64
	go runRuntimeClientControlHelper(
		bufio.NewReader(controlReadFile),
		json.NewEncoder(controlWriteFile),
		revoked,
		&revokeOnce,
		&heartbeatCount,
		hello.Limits,
	)
	encoder := json.NewEncoder(os.Stdout)
	var multiplexInvocations atomic.Int64
	var lateArtifactInvocation *ipcFrame
	var lateArtifactInvocationCount int
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
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_LATE_ARTIFACT_AFTER_CANCEL") == "1" {
				lateArtifactInvocationCount++
				if lateArtifactInvocationCount == 1 {
					requestCopy := request
					lateArtifactInvocation = &requestCopy
					writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightRegister)
					continue
				}
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_MULTIPLEX") == "1" {
				invocationNumber := multiplexInvocations.Add(1)
				go func(request ipcFrame, invocationNumber int64) {
					if invocationNumber == 1 {
						time.Sleep(150 * time.Millisecond)
					}
					raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: json.RawMessage(`{"data":{"from_runtime":true}}`)})
					_ = encoder.Encode(ipcFrame{
						IPCVersion:          version.RustIPCVersion,
						FrameType:           ipcFrameTypeInvokeWorkerResult,
						RequestID:           request.RequestID,
						RuntimeGenerationID: request.RuntimeGenerationID,
						Payload:             raw,
					})
				}(request, invocationNumber)
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_SIGNED_LEASE") == "1" && !verifySignedLeaseFromHelper(request, hello) {
				os.Exit(62)
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BLOCK_INVOKE") == "1" {
				time.Sleep(10 * time.Second)
				continue
			}
			if rawDelay := strings.TrimSpace(os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_DELAY_INVOKE_MILLIS")); rawDelay != "" {
				delayMillis, parseErr := strconv.Atoi(rawDelay)
				if parseErr != nil || delayMillis <= 0 {
					os.Exit(63)
				}
				time.Sleep(time.Duration(delayMillis) * time.Millisecond)
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_WAIT_FOR_REVOKE_DURING_INVOKE") == "1" {
				<-revoked
				resultPayload := runtimeResponsePayload{OK: false, Code: "RUNTIME_CAPABILITY_REVOKED", Message: "runtime capability was revoked", ErrorOrigin: WorkerErrorOriginRuntime}
				raw, _ := json.Marshal(resultPayload)
				_ = encoder.Encode(ipcFrame{
					IPCVersion:          version.RustIPCVersion,
					FrameType:           ipcFrameTypeInvokeWorkerResult,
					RequestID:           request.RequestID,
					RuntimeGenerationID: request.RuntimeGenerationID,
					Payload:             raw,
				})
				continue
			}
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUIRE_HEARTBEAT_DURING_INVOKE") == "1" && heartbeatCount.Load() == 0 {
				resultPayload := runtimeResponsePayload{OK: false, Code: "RUNTIME_CONTROL_CHANNEL_STALE", Message: "heartbeat did not run during invocation", ErrorOrigin: WorkerErrorOriginRuntime}
				raw, _ := json.Marshal(resultPayload)
				_ = encoder.Encode(ipcFrame{
					IPCVersion:          version.RustIPCVersion,
					FrameType:           ipcFrameTypeInvokeWorkerResult,
					RequestID:           request.RequestID,
					RuntimeGenerationID: request.RuntimeGenerationID,
					Payload:             raw,
				})
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
				resultPayload = runtimeResponsePayload{OK: false, Code: "WASM_WORKER_FAILED", Message: "runtime worker execution failed", ErrorOrigin: WorkerErrorOriginRuntime}
			}
			raw, _ := json.Marshal(resultPayload)
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeInvokeWorkerResult,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		case ipcFrameTypeCancelInvoke:
			var cancelRequest cancelInvokeRequestPayload
			_ = json.Unmarshal(request.Payload, &cancelRequest)
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(cancelInvokeAckResultPayload{
				InvocationRequestID: cancelRequest.InvocationRequestID,
				Disposition:         "running",
			})})
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeCancelInvokeAck,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
			if lateArtifactInvocation != nil {
				time.Sleep(25 * time.Millisecond)
				invocation := *lateArtifactInvocation
				artifact := artifactRequestPayloadFromInvoke(invocation)
				_ = encoder.Encode(ipcFrame{
					IPCVersion:          version.RustIPCVersion,
					FrameType:           ipcFrameTypeOpenHandle,
					RequestID:           invocation.RequestID + ":artifact",
					ParentRequestID:     invocation.RequestID,
					RuntimeGenerationID: invocation.RuntimeGenerationID,
					Payload:             mustMarshalRaw(artifact),
				})
			}
		case ipcFrameTypeOpenHandle:
			if lateArtifactInvocation == nil || request.RequestID != lateArtifactInvocation.RequestID+":artifact" {
				os.Exit(69)
			}
			invocation := *lateArtifactInvocation
			artifact := artifactRequestPayloadFromInvoke(invocation)
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           "compile_flight_complete",
				RequestID:           invocation.RequestID + ":artifact:complete",
				ParentRequestID:     invocation.RequestID,
				RuntimeGenerationID: invocation.RuntimeGenerationID,
				Payload: mustMarshalRaw(map[string]any{
					"artifact_request_id": invocation.RequestID + ":artifact",
					"package_hash":        artifact.PackageHash,
					"artifact":            artifact.Artifact,
					"artifact_sha256":     artifact.ArtifactSHA256,
					"wasm_abi_version":    version.WASMABIVersion,
				}),
			})
			canceledPayload, _ := json.Marshal(runtimeResponsePayload{
				OK: false, Code: "RUNTIME_INVOCATION_CANCELED", Message: "runtime invocation was canceled", ErrorOrigin: WorkerErrorOriginRuntime,
			})
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeInvokeWorkerResult,
				RequestID:           invocation.RequestID,
				RuntimeGenerationID: invocation.RuntimeGenerationID,
				Payload:             canceledPayload,
			})
			lateArtifactInvocation = nil
		default:
			os.Exit(6)
		}
	}
}

func envOrDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

type notifyingArtifactProvider struct {
	called chan ArtifactRequest
}

func (p *notifyingArtifactProvider) ReadArtifact(_ context.Context, req ArtifactRequest) (ArtifactResult, error) {
	p.called <- req
	return ArtifactResult{Content: []byte("wasm bytes"), SHA256: req.ArtifactSHA256}, nil
}

func runRuntimeClientControlHelper(
	reader *bufio.Reader,
	encoder *json.Encoder,
	revoked chan struct{},
	revokeOnce *sync.Once,
	heartbeatCount *atomic.Int64,
	limits RuntimeLimits,
) {
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request ipcFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(67)
		}
		switch request.FrameType {
		case ipcFrameTypeHeartbeat:
			if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_BLOCK_HEARTBEAT") == "1" {
				time.Sleep(10 * time.Second)
				continue
			}
			heartbeatCount.Add(1)
			var heartbeatReq heartbeatRequestPayload
			_ = json.Unmarshal(request.Payload, &heartbeatReq)
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
				"runtime_generation_id": request.RuntimeGenerationID,
				"runtime_unix_nano":     time.Now().UnixNano(),
				"max_staleness_ms":      heartbeatReq.MaxStalenessMillis,
				"host_sent_unix_nano":   heartbeatReq.SentUnixNano,
				"active_invocations":    0,
				"queued_invocations":    0,
				"limits":                limits,
				"module_cache":          ModuleCacheMetrics{},
			})})
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeHeartbeat,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		case ipcFrameTypeRevokeEpoch:
			if writeUnexpectedControlHostcall(encoder, request) {
				continue
			}
			var revokeReq revokeEpochRequestPayload
			_ = json.Unmarshal(request.Payload, &revokeReq)
			revokeOnce.Do(func() { close(revoked) })
			raw, _ := json.Marshal(runtimeResponsePayload{OK: true, Result: mustMarshalRaw(map[string]any{
				"plugin_instance_id":          revokeReq.PluginInstanceID,
				"revoke_epoch":                revokeReq.RevokeEpoch,
				"closed_socket_count":         2,
				"closed_stream_count":         3,
				"closed_storage_handle_count": 4,
			})})
			_ = encoder.Encode(ipcFrame{
				IPCVersion:          version.RustIPCVersion,
				FrameType:           ipcFrameTypeRevokeEpochAck,
				RequestID:           request.RequestID,
				RuntimeGenerationID: request.RuntimeGenerationID,
				Payload:             raw,
			})
		default:
			os.Exit(68)
		}
	}
}

func writeUnexpectedControlHostcall(encoder *json.Encoder, request ipcFrame) bool {
	var frameType string
	var payload any
	switch {
	case os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE_ON_REVOKE") != "":
		frameType = ipcFrameTypeStorageFile
		payload = storageFileRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_FILE_ON_REVOKE"))
	case os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV_ON_REVOKE") != "":
		frameType = ipcFrameTypeStorageKV
		payload = storageKVRequestFromInvoke(request, os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_STORAGE_KV_ON_REVOKE"))
	case os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_NETWORK_GRANT_ON_REVOKE") == "1":
		frameType = ipcFrameTypeNetworkGrant
		payload = networkGrantRequestFromInvoke(request)
	case os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_VALIDATE_HANDLE_ON_REVOKE") == "1":
		frameType = ipcFrameTypeValidateHandleGrant
		payload = handleGrantValidationRequestFromInvoke(request)
	default:
		return false
	}
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           request.RequestID + ":unexpected-hostcall",
		ParentRequestID:     request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             mustMarshalRaw(payload),
	})
	return true
}

func waitForSustainedIPCLock(t *testing.T, supervisor *ProcessSupervisor, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var occupiedSince time.Time
	for time.Now().Before(deadline) {
		supervisor.pendingMu.Lock()
		pending := len(supervisor.pending)
		supervisor.pendingMu.Unlock()
		if pending == 0 {
			occupiedSince = time.Time{}
		} else {
			if occupiedSince.IsZero() {
				occupiedSince = time.Now()
			} else if time.Since(occupiedSince) >= duration {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("IPC lock did not remain occupied by the invocation")
}

func waitForInvocationAdmissionCount(t *testing.T, supervisor *ProcessSupervisor, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		supervisor.admission.mu.Lock()
		got := supervisor.admission.active
		supervisor.admission.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	supervisor.admission.mu.Lock()
	got := supervisor.admission.active
	supervisor.admission.mu.Unlock()
	t.Fatalf("invocation admission count = %d, want %d", got, want)
}

func verifySignedLeaseFromHelper(request ipcFrame, hello helloRequestPayload) bool {
	if len(hello.RuntimeLeasePublicKeys) != 1 {
		return false
	}
	var payload invokeWorkerRequestPayload
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		return false
	}
	publicKey := hello.RuntimeLeasePublicKeys[0]
	rawKey, err := base64.StdEncoding.DecodeString(publicKey.PublicKeyBase64)
	if err != nil || len(rawKey) != ed25519.PublicKeySize || payload.Lease.KeyID != publicKey.KeyID || payload.Lease.Signature == "" {
		return false
	}
	verifier := Ed25519RuntimeLeaseVerifier{
		Keyring: StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{
			KeyID: publicKey.KeyID, PublicKey: ed25519.PublicKey(rawKey),
		}}},
		Now: func() time.Time { return time.UnixMilli(payload.Lease.IssuedAtUnixMillis).Add(time.Second) },
	}
	return verifier.VerifyRuntimeLease(context.Background(), RuntimeLeaseVerificationRequest{
		Lease: payload.Lease, Method: payload.Method, Now: time.UnixMilli(payload.Lease.IssuedAtUnixMillis).Add(time.Second),
	}) == nil
}

func requestArtifactFromHelper(reader *bufio.Reader, encoder *json.Encoder, request ipcFrame) bool {
	artifactReq := artifactRequestPayloadFromInvoke(request)
	writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightRegister)
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_REQUEST_WRONG_ARTIFACT") == "1" {
		artifactReq.Artifact = "workers/other.wasm"
	}
	rawArtifactReq, _ := json.Marshal(artifactReq)
	parentRequestID := request.RequestID
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_HOSTCALL_PARENT") == "1" {
		parentRequestID = request.RequestID + ":unknown"
	}
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeOpenHandle,
		RequestID:           request.RequestID + ":artifact",
		ParentRequestID:     parentRequestID,
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
	if response.FrameType != ipcFrameTypeOpenHandle || response.RequestID != request.RequestID+":artifact" || response.ParentRequestID != request.RequestID {
		os.Exit(9)
	}
	var artifact artifactHandleResultPayload
	if err := json.Unmarshal(response.Payload, &artifact); err != nil {
		os.Exit(10)
	}
	if !artifact.OK {
		writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightComplete)
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: artifact.Code, Message: artifact.Message, ErrorOrigin: artifact.ErrorOrigin})
		_ = encoder.Encode(ipcFrame{
			IPCVersion:          version.RustIPCVersion,
			FrameType:           ipcFrameTypeInvokeWorkerResult,
			RequestID:           request.RequestID,
			RuntimeGenerationID: request.RuntimeGenerationID,
			Payload:             raw,
		})
		return false
	}
	writeCompileFlightLifecycleFromHelper(encoder, request, ipcFrameTypeCompileFlightComplete)
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

func writeCompileFlightLifecycleFromHelper(encoder *json.Encoder, request ipcFrame, frameType string) {
	artifact := artifactRequestPayloadFromInvoke(request)
	artifactRequestID := request.RequestID + ":artifact"
	if os.Getenv("REDEVPLUGIN_RUNTIMECLIENT_UNKNOWN_COMPILE_FLIGHT") == frameType {
		artifactRequestID += ":unknown"
	}
	suffix := ":register"
	if frameType == ipcFrameTypeCompileFlightComplete {
		suffix = ":complete"
	}
	_ = encoder.Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           artifactRequestID + suffix,
		ParentRequestID:     request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload: mustMarshalRaw(compileFlightLifecyclePayload{
			ArtifactRequestID: artifactRequestID,
			PackageHash:       artifact.PackageHash,
			Artifact:          artifact.Artifact,
			ArtifactSHA256:    artifact.ArtifactSHA256,
			WASMABIVersion:    version.WASMABIVersion,
		}),
	})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeValidateHandleGrant || response.RequestID != request.RequestID+":handle_grant" || response.ParentRequestID != request.RequestID {
		os.Exit(15)
	}
	var grant handleGrantValidationResultPayload
	if err := json.Unmarshal(response.Payload, &grant); err != nil {
		os.Exit(16)
	}
	if !grant.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: grant.Code, Message: grant.Message, ErrorOrigin: grant.ErrorOrigin})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeStorageFile || response.RequestID != request.RequestID+":storage_file" || response.ParentRequestID != request.RequestID {
		os.Exit(19)
	}
	var storageFile storageFileResponsePayload
	if err := json.Unmarshal(response.Payload, &storageFile); err != nil {
		os.Exit(20)
	}
	if !storageFile.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageFile.Code, Message: storageFile.Message, ErrorOrigin: storageFile.ErrorOrigin})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeStorageKV || response.RequestID != request.RequestID+":storage_kv" || response.ParentRequestID != request.RequestID {
		os.Exit(43)
	}
	var storageKV storageKVResponsePayload
	if err := json.Unmarshal(response.Payload, &storageKV); err != nil {
		os.Exit(44)
	}
	if !storageKV.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageKV.Code, Message: storageKV.Message, ErrorOrigin: storageKV.ErrorOrigin})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeStorageSQLite || response.RequestID != request.RequestID+":storage_sqlite" || response.ParentRequestID != request.RequestID {
		os.Exit(53)
	}
	var storageSQLite storageSQLiteResponsePayload
	if err := json.Unmarshal(response.Payload, &storageSQLite); err != nil {
		os.Exit(54)
	}
	if !storageSQLite.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: storageSQLite.Code, Message: storageSQLite.Message, ErrorOrigin: storageSQLite.ErrorOrigin})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeNetworkGrant || response.RequestID != request.RequestID+":network_grant" || response.ParentRequestID != request.RequestID {
		os.Exit(23)
	}
	var networkGrant networkGrantResponsePayload
	if err := json.Unmarshal(response.Payload, &networkGrant); err != nil {
		os.Exit(24)
	}
	if !networkGrant.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: networkGrant.Code, Message: networkGrant.Message, ErrorOrigin: networkGrant.ErrorOrigin})
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
		ParentRequestID:     request.RequestID,
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
	if response.FrameType != ipcFrameTypeNetworkExecute || response.RequestID != request.RequestID+":network_execute" || response.ParentRequestID != request.RequestID {
		os.Exit(27)
	}
	var networkExecute networkExecuteResponsePayload
	if err := json.Unmarshal(response.Payload, &networkExecute); err != nil {
		os.Exit(28)
	}
	if !networkExecute.OK {
		raw, _ := json.Marshal(runtimeResponsePayload{OK: false, Code: networkExecute.Code, Message: networkExecute.Message, ErrorOrigin: networkExecute.ErrorOrigin})
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
			req.ActiveFingerprint = payload.Lease.ActiveFingerprint
			req.RuntimeInstanceID = payload.Lease.RuntimeInstanceID
			req.RuntimeGenerationID = payload.Lease.RuntimeGenerationID
			req.RuntimeShardID = payload.Lease.RuntimeShardID
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
			req.ActiveFingerprint = payload.Lease.ActiveFingerprint
			req.RuntimeInstanceID = payload.Lease.RuntimeInstanceID
			req.RuntimeGenerationID = payload.Lease.RuntimeGenerationID
			req.RuntimeShardID = payload.Lease.RuntimeShardID
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
			req.ActiveFingerprint = payload.Lease.ActiveFingerprint
			req.RuntimeInstanceID = payload.Lease.RuntimeInstanceID
			req.RuntimeGenerationID = payload.Lease.RuntimeGenerationID
			req.RuntimeShardID = payload.Lease.RuntimeShardID
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
		PluginID:            "com.example.worker",
		PluginInstanceID:    grantReq.PluginInstanceID,
		ActiveFingerprint:   grantReq.ActiveFingerprint,
		ResourceScope:       grantReq.ResourceScope,
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
		Query:               url.Values{"units": []string{"metric"}, "lang": []string{"en"}},
		Headers:             http.Header{"X-Test": []string{"ok"}},
		BodyBase64:          base64.StdEncoding.EncodeToString([]byte(`{"hello":"network"}`)),
		MaxRequestBytes:     2048,
		MaxResponseBytes:    1024,
		TimeoutMillis:       2000,
	}
	if request.FrameType == ipcFrameTypeInvokeWorker {
		var payload invokeWorkerRequestPayload
		var invocation struct {
			PluginID             string `json:"plugin_id"`
			ActiveFingerprint    string `json:"active_fingerprint"`
			Method               string `json:"method"`
			Effect               string `json:"effect"`
			Execution            string `json:"execution"`
			SurfaceInstanceID    string `json:"surface_instance_id"`
			OwnerSessionHash     string `json:"owner_session_hash"`
			OwnerUserHash        string `json:"owner_user_hash"`
			OwnerEnvHash         string `json:"owner_env_hash"`
			SessionChannelIDHash string `json:"session_channel_id_hash"`
			BridgeChannelID      string `json:"bridge_channel_id"`
			StreamID             string `json:"stream_id"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err == nil {
			_ = json.Unmarshal(payload.Invocation, &invocation)
			if strings.TrimSpace(invocation.PluginID) != "" {
				req.PluginID = invocation.PluginID
			}
			if strings.TrimSpace(invocation.ActiveFingerprint) != "" {
				req.ActiveFingerprint = invocation.ActiveFingerprint
			}
			req.StreamMethod = invocation.Method
			req.StreamEffect = invocation.Effect
			req.StreamExecution = invocation.Execution
			req.SurfaceInstanceID = invocation.SurfaceInstanceID
			req.OwnerSessionHash = invocation.OwnerSessionHash
			req.OwnerUserHash = invocation.OwnerUserHash
			req.OwnerEnvHash = invocation.OwnerEnvHash
			req.SessionChannelIDHash = invocation.SessionChannelIDHash
			req.BridgeChannelID = invocation.BridgeChannelID
			req.StreamID = invocation.StreamID
		}
	}
	switch operation {
	case "http_stream":
		req.MaxChunkBytes = 4
		req.MaxBufferedBytes = 64 * 1024
		req.ContentType = "text/plain"
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
		ResourceScope:       sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
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
			req.ActiveFingerprint = payload.Lease.ActiveFingerprint
			req.ResourceScope = sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: payload.Lease.OwnerEnvHash, OwnerUserHash: payload.Lease.OwnerUserHash}
			req.RuntimeInstanceID = payload.Lease.RuntimeInstanceID
			req.RuntimeGenerationID = payload.Lease.RuntimeGenerationID
			req.RuntimeShardID = payload.Lease.RuntimeShardID
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
			req.ActiveFingerprint = payload.Lease.ActiveFingerprint
			req.RuntimeInstanceID = payload.Lease.RuntimeInstanceID
			req.RuntimeGenerationID = payload.Lease.RuntimeGenerationID
			req.RuntimeShardID = payload.Lease.RuntimeShardID
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

func waitForDiagnostic(t *testing.T, store *runtimeDiagnosticSink, eventType string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events := store.list(eventType)
		if len(events) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	events := store.list("")
	t.Fatalf("timed out waiting for diagnostic %q; events=%#v", eventType, events)
}

type runtimeDiagnosticSink struct {
	mu     sync.Mutex
	events []observability.DiagnosticEvent
}

func (s *runtimeDiagnosticSink) AppendPluginDiagnostic(_ context.Context, event observability.DiagnosticEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *runtimeDiagnosticSink) list(eventType string) []observability.DiagnosticEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]observability.DiagnosticEvent, 0, len(s.events))
	for _, event := range s.events {
		if eventType == "" || event.Type == eventType {
			events = append(events, event)
		}
	}
	return events
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

type cancelAwareArtifactProvider struct {
	started  chan time.Time
	canceled chan error
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(payload)
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Len()
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

type recordingHandleGrantValidator struct {
	calls  int
	last   HandleGrantValidationRequest
	result HandleGrantValidationResult
	err    error
}

type recordingStorageFilesBroker struct {
	readCalls          int
	writeCalls         int
	deleteCalls        int
	listCalls          int
	lastRead           storage.FileReadRequest
	lastWrite          storage.FileWriteRequest
	lastDelete         storage.FileDeleteRequest
	lastList           storage.FileListRequest
	lastReadCalledAt   time.Time
	lastReadDeadline   time.Time
	lastReadDeadlineOK bool
	readResult         storage.FileReadResult
	writeResult        storage.FileWriteResult
	listResult         storage.FileListResult
	err                error
}

type recordingStorageKVBroker struct {
	getCalls          int
	putCalls          int
	deleteCalls       int
	listCalls         int
	lastGet           storage.KVGetRequest
	lastPut           storage.KVPutRequest
	lastDelete        storage.KVDeleteRequest
	lastList          storage.KVListRequest
	lastPutCalledAt   time.Time
	lastPutDeadline   time.Time
	lastPutDeadlineOK bool
	getResult         storage.KVGetResult
	putResult         storage.KVPutResult
	listResult        storage.KVListResult
	err               error
}

type recordingStorageSQLiteBroker struct {
	execCalls           int
	queryCalls          int
	lastExec            storage.SQLiteExecRequest
	lastQuery           storage.SQLiteQueryRequest
	lastQueryCalledAt   time.Time
	lastQueryDeadline   time.Time
	lastQueryDeadlineOK bool
	execResult          storage.SQLiteExecResult
	queryResult         storage.SQLiteQueryResult
	err                 error
}

type recordingConnectivityBroker struct {
	calls          int
	installCall    int
	removeCall     int
	last           connectivity.GrantRequest
	lastSession    sessionctx.Context
	hasLastSession bool
	lastCalledAt   time.Time
	lastDeadline   time.Time
	lastDeadlineOK bool
	grant          connectivity.ConnectionGrant
	err            error
}

type recordingNetworkExecutor struct {
	httpCalls          int
	streamCalls        int
	websocketCalls     int
	tcpCalls           int
	udpCalls           int
	lastHTTP           connectivity.HTTPRequest
	lastStreamHTTP     connectivity.HTTPRequest
	lastWebSocket      connectivity.WebSocketRoundTripRequest
	lastTCP            connectivity.TCPRoundTripRequest
	lastUDP            connectivity.UDPRoundTripRequest
	lastHTTPCalledAt   time.Time
	lastHTTPDeadline   time.Time
	lastHTTPDeadlineOK bool
	httpResponse       connectivity.HTTPResponse
	streamResponse     connectivity.HTTPStreamResponse
	streamChunks       [][]byte
	wsResponse         connectivity.WebSocketRoundTripResponse
	tcpResponse        connectivity.TCPRoundTripResponse
	udpResponse        connectivity.UDPRoundTripResponse
	err                error
}

func (b *recordingConnectivityBroker) InstallPolicy(context.Context, connectivity.PolicySet) error {
	b.installCall++
	return nil
}

func (b *recordingConnectivityBroker) RemovePolicy(context.Context, string) error {
	b.removeCall++
	return nil
}

func (b *recordingConnectivityBroker) MintConnectionGrant(ctx context.Context, req connectivity.GrantRequest) (connectivity.ConnectionGrant, error) {
	b.calls++
	b.last = req
	b.lastSession, b.hasLastSession = sessionctx.FromContext(ctx)
	b.lastCalledAt = time.Now()
	b.lastDeadline, b.lastDeadlineOK = ctx.Deadline()
	if b.err != nil {
		return connectivity.ConnectionGrant{}, b.err
	}
	grant := b.grant
	if !grant.ResourceScope.Valid() {
		grant.ResourceScope = req.ResourceScope
	}
	return grant, nil
}

func (e *recordingNetworkExecutor) DoHTTP(ctx context.Context, req connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	e.httpCalls++
	e.lastHTTP = req
	e.lastHTTPCalledAt = time.Now()
	e.lastHTTPDeadline, e.lastHTTPDeadlineOK = ctx.Deadline()
	if e.err != nil {
		return connectivity.HTTPResponse{}, e.err
	}
	return e.httpResponse, nil
}

func (e *recordingNetworkExecutor) StreamHTTP(ctx context.Context, req connectivity.HTTPRequest, onChunk func(connectivity.HTTPResponseChunk) error) (connectivity.HTTPStreamResponse, error) {
	e.streamCalls++
	e.lastStreamHTTP = req
	e.lastHTTPCalledAt = time.Now()
	e.lastHTTPDeadline, e.lastHTTPDeadlineOK = ctx.Deadline()
	if e.err != nil {
		return connectivity.HTTPStreamResponse{}, e.err
	}
	var bytesRead int64
	for index, chunk := range e.streamChunks {
		if err := onChunk(connectivity.HTTPResponseChunk{Index: index, Data: append([]byte(nil), chunk...)}); err != nil {
			return connectivity.HTTPStreamResponse{}, err
		}
		bytesRead += int64(len(chunk))
	}
	result := e.streamResponse
	if result.StatusCode == 0 {
		result.StatusCode = http.StatusOK
	}
	if result.BytesRead == 0 {
		result.BytesRead = bytesRead
	}
	if result.ChunkCount == 0 {
		result.ChunkCount = len(e.streamChunks)
	}
	return result, nil
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

func (b *recordingStorageFilesBroker) ReadFile(ctx context.Context, req storage.FileReadRequest) (storage.FileReadResult, error) {
	b.readCalls++
	b.lastRead = req
	b.lastReadCalledAt = time.Now()
	b.lastReadDeadline, b.lastReadDeadlineOK = ctx.Deadline()
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

func (b *recordingStorageKVBroker) PutKV(ctx context.Context, req storage.KVPutRequest) (storage.KVPutResult, error) {
	b.putCalls++
	b.lastPut = req
	b.lastPutCalledAt = time.Now()
	b.lastPutDeadline, b.lastPutDeadlineOK = ctx.Deadline()
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

func (b *recordingStorageSQLiteBroker) QuerySQLite(ctx context.Context, req storage.SQLiteQueryRequest) (storage.SQLiteQueryResult, error) {
	b.queryCalls++
	b.lastQuery = req
	b.lastQueryCalledAt = time.Now()
	b.lastQueryDeadline, b.lastQueryDeadlineOK = ctx.Deadline()
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

func (p *cancelAwareArtifactProvider) ReadArtifact(ctx context.Context, _ ArtifactRequest) (ArtifactResult, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > defaultRuntimeHostcallTimeout+250*time.Millisecond {
		return ArtifactResult{}, errors.New("artifact context deadline is not bounded")
	}
	p.started <- time.Now()
	<-ctx.Done()
	p.canceled <- ctx.Err()
	return ArtifactResult{}, ctx.Err()
}

func assertBoundedDeadline(t *testing.T, label string, calledAt time.Time, deadline time.Time, ok bool, max time.Duration) {
	t.Helper()
	if !ok {
		t.Fatalf("%s context missing deadline", label)
	}
	remaining := deadline.Sub(calledAt)
	if remaining <= 0 || remaining > max+250*time.Millisecond {
		t.Fatalf("%s deadline remaining = %v, want >0 and <= %v", label, remaining, max)
	}
}

func workerInvocationFixture() []byte {
	return workerInvocationFixtureWithAccess(workerBrokerAccess{
		Storage: []workerStorageBrokerAccess{
			{StoreID: "workspace", Operations: []string{"read", "write", "delete", "list"}},
			{StoreID: "settings", Operations: []string{"get", "put", "delete", "list"}},
			{StoreID: "db", Operations: []string{"exec", "query"}},
		},
		Network: []workerNetworkBrokerAccess{
			{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http", "http_stream"}, HTTPMethods: []string{"GET", "POST"}},
			{ConnectorID: "api", Transport: "websocket", Scope: "user", Operations: []string{"websocket_round_trip"}},
			{ConnectorID: "api", Transport: "tcp", Scope: "user", Operations: []string{"tcp_round_trip"}},
			{ConnectorID: "api", Transport: "udp", Scope: "user", Operations: []string{"udp_round_trip"}},
		},
	})
}

func workerInvocationFixtureForPlugin(pluginInstanceID string) []byte {
	return bytes.ReplaceAll(workerInvocationFixture(), []byte(`"plugin_instance_id":"plugini_1"`), []byte(`"plugin_instance_id":"`+pluginInstanceID+`"`))
}

func workerInvocationLeaseFixture() Lease {
	return Lease{
		PluginID:             "com.example.worker",
		PluginInstanceID:     "plugini_1",
		ActiveFingerprint:    "sha256:active",
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_test",
		RuntimeShardID:       "runtime_shard_1",
		Method:               "worker.echo",
		Effect:               "read",
		Execution:            "subscription",
		SurfaceInstanceID:    "surface_runtime",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_runtime",
		OperationID:          "operation_runtime_1",
		StreamID:             "stream_runtime_1",
		AuditCorrelationID:   "audit_runtime_1",
		PolicyRevision:       1,
		ManagementRevision:   2,
		RevokeEpoch:          3,
	}
}

func workerInvocationFixtureWithAccess(access workerBrokerAccess) []byte {
	rawAccess, err := json.Marshal(access)
	if err != nil {
		panic(err)
	}
	accessSum := sha256.Sum256(rawAccess)
	accessHash := "sha256:" + hex.EncodeToString(accessSum[:])
	return []byte(fmt.Sprintf(`{"plugin_id":"com.example.worker","plugin_instance_id":"plugini_1","active_fingerprint":"sha256:active","runtime_instance_id":"runtime_1","runtime_generation_id":"runtime_gen_test","package_hash":%q,"worker_id":"echo_worker","worker_mode":"job","worker_scope":"default","artifact":%q,"artifact_sha256":%q,"abi":"redevplugin-wasm-worker-v2","method":"worker.echo","effect":"read","execution":"subscription","surface_instance_id":"surface_runtime","owner_session_hash":"session_hash","owner_user_hash":"user_hash","owner_env_hash":"env_hash","session_channel_id_hash":"channel_hash","bridge_channel_id":"bridge_runtime","operation_id":"operation_runtime_1","stream_id":"stream_runtime_1","audit_correlation_id":"audit_runtime_1","broker_access":%s,"broker_access_sha256":%q,"params":{"message":"hello"}}`, fixturePackageHash, fixtureArtifact, fixtureArtifactSHA, rawAccess, accessHash))
}

func (s *ProcessSupervisor) invokeWorkerForTest(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error) {
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now()
	}
	health := s.healthSnapshot()
	if lease.LeaseID == "" {
		lease.LeaseID = "lease_test"
	}
	if lease.LeaseNonce == "" {
		lease.LeaseNonce = "nonce_" + lease.LeaseID + "_1234567890"
	}
	if lease.PluginID == "" {
		lease.PluginID = "com.example.worker"
	}
	if lease.PluginVersion == "" {
		lease.PluginVersion = "1.0.0"
	}
	if lease.ActiveFingerprint == "" {
		lease.ActiveFingerprint = "sha256:active"
	}
	if lease.PluginInstanceID == "" {
		lease.PluginInstanceID = "plugini_1"
	}
	if lease.Method == "" {
		lease.Method = method
	}
	if lease.Effect == "" {
		lease.Effect = "read"
	}
	if lease.Execution == "" {
		lease.Execution = "subscription"
	}
	if lease.Execution == "operation" && lease.OperationID == "" {
		lease.OperationID = "operation_runtime_1"
	}
	if lease.Execution == "subscription" {
		if lease.OperationID == "" {
			lease.OperationID = "operation_runtime_1"
		}
		if lease.StreamID == "" {
			lease.StreamID = "stream_runtime_1"
		}
	}
	if lease.AuditCorrelationID == "" {
		lease.AuditCorrelationID = "audit_runtime_1"
	}
	if lease.SurfaceInstanceID == "" {
		lease.SurfaceInstanceID = "surface_runtime"
	}
	if lease.OwnerSessionHash == "" {
		lease.OwnerSessionHash = "session_hash"
	}
	if lease.OwnerUserHash == "" {
		lease.OwnerUserHash = "user_hash"
	}
	if lease.OwnerEnvHash == "" {
		lease.OwnerEnvHash = "env_hash"
	}
	if lease.SessionChannelIDHash == "" {
		lease.SessionChannelIDHash = "channel_hash"
	}
	if lease.BridgeChannelID == "" {
		lease.BridgeChannelID = "bridge_runtime"
	}
	if len(lease.TargetDescriptorHashes) == 0 {
		lease.TargetDescriptorHashes = []string{"invocation:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}
	if lease.Limits.MemoryBytes == 0 {
		lease.Limits.MemoryBytes = 64 * 1024
	}
	if lease.PolicyRevision == 0 {
		lease.PolicyRevision = 1
	}
	if lease.ManagementRevision == 0 {
		lease.ManagementRevision = 1
	}
	if lease.RevokeEpoch == 0 {
		lease.RevokeEpoch = 1
	}
	if lease.RuntimeInstanceID == "" {
		lease.RuntimeInstanceID = health.RuntimeInstanceID
	}
	if lease.RuntimeShardID == "" {
		lease.RuntimeShardID = "runtime_shard_test"
	}
	if lease.RuntimeGenerationID == "" {
		lease.RuntimeGenerationID = health.RuntimeGenerationID
	}
	if lease.IPCChannelID == "" {
		lease.IPCChannelID = health.IPCChannelID
	}
	if lease.ConnectionNonce == "" {
		lease.ConnectionNonce = health.ConnectionNonce
	}
	if lease.TokenID == "" {
		lease.TokenID = lease.LeaseID
	}
	if lease.IssuedAtUnixMillis == 0 {
		lease.IssuedAtUnixMillis = now.Add(-time.Second).UnixMilli()
	}
	if lease.ExpiresAtUnixMillis == 0 {
		lease.ExpiresAtUnixMillis = now.Add(time.Minute).UnixMilli()
	}
	payload = bindWorkerInvocationFixtureToLease(payload, lease)
	return s.InvokeWorker(ctx, lease, method, payload)
}

func bindWorkerInvocationFixtureToLease(payload []byte, lease Lease) []byte {
	var invocation map[string]any
	if json.Unmarshal(payload, &invocation) != nil {
		return payload
	}
	if _, ok := invocation["package_hash"]; !ok {
		return payload
	}
	bindings := map[string]string{
		"plugin_id":               lease.PluginID,
		"plugin_instance_id":      lease.PluginInstanceID,
		"active_fingerprint":      lease.ActiveFingerprint,
		"runtime_instance_id":     lease.RuntimeInstanceID,
		"runtime_generation_id":   lease.RuntimeGenerationID,
		"method":                  lease.Method,
		"effect":                  lease.Effect,
		"execution":               lease.Execution,
		"surface_instance_id":     lease.SurfaceInstanceID,
		"owner_session_hash":      lease.OwnerSessionHash,
		"owner_user_hash":         lease.OwnerUserHash,
		"owner_env_hash":          lease.OwnerEnvHash,
		"session_channel_id_hash": lease.SessionChannelIDHash,
		"bridge_channel_id":       lease.BridgeChannelID,
		"operation_id":            lease.OperationID,
		"stream_id":               lease.StreamID,
		"audit_correlation_id":    lease.AuditCorrelationID,
	}
	for field, value := range bindings {
		if value == "" {
			delete(invocation, field)
			continue
		}
		invocation[field] = value
	}
	raw, err := json.Marshal(invocation)
	if err != nil {
		panic(err)
	}
	return raw
}

type storeRuntimeStreamSink struct {
	store stream.Store
}

func (s storeRuntimeStreamSink) AppendRuntimeStream(ctx context.Context, streamID, kind string, data []byte) error {
	_, err := s.store.Append(ctx, stream.AppendRequest{StreamID: streamID, Kind: kind, Data: data})
	return err
}

func (s storeRuntimeStreamSink) CloseRuntimeStream(ctx context.Context, streamID string) error {
	_, err := s.store.Close(ctx, stream.CloseRequest{StreamID: streamID, Status: stream.StatusClosed})
	return err
}

func (s storeRuntimeStreamSink) FailRuntimeStream(ctx context.Context, streamID string, code capability.ExecutionFailureCode, _ error) error {
	_, err := s.store.Close(ctx, stream.CloseRequest{StreamID: streamID, Status: stream.StatusFailed, FailureCode: code})
	return err
}

func stopRuntimeSupervisor(t *testing.T, supervisor *ProcessSupervisor) {
	t.Helper()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}
