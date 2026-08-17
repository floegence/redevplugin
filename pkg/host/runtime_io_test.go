package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

type recordingHostMountAdapter struct {
	list       MountListRequest
	resolveErr error
}

func (adapter *recordingHostMountAdapter) ResolveMount(context.Context, MountRequest) (Mount, error) {
	if adapter.resolveErr != nil {
		return Mount{}, adapter.resolveErr
	}
	return Mount{}, errors.New("unexpected ResolveMount")
}

func TestHostMountResolverPreservesMountUnavailable(t *testing.T) {
	resolver := hostMountResolver{adapter: &recordingHostMountAdapter{resolveErr: ErrMountUnavailable}}
	_, err := resolver.ResolveMount(context.Background(), runtimeIOTestInvocation("invocation-mount", "session-mount", "channel-mount"), "workspace")
	if !errors.Is(err, resourceio.ErrMountUnavailable) {
		t.Fatalf("ResolveMount() error = %v, want resourceio.ErrMountUnavailable", err)
	}
}

func (adapter *recordingHostMountAdapter) ListMounts(_ context.Context, request MountListRequest) ([]Mount, error) {
	adapter.list = request
	return []Mount{{ID: "workspace", Path: "/host/private/workspace", ReadOnly: false}}, nil
}

type recordingHostNetworkAdapter struct {
	request NetworkAuthorizationRequest
	err     error
}

func (adapter *recordingHostNetworkAdapter) AuthorizeNetwork(_ context.Context, request NetworkAuthorizationRequest) error {
	adapter.request = request
	return adapter.err
}

func TestHostRuntimeIOBrokerProjectsExactTrustedAdapterContext(t *testing.T) {
	mounts := &recordingHostMountAdapter{}
	networkDenied := errors.New("fixture network policy denial")
	network := &recordingHostNetworkAdapter{err: networkDenied}
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{FileSystem: mounts, NetworkPolicy: network})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.closeAll() })

	invocation := resourceio.Invocation{
		Owner: resourceio.Owner{
			PluginInstanceID:   "plugini_io_projection",
			ActiveFingerprint:  "sha256:active-projection",
			Scope:              sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env-projection", OwnerUserHash: "user-projection"},
			Session:            sessionctx.SessionScope{OwnerSessionHash: "session-projection", OwnerUserHash: "user-projection", OwnerEnvHash: "env-projection", SessionChannelIDHash: "channel-projection"},
			RuntimeGeneration:  "generation-projection",
			ManagementRevision: 17,
			RevokeEpoch:        19,
			InvocationID:       "invocation-projection",
			Lifetime:           resourceio.LifetimeInvocation,
		},
		Plugin: resourceio.Plugin{ID: "com.example.projection", InstanceID: "plugini_io_projection", Version: "9.0.0"},
		Permissions: map[string]bool{
			resourceio.PermissionFSWorkspaceRead: true,
			resourceio.PermissionNetworkClient:   true,
		},
		CanRead:  true,
		CanWrite: false,
	}
	if err := broker.register(invocation.Owner.InvocationID, hostRuntimeIORegistration{resource: invocation}); err != nil {
		t.Fatal(err)
	}

	mountResponse, err := broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(`{"plugin_api":1,"operation":"fs.mounts","arguments":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(mountResponse) == "" || json.Valid(mountResponse) == false {
		t.Fatalf("mount response = %s", mountResponse)
	}
	if bytes.Contains(mountResponse, []byte("/host/private/workspace")) {
		t.Fatalf("mount response leaked Host path: %s", mountResponse)
	}
	assertProjectedIOContext(t, mounts.list.Session, mounts.list.Plugin)

	_, err = broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(`{"plugin_api":1,"operation":"net.http.begin","arguments":{"method":"GET","url":"https://example.test:8443/data","headers":[],"redirect":"error","timeout_ms":1000}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertProjectedIOContext(t, network.request.Session, network.request.Plugin)
	if network.request.Operation != "net.http.begin" || network.request.Listen || network.request.Destination != (NetworkDestination{
		Transport: "http", Scheme: "https", Host: "example.test", Port: 8443, URL: "https://example.test:8443/data",
	}) {
		t.Fatalf("network projection = %#v", network.request)
	}
}

func assertProjectedIOContext(t *testing.T, session sessionctx.Context, plugin PluginRef) {
	t.Helper()
	if session.OwnerSessionHash != "session-projection" || session.OwnerUserHash != "user-projection" || session.OwnerEnvHash != "env-projection" || session.SessionChannelIDHash != "channel-projection" || !session.CanRead || session.CanWrite {
		t.Fatalf("session projection = %#v", session)
	}
	if plugin != (PluginRef{PluginID: "com.example.projection", PluginInstanceID: "plugini_io_projection", Version: "9.0.0", ActiveFingerprint: "sha256:active-projection"}) {
		t.Fatalf("plugin projection = %#v", plugin)
	}
}

func TestHostRuntimeIOBrokerRevokesExactSessionThenPlugin(t *testing.T) {
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{FileSystem: &recordingHostMountAdapter{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.closeAll() })
	first := runtimeIOTestInvocation("invocation-first", "session-first", "channel-first")
	second := runtimeIOTestInvocation("invocation-second", "session-second", "channel-second")
	if err := broker.register(first.Owner.InvocationID, hostRuntimeIORegistration{resource: first}); err != nil {
		t.Fatal(err)
	}
	if err := broker.register(second.Owner.InvocationID, hostRuntimeIORegistration{resource: second}); err != nil {
		t.Fatal(err)
	}
	if err := broker.revokeSession(first.Owner.Session); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"plugin_api":1,"operation":"fs.mounts","arguments":{}}`)
	if _, err := broker.Control(context.Background(), first.Owner.InvocationID, request); !errors.Is(err, errRuntimeIOInvocationUnknown) {
		t.Fatalf("first session Control() error = %v", err)
	}
	if response, err := broker.Control(context.Background(), second.Owner.InvocationID, request); err != nil || !json.Valid(response) {
		t.Fatalf("sibling session Control() = %s, %v", response, err)
	}
	if err := broker.revokePlugin(second.Owner.Scope.OwnerEnvHash, second.Owner.PluginInstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Control(context.Background(), second.Owner.InvocationID, request); !errors.Is(err, errRuntimeIOInvocationUnknown) {
		t.Fatalf("plugin-revoked Control() error = %v", err)
	}
}

type recordingStorageBroker struct {
	fileRead    storage.FileReadRequest
	kvPut       storage.KVPutRequest
	sqliteQuery storage.SQLiteQueryRequest
	calls       int
}

func (broker *recordingStorageBroker) ReadFile(_ context.Context, req storage.FileReadRequest) (storage.FileReadResult, error) {
	broker.calls++
	broker.fileRead = req
	return storage.FileReadResult{Path: req.Path, Data: []byte("memo"), SizeBytes: 4, Usage: storage.Usage{PluginInstanceID: req.PluginInstanceID, StoreID: req.StoreID, UsageBytes: 4, QuotaBytes: 1024}}, nil
}

func (*recordingStorageBroker) WriteFile(context.Context, storage.FileWriteRequest) (storage.FileWriteResult, error) {
	panic("unexpected WriteFile")
}

func (*recordingStorageBroker) DeleteFile(context.Context, storage.FileDeleteRequest) error {
	panic("unexpected DeleteFile")
}

func (*recordingStorageBroker) ListFiles(context.Context, storage.FileListRequest) (storage.FileListResult, error) {
	panic("unexpected ListFiles")
}

func (*recordingStorageBroker) GetKV(context.Context, storage.KVGetRequest) (storage.KVGetResult, error) {
	panic("unexpected GetKV")
}

func (broker *recordingStorageBroker) PutKV(_ context.Context, req storage.KVPutRequest) (storage.KVPutResult, error) {
	broker.calls++
	broker.kvPut = req
	return storage.KVPutResult{Key: req.Key, SizeBytes: int64(len(req.Value)), Usage: storage.Usage{PluginInstanceID: req.PluginInstanceID, StoreID: req.StoreID, UsageBytes: int64(len(req.Value)), QuotaBytes: 1024}}, nil
}

func (*recordingStorageBroker) DeleteKV(context.Context, storage.KVDeleteRequest) error {
	panic("unexpected DeleteKV")
}

func (*recordingStorageBroker) ListKV(context.Context, storage.KVListRequest) (storage.KVListResult, error) {
	panic("unexpected ListKV")
}

func (*recordingStorageBroker) ExecSQLite(context.Context, storage.SQLiteExecRequest) (storage.SQLiteExecResult, error) {
	panic("unexpected ExecSQLite")
}

func (broker *recordingStorageBroker) QuerySQLite(_ context.Context, req storage.SQLiteQueryRequest) (storage.SQLiteQueryResult, error) {
	broker.calls++
	broker.sqliteQuery = req
	text := "Launch"
	return storage.SQLiteQueryResult{
		Database: req.Database,
		Columns:  []string{"title"},
		Rows:     [][]storage.SQLiteValue{{{Text: &text}}},
		Usage:    storage.Usage{PluginInstanceID: req.PluginInstanceID, StoreID: req.StoreID, UsageBytes: 64, QuotaBytes: 1024},
	}, nil
}

func TestHostRuntimeIOBrokerDispatchesAuthorizedStorageFromTrustedRegistration(t *testing.T) {
	pluginData := &recordingStorageBroker{}
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	broker.storageFiles = pluginData
	broker.storageKV = pluginData
	broker.storageSQLite = pluginData
	t.Cleanup(func() { _ = broker.closeAll() })

	invocation := runtimeIOTestInvocation("invocation-storage", "session-storage", "channel-storage")
	invocation.CanWrite = true
	registration, err := newHostRuntimeIORegistration(invocation, workerBrokerAccess{Storage: []workerStorageBrokerAccess{
		{StoreID: "files", Kind: "files", Scope: "user", Operations: []string{"read"}},
		{StoreID: "settings", Kind: "kv", Scope: "environment", Operations: []string{"put"}},
		{StoreID: "notes", Kind: "sqlite", Scope: "user", Operations: []string{"query"}},
	}}, map[string]string{"files": "grant-files", "settings": "grant-settings", "notes": "grant-notes"})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.register(invocation.Owner.InvocationID, registration); err != nil {
		t.Fatal(err)
	}

	fileResponse := runtimeIOControl(t, broker, invocation.Owner.InvocationID, `{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"files","path":"memo.txt","max_bytes":32}}`)
	if fileResponse["ok"] != true || fileResponse["result"].(map[string]any)["data_base64"] != base64.StdEncoding.EncodeToString([]byte("memo")) {
		t.Fatalf("file response = %#v", fileResponse)
	}
	if pluginData.fileRead.PluginInstanceID != invocation.Owner.PluginInstanceID || pluginData.fileRead.StoreID != "files" || pluginData.fileRead.Path != "memo.txt" || !pluginData.fileRead.ResourceScope.Matches(invocation.Owner.Scope) {
		t.Fatalf("file request = %#v", pluginData.fileRead)
	}

	runtimeIOControl(t, broker, invocation.Owner.InvocationID, `{"plugin_api":1,"operation":"storage.kv","arguments":{"operation":"put","store_id":"settings","key":"theme","value_base64":"ZGFyaw=="}}`)
	if pluginData.kvPut.PluginInstanceID != invocation.Owner.PluginInstanceID || pluginData.kvPut.ResourceScope.Kind != sessionctx.ScopeEnvironment || pluginData.kvPut.ResourceScope.OwnerUserHash != "" || string(pluginData.kvPut.Value) != "dark" {
		t.Fatalf("kv request = %#v", pluginData.kvPut)
	}

	sqliteResponse := runtimeIOControl(t, broker, invocation.Owner.InvocationID, `{"plugin_api":1,"operation":"storage.sqlite","arguments":{"operation":"query","store_id":"notes","database":"notes.sqlite","sql":"SELECT title FROM notes","args":[],"max_rows":10,"max_response_bytes":4096,"timeout_ms":1000}}`)
	if sqliteResponse["ok"] != true || pluginData.sqliteQuery.PluginInstanceID != invocation.Owner.PluginInstanceID || pluginData.sqliteQuery.ResourceScope.Kind != sessionctx.ScopeUser || pluginData.sqliteQuery.Timeout != time.Second {
		t.Fatalf("sqlite response = %#v, request = %#v", sqliteResponse, pluginData.sqliteQuery)
	}
}

func TestHostRuntimeIOBrokerStorageFailsClosedOutsideTrustedAccess(t *testing.T) {
	pluginData := &recordingStorageBroker{}
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	broker.storageFiles = pluginData
	broker.storageKV = pluginData
	broker.storageSQLite = pluginData
	t.Cleanup(func() { _ = broker.closeAll() })

	invocation := runtimeIOTestInvocation("invocation-storage-denied", "session-storage-denied", "channel-storage-denied")
	registration, err := newHostRuntimeIORegistration(invocation, workerBrokerAccess{Storage: []workerStorageBrokerAccess{
		{StoreID: "files", Kind: "files", Scope: "user", Operations: []string{"read"}},
	}}, map[string]string{"files": "grant-files"})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.register(invocation.Owner.InvocationID, registration); err != nil {
		t.Fatal(err)
	}

	requests := []string{
		`{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"other","path":"memo.txt"}}`,
		`{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"write","store_id":"files","path":"memo.txt","data_base64":"bWVtbw=="}}`,
		`{"plugin_api":1,"operation":"storage.kv","arguments":{"operation":"get","store_id":"files","key":"memo"}}`,
		`{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"files","path":"memo.txt","plugin_instance_id":"attacker"}}`,
		`{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"files","path":"memo.txt","resource_scope":{"kind":"environment","owner_env_hash":"attacker"}}}`,
		`{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"files","path":"memo.txt","management_revision":999,"revoke_epoch":0}}`,
		`{"plugin_api":1,"operation":"network.execute","arguments":{}}`,
	}
	for _, request := range requests {
		response := runtimeIOControl(t, broker, invocation.Owner.InvocationID, request)
		if response["ok"] != false {
			t.Fatalf("request %s response = %#v, want failure", request, response)
		}
	}
	if pluginData.calls != 0 {
		t.Fatalf("storage broker calls = %d, want 0", pluginData.calls)
	}

	if err := broker.release(invocation.Owner.InvocationID); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(requests[0])); !errors.Is(err, errRuntimeIOInvocationUnknown) {
		t.Fatalf("released invocation Control() error = %v", err)
	}
}

func TestHostRuntimeIORegistrationRejectsMissingGrantAndScopeDrift(t *testing.T) {
	invocation := runtimeIOTestInvocation("invocation-invalid-storage", "session-invalid-storage", "channel-invalid-storage")
	for _, fixture := range []struct {
		access workerStorageBrokerAccess
		grants map[string]string
	}{
		{access: workerStorageBrokerAccess{StoreID: "notes", Kind: "sqlite", Scope: "user", Operations: []string{"query"}}},
		{access: workerStorageBrokerAccess{StoreID: "notes", Kind: "sqlite", Scope: "other", Operations: []string{"query"}}, grants: map[string]string{"notes": "grant-notes"}},
		{access: workerStorageBrokerAccess{StoreID: "notes", Kind: "files", Scope: "user", Operations: []string{"query"}}, grants: map[string]string{"notes": "grant-notes"}},
	} {
		if _, err := newHostRuntimeIORegistration(invocation, workerBrokerAccess{Storage: []workerStorageBrokerAccess{fixture.access}}, fixture.grants); err == nil {
			t.Fatalf("newHostRuntimeIORegistration(%#v) succeeded", fixture.access)
		}
	}
}

func runtimeIOControl(t *testing.T, broker *hostRuntimeIOBroker, invocationID, request string) map[string]any {
	t.Helper()
	raw, err := broker.Control(context.Background(), invocationID, []byte(request))
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode response %s: %v", raw, err)
	}
	return response
}

func runtimeIOTestInvocation(invocationID, ownerSessionHash, channelHash string) resourceio.Invocation {
	return resourceio.Invocation{
		Owner: resourceio.Owner{
			PluginInstanceID:   "plugini_revoke",
			ActiveFingerprint:  "sha256:revoke",
			Scope:              sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env-revoke", OwnerUserHash: "user-revoke"},
			Session:            sessionctx.SessionScope{OwnerSessionHash: ownerSessionHash, OwnerUserHash: "user-revoke", OwnerEnvHash: "env-revoke", SessionChannelIDHash: channelHash},
			RuntimeGeneration:  "generation-revoke",
			ManagementRevision: 1,
			RevokeEpoch:        1,
			InvocationID:       invocationID,
			Lifetime:           resourceio.LifetimeInvocation,
		},
		Plugin:      resourceio.Plugin{ID: "com.example.revoke", InstanceID: "plugini_revoke", Version: "9.0.0"},
		Permissions: map[string]bool{resourceio.PermissionFSWorkspaceRead: true},
		CanRead:     true,
	}
}
