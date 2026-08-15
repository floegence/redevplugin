package resourceio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type fixtureMountResolver struct {
	path  string
	calls int
}

func (resolver *fixtureMountResolver) ResolveMount(_ context.Context, _ Invocation, id string) (MountSpec, error) {
	resolver.calls++
	if id != "workspace" {
		return MountSpec{}, ErrInvalidURI
	}
	return MountSpec{ID: id, Path: resolver.path}, nil
}

func (resolver *fixtureMountResolver) ListMounts(context.Context, Invocation) ([]MountSpec, error) {
	resolver.calls++
	return []MountSpec{{ID: "workspace", Path: resolver.path}}, nil
}

func fixtureInvocation(session string) Invocation {
	owner := testOwner(session)
	owner.InvocationID = "invoke-1"
	return Invocation{
		Owner:       owner,
		Plugin:      Plugin{ID: "com.example.fixture", InstanceID: owner.PluginInstanceID, Version: "1.0.0"},
		Permissions: map[string]bool{PermissionFSWorkspaceRead: true, PermissionFSWorkspaceWrite: true, PermissionNetworkClient: true},
		CanRead:     true,
		CanWrite:    true,
	}
}

func callControl(t *testing.T, service *Service, invocation Invocation, operation, arguments string) map[string]any {
	t.Helper()
	raw, err := service.Control(context.Background(), invocation, []byte(fmt.Sprintf(`{"api":1,"operation":%q,"arguments":%s}`, operation, arguments)))
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode control response %s: %v", raw, err)
	}
	return response
}

func resultHandle(t *testing.T, response map[string]any, key string) uint64 {
	t.Helper()
	if response["ok"] != true {
		t.Fatalf("control response failed: %#v", response)
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("control result = %#v", response["result"])
	}
	value, ok := result[key].(json.Number)
	if !ok {
		t.Fatalf("control handle = %#v", result[key])
	}
	handle, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || handle == 0 {
		t.Fatalf("control handle = %#v, %v", result[key], err)
	}
	return handle
}

func TestServiceFileControlAndRawDataPlane(t *testing.T) {
	resolver := &fixtureMountResolver{path: t.TempDir()}
	table, err := NewTableWithLimits(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(table, resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	invocation := fixtureInvocation("session-a")
	response := callControl(t, service, invocation, "fs.open", `{"uri":"redevfs://workspace/data.bin","options":{"read":true,"write":true,"create_new":true,"mode":384}}`)
	handle := resultHandle(t, response, "handle")
	payload := []byte{0, 1, 2, 0xff, 0, 4}
	if n, err := service.Write(context.Background(), invocation, handle, payload, 0); err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if position, err := service.Seek(invocation, handle, 0, 0); err != nil || position != 0 {
		t.Fatalf("Seek() = %d, %v", position, err)
	}
	buffer := make([]byte, len(payload))
	if n, flags, err := service.Read(context.Background(), invocation, handle, buffer); err != nil || n != len(payload) || flags != 0 || !bytes.Equal(buffer, payload) {
		t.Fatalf("Read() = %d, %d, %v, %x", n, flags, err, buffer)
	}
	if err := service.Close(invocation, handle); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Read(context.Background(), invocation, handle, buffer); err != ErrResourceClosed {
		t.Fatalf("closed Read() error = %v", err)
	}
}

func TestServicePlatformDiscoveryDoesNotExposeAuthorityFacts(t *testing.T) {
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, nil, nil)
	invocation := fixtureInvocation("session-discovery")
	capabilities := callControl(t, service, invocation, "platform.capabilities", `{}`)
	if capabilities["ok"] != true {
		t.Fatalf("platform.capabilities = %#v", capabilities)
	}
	contextResponse := callControl(t, service, invocation, "platform.context", `{}`)
	raw, _ := json.Marshal(contextResponse)
	for _, forbidden := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "runtime_generation", "management_revision", "revoke_epoch", "invocation_id", "permissions"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("platform.context leaked %q: %s", forbidden, raw)
		}
	}
	result, ok := contextResponse["result"].(map[string]any)
	if contextResponse["ok"] != true || !ok || result["plugin_id"] != invocation.Plugin.ID || result["plugin_version"] != invocation.Plugin.Version || result["scope_kind"] != string(invocation.Owner.Scope.Kind) {
		t.Fatalf("platform.context = %#v", contextResponse)
	}
}

func TestServiceRejectsPermissionAndSessionCapsBeforeMountIO(t *testing.T) {
	resolver := &fixtureMountResolver{path: t.TempDir()}
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, resolver, nil)
	invocation := fixtureInvocation("session-a")
	invocation.CanWrite = false
	response := callControl(t, service, invocation, "fs.open", `{"uri":"redevfs://workspace/data.bin","options":{"write":true,"create_new":true}}`)
	if response["ok"] != false || resolver.calls != 0 {
		t.Fatalf("session-cap response = %#v, mount calls = %d", response, resolver.calls)
	}
	encoded, _ := json.Marshal(response)
	if strings.Contains(string(encoded), resolver.path) {
		t.Fatal("control error leaked the mount path")
	}
	invocation.CanWrite = true
	delete(invocation.Permissions, PermissionFSWorkspaceWrite)
	response = callControl(t, service, invocation, "fs.open", `{"uri":"redevfs://workspace/data.bin","options":{"write":true,"create_new":true}}`)
	if response["ok"] != false || resolver.calls != 0 {
		t.Fatalf("permission response = %#v, mount calls = %d", response, resolver.calls)
	}
}

func TestServiceRejectsCrossOwnerHandleAndDuplicateControlFields(t *testing.T) {
	resolver := &fixtureMountResolver{path: t.TempDir()}
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, resolver, nil)
	first := fixtureInvocation("session-a")
	response := callControl(t, service, first, "fs.open", `{"uri":"redevfs://workspace/data.bin","options":{"write":true,"create_new":true}}`)
	handle := resultHandle(t, response, "handle")
	second := fixtureInvocation("session-b")
	if _, err := service.Write(context.Background(), second, handle, []byte("denied"), 0); err != ErrOwnerMismatch {
		t.Fatalf("cross-owner write error = %v", err)
	}
	raw, err := service.Control(context.Background(), first, []byte(`{"api":1,"api":1,"operation":"fs.mounts","arguments":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"code":"INVALID_ARGUMENT"`)) {
		t.Fatalf("duplicate control response = %s", raw)
	}
}

func TestStableServiceErrorDistinguishesNotEmptyAndNetworkFailures(t *testing.T) {
	if code, _ := stableServiceError(syscall.ENOTEMPTY); code != "NOT_EMPTY" {
		t.Fatalf("ENOTEMPTY code = %q, want NOT_EMPTY", code)
	}
	if code, _ := stableServiceError(&net.DNSError{Err: "fixture", Name: "example.test"}); code != "NETWORK_ERROR" {
		t.Fatalf("DNS error code = %q, want NETWORK_ERROR", code)
	}
}

func TestServiceWebSocketCloseUsesRequestedCodeAndReason(t *testing.T) {
	closed := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			closed <- err
			return
		}
		defer connection.CloseNow()
		_, _, err = connection.Read(request.Context())
		closed <- err
	}))
	defer server.Close()

	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, nil, nil)
	invocation := fixtureInvocation("websocket-close")
	response := callControl(t, service, invocation, "net.websocket.open", fmt.Sprintf(`{"url":%q,"timeout_ms":1000}`, "ws"+server.URL[len("http"):]))
	handle := resultHandle(t, response, "handle")
	response = callControl(t, service, invocation, "net.websocket.close", fmt.Sprintf(`{"handle":%d,"code":1000,"reason":"finished"}`, handle))
	if response["ok"] != true {
		t.Fatalf("close response = %#v", response)
	}
	select {
	case err := <-closed:
		if websocket.CloseStatus(err) != websocket.StatusNormalClosure || !strings.Contains(err.Error(), "finished") {
			t.Fatalf("server close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe WebSocket close")
	}
}
