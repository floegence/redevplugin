package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"testing"
)

type socketAdmissionObserver struct {
	connectivity.NetworkExecutor
	calls   int
	request connectivity.WebSocketOpenRequest
}

func (o *socketAdmissionObserver) OpenWebSocket(_ context.Context, req connectivity.WebSocketOpenRequest) (connectivity.WebSocketConnection, error) {
	o.calls++
	o.request = req
	return connectivity.WebSocketConnection{}, errors.New("test connection unavailable")
}
func TestWebSocketRequiresSurfaceGrantAndExactConnection(t *testing.T) {
	observer := &socketAdmissionObserver{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, networkExecutor: observer})
	var m map[string]any
	_ = json.Unmarshal([]byte(currentNetworkManifestJSON()), &m)
	m["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1", "net.websocket.v1"}
	connector := m["network_access"].(map[string]any)["connectors"].([]any)[0].(map[string]any)
	connector["transport"] = "websocket"
	connector["destinations"] = []string{"wss://api.example.com"}
	m["surfaces"].([]any)[0].(map[string]any)["web"].(map[string]any)["network"] = []any{map[string]any{"connector_id": "api", "transport": "websocket", "operations": []string{"websocket"}}}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	first, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_socket_first", hostRuntimeWritableTestContext())
	second, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_socket_second", hostRuntimeWritableTestContext())
	request := WebSocketConnectionRequest{WebConnectionRequest: WebConnectionRequest{WebSurfaceRequest: first, ConnectorID: "api"}, ConnectionID: "fixed-0", RequestURI: "/events?cursor=a%2fb"}
	for _, change := range []func(*WebSocketConnectionRequest){func(r *WebSocketConnectionRequest) { r.Token = second.Token }, func(r *WebSocketConnectionRequest) { r.ConnectionID = "fixed-1" }, func(r *WebSocketConnectionRequest) { r.RequestURI = "//evil.example/path" }} {
		bad := request
		change(&bad)
		if _, err := h.OpenWebSocketConnection(context.Background(), bad); err == nil {
			t.Fatal("invalid socket accepted")
		}
	}
	if observer.calls != 0 {
		t.Fatal("denied request reached network")
	}
	if _, err := h.OpenWebSocketConnection(context.Background(), request); err == nil {
		t.Fatal("test network failure lost")
	}
	if observer.calls != 1 || observer.request.URL != "wss://api.example.com:443/events?cursor=a%2fb" {
		t.Fatalf("target changed: %d %s", observer.calls, observer.request.URL)
	}
}
