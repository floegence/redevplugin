package host

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
)

type webNetworkObserver struct {
	connectivity.NetworkExecutor
	requests []connectivity.HTTPRequest
	contexts []context.Context
}

func (e *webNetworkObserver) OpenHTTP(ctx context.Context, req connectivity.HTTPRequest) (connectivity.HTTPBodyResponse, error) {
	e.requests = append(e.requests, req)
	e.contexts = append(e.contexts, ctx)
	return connectivity.HTTPBodyResponse{StatusCode: 200, Headers: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("stream"))}, nil
}
func TestWebConnectionDeclarationURLAndWindowLifetime(t *testing.T) {
	observer := &webNetworkObserver{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, networkExecutor: observer})
	var m map[string]any
	if err := json.Unmarshal([]byte(currentNetworkManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	m["surfaces"].([]any)[0].(map[string]any)["web"].(map[string]any)["network"] = []any{map[string]any{"connector_id": "api", "transport": "http", "operations": []string{"http"}, "http_methods": []string{"GET"}}}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	first, b1 := openTestWebSurface(t, h, record.PluginInstanceID, "surface_connection_first", hostRuntimeWritableTestContext())
	second, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_connection_second", hostRuntimeWritableTestContext())
	connection, err := h.GetWebConnection(context.Background(), WebConnectionRequest{WebSurfaceRequest: first, ConnectorID: "api"})
	if err != nil || connection.ConnectionID != "fixed-0" {
		t.Fatalf("connection: %+v %v", connection, err)
	}
	request := WebConnectionHTTPRequest{WebConnectionRequest: WebConnectionRequest{WebSurfaceRequest: first, ConnectorID: "api"}, ConnectionID: connection.ConnectionID, Method: "GET", RequestURI: "/a%2fb?signature=a%2fb&literal=%25"}
	response, err := h.OpenWebConnectionHTTP(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if len(observer.requests) != 1 || observer.requests[0].RequestURI != request.RequestURI {
		t.Fatalf("URI changed: %+v", observer.requests)
	}
	denied := request
	denied.Method = "POST"
	if _, err := h.OpenWebConnectionHTTP(context.Background(), denied); err == nil {
		t.Fatal("undeclared POST reached executor")
	}
	denied = request
	denied.Token = second.Token
	if _, err := h.OpenWebConnectionHTTP(context.Background(), denied); err == nil {
		t.Fatal("sibling token accepted")
	}
	if len(observer.requests) != 1 {
		t.Fatal("denied request reached executor")
	}
	request.WebSurfaceRequest = second
	sibling, err := h.OpenWebConnectionHTTP(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Body.Close()
	if err := h.DisposeSurface(hostTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: b1.SurfaceInstanceID, BridgeNonce: b1.BridgeNonce, Now: first.Now}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observer.contexts[0].Done():
	case <-time.After(time.Second):
		t.Fatal("closed window retained stream")
	}
	select {
	case <-observer.contexts[1].Done():
		t.Fatal("closing one window canceled sibling")
	default:
	}
}
func TestWebConnectionCannotBorrowWorkerDeclaration(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	record := installAndEnablePlugin(t, h, buildWorkerNetworkFixturePackage(t))
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	record, _ = h.getPluginRecord(hostTestContext(), record.PluginInstanceID)
	now := time.Now()
	b, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, SurfaceID: "worker.view", SurfaceInstanceID: "surface_no_network", ExpectedManagementRevision: record.ManagementRevision, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(b, now))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := url.Parse(prepared.Document.BootstrapURL)
	request := WebSurfaceRequest{Origin: prepared.Document.Origin, Token: entry.Fragment}
	session, err := h.EnterWebSurface(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Token = session.ResourceToken
	handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
	channel := "bridge_no_network"
	if _, err := h.MintBridgeToken(hostTestContext(), MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel), Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GetWebConnection(context.Background(), WebConnectionRequest{WebSurfaceRequest: request, ConnectorID: "api"}); err == nil {
		t.Fatal("surface borrowed worker declaration")
	}
}
