package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

func TestRealDemoWebSecurityGuardAllowsOnlyHostOrigin(t *testing.T) {
	hostOrigin := "http://app.redevplugin.localhost:4175"
	guard := realDemoWebSecurityGuard{hostOrigin: hostOrigin}
	for _, tc := range []struct {
		name      string
		origin    string
		wantAllow bool
		wantErr   bool
	}{
		{name: "same origin", origin: hostOrigin, wantAllow: true},
		{name: "non-browser request", origin: "", wantAllow: true},
		{name: "cross origin", origin: "http://evil.example", wantAllow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/surfaces/open", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			requestContext, decision, err := guard.Evaluate(req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got := decision == websecurity.OriginTrustedParent; got != tc.wantAllow {
				t.Fatalf("origin decision = %q, wantAllow=%v", decision, tc.wantAllow)
			}
			if tc.wantAllow && (requestContext.Scope.OwnerSessionHash != realDemoOwner || requestContext.Scope.SessionChannelIDHash != realDemoChannel) {
				t.Fatalf("request scope = %#v", requestContext.Scope)
			}
		})
	}
}

func TestRealDemoBootstrapCarriesRuntimeGeneration(t *testing.T) {
	payload := realDemoBootstrap(bridge.SurfaceBootstrap{RuntimeGenerationID: "runtime_generation_test"})
	if payload.RuntimeGenerationID != "runtime_generation_test" {
		t.Fatalf("runtime generation = %q", payload.RuntimeGenerationID)
	}
}

func TestRealDemoHTMLUsesOpaqueSurfaceHost(t *testing.T) {
	html := realDemoHostHTML()

	for _, want := range []string{
		`createReDevPluginSurfaceTransport`,
		`PluginSurfaceHost.create`,
		`surfaceHost.element`,
		`surfaceMount.replaceChildren(iframe)`,
		`await surfaceHost.open()`,
		`await surfaceHost.close()`,
		`toPluginSurfaceHostBootstrap`,
		`bootstrap: toPluginSurfaceHostBootstrap(bootstrap)`,
		`hostTransport: createReDevPluginSurfaceTransport({ fetch: hostFetch })`,
		`isBrokeredRuntimeMethod(body.method)`,
		`method === "` + realDemoScheduleMethod + `"`,
		`fetchBrokerGrants`,
		`fetch("/demo/real/bootstrap"`,
		`method: "POST"`,
		`brokerConfig.broker_grants_url`,
		`storage_handle_grant_token: grants.storage_handle_grant_token`,
		`storage_kv_handle_grant_token: grants.storage_kv_handle_grant_token`,
		`storage_sqlite_handle_grant_token: grants.storage_sqlite_handle_grant_token`,
		`intent.signal.addEventListener("abort"`,
		`progressEvents`,
		`confirmationAborted`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("real demo html missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`new PluginSurfaceHost`,
		`<iframe id="plugin-frame"`,
		`allow-same-origin`,
		`pluginOrigin`,
		`parentOrigin`,
		`/_redevplugin/bootstrap`,
		`/_redevplugin/assets/`,
		`/_redevplugin/csp-report`,
		`Access-Control-Allow-Origin`,
		`credentials: "include"`,
		`owner_session_hash`,
		`session_channel_id_hash`,
		`storage_path: brokerConfig.storage_path`,
		`storage_data_base64: brokerConfig.storage_data_base64`,
		`storage_kv_value_base64: brokerConfig.storage_kv_value_base64`,
		`storage_sqlite_sql: brokerConfig.storage_sqlite_sql`,
		`network_body_base64: brokerConfig.network_body_base64`,
		`ticket_secret`,
		`asset_nonce`,
		`runtime_generation_canary_12345678`,
		`entryPath: bootstrap.entry_path`,
		`entrySHA256: bootstrap.entry_sha256`,
		`assetSessionNonce: bootstrap.asset_session_nonce`,
		`pluginStateVersion: bootstrap.plugin_state_version`,
		`revokeEpoch: bootstrap.revoke_epoch`,
		`"data":{"bootstrap"`,
		`response.clone().json()`,
		`storage_secret`,
		`kv_secret`,
		`sqlite_secret`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("real demo html contains forbidden legacy flow %q", forbidden)
		}
	}
}

func TestRealDemoPluginSurfaceDoesNotCarryParentOnlyBrokerGrant(t *testing.T) {
	html := realDemoPluginHTML()
	js := string(realDemoPluginWorkerJS)

	for _, want := range []string{
		`type="text/redevplugin-worker"`,
		`PluginBridgeClient`,
		`invoke-broker`,
		`invoke-schedule`,
		`invoke-network-matrix`,
		`invoke-stream`,
		`worker.brokerDemo`,
		realDemoScheduleMethod,
		realDemoStreamMethod,
		`parseScheduleRows`,
		`bridge.readStream`,
		`runWorkerSecurityProbe`,
		`worker.networkWebSocket`,
		`worker.networkTCP`,
		`worker.networkUDP`,
		`parseNetworkBody`,
		`parseNetworkPayload`,
		`storage_credential_visible`,
		`network_credential_visible`,
	} {
		if !strings.Contains(html+js, want) {
			t.Fatalf("real demo plugin surface missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`window.parent.postMessage`,
		`parent_origin`,
		`redevplugin.bridge.handshake`,
		`asset_ticket`,
		`plugin_gateway_token`,
		`storage_path`,
		`storage_sqlite_sql`,
		`network_body_base64`,
		`brokerConfig`,
	} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("plugin iframe script contains parent-only broker field %q", forbidden)
		}
	}
}

func TestRealDemoStreamWorkerUsesRealHTTPStreamHostcall(t *testing.T) {
	raw := string(realDemoNetworkWorkerWASM(realDemoHTTPStreamCase))
	for _, want := range []string{
		`"operation":"http_stream"`,
		`"path":"/v1/stream"`,
		`"max_chunk_bytes":1024`,
		`"max_buffered_bytes":65536`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("stream worker wasm missing %q", want)
		}
	}
}

func TestRealDemoScheduleWorkerUsesRealStorageHostcalls(t *testing.T) {
	raw := string(realDemoScheduleWorkerWASM())
	for _, want := range []string{
		"schedule/agenda-export.json",
		"schedule/current_view",
		"CREATE TABLE IF NOT EXISTS schedule_items",
		"INSERT INTO schedule_items",
		"SELECT title, starts_at, location, source FROM schedule_items",
		"Design plugin rollout",
		"Focus Room A",
		"rust runtime storage",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("schedule worker wasm missing %q", want)
		}
	}
}

func TestRealDemoNetworkExecutorCoversAllSupportedTransports(t *testing.T) {
	executor := realDemoNetworkExecutor{}
	ctx := context.Background()

	httpResponse, err := executor.DoHTTP(ctx, connectivity.HTTPRequest{
		Grant:  connectivity.ConnectionGrant{ConnectorID: "api", Destination: connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "https", Host: "api.example.com", Port: 443}},
		Method: http.MethodPost,
		Path:   "/v1/matrix",
		Body:   []byte("hello http"),
	})
	if err != nil {
		t.Fatalf("DoHTTP() error = %v", err)
	}
	if !strings.Contains(string(httpResponse.Body), `"echo":"http:hello http"`) {
		t.Fatalf("HTTP body = %s", httpResponse.Body)
	}

	var streamBody strings.Builder
	streamResponse, err := executor.StreamHTTP(ctx, connectivity.HTTPRequest{}, func(chunk connectivity.HTTPResponseChunk) error {
		streamBody.Write(chunk.Data)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamHTTP() error = %v", err)
	}
	if streamResponse.StatusCode != http.StatusOK || streamResponse.ChunkCount != 2 || streamBody.String() != "real stream line 1\nreal stream line 2\n" {
		t.Fatalf("stream response = %#v body = %q", streamResponse, streamBody.String())
	}

	wsResponse, err := executor.WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
		MessageType: connectivity.WebSocketMessageText,
		Payload:     []byte("hello websocket"),
	})
	if err != nil {
		t.Fatalf("WebSocketRoundTrip() error = %v", err)
	}
	if wsResponse.MessageType != connectivity.WebSocketMessageText || string(wsResponse.Payload) != "websocket:hello websocket" {
		t.Fatalf("websocket response = %#v", wsResponse)
	}

	tcpResponse, err := executor.TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{Payload: []byte("hello tcp")})
	if err != nil {
		t.Fatalf("TCPRoundTrip() error = %v", err)
	}
	if string(tcpResponse.Payload) != "tcp:hello tcp" {
		t.Fatalf("tcp payload = %q", tcpResponse.Payload)
	}

	udpResponse, err := executor.UDPRoundTrip(ctx, connectivity.UDPRoundTripRequest{Payload: []byte("hello udp")})
	if err != nil {
		t.Fatalf("UDPRoundTrip() error = %v", err)
	}
	if string(udpResponse.Payload) != "udp:hello udp" {
		t.Fatalf("udp payload = %q", udpResponse.Payload)
	}
}

func TestRealDemoRefreshesPolicyAfterPermissionGrant(t *testing.T) {
	source := readSourceForTest(t, "real_demo.go")
	grantIndex := strings.Index(source, "grantRealDemoDeclaredPermissions(ctx, pluginHost, record)")
	if grantIndex < 0 {
		t.Fatal("real demo does not grant declared permissions")
	}
	refreshIndex := strings.Index(source[grantIndex:], "record, err = currentPluginRecord(ctx, pluginHost, record.PluginInstanceID)")
	if refreshIndex < 0 {
		t.Fatal("real demo must refresh enabled policy after permission grant")
	}
}

func readSourceForTest(t *testing.T, filename string) string {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
