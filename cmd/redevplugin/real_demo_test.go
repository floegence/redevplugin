package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/connectivity"
)

func TestRealDemoSandboxHandlerOnlyExposesSandboxRoutes(t *testing.T) {
	hostOrigin := "http://app.redevplugin.localhost:4175"
	var platformCalls []string
	platform := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platformCalls = append(platformCalls, r.Method+" "+r.URL.Path)
		w.Header().Set("X-Platform-Handler", "called")
		w.WriteHeader(http.StatusNoContent)
	})
	handler := realDemoSandboxHandler(hostOrigin, platform)

	for _, tc := range []struct {
		name         string
		method       string
		path         string
		origin       string
		wantStatus   int
		wantPlatform bool
	}{
		{
			name:         "bootstrap preflight is allowed only from host origin",
			method:       http.MethodOptions,
			path:         "/_redevplugin/bootstrap",
			origin:       hostOrigin,
			wantStatus:   http.StatusNoContent,
			wantPlatform: false,
		},
		{
			name:         "bootstrap post delegates to canonical sandbox bootstrap handler",
			method:       http.MethodPost,
			path:         "/_redevplugin/bootstrap",
			origin:       hostOrigin,
			wantStatus:   http.StatusNoContent,
			wantPlatform: true,
		},
		{
			name:         "bootstrap rejects unknown origins",
			method:       http.MethodPost,
			path:         "/_redevplugin/bootstrap",
			origin:       "http://evil.example",
			wantStatus:   http.StatusForbidden,
			wantPlatform: false,
		},
		{
			name:         "packaged ui assets delegate to canonical asset handler",
			method:       http.MethodGet,
			path:         "/_redevplugin/assets/asset_session_test/ui/index.html",
			wantStatus:   http.StatusNoContent,
			wantPlatform: true,
		},
		{
			name:         "sandbox origin does not expose management api",
			method:       http.MethodPost,
			path:         "/_redevplugin/api/plugins/install",
			origin:       hostOrigin,
			wantStatus:   http.StatusNotFound,
			wantPlatform: false,
		},
		{
			name:         "legacy static ui path is not served",
			method:       http.MethodGet,
			path:         "/ui/index.html",
			wantStatus:   http.StatusNotFound,
			wantPlatform: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			platformCalls = nil
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d body = %s, want %d", rec.Code, rec.Body.String(), tc.wantStatus)
			}
			if (len(platformCalls) > 0) != tc.wantPlatform {
				t.Fatalf("platform calls = %#v, wantPlatform=%v", platformCalls, tc.wantPlatform)
			}
			if tc.origin == hostOrigin && tc.path == "/_redevplugin/bootstrap" {
				if got := rec.Header().Get("Access-Control-Allow-Origin"); got != hostOrigin {
					t.Fatalf("allow-origin = %q, want %q", got, hostOrigin)
				}
				if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
					t.Fatalf("allow-credentials = %q", got)
				}
			}
		})
	}
}

func TestRealDemoHTMLUsesCanonicalAssetSessionFlow(t *testing.T) {
	html := realDemoHostHTML(
		"http://app.redevplugin.localhost:4175",
		"http://plg-real.redevplugin.localhost:4176",
		`{"plugin_id":"com.example.real.demo","plugin_instance_id":"plugin_real","surface_id":"com.example.real.demo.activity","surface_instance_id":"surface_real","active_fingerprint":"sha256:real","owner_session_hash":"owner","owner_user_hash":"user","session_channel_id_hash":"channel","asset_ticket":"ticket_secret","asset_ticket_id":"ticket_id","bridge_nonce":"nonce"}`,
		`{"storage_handle_grant_token":"storage_secret","storage_kv_handle_grant_token":"kv_secret","storage_sqlite_handle_grant_token":"sqlite_secret"}`,
		"runtime_generation",
	)

	for _, want := range []string{
		`new URL("/_redevplugin/assets/" + encodeURIComponent(assetSessionId) + "/ui/index.html", pluginOrigin)`,
		`new URL("/_redevplugin/bootstrap", pluginOrigin)`,
		`asset bootstrap response omitted asset_session_id`,
		`credentials: "include"`,
		`surface_instance_id: bootstrap.surface_instance_id`,
		`asset_ticket: bootstrap.asset_ticket`,
		`body.method === "worker.brokerDemo"`,
		`storage_handle_grant_token: brokerConfig.storage_handle_grant_token`,
		`storage_kv_handle_grant_token: brokerConfig.storage_kv_handle_grant_token`,
		`storage_sqlite_handle_grant_token: brokerConfig.storage_sqlite_handle_grant_token`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("real demo html missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`new URL("/_redevplugin/assets/ui/index.html", pluginOrigin)`,
		`new URL("/ui/index.html", pluginOrigin)`,
		`/_redevplugin/api/plugins/surfaces/`,
		`credentials: "same-origin"`,
		`storage_path: brokerConfig.storage_path`,
		`storage_data_base64: brokerConfig.storage_data_base64`,
		`storage_kv_value_base64: brokerConfig.storage_kv_value_base64`,
		`storage_sqlite_sql: brokerConfig.storage_sqlite_sql`,
		`network_body_base64: brokerConfig.network_body_base64`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("real demo html contains forbidden legacy flow %q", forbidden)
		}
	}
}

func TestRealDemoPluginSurfaceDoesNotCarryParentOnlyBrokerGrant(t *testing.T) {
	html := realDemoPluginHTML()
	js := realDemoPluginJS()

	for _, want := range []string{
		`id="invoke-broker"`,
		`id="invoke-network-matrix"`,
		`worker.brokerDemo`,
		`worker.networkWebSocket`,
		`worker.networkTCP`,
		`worker.networkUDP`,
		`parseNetworkBody`,
		`parseNetworkPayload`,
		`storage_grant_visible`,
		`network_grant_visible`,
	} {
		if !strings.Contains(html+js, want) {
			t.Fatalf("real demo plugin surface missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`storage_handle_grant_token`,
		`storage_kv_handle_grant_token`,
		`storage_kv_value_base64`,
		`storage_sqlite_handle_grant_token`,
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
	refreshIndex := strings.Index(source[grantIndex:], "pluginHost.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID})")
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
