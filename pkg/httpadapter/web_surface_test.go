package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/host"
)

func TestWebHTTPRejectedOriginsRetainConfinement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		err    error
	}{
		{name: "resolver rejection", err: errors.New("route expired")},
		{name: "host mismatch", origin: "https://other.example"},
		{name: "invalid origin", origin: "https://%"},
		{name: "insecure origin", origin: "http://app.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://app.example/index.html", nil)
			serveWebSurface(nil, func(*http.Request) (string, error) { return tc.origin, tc.err }, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want forbidden", w.Code)
			}
			for key, want := range map[string]string{
				"Content-Security-Policy": webSurfaceCSP,
				"Connection-Allowlist":    "(response-origin)",
				"Cache-Control":           "no-store",
				"X-Content-Type-Options":  "nosniff",
				"Referrer-Policy":         "no-referrer",
				"Origin-Agent-Cluster":    "?1",
			} {
				if got := w.Header().Get(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestWebHTTPResourceBoundary(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, nextHTTPTestPluginInstanceID(t), buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.OpenSurface(httpTestContext(), host.OpenSurfaceRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceID: "http.view", ExpectedManagementRevision: installed.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.PrepareSurface(httpTestContext(), host.PrepareSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, AssetTicket: b.AssetTicket})
	if err != nil {
		t.Fatal(err)
	}
	origin := prepared.Document.Origin
	handler, err := NewWebSurfaceHandler(h, func(r *http.Request) (string, error) {
		if r.Host != strings.TrimPrefix(origin, "https://") {
			return "", errors.New("wrong route")
		}
		return origin, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	entry, _ := url.Parse(prepared.Document.BootstrapURL)
	raw, _ := json.Marshal(map[string]string{"token": entry.Fragment})
	headers := map[string]string{"Origin": origin, "Content-Type": "application/json"}
	if got := request("POST", host.WebSurfacePlatformPath+"enter", string(raw), nil, map[string]string{"Origin": "https://wrong.example", "Content-Type": "application/json"}); got.Code != 403 {
		t.Fatalf("wrong origin: %d", got.Code)
	}
	entered := request("POST", host.WebSurfacePlatformPath+"enter", string(raw), nil, headers)
	if entered.Code != 200 {
		t.Fatalf("entry: %d %s", entered.Code, entered.Body.String())
	}
	cookies := entered.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("one resource cookie required")
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || !cookie.Partitioned || cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("unsafe cookie: %#v", cookie)
	}
	if got := request("POST", host.WebSurfacePlatformPath+"enter", string(raw), nil, headers); got.Code != 403 {
		t.Fatalf("entry replay: %d", got.Code)
	}
	if got := request("GET", "/status.png", "", cookie, nil); got.Code != 403 {
		t.Fatalf("resource before bridge admission: %d", got.Code)
	}
	handshake := bridge.Handshake{PluginID: b.PluginID, SurfaceID: b.SurfaceID, SurfaceInstanceID: b.SurfaceInstanceID, ActiveFingerprint: b.ActiveFingerprint, BridgeNonce: b.BridgeNonce, AssetSessionNonce: b.AssetSessionNonce, ManagementRevision: b.ManagementRevision, RevokeEpoch: b.RevokeEpoch}
	channel := "bridge_web_http"
	_, err = h.MintBridgeToken(httpTestContext(), host.MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: channel, HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, channel)})
	if err != nil {
		t.Fatal(err)
	}
	resource := request("GET", "/status.png", "", cookie, nil)
	if resource.Code != 200 || !bytes.Equal(resource.Body.Bytes(), minimalHTTPPNGForTest()) {
		t.Fatalf("resource: %d %q", resource.Code, resource.Body.String())
	}
	for key, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Connection-Allowlist": "(response-origin)", "Referrer-Policy": "no-referrer", "Origin-Agent-Cluster": "?1"} {
		if resource.Header().Get(key) != want {
			t.Fatalf("%s=%q", key, resource.Header().Get(key))
		}
	}
	for _, tc := range []struct {
		path    string
		headers map[string]string
		status  int
	}{
		{"/missing.js", nil, 404}, {"/index.html", nil, 403}, {"/../manifest.json", nil, 403}, {"/%2e%2e/manifest.json", nil, 403}, {"/app.js", map[string]string{"Service-Worker": "script"}, 403}, {"/app.js", map[string]string{"Sec-Fetch-Dest": "serviceworker"}, 403}, {"/_redevplugin/api/plugins/catalog/query", nil, 404},
	} {
		got := request("GET", tc.path, "", cookie, tc.headers)
		if got.Code != tc.status {
			t.Errorf("%s: %d want %d", tc.path, got.Code, tc.status)
		}
	}
	if got := request("HEAD", "/status.png", "", cookie, nil); got.Code != 200 || got.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %d", got.Code, got.Body.Len())
	}
	for _, target := range []string{"/%2e%2e/manifest.json", "/%252e%252e/manifest.json", "/%2Findex.html", "/%5cindex.html", "/%00index.html", "/%ZZ"} {
		path := host.WebSurfacePlatformPath + "document?path=" + url.QueryEscape(target)
		if got := request("GET", path, "", cookie, nil); got.Code != http.StatusForbidden {
			t.Errorf("ambiguous document path %q: %d", target, got.Code)
		}
	}
	if got := request("GET", host.WebSurfacePlatformPath+"document?path=%2Findex.html", "", cookie, nil); got.Code != http.StatusOK {
		t.Fatalf("canonical document query: %d %s", got.Code, got.Body.String())
	}
	if got := request("GET", "/status.png", "", nil, nil); got.Code != 403 {
		t.Fatalf("missing cookie: %d", got.Code)
	}
	if err = h.DisposeSurface(httpTestContext(), host.DisposeSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, BridgeNonce: b.BridgeNonce}); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", "/status.png", "", cookie, nil); got.Code != 410 {
		t.Fatalf("revoked resource: %d", got.Code)
	}
	if _, err = h.ValidateWebSurface(context.Background(), host.WebSurfaceRequest{Origin: origin, Token: cookie.Value}); err == nil {
		t.Fatal("revoked credential accepted")
	}
}
