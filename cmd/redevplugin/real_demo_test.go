package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
			path:         "/_redevplugin/assets/ui/index.html",
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
		"runtime_generation",
	)

	for _, want := range []string{
		`new URL("/_redevplugin/assets/ui/index.html", pluginOrigin)`,
		`new URL("/_redevplugin/bootstrap", pluginOrigin)`,
		`credentials: "include"`,
		`surface_instance_id: bootstrap.surface_instance_id`,
		`asset_ticket: bootstrap.asset_ticket`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("real demo html missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`new URL("/ui/index.html", pluginOrigin)`,
		`/_redevplugin/api/plugins/surfaces/`,
		`credentials: "same-origin"`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("real demo html contains forbidden legacy flow %q", forbidden)
		}
	}
}
