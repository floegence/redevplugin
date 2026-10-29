package httpadapter

import (
	"github.com/floegence/redevplugin/v3/pkg/host"
	"net/http/httptest"
	"testing"
)

func TestWebConnectionRejectsResourceAndCrossSiteRequestsBeforeHost(t *testing.T) {
	for _, dest := range []string{"", "script", "document", "iframe", "worker", "serviceworker", "image", "style"} {
		r := httptest.NewRequest("GET", "https://app.example/_redevplugin_web/connections/api/fixed-0/script.js", nil)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Sec-Fetch-Dest", dest)
		w := httptest.NewRecorder()
		serveWebConnection(nil, w, r, host.WebSurfaceRequest{Origin: "https://app.example"}, "connections/api/fixed-0/script.js")
		if w.Code != 403 {
			t.Fatalf("destination %q status %d", dest, w.Code)
		}
	}
	for _, site := range []string{"", "same-site", "cross-site", "none"} {
		r := httptest.NewRequest("GET", "https://app.example/_redevplugin_web/connection?connector_id=api", nil)
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		w := httptest.NewRecorder()
		serveWebConnection(nil, w, r, host.WebSurfaceRequest{Origin: "https://app.example"}, "connection")
		if w.Code != 403 {
			t.Fatalf("site %q status %d", site, w.Code)
		}
	}
}
func TestWebConnectionDoesNotForwardSurfaceOrProxyCredentials(t *testing.T) {
	for _, name := range []string{"Cookie", "Sec-Fetch-Site", "Origin", "Referer", "X-Forwarded-Host", "Proxy-Authorization", "Connection", "Forwarded", "Content-Length"} {
		if webConnectionRequestHeader(name) {
			t.Errorf("forwards %s", name)
		}
	}
	for _, name := range []string{"Accept", "Content-Type", "Authorization", "If-Match", "X-API-Version"} {
		if !webConnectionRequestHeader(name) {
			t.Errorf("strips application header %s", name)
		}
	}
}
