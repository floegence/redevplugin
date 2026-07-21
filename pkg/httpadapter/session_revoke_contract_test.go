package httpadapter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/redevplugin/pkg/websecurity"
)

func TestRouteSetReplacesSurfaceRevokeWithClosedSessionRevoke(t *testing.T) {
	var foundSession bool
	for _, route := range routes {
		if route.Path == "/_redevplugin/api/plugins/surfaces/revoke-scope" {
			t.Fatal("retired surface revoke route remains registered")
		}
		if route.Path == "/_redevplugin/api/plugins/session/revoke-scope" {
			foundSession = true
			if route.Method != http.MethodPost || route.action != websecurity.RouteActionRevokeSessionScope {
				t.Fatalf("session revoke route = %#v", route)
			}
		}
	}
	if !foundSession {
		t.Fatal("session revoke route is not registered")
	}
}

func TestSessionRevokeAcceptsOnlyClosedEmptyJSONObject(t *testing.T) {
	for name, body := range map[string]string{
		"null":          `null`,
		"array":         `[]`,
		"scalar":        `true`,
		"owner":         `{"owner_session_hash":"injected"}`,
		"identity":      `{"identity":{}}`,
		"operation id":  `{"operation_id":"injected"}`,
		"duplicate key": `{"identity":{},"identity":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
			req := httptest.NewRequest(
				http.MethodPost,
				"/_redevplugin/api/plugins/session/revoke-scope",
				bytes.NewBufferString(body),
			)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestRetiredSurfaceRevokeRouteIsNotFound(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/surfaces/revoke-scope", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body = %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestSessionRevokeCompletesWithoutRuntimeModule(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())

	result := postJSON[sessionScopeRevokeResponse](t, handler, "/_redevplugin/api/plugins/session/revoke-scope", map[string]any{})
	if result.State != "complete" || !result.Fenced || !result.Complete || result.Counts != (sessionScopeRevokeCountsResponse{}) {
		t.Fatalf("session revoke response = %#v", result)
	}
}
