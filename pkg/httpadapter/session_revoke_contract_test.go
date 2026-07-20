package httpadapter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/runtimeclient"
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

func TestSessionRevokeCompletesWithStoppedRuntimeWithoutRestart(t *testing.T) {
	runtimeManager := newHTTPRecordingRuntimeManager(t)
	runtimeManager.health.Ready = false
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeManager: runtimeManager}), allowHTTPTestGuard())
	runtimeManager.preflightCalls = 0
	runtimeManager.startCalls = 0

	result := postJSON[sessionScopeRevokeResponse](t, handler, "/_redevplugin/api/plugins/session/revoke-scope", map[string]any{})
	if result.State != "complete" || !result.Fenced || !result.Complete || result.Counts != (sessionScopeRevokeCountsResponse{}) {
		t.Fatalf("session revoke response = %#v", result)
	}
	if runtimeManager.preflightCalls != 0 || runtimeManager.startCalls != 0 || runtimeManager.sessionRevokeCalls != 1 {
		t.Fatalf("runtime calls: preflight=%d start=%d session_revoke=%d", runtimeManager.preflightCalls, runtimeManager.startCalls, runtimeManager.sessionRevokeCalls)
	}
}

func TestSessionRevokeCompletesWhenRuntimeArtifactIsAbsentAndNeverStarted(t *testing.T) {
	descriptor := newHTTPRecordingRuntimeManager(t).health.Descriptor
	runtimeManager, err := runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
		ShardCount: 1,
		Supervisor: runtimeclient.ProcessSupervisorOptions{
			RuntimePath:           filepath.Join(t.TempDir(), "missing-redevplugin-runtime"),
			Descriptor:            descriptor,
			Limits:                runtimeclient.DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeManager: runtimeManager}), allowHTTPTestGuard())

	result := postJSON[sessionScopeRevokeResponse](t, handler, "/_redevplugin/api/plugins/session/revoke-scope", map[string]any{})
	if result.State != "complete" || !result.Fenced || !result.Complete || result.Counts != (sessionScopeRevokeCountsResponse{}) {
		t.Fatalf("session revoke response = %#v", result)
	}
}
