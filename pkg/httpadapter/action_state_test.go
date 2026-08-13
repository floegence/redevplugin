package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCatalogProjectsHostActionStateWithoutRecomputingIt(t *testing.T) {
	h := newHTTPTestHost(t)
	installed := postLocalImport[map[string]any](t, mustNewHandler(t, h, allowHTTPTestGuard()), "plugini_http_action_state", buildHTTPFixturePackage(t))
	_ = installed
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	records := postJSON[struct {
		Plugins []struct {
			ActionState map[string]any `json:"action_state"`
		} `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog/query", map[string]any{})
	if len(records.Plugins) != 1 {
		t.Fatalf("catalog plugins = %#v", records.Plugins)
	}
	action := records.Plugins[0].ActionState
	if got, ok := action["can_open"].(bool); !ok || got {
		t.Fatalf("disabled Host action_state.can_open = %#v, want false", action["can_open"])
	}
	if reason, _ := action["blocked_reason"].(string); reason != "disabled" {
		t.Fatalf("disabled Host action_state.blocked_reason = %q", reason)
	}
	if _, ok := action["trust_state"]; ok {
		t.Fatalf("catalog action_state leaked derived trust state: %s", mustJSON(t, action))
	}
}

func TestRecoveryHTTPResponseUsesSingleHostSnapshotShape(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	record := postLocalImport[map[string]any](t, handler, "plugini_http_recovery", buildHTTPFixturePackage(t))
	_ = record
	response := postJSON[struct {
		Revision int64 `json:"revision"`
		Complete bool  `json:"complete"`
		Results  []struct {
			PluginInstanceID string `json:"plugin_instance_id"`
			Status           string `json:"status"`
		} `json:"results"`
	}](t, handler, "/_redevplugin/api/plugins/runtime/recover-enabled", map[string]any{})
	if response.Revision == 0 || response.Results == nil {
		t.Fatalf("recovery response is not a Host snapshot: %#v", response)
	}
	if !response.Complete || len(response.Results) != 0 {
		t.Fatalf("empty enabled recovery should be complete: %#v", response)
	}
}

func TestRecoveryHTTPResponseUsesClosedWireDTO(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/runtime/recover-enabled", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("recover-enabled status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if got := mustJSON(t, envelope); got != `{"data":{"complete":true,"results":[],"revision":1},"ok":true}` {
		t.Fatalf("recover-enabled wire envelope = %s", got)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

var _ = http.StatusOK
