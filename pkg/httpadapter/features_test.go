package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeaturesRouteReturnsConfiguredModules(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/features/query", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("features status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var envelope struct {
		OK   bool     `json:"ok"`
		Data []string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode features response: %v", err)
	}
	if !envelope.OK {
		t.Fatalf("features response is not successful: %s", rec.Body.String())
	}
	if len(envelope.Data) == 0 {
		t.Fatal("features response is empty")
	}
}
