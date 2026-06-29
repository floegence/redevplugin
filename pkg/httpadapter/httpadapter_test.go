package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
)

func TestRouteSetHasManagementAndSandboxRoutes(t *testing.T) {
	routes := RouteSet()
	want := map[string]bool{
		"POST /_redeven_proxy/api/plugins/install":                                     false,
		"POST /_redeven_proxy/api/plugins/enable":                                      false,
		"POST /_redeven_proxy/api/plugins/surfaces/open":                               false,
		"POST /_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bootstrap":    false,
		"POST /_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bridge-token": false,
		"POST /_redeven_proxy/api/plugins/rpc":                                         false,
		"POST /_redeven_proxy/api/plugins/data/export":                                 false,
		"POST /_redeven_plugin/bootstrap":                                              false,
		"GET /_redeven_plugin/assets/{asset_path...}":                                  false,
		"POST /_redeven_plugin/csp-report":                                             false,
	}
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("RouteSet() missing %s", key)
		}
	}
}

func TestHandlerSurfaceBridgeFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redeven_proxy/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.activity",
		"surface_instance_id":     "surface_http",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	if openResp.AssetTicket == "" || openResp.BridgeNonce == "" {
		t.Fatalf("open response missing ticket/nonce: %#v", openResp)
	}

	postJSON[bridge.AssetSessionResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})

	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http",
		"handshake": map[string]any{
			"plugin_id":           openResp.PluginID,
			"surface_id":          openResp.SurfaceID,
			"surface_instance_id": openResp.SurfaceInstanceID,
			"active_fingerprint":  openResp.ActiveFingerprint,
			"bridge_nonce":        openResp.BridgeNonce,
			"ui_protocol_version": "plugin-ui-v1",
		},
	})
	if bridgeResp.GatewayToken == "" {
		t.Fatalf("bridge token response is empty: %#v", bridgeResp)
	}
}

func TestHandlerRejectsTrailingJSON(t *testing.T) {
	h := newHTTPTestHost(t)
	req := httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/surfaces/open", bytes.NewBufferString(`{} {}`))
	rec := httptest.NewRecorder()
	Handler{Host: h}.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerDataExportImportFlow(t *testing.T) {
	storageBroker := storage.NewMemoryBroker()
	h := newHTTPTestHostWithStorage(t, storageBroker)
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if err := storageBroker.SetUsage(context.Background(), installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	exported := postJSON[host.ExportDataResult](t, handler, "/_redeven_proxy/api/plugins/data/export", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if exported.ArchiveRef == "" {
		t.Fatal("export response missing archive_ref")
	}

	postJSON[map[string]bool](t, handler, "/_redeven_proxy/api/plugins/data/import", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"archive_ref":        exported.ArchiveRef,
		"delete_existing":    true,
	})
}

func postJSON[T any](t *testing.T, handler http.Handler, path string, body any) T {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s status = %d body = %s", path, rec.Code, rec.Body.String())
	}
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("POST %s returned not ok: %s", path, rec.Body.String())
	}
	var data T
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func newHTTPTestHost(t *testing.T) *host.Host {
	return newHTTPTestHostWithStorage(t, nil)
}

func newHTTPTestHostWithStorage(t *testing.T, storageBroker storage.Broker) *host.Host {
	t.Helper()
	h, err := host.New(host.Adapters{
		SessionResolver: httpTestSessionResolver{},
		Policy:          httpTestPolicy{},
		Storage:         storageBroker,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func buildHTTPFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPStorageFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpStorageFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Storage</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeHTTPFile(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func httpFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http",
			"display_name": "HTTP",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.activity", "kind": "activity", "label": "HTTP", "entry": "ui/index.html"}
		]
	}`
}

func httpStorageFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.storage",
			"display_name": "HTTP Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.storage.activity", "kind": "activity", "label": "HTTP Storage", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "environment",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

type httpTestSessionResolver struct{}

func (httpTestSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type httpTestPolicy struct{}

func (httpTestPolicy) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (httpTestPolicy) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

func (httpTestPolicy) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}
