package httpadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
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

func TestHandlerManagementLifecycleFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	packageBytes := buildHTTPFixturePackage(t)

	installed := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(packageBytes),
		"trust_state":    "verified",
	})
	if installed.PluginInstanceID == "" || installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install response mismatch: %#v", installed)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable response mismatch: %#v", enabled)
	}

	catalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redeven_proxy/api/plugins/catalog")
	if len(catalog.Plugins) != 1 || catalog.Plugins[0].PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("catalog mismatch: %#v", catalog)
	}

	disabled := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/disable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"reason":             "test",
	})
	if disabled.EnableState != registry.EnableDisabled || disabled.DisabledReason != "test" {
		t.Fatalf("disable response mismatch: %#v", disabled)
	}

	uninstalled := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/uninstall", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        true,
	})
	if uninstalled.RetainedDataState != registry.RetainedDataDeleted {
		t.Fatalf("uninstall response mismatch: %#v", uninstalled)
	}

	emptyCatalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redeven_proxy/api/plugins/catalog")
	if len(emptyCatalog.Plugins) != 0 {
		t.Fatalf("catalog after uninstall mismatch: %#v", emptyCatalog)
	}
}

func TestHandlerManagementRejectsInvalidInstallAndUntrustedEnable(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	req := httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/install", bytes.NewBufferString(`{"package_base64":"not-base64"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid install status = %d body = %s", rec.Code, rec.Body.String())
	}

	installed := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"trust_state":    "untrusted",
	})
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/enable", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted enable status = %d body = %s", rec.Code, rec.Body.String())
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

func TestHandlerRPCFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redeven_proxy/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.rpc.activity",
		"surface_instance_id":     "surface_http_rpc",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http_rpc/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http_rpc/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http_rpc",
		"handshake": map[string]any{
			"plugin_id":           openResp.PluginID,
			"surface_id":          openResp.SurfaceID,
			"surface_instance_id": openResp.SurfaceInstanceID,
			"active_fingerprint":  openResp.ActiveFingerprint,
			"bridge_nonce":        openResp.BridgeNonce,
			"ui_protocol_version": "plugin-ui-v1",
		},
	})

	result := postJSON[host.CallMethodResult](t, handler, "/_redeven_proxy/api/plugins/rpc", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_rpc",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_rpc",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "echo.ping",
		"params":                  map[string]any{"message": "hello"},
	})
	if result.Data == nil {
		t.Fatalf("rpc result missing data: %#v", result)
	}
	if adapter.last.PluginInstanceID != installed.PluginInstanceID || adapter.last.Method != "echo.ping" {
		t.Fatalf("capability invocation mismatch: %#v", adapter.last)
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

func getJSON[T any](t *testing.T, handler http.Handler, path string) T {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d body = %s", path, rec.Code, rec.Body.String())
	}
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("GET %s returned not ok: %s", path, rec.Body.String())
	}
	var data T
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func newHTTPTestHost(t *testing.T) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{})
}

func newHTTPTestHostWithStorage(t *testing.T, storageBroker storage.Broker) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{storageBroker: storageBroker})
}

type httpTestHostOptions struct {
	storageBroker     storage.Broker
	capabilityID      string
	capabilityAdapter capability.Adapter
}

func newHTTPTestHostWithOptions(t *testing.T, opts httpTestHostOptions) *host.Host {
	t.Helper()
	capabilities := capability.NewRegistry()
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		capabilities.Register(opts.capabilityID, opts.capabilityAdapter)
	}
	h, err := host.New(host.Adapters{
		SessionResolver: httpTestSessionResolver{},
		Policy:          httpTestPolicy{},
		Storage:         opts.storageBroker,
		Capabilities:    capabilities,
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

func buildHTTPRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpRPCFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP RPC</title>")
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

func httpRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.rpc",
			"display_name": "HTTP RPC",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.rpc.activity", "kind": "activity", "label": "HTTP RPC", "entry": "ui/index.html", "method": "echo.ping"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "echo.ping",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "echo.ping"}
			}
		]
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

type httpRecordingCapabilityAdapter struct {
	last   capability.Invocation
	result capability.Result
}

func (a *httpRecordingCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.last = req
	return a.result, nil
}
