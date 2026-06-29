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
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
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

func TestRouteSetRoutesAreHandled(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	for _, route := range RouteSet() {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			path := samplePathForRoute(route.Path)
			body := ""
			if route.Method == http.MethodPost {
				body = `{}`
			}
			req := httptest.NewRequest(route.Method, path, bytes.NewBufferString(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("declared route fell through to 404: %s %s body = %s", route.Method, route.Path, rec.Body.String())
			}
		})
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

func TestHandlerEnableMapsBlockedNetworkTarget(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{storageBroker: storage.NewMemoryBroker()})
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redeven_proxy/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPBlockedNetworkFixturePackage(t)),
		"trust_state":    "verified",
	})
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/enable", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked network enable status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrNetworkTargetDenied) {
		t.Fatalf("error_code = %q body = %s", envelope.ErrorCode, rec.Body.String())
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

func TestHandlerSandboxBootstrapAndAssetFlow(t *testing.T) {
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
		"surface_instance_id":     "surface_http_asset",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})

	raw, err := json.Marshal(map[string]any{
		"surface_instance_id": openResp.SurfaceInstanceID,
		"asset_ticket":        openResp.AssetTicket,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redeven_plugin/bootstrap", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sandbox bootstrap status = %d body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != assetSessionCookieName || cookies[0].Value == "" || cookies[0].Path != "/" || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("asset session cookie mismatch: %#v", cookies)
	}

	req = httptest.NewRequest(http.MethodGet, "/_redeven_plugin/assets/ui/index.html", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "<!doctype html><title>HTTP</title>" {
		t.Fatalf("asset body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("asset content-type = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("asset nosniff = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/_redeven_plugin/assets/manifest.json", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("manifest asset status = %d body = %s", rec.Code, rec.Body.String())
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

func TestHandlerRPCConfirmationFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"done": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPDangerousRPCFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redeven_proxy/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.danger.activity",
		"surface_instance_id":     "surface_http_danger",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http_danger/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/surface_http_danger/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http_danger",
		"handshake": map[string]any{
			"plugin_id":           openResp.PluginID,
			"surface_id":          openResp.SurfaceID,
			"surface_instance_id": openResp.SurfaceInstanceID,
			"active_fingerprint":  openResp.ActiveFingerprint,
			"bridge_nonce":        openResp.BridgeNonce,
			"ui_protocol_version": "plugin-ui-v1",
		},
	})
	body := map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_danger",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_danger",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "danger.run",
		"params":                  map[string]any{"target": "db"},
	}

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("danger rpc status = %d body = %s", rec.Code, rec.Body.String())
	}
	var conflict Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatal(err)
	}
	if conflict.ErrorCode != string(security.ErrConfirmationRequired) {
		t.Fatalf("danger rpc error code = %s body = %s", conflict.ErrorCode, rec.Body.String())
	}
	if adapter.last.Method != "" {
		t.Fatalf("capability adapter should not be called before confirmation: %#v", adapter.last)
	}

	confirmation := postJSON[host.ConfirmMethodResult](t, handler, "/_redeven_proxy/api/plugins/confirm", body)
	if confirmation.ConfirmationToken == "" || confirmation.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", confirmation)
	}
	body["confirmation_token"] = confirmation.ConfirmationToken
	result := postJSON[host.CallMethodResult](t, handler, "/_redeven_proxy/api/plugins/rpc", body)
	if result.Data == nil || adapter.last.Method != "danger.run" {
		t.Fatalf("confirmed rpc mismatch: result=%#v invocation=%#v", result, adapter.last)
	}
}

func TestHandlerOperationManagementFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{OperationID: "op_http_1"}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.activity", "surface_http_operation", "bridge_http_operation")

	result := postJSON[host.CallMethodResult](t, handler, "/_redeven_proxy/api/plugins/rpc", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_operation",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_operation",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "images.pull",
	})
	if result.OperationID != "op_http_1" {
		t.Fatalf("rpc operation result mismatch: %#v", result)
	}

	listed := getJSON[struct {
		Operations []operation.Record `json:"operations"`
	}](t, handler, "/_redeven_proxy/api/plugins/operations?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Operations) != 1 || listed.Operations[0].OperationID != "op_http_1" {
		t.Fatalf("operation list mismatch: %#v", listed)
	}

	detail := getJSON[operation.Record](t, handler, "/_redeven_proxy/api/plugins/operations/op_http_1")
	if detail.Method != "images.pull" || detail.Status != operation.StatusRunning {
		t.Fatalf("operation detail mismatch: %#v", detail)
	}

	canceled := postJSON[operation.Record](t, handler, "/_redeven_proxy/api/plugins/operations/op_http_1/cancel", map[string]any{
		"reason": "user",
	})
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel response mismatch: %#v", canceled)
	}
}

func TestHandlerUninstallDeleteDataBlockedByOperation(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{OperationID: "op_block_delete"}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.activity", "surface_http_block_delete", "bridge_http_block_delete")
	postJSON[host.CallMethodResult](t, handler, "/_redeven_proxy/api/plugins/rpc", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_block_delete",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_block_delete",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "images.pull",
	})

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redeven_proxy/api/plugins/uninstall", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("uninstall status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrOperationBlocked) {
		t.Fatalf("error code = %s body = %s", envelope.ErrorCode, rec.Body.String())
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

func TestHandlerSecretLifecycleFlow(t *testing.T) {
	secrets := &httpRecordingSecretStore{}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secrets})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	postJSON[map[string]bool](t, handler, "/_redeven_proxy/api/plugins/secrets/bind", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	postJSON[map[string]bool](t, handler, "/_redeven_proxy/api/plugins/secrets/test", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	postJSON[map[string]bool](t, handler, "/_redeven_proxy/api/plugins/secrets/delete", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})

	if secrets.bind.PluginInstanceID != installed.PluginInstanceID || secrets.bind.SecretRef != "api_token" || secrets.test.SecretRef != "api_token" || secrets.delete.SecretRef != "api_token" {
		t.Fatalf("secret adapter calls mismatch: %#v", secrets)
	}
}

func TestHandlerCSPReportFlow(t *testing.T) {
	diagnostics := &httpDiagnosticSink{}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{diagnostics: diagnostics})
	handler := Handler{Host: h}

	postJSON[map[string]bool](t, handler, "/_redeven_plugin/csp-report", map[string]any{
		"plugin_id":           "com.example.http",
		"plugin_instance_id":  "plugin_http",
		"surface_id":          "http.activity",
		"surface_instance_id": "surface_http",
		"active_fingerprint":  "sha256:fingerprint",
		"csp-report": map[string]any{
			"document-uri":        "https://plugin.example/ui/index.html",
			"blocked-uri":         "inline",
			"effective-directive": "script-src",
			"line-number":         7,
		},
	})
	if len(diagnostics.events) != 1 {
		t.Fatalf("diagnostic events = %#v", diagnostics.events)
	}
	event := diagnostics.events[0]
	if event.Type != "plugin.csp.violation" || event.PluginID != "com.example.http" || event.SurfaceInstanceID != "surface_http" || event.Details["effective_directive"] != "script-src" {
		t.Fatalf("diagnostic event mismatch: %#v", event)
	}
}

func TestHandlerDeclaredRoutesReturnContractMismatchWhenNotImplemented(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	cases := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/_redeven_proxy/api/plugins/update", body: `{}`},
		{method: http.MethodPost, path: "/_redeven_proxy/api/plugins/downgrade", body: `{}`},
		{method: http.MethodGet, path: "/_redeven_plugin/stream/stream_1"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope Envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.ErrorCode != string(security.ErrContractMismatch) {
				t.Fatalf("envelope mismatch: %#v body = %s", envelope, rec.Body.String())
			}
		})
	}
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

func samplePathForRoute(path string) string {
	switch path {
	case "/_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bootstrap":
		return "/_redeven_proxy/api/plugins/surfaces/surface_test/bootstrap"
	case "/_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bridge-token":
		return "/_redeven_proxy/api/plugins/surfaces/surface_test/bridge-token"
	case "/_redeven_proxy/api/plugins/operations/{operation_id}":
		return "/_redeven_proxy/api/plugins/operations/op_test"
	case "/_redeven_proxy/api/plugins/operations/{operation_id}/cancel":
		return "/_redeven_proxy/api/plugins/operations/op_test/cancel"
	case "/_redeven_plugin/assets/{asset_path...}":
		return "/_redeven_plugin/assets/ui/index.html"
	case "/_redeven_plugin/stream/{stream_id}":
		return "/_redeven_plugin/stream/stream_test"
	default:
		return path
	}
}

func newHTTPTestHost(t *testing.T) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{})
}

func newHTTPTestHostWithStorage(t *testing.T, storageBroker storage.Broker) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{storageBroker: storageBroker})
}

type httpTestHostOptions struct {
	storageBroker     storage.Broker
	secrets           host.SecretStoreAdapter
	diagnostics       host.DiagnosticsSink
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
		Secrets:         opts.secrets,
		Diagnostics:     opts.diagnostics,
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

func buildHTTPDangerousRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpDangerousRPCFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Danger</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPOperationRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpOperationRPCFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Operation</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPBlockedNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpBlockedNetworkFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Network</title>")
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

func httpDangerousRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.danger",
			"display_name": "HTTP Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.danger.activity", "kind": "activity", "label": "HTTP Danger", "entry": "ui/index.html", "method": "danger.run"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "danger.run",
				"effect": "execute",
				"execution": "sync",
				"dangerous": true,
				"confirmation": {"mode": "required", "request_hash_fields": ["target"]},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "danger.run"}
			}
		]
	}`
}

func httpOperationRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.operation",
			"display_name": "HTTP Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.operation.activity", "kind": "activity", "label": "HTTP Operation", "entry": "ui/index.html", "method": "images.pull"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "images.pull",
				"effect": "execute",
				"execution": "operation",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "cancel",
					"uninstall_behavior": "cancel_then_block_delete",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "images.pull"}
			}
		]
	}`
}

func httpBlockedNetworkFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.network",
			"display_name": "HTTP Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.network.activity", "kind": "activity", "label": "HTTP Network", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
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
		},
		"network_access": {
			"connectors": [
				{"connector_id": "metadata", "transport": "http", "scope": "user", "destinations": ["http://169.254.169.254"]}
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

type httpRecordingCapabilityAdapter struct {
	last   capability.Invocation
	result capability.Result
}

type httpRecordingSecretStore struct {
	bind   host.SecretBindRequest
	test   host.SecretTestRequest
	delete host.SecretDeleteRequest
}

type httpDiagnosticSink struct {
	events []host.DiagnosticEvent
}

func openHTTPBridge(t *testing.T, handler http.Handler, pluginInstanceID string, surfaceID string, surfaceInstanceID string, bridgeChannelID string) bridge.GatewayTokenResult {
	t.Helper()
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redeven_proxy/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      pluginInstanceID,
		"surface_id":              surfaceID,
		"surface_instance_id":     surfaceInstanceID,
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/"+surfaceInstanceID+"/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	return postJSON[bridge.GatewayTokenResult](t, handler, "/_redeven_proxy/api/plugins/surfaces/"+surfaceInstanceID+"/bridge-token", map[string]any{
		"bridge_channel_id": bridgeChannelID,
		"handshake": map[string]any{
			"plugin_id":           openResp.PluginID,
			"surface_id":          openResp.SurfaceID,
			"surface_instance_id": openResp.SurfaceInstanceID,
			"active_fingerprint":  openResp.ActiveFingerprint,
			"bridge_nonce":        openResp.BridgeNonce,
			"ui_protocol_version": "plugin-ui-v1",
		},
	})
}

func (a *httpRecordingCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.last = req
	return a.result, nil
}

func (s *httpRecordingSecretStore) BindSecretRef(_ context.Context, req host.SecretBindRequest) error {
	s.bind = req
	return nil
}

func (s *httpRecordingSecretStore) TestSecretRef(_ context.Context, req host.SecretTestRequest) error {
	s.test = req
	return nil
}

func (s *httpRecordingSecretStore) DeleteSecretRef(_ context.Context, req host.SecretDeleteRequest) error {
	s.delete = req
	return nil
}

func (s *httpDiagnosticSink) AppendPluginDiagnostic(_ context.Context, event host.DiagnosticEvent) error {
	s.events = append(s.events, event)
	return nil
}
