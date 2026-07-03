package httpadapter

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/browsersite"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/retaineddata"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

func TestRouteSetHasManagementAndSandboxRoutes(t *testing.T) {
	routes := RouteSet()
	want := map[string]bool{
		"POST /_redevplugin/api/plugins/install":                                     false,
		"POST /_redevplugin/api/plugins/enable":                                      false,
		"POST /_redevplugin/api/plugins/surfaces/open":                               false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/bootstrap":    false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token": false,
		"POST /_redevplugin/api/plugins/rpc":                                         false,
		"POST /_redevplugin/api/plugins/data/export":                                 false,
		"GET /_redevplugin/api/plugins/retained-data":                                false,
		"POST /_redevplugin/api/plugins/retained-data/delete":                        false,
		"POST /_redevplugin/api/plugins/retained-data/cleanup-expired":               false,
		"GET /_redevplugin/api/plugins/intents":                                      false,
		"POST /_redevplugin/api/plugins/intents/invoke":                              false,
		"GET /_redevplugin/api/plugins/platform/compatibility":                       false,
		"GET /_redevplugin/api/plugins/permissions":                                  false,
		"POST /_redevplugin/api/plugins/permissions/grant":                           false,
		"POST /_redevplugin/api/plugins/permissions/revoke":                          false,
		"GET /_redevplugin/api/plugins/audit":                                        false,
		"GET /_redevplugin/api/plugins/diagnostics":                                  false,
		"GET /_redevplugin/api/plugins/runtime/health":                               false,
		"POST /_redevplugin/api/plugins/runtime/refresh-enabled":                     false,
		"POST /_redevplugin/api/plugins/runtime/start":                               false,
		"POST /_redevplugin/api/plugins/runtime/stop":                                false,
		"GET /_redevplugin/api/plugins/{plugin_instance_id}/settings":                false,
		"PATCH /_redevplugin/api/plugins/{plugin_instance_id}/settings":              false,
		"GET /_redevplugin/api/plugins/{plugin_instance_id}/settings/schema":         false,
		"POST /_redevplugin/bootstrap":                                               false,
		"GET /_redevplugin/assets/{asset_session_id}/{asset_path...}":                false,
		"POST /_redevplugin/csp-report":                                              false,
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

func TestHandlerCompatibilityManifest(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	got := getJSON[struct {
		SchemaVersion string `json:"schema_version"`
		Matrix        struct {
			PluginHostProtocolVersion string `json:"plugin_host_protocol_version"`
			PluginPlatformOpenAPI     string `json:"plugin_platform_openapi_version"`
		} `json:"matrix"`
		Contracts []struct {
			ID     string `json:"id"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"contracts"`
	}](t, handler, "/_redevplugin/api/plugins/platform/compatibility")

	if got.SchemaVersion != "redevplugin.compatibility.v1" {
		t.Fatalf("schema_version = %q", got.SchemaVersion)
	}
	if got.Matrix.PluginHostProtocolVersion != "plugin-host-v1" || got.Matrix.PluginPlatformOpenAPI != "plugin-platform-v1" {
		t.Fatalf("matrix mismatch: %#v", got.Matrix)
	}
	contracts := map[string]struct {
		Path   string
		SHA256 string
	}{}
	for _, contract := range got.Contracts {
		contracts[contract.ID] = struct {
			Path   string
			SHA256 string
		}{Path: contract.Path, SHA256: contract.SHA256}
	}
	openapi, ok := contracts["plugin-platform-openapi"]
	if !ok {
		t.Fatalf("compatibility manifest missing plugin-platform-openapi: %#v", got.Contracts)
	}
	if openapi.Path != "spec/openapi/plugin-platform-v1.yaml" || openapi.SHA256 == "" {
		t.Fatalf("plugin-platform-openapi contract mismatch: %#v", openapi)
	}
}

func TestHandlerJSONLimitErrorsExposeReason(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	deepBody := strings.Repeat("[", defaultJSONMaxDepth) + "0" + strings.Repeat("]", defaultJSONMaxDepth)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantReason string
	}{
		{
			name:       "payload bytes",
			body:       strings.Repeat(" ", defaultJSONRequestMaxBytes+1),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantReason: string(jsonLimitReasonPayloadBytes),
		},
		{
			name:       "json depth",
			body:       deepBody,
			wantStatus: http.StatusBadRequest,
			wantReason: string(jsonLimitReasonDepth),
		},
		{
			name:       "prototype key",
			body:       `{"plugin_instance_id":"plugini_test","__proto__":{}}`,
			wantStatus: http.StatusBadRequest,
			wantReason: string(jsonLimitReasonPrototypeKey),
		},
		{
			name:       "number precision",
			body:       `{"plugin_instance_id":9007199254740992}`,
			wantStatus: http.StatusBadRequest,
			wantReason: string(jsonLimitReasonNumberPrecision),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope Envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.ErrorCode != string(security.ErrJSONLimitExceeded) {
				t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
			}
			if got := envelope.ErrorDetails["reason"]; got != tt.wantReason {
				t.Fatalf("error_details.reason = %#v, want %q body = %s", got, tt.wantReason, rec.Body.String())
			}
		})
	}
}

func TestHandlerMalformedJSONRemainsInvalidRequest(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(`{"plugin_instance_id":`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrInvalidRequest) || len(envelope.ErrorDetails) != 0 {
		t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
	}
}

func TestHandlerWebSecurityRejectsDeniedOrigin(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginDeny}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied origin status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.evaluateCount != 1 {
		t.Fatalf("Evaluate count = %d, want 1", guard.evaluateCount)
	}
	if guard.csrfCount != 0 {
		t.Fatalf("CSRF count = %d, want 0 for safe method", guard.csrfCount)
	}
}

func TestHandlerWebSecurityRequiresCSRFForUnsafeProxyRoutes(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginAllow, csrfErr: websecurity.ErrCSRFRequired}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(`{}`))
	req.Header.Set(OwnerSessionHashHeader, "session_hash")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.evaluateCount != 1 || guard.csrfCount != 1 || guard.lastSessionHash != "session_hash" {
		t.Fatalf("guard calls = evaluate:%d csrf:%d session:%q", guard.evaluateCount, guard.csrfCount, guard.lastSessionHash)
	}
}

func TestHandlerWebSecurityAllowsSafeProxyRouteWithoutCSRF(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginAllow, csrfErr: websecurity.ErrCSRFRequired}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("catalog status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.evaluateCount != 1 || guard.csrfCount != 0 {
		t.Fatalf("guard calls = evaluate:%d csrf:%d", guard.evaluateCount, guard.csrfCount)
	}
}

func TestHandlerWebSecurityDoesNotRequireCSRFForSandboxBootstrap(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginAllow, csrfErr: websecurity.ErrCSRFRequired}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/bootstrap", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sandbox bootstrap status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.evaluateCount != 1 || guard.csrfCount != 0 {
		t.Fatalf("guard calls = evaluate:%d csrf:%d", guard.evaluateCount, guard.csrfCount)
	}
}

func TestHandlerWebSecurityCSRFClassificationCoversRouteSet(t *testing.T) {
	csrfExemptUnsafePaths := map[string]struct{}{
		"/_redevplugin/bootstrap":  {},
		"/_redevplugin/csp-report": {},
	}
	for _, route := range RouteSet() {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			guard := &httpTestWebSecurityGuard{decision: websecurity.OriginAllow}
			handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
			body := ""
			if route.Method == http.MethodPost || route.Method == http.MethodPatch || route.Method == http.MethodPut {
				body = `{}`
			}
			req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path), bytes.NewBufferString(body))
			req.Header.Set(OwnerSessionHashHeader, "session_hash")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if guard.evaluateCount != 1 {
				t.Fatalf("Evaluate count = %d, want 1", guard.evaluateCount)
			}
			_, csrfExempt := csrfExemptUnsafePaths[route.Path]
			wantCSRF := route.Method != http.MethodGet &&
				route.Method != http.MethodHead &&
				route.Method != http.MethodOptions &&
				strings.HasPrefix(route.Path, "/_redevplugin/api/plugins/") &&
				!csrfExempt
			if wantCSRF && guard.csrfCount != 1 {
				t.Fatalf("CSRF count = %d, want 1 for %s", guard.csrfCount, route.Path)
			}
			if !wantCSRF && guard.csrfCount != 0 {
				t.Fatalf("CSRF count = %d, want 0 for %s", guard.csrfCount, route.Path)
			}
		})
	}
}

func TestOpenAPIDeclaresOwnerSessionHashForCSRFRoutes(t *testing.T) {
	spec := readOpenAPIContract(t)
	for _, route := range RouteSet() {
		req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path), nil)
		if !requiresCSRF(req) {
			continue
		}
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			block, ok := openAPIOperationBlock(spec, route.Path, route.Method)
			if !ok {
				t.Fatalf("OpenAPI missing operation for %s %s", route.Method, route.Path)
			}
			if !strings.Contains(block, `#/components/parameters/OwnerSessionHashHeader`) {
				t.Fatalf("OpenAPI operation for %s %s must declare %s; block:\n%s", route.Method, route.Path, OwnerSessionHashHeader, block)
			}
		})
	}
}

func TestOpenAPIConfirmationResponseBelongsToConfirmRoute(t *testing.T) {
	spec := readOpenAPIContract(t)
	rpcBlock, ok := openAPIOperationBlock(spec, "/_redevplugin/api/plugins/rpc", http.MethodPost)
	if !ok {
		t.Fatal("OpenAPI missing rpc operation")
	}
	if strings.Contains(rpcBlock, `#/components/responses/ConfirmEnvelope`) {
		t.Fatalf("rpc operation must not use ConfirmEnvelope; block:\n%s", rpcBlock)
	}
	confirmBlock, ok := openAPIOperationBlock(spec, "/_redevplugin/api/plugins/confirm", http.MethodPost)
	if !ok {
		t.Fatal("OpenAPI missing confirm operation")
	}
	if !strings.Contains(confirmBlock, `#/components/responses/ConfirmEnvelope`) {
		t.Fatalf("confirm operation must use ConfirmEnvelope; block:\n%s", confirmBlock)
	}
}

func TestHandlerWebSecurityIgnoresNonPluginPaths(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginDeny, csrfErr: websecurity.ErrCSRFRequired}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodPost, "/healthz", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-plugin path status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.evaluateCount != 0 || guard.csrfCount != 0 {
		t.Fatalf("guard should not run for non-plugin path, evaluate=%d csrf=%d", guard.evaluateCount, guard.csrfCount)
	}
}

func TestHandlerInstallVerifiedRequiresHostTrustVerifier(t *testing.T) {
	h, err := host.New(host.Adapters{
		SessionResolver: httpTestSessionResolver{},
		Policy:          httpTestPolicy{},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	raw, err := json.Marshal(map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"trust_state":    "verified",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/install", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("install status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == "" {
		t.Fatalf("install envelope = %#v", envelope)
	}
}

func TestHandlerManagementLifecycleFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	packageBytes := buildHTTPFixturePackage(t)

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(packageBytes),
		"trust_state":    "verified",
	})
	if installed.PluginInstanceID == "" || installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install response mismatch: %#v", installed)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable response mismatch: %#v", enabled)
	}

	catalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog")
	if len(catalog.Plugins) != 1 || catalog.Plugins[0].PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("catalog mismatch: %#v", catalog)
	}

	disabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/disable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"reason":             "test",
	})
	if disabled.EnableState != registry.EnableDisabled || disabled.DisabledReason != "test" {
		t.Fatalf("disable response mismatch: %#v", disabled)
	}

	uninstalled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        true,
	})
	if uninstalled.RetainedDataState != registry.RetainedDataDeleted {
		t.Fatalf("uninstall response mismatch: %#v", uninstalled)
	}

	emptyCatalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog")
	if len(emptyCatalog.Plugins) != 0 {
		t.Fatalf("catalog after uninstall mismatch: %#v", emptyCatalog)
	}
}

func TestHandlerUpdateAndDowngradeFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	v1 := buildHTTPVersionedFixturePackage(t, "1.0.0", "HTTP")
	v2 := buildHTTPVersionedFixturePackage(t, "2.0.0", "HTTP v2")

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(v1),
		"trust_state":    "verified",
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable response mismatch: %#v", enabled)
	}

	updated := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/update", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"package_base64":     base64.StdEncoding.EncodeToString(v2),
	})
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("update response mismatch: %#v", updated)
	}

	downgraded := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/downgrade", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"version":            "1.0.0",
	})
	if downgraded.Version != "1.0.0" || downgraded.ActiveFingerprint != installed.ActiveFingerprint || len(downgraded.VersionHistory) != 1 || downgraded.VersionHistory[0].Version != "2.0.0" {
		t.Fatalf("downgrade response mismatch: %#v", downgraded)
	}
}

func TestHandlerManagementRejectsInvalidInstallAndUntrustedEnable(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/install", bytes.NewBufferString(`{"package_base64":"not-base64"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid install status = %d body = %s", rec.Code, rec.Body.String())
	}

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"trust_state":    "untrusted",
	})
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted enable status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerInstallMapsPackageValidationErrorDetails(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	tests := []struct {
		name        string
		entries     map[string][]byte
		wantStatus  int
		wantCode    security.ErrorCode
		wantReason  string
		wantPath    string
		wantPointer string
	}{
		{
			name: "manifest invalid",
			entries: map[string][]byte{
				"manifest.json": []byte(httpVersionedFixtureManifestJSON("", "HTTP")),
				"ui/index.html": []byte("<!doctype html><title>HTTP</title>"),
			},
			wantStatus:  http.StatusBadRequest,
			wantCode:    security.ErrManifestInvalid,
			wantReason:  "manifest_field",
			wantPath:    "manifest.json",
			wantPointer: "/plugin/version",
		},
		{
			name: "path forbidden",
			entries: map[string][]byte{
				"../manifest.json": []byte("{}"),
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   security.ErrPackagePathForbidden,
			wantReason: "path_traversal",
			wantPath:   "../manifest.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"package_base64": base64.StdEncoding.EncodeToString(buildHTTPRawPackage(t, tt.entries)),
				"trust_state":    "verified",
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/install", bytes.NewReader(raw))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("install status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope Envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.ErrorCode != string(tt.wantCode) {
				t.Fatalf("install envelope = %#v, want code %s", envelope, tt.wantCode)
			}
			if got := envelope.ErrorDetails["reason"]; got != tt.wantReason {
				t.Fatalf("error_details.reason = %#v, want %q body = %s", got, tt.wantReason, rec.Body.String())
			}
			if got := envelope.ErrorDetails["path"]; got != tt.wantPath {
				t.Fatalf("error_details.path = %#v, want %q body = %s", got, tt.wantPath, rec.Body.String())
			}
			if tt.wantPointer != "" {
				if got := envelope.ErrorDetails["pointer"]; got != tt.wantPointer {
					t.Fatalf("error_details.pointer = %#v, want %q body = %s", got, tt.wantPointer, rec.Body.String())
				}
			}
		})
	}
}

func TestHandlerEnableMapsBlockedNetworkTarget(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{storageBroker: storage.NewMemoryBroker()})
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPBlockedNetworkFixturePackage(t)),
		"trust_state":    "verified",
	})
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewReader(raw))
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
	browserSite := browsersite.NewMemoryStore()
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{browserSite: browserSite})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.activity",
		"surface_instance_id":     "surface_http",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
		"sandbox_origin":          "https://plg-http.sandbox.redevplugin.local",
	})
	if openResp.AssetTicket == "" || openResp.BridgeNonce == "" {
		t.Fatalf("open response missing ticket/nonce: %#v", openResp)
	}
	origins, err := browserSite.ListOrigins(context.Background(), browsersite.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 1 || origins[0].Origin != "https://plg-http.sandbox.redevplugin.local" || origins[0].SurfaceInstanceID != "surface_http" {
		t.Fatalf("registered browser origins mismatch: %#v", origins)
	}

	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})

	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http",
		"handshake": map[string]any{
			"type":                "redevplugin.bridge.handshake",
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

func TestHandlerBridgeTokenRejectsInvalidHandshakeType(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.activity",
		"surface_instance_id":     "surface_http_bad_type",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_type/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	raw, err := json.Marshal(map[string]any{
		"bridge_channel_id": "bridge_http",
		"handshake": map[string]any{
			"type":                "redevplugin.bridge.call",
			"plugin_id":           openResp.PluginID,
			"surface_id":          openResp.SurfaceID,
			"surface_instance_id": openResp.SurfaceInstanceID,
			"active_fingerprint":  openResp.ActiveFingerprint,
			"bridge_nonce":        openResp.BridgeNonce,
			"ui_protocol_version": "plugin-ui-v1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/surfaces/surface_http_bad_type/bridge-token", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bridge token status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrInvalidRequest) {
		t.Fatalf("bridge token envelope = %#v", envelope)
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{
		Host: h,
		SandboxAssetSecurity: SandboxAssetSecurity{
			FrameAncestors: []string{"https://app.example"},
		},
	}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
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
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/bootstrap", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sandbox bootstrap status = %d body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	var bootstrapEnvelope struct {
		OK   bool `json:"ok"`
		Data struct {
			AssetSessionID string `json:"asset_session_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bootstrapEnvelope); err != nil {
		t.Fatal(err)
	}
	assetURL := "/_redevplugin/assets/" + bootstrapEnvelope.Data.AssetSessionID + "/ui/index.html"
	if len(cookies) != 1 || cookies[0].Name != assetSessionCookieName || cookies[0].Value == "" || cookies[0].Path != assetSessionCookiePath(bootstrapEnvelope.Data.AssetSessionID) || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("asset session cookie mismatch: %#v", cookies)
	}
	if strings.Contains(rec.Body.String(), cookies[0].Value) || strings.Contains(rec.Body.String(), `"asset_session"`) {
		t.Fatalf("sandbox bootstrap body leaked asset session token: %s", rec.Body.String())
	}

	assetTicketReplay := postJSONError(t, handler, "/_redevplugin/bootstrap", map[string]any{
		"surface_instance_id": openResp.SurfaceInstanceID,
		"asset_ticket":        openResp.AssetTicket,
	}, http.StatusForbidden)
	if assetTicketReplay.ErrorCode != string(security.ErrAssetTicketInvalid) {
		t.Fatalf("asset ticket replay error_code = %s body = %#v", assetTicketReplay.ErrorCode, assetTicketReplay)
	}

	req = httptest.NewRequest(http.MethodGet, assetURL, nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site asset fetch status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("cross-site asset fetch error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cross-site asset fetch cache-control = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, assetURL, nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
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
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("asset cache-control = %q", got)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, snippet := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"connect-src 'self'",
		"worker-src 'none'",
		"webrtc 'block'",
		"frame-ancestors https://app.example",
		"report-to redevplugin-plugin-csp",
		"report-uri /_redevplugin/csp-report",
	} {
		if !strings.Contains(csp, snippet) {
			t.Fatalf("asset CSP missing %q: %s", snippet, csp)
		}
	}
	if got := rec.Header().Get("Reporting-Endpoints"); got != `redevplugin-plugin-csp="/_redevplugin/csp-report"` {
		t.Fatalf("reporting endpoints = %q", got)
	}
	if got := rec.Header().Get("Permissions-Policy"); !strings.Contains(got, "camera=()") || !strings.Contains(got, "fullscreen=()") {
		t.Fatalf("permissions policy = %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("referrer policy = %q", got)
	}
	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("cross-origin resource policy = %q", got)
	}
	if got := rec.Header().Get("Service-Worker-Allowed"); got != "/_redevplugin/assets/"+bootstrapEnvelope.Data.AssetSessionID+"/ui/" {
		t.Fatalf("service-worker-allowed = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, assetURL, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing asset session status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("missing asset session error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("missing asset session cache-control = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/assets/asset_session_other/ui/index.html", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched asset session id status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("mismatched asset session error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/assets/"+bootstrapEnvelope.Data.AssetSessionID+"/manifest.json", nil)
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.rpc.activity",
		"surface_instance_id":     "surface_http_rpc",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_rpc/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_rpc/bridge-token", map[string]any{
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

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
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

func TestHandlerRPCGatewayTokenErrorsUseStableCodes(t *testing.T) {
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.activity", "surface_http_gateway_errors", "bridge_http_gateway")
	baseBody := map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_gateway_errors",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_gateway",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "echo.ping",
	}

	invalidBody := cloneMap(baseBody)
	invalidBody["plugin_gateway_token"] = "plugin_gateway_token.invalid"
	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", invalidBody, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrGatewayTokenInvalid) {
		t.Fatalf("invalid gateway token error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}

	wrongChannelBody := cloneMap(baseBody)
	wrongChannelBody["bridge_channel_id"] = "bridge_http_other"
	envelope = postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", wrongChannelBody, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrGatewayTokenChannelMismatch) {
		t.Fatalf("gateway token channel mismatch error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestHandlerBridgeTokenDuplicateChannelUsesGatewayMismatchCode(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.activity",
		"surface_instance_id":     "surface_http_duplicate_channel",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	handshake := map[string]any{
		"plugin_id":           openResp.PluginID,
		"surface_id":          openResp.SurfaceID,
		"surface_instance_id": openResp.SurfaceInstanceID,
		"active_fingerprint":  openResp.ActiveFingerprint,
		"bridge_nonce":        openResp.BridgeNonce,
		"ui_protocol_version": "plugin-ui-v1",
	}
	postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http_a",
		"handshake":         handshake,
	})

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", map[string]any{
		"bridge_channel_id": "bridge_http_b",
		"handshake":         handshake,
	}, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrGatewayTokenChannelMismatch) {
		t.Fatalf("duplicate bridge channel error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestRPCErrorCodeMapsGatewayTokenReplay(t *testing.T) {
	if got := errorCodeForRPCError(bridge.ErrTokenReplay); got != security.ErrGatewayTokenReplayed {
		t.Fatalf("gateway token replay error_code = %s, want %s", got, security.ErrGatewayTokenReplayed)
	}
}

func TestHandlerPermissionGrantRevokeFlow(t *testing.T) {
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
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.activity", "surface_http_permissions", "bridge_http_permissions")
	callBody := map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_permissions",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_permissions",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "echo.ping",
	}

	raw, err := json.Marshal(callBody)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc without grant status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("rpc without grant error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}

	grant := postJSON[permissions.Record](t, handler, "/_redevplugin/api/plugins/permissions/grant", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"permission_id":      "read",
		"granted_by":         "admin",
	})
	if grant.PermissionID != "read" || grant.GrantedBy != "admin" || grant.RevokedAt != nil {
		t.Fatalf("grant response mismatch: %#v", grant)
	}
	listed := getJSON[struct {
		Permissions []permissions.Record `json:"permissions"`
	}](t, handler, "/_redevplugin/api/plugins/permissions?plugin_instance_id="+installed.PluginInstanceID+"&active_only=true")
	if len(listed.Permissions) != 1 || listed.Permissions[0].PermissionID != "read" {
		t.Fatalf("permissions list mismatch: %#v", listed)
	}

	req = httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc with stale token status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrGatewayTokenInvalid) {
		t.Fatalf("stale token error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}

	bridgeResp = openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.activity", "surface_http_permissions", "bridge_http_permissions")
	callBody["plugin_gateway_token"] = bridgeResp.GatewayToken
	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", callBody)
	if result.Data == nil || adapter.last.Method != "echo.ping" {
		t.Fatalf("rpc after grant mismatch: result=%#v invocation=%#v", result, adapter.last)
	}

	revoked := postJSON[permissions.Record](t, handler, "/_redevplugin/api/plugins/permissions/revoke", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"permission_id":      "read",
		"revoked_by":         "admin",
		"reason":             "test",
	})
	if revoked.RevokedAt == nil || revoked.RevokedBy != "admin" || revoked.RevokedReason != "test" {
		t.Fatalf("revoke response mismatch: %#v", revoked)
	}
	active := getJSON[struct {
		Permissions []permissions.Record `json:"permissions"`
	}](t, handler, "/_redevplugin/api/plugins/permissions?plugin_instance_id="+installed.PluginInstanceID+"&active_only=true")
	if len(active.Permissions) != 0 {
		t.Fatalf("active permissions after revoke mismatch: %#v", active)
	}
	bridgeResp = openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.activity", "surface_http_permissions", "bridge_http_permissions")
	callBody["plugin_gateway_token"] = bridgeResp.GatewayToken
	raw, err = json.Marshal(callBody)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc after revoke status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("rpc after revoke error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_id":              "http.danger.activity",
		"surface_instance_id":     "surface_http_danger",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_danger/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_danger/bridge-token", map[string]any{
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
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
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

	confirmation := postJSON[host.ConfirmMethodResult](t, handler, "/_redevplugin/api/plugins/confirm", body)
	if confirmation.ConfirmationID == "" || confirmation.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", confirmation)
	}
	body["confirmation_id"] = confirmation.ConfirmationID
	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", body)
	if result.Data == nil || adapter.last.Method != "danger.run" {
		t.Fatalf("confirmed rpc mismatch: result=%#v invocation=%#v", result, adapter.last)
	}
}

func TestHandlerIntentListAndInvokeFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, false), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}

	listed := getJSON[struct {
		Intents []host.IntentRecord `json:"intents"`
	}](t, handler, "/_redevplugin/api/plugins/intents?intent_id=example.echo&plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Intents) != 1 || listed.Intents[0].IntentID != "example.echo" || listed.Intents[0].Method != "echo.ping" || listed.Intents[0].PayloadSchema["type"] != "object" {
		t.Fatalf("intent list mismatch: %#v", listed)
	}

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/intents/invoke", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"intent_id":               "example.echo",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
		"params":                  map[string]any{"message": "from http intent"},
	})
	if result.Data == nil || adapter.last.PluginInstanceID != installed.PluginInstanceID || adapter.last.Method != "echo.ping" || adapter.last.Arguments["message"] != "from http intent" {
		t.Fatalf("intent invoke mismatch: result=%#v invocation=%#v", result, adapter.last)
	}
}

func TestHandlerIntentInvokeRequiresPermission(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, false), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"intent_id":          "example.echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/intents/invoke", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("intent without grant status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("intent without grant error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	if adapter.last.Method != "" {
		t.Fatalf("capability adapter should not be called without grant: %#v", adapter.last)
	}
}

func TestHandlerIntentInvokeDangerousFailsClosed(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"done": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, true), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"intent_id":          "example.danger",
		"params":             map[string]any{"target": "db"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/intents/invoke", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("danger intent status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrConfirmationRequired) {
		t.Fatalf("danger intent error code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	if adapter.last.Method != "" {
		t.Fatalf("capability adapter should not be called for dangerous intent: %#v", adapter.last)
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.activity", "surface_http_operation", "bridge_http_operation")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
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
	}](t, handler, "/_redevplugin/api/plugins/operations?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Operations) != 1 || listed.Operations[0].OperationID != "op_http_1" {
		t.Fatalf("operation list mismatch: %#v", listed)
	}

	detail := getJSON[operation.Record](t, handler, "/_redevplugin/api/plugins/operations/op_http_1")
	if detail.Method != "images.pull" || detail.Status != operation.StatusRunning {
		t.Fatalf("operation detail mismatch: %#v", detail)
	}

	canceled := postJSON[operation.Record](t, handler, "/_redevplugin/api/plugins/operations/op_http_1/cancel", map[string]any{
		"reason": "user",
	})
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel response mismatch: %#v", canceled)
	}
}

func TestHandlerPluginStreamFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{StreamID: "stream_http_1"}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPSubscriptionRPCFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	sandboxOrigin := "https://plg-stream.sandbox.redevplugin.local"
	bridgeResp := openHTTPBridgeWithSandboxOrigin(t, handler, installed.PluginInstanceID, "http.subscription.activity", "surface_http_stream", "bridge_http_stream", sandboxOrigin)

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_stream",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_stream",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "logs.tail",
	})
	if result.StreamID != "stream_http_1" || result.StreamTicket == "" {
		t.Fatalf("rpc stream result mismatch: %#v", result)
	}
	if _, err := h.AppendStreamEvent(context.Background(), host.AppendStreamEventRequest{
		StreamID: "stream_http_1",
		Data:     []byte("line 1"),
	}); err != nil {
		t.Fatalf("AppendStreamEvent() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/stream/stream_http_1", nil)
	req.Header.Set("Origin", sandboxOrigin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stream without ticket status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrStreamTicketInvalid) {
		t.Fatalf("stream without ticket error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	assertStreamSecurityHeaders(t, rec)

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/stream/stream_http_1?ticket="+result.StreamTicket, nil)
	req.Header.Set("Origin", sandboxOrigin)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stream cross-site fetch metadata status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrStreamTicketInvalid) {
		t.Fatalf("stream cross-site fetch metadata error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	assertStreamSecurityHeaders(t, rec)

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/stream/stream_http_1?ticket="+result.StreamTicket, nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stream wrong origin status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrStreamTicketInvalid) {
		t.Fatalf("stream wrong origin error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	assertStreamSecurityHeaders(t, rec)

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/stream/stream_http_1?ticket="+result.StreamTicket, nil)
	req.Header.Set("Origin", sandboxOrigin)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stream status = %d body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q", got)
	}
	assertStreamSecurityHeaders(t, rec)
	var event struct {
		StreamID string `json:"stream_id"`
		Sequence uint64 `json:"sequence"`
		Data     []byte `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &event); err != nil {
		t.Fatalf("decode stream event: %v body = %s", err, rec.Body.String())
	}
	if event.StreamID != "stream_http_1" || event.Sequence != 1 || string(event.Data) != "line 1" {
		t.Fatalf("stream event mismatch: %#v body = %s", event, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/_redevplugin/stream/stream_http_1?ticket="+result.StreamTicket, nil)
	req.Header.Set("Origin", sandboxOrigin)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stream replay status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrStreamTicketInvalid) {
		t.Fatalf("stream replay error_code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
	assertStreamSecurityHeaders(t, rec)
}

func TestStreamTokenValidationErrorsMapToInvalidCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "missing ticket", err: host.ErrStreamTicketRequired},
		{name: "expired ticket", err: bridge.ErrTokenExpired},
		{name: "replayed ticket", err: bridge.ErrTokenReplay},
		{name: "invalid ticket", err: bridge.ErrTokenInvalid},
		{name: "audience mismatch", err: bridge.ErrTokenAudience},
		{name: "revoked ticket", err: bridge.ErrTokenRevoked},
		{name: "wrong token kind", err: bridge.ErrTokenKind},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorCodeForStreamError(tc.err); got != security.ErrStreamTicketInvalid {
				t.Fatalf("errorCodeForStreamError(%v) = %s, want %s", tc.err, got, security.ErrStreamTicketInvalid)
			}
			if got := httpStatusForStreamError(tc.err); got != http.StatusForbidden {
				t.Fatalf("httpStatusForStreamError(%v) = %d, want %d", tc.err, got, http.StatusForbidden)
			}
		})
	}
}

func assertStreamSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("stream cache-control = %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("stream referrer-policy = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("stream nosniff = %q", got)
	}
}

func TestHandlerCoreActionRPCFlow(t *testing.T) {
	coreAdapter := &httpRecordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{coreActions: coreAdapter})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPCoreActionFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.core.activity", "surface_http_core", "bridge_http_core")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_core",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_core",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "core.open",
		"params":                  map[string]any{"target": "settings"},
	})
	if result.Data == nil {
		t.Fatalf("core action rpc result missing data: %#v", result)
	}
	if coreAdapter.last.TargetMethod != "example.open_settings" || coreAdapter.last.Arguments["target"] != "settings" {
		t.Fatalf("core action invocation mismatch: %#v", coreAdapter.last)
	}
}

func TestHandlerWorkerRuntimeErrorMapsToRuntimeUnavailable(t *testing.T) {
	runtime := &httpRecordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", Ready: true},
		err:    runtimeclient.ErrRuntimeRequestFailed,
	}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeSupervisor: runtime})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPWorkerFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.worker.activity", "surface_http_worker", "bridge_http_worker")

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id":      installed.PluginInstanceID,
		"surface_instance_id":     "surface_http_worker",
		"session_channel_id_hash": "channel_hash",
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"bridge_channel_id":       "bridge_http_worker",
		"plugin_gateway_token":    bridgeResp.GatewayToken,
		"method":                  "worker.echo",
		"params":                  map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("worker runtime error status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("worker runtime error code = %s body = %s", envelope.ErrorCode, rec.Body.String())
	}
}

func TestHandlerSettingsFlow(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: &httpRecordingSecretStore{}})
	handler := Handler{Host: h}
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}

	schema := getJSON[host.SettingsSchemaResult](t, handler, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings/schema")
	if schema.SchemaVersion != 1 || len(schema.Fields) != 3 || schema.SettingsRevision == 0 {
		t.Fatalf("settings schema mismatch: %#v", schema)
	}
	initial := getJSON[host.SettingsResult](t, handler, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings")
	if initial.Values["default_engine"] != "docker" {
		t.Fatalf("settings defaults mismatch: %#v", initial)
	}
	secretRaw, ok := initial.Values["api_token"].(map[string]any)
	if !ok || secretRaw["set"] != false {
		t.Fatalf("secret setting should be redacted unset state: %#v", initial.Values["api_token"])
	}

	patched := patchJSON[host.SettingsResult](t, handler, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings", map[string]any{
		"values": map[string]any{"default_engine": "podman"},
	})
	if patched.SettingsRevision <= initial.SettingsRevision || patched.Values["default_engine"] != "podman" {
		t.Fatalf("patched settings mismatch: before=%#v after=%#v", initial, patched)
	}

	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/secrets/bind", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	withSecret := getJSON[host.SettingsResult](t, handler, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings")
	secretRaw, ok = withSecret.Values["api_token"].(map[string]any)
	if !ok || secretRaw["set"] != true {
		t.Fatalf("secret setting should be redacted set state: %#v", withSecret.Values["api_token"])
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
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.activity", "surface_http_block_delete", "bridge_http_block_delete")
	postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
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
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/uninstall", bytes.NewReader(raw))
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
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/surfaces/open", bytes.NewBufferString(`{} {}`))
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

	exported := postJSON[host.ExportDataResult](t, handler, "/_redevplugin/api/plugins/data/export", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if exported.ArchiveRef == "" {
		t.Fatal("export response missing archive_ref")
	}

	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/data/import", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"archive_ref":        exported.ArchiveRef,
		"delete_existing":    true,
	})
}

func TestHandlerRetainedDataLifecycleFlow(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	h := newHTTPTestHostWithStorage(t, storageBroker)
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t)),
		"trust_state":    "verified",
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if err := storageBroker.SetUsage(ctx, installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatalf("SetUsage() error = %v", err)
	}
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        false,
	})

	listed := getJSON[struct {
		RetainedData []retaineddata.Record `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?source_plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.RetainedData) != 1 || listed.RetainedData[0].State != retaineddata.StateRetained {
		t.Fatalf("retained-data list mismatch: %#v", listed.RetainedData)
	}
	deleted := postJSON[retaineddata.Record](t, handler, "/_redevplugin/api/plugins/retained-data/delete", map[string]any{
		"retained_id": listed.RetainedData[0].RetainedID,
	})
	if deleted.State != retaineddata.StateDeleted {
		t.Fatalf("retained-data delete mismatch: %#v", deleted)
	}
	if namespaces, err := storageBroker.ListNamespaces(ctx, installed.PluginInstanceID); err != nil {
		t.Fatal(err)
	} else if len(namespaces) != 0 {
		t.Fatalf("retained storage still present after HTTP delete: %#v", namespaces)
	}
}

func TestHandlerBindRetainedDataRestoresPayload(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	h := newHTTPTestHostWithStorage(t, storageBroker)
	handler := Handler{Host: h}
	packageBase64 := base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t))
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": packageBase64,
		"trust_state":    "verified",
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if err := storageBroker.SetUsage(ctx, installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatal(err)
	}
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        false,
	})
	listed := getJSON[struct {
		RetainedData []retaineddata.Record `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?source_plugin_instance_id="+installed.PluginInstanceID)
	target := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64":     packageBase64,
		"trust_state":        "verified",
		"plugin_instance_id": "plugini_http_storage_rebind_target",
	})

	bound := postJSON[retaineddata.Record](t, handler, "/_redevplugin/api/plugins/retained-data/bind", map[string]any{
		"retained_id":               listed.RetainedData[0].RetainedID,
		"target_plugin_instance_id": target.PluginInstanceID,
	})
	if bound.State != retaineddata.StateBound || bound.BoundPluginInstanceID != target.PluginInstanceID {
		t.Fatalf("bound retained-data response mismatch: %#v", bound)
	}
	usage, err := storageBroker.Usage(ctx, target.PluginInstanceID, "db")
	if err != nil {
		t.Fatalf("Usage(bound target) error = %v", err)
	}
	if usage.UsageBytes != 1024 {
		t.Fatalf("bound target usage = %d, want 1024", usage.UsageBytes)
	}
}

func TestHandlerRetainedDataDeleteFailureReturnsCleanupCodeAndRecord(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	h := newHTTPTestHostWithStorage(t, storageBroker)
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t)),
		"trust_state":    "verified",
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"delete_data":        false,
	})
	listed := getJSON[struct {
		RetainedData []retaineddata.Record `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?source_plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.RetainedData) != 1 {
		t.Fatalf("retained-data list mismatch: %#v", listed.RetainedData)
	}
	if err := storageBroker.EnsureNamespace(ctx, storage.Namespace{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "db",
		Kind:             storage.StoreSQLite,
		QuotaBytes:       1024 * 1024,
		SchemaVersion:    1,
	}); err != nil {
		t.Fatalf("EnsureNamespace(reactivate) error = %v", err)
	}

	reqBody, err := json.Marshal(map[string]any{"retained_id": listed.RetainedData[0].RetainedID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/retained-data/delete", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete retained data status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		OK        bool                `json:"ok"`
		ErrorCode string              `json:"error_code"`
		Data      retaineddata.Record `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrRetainedDataCleanupFailed) || envelope.Data.State != retaineddata.StateDeleteFailedRetryable {
		t.Fatalf("cleanup failure envelope mismatch: %#v", envelope)
	}
}

func TestHandlerCleanupExpiredRetainedDataRejectsInvalidMaxRecords(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/retained-data/cleanup-expired", bytes.NewBufferString(`{"max_records":0}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cleanup max_records status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrInvalidRequest) {
		t.Fatalf("cleanup max_records envelope mismatch: %#v", envelope)
	}
}

func TestHandlerDataExportImportSettingsArchive(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PatchPluginSettings(context.Background(), host.PatchSettingsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Values:           map[string]any{"default_engine": "podman"},
	}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	exported := postJSON[host.ExportDataResult](t, handler, "/_redevplugin/api/plugins/data/export", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if exported.SettingsArchiveRef == "" {
		t.Fatal("export response missing settings_archive_ref")
	}

	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/data/import", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"settings_archive_ref": exported.SettingsArchiveRef,
		"delete_existing":      true,
	})
}

func TestHandlerSecretLifecycleFlow(t *testing.T) {
	secrets := &httpRecordingSecretStore{}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secrets})
	installed, err := host.InstallPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h}

	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/secrets/bind", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/secrets/test", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/secrets/delete", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})

	if secrets.bind.PluginInstanceID != installed.PluginInstanceID || secrets.bind.SecretRef != "api_token" || secrets.test.SecretRef != "api_token" || secrets.delete.SecretRef != "api_token" {
		t.Fatalf("secret adapter calls mismatch: %#v", secrets)
	}
}

func TestHandlerCSPReportFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}

	postJSON[map[string]bool](t, handler, "/_redevplugin/csp-report", map[string]any{
		"plugin_id":           "com.example.http",
		"plugin_instance_id":  "plugin_http",
		"surface_id":          "http.activity",
		"surface_instance_id": "surface_http",
		"sandbox_origin":      "https://plg-http.sandbox.redevplugin.local",
		"active_fingerprint":  "sha256:fingerprint",
		"csp-report": map[string]any{
			"document-uri":        "https://plugin.example/ui/index.html",
			"blocked-uri":         "inline",
			"effective-directive": "script-src",
			"line-number":         7,
		},
	})

	listed := getJSON[struct {
		DiagnosticEvents []host.DiagnosticEvent `json:"diagnostic_events"`
	}](t, handler, "/_redevplugin/api/plugins/diagnostics?plugin_instance_id=plugin_http&severity=warning")
	if len(listed.DiagnosticEvents) != 1 {
		t.Fatalf("diagnostic events = %#v", listed.DiagnosticEvents)
	}
	event := listed.DiagnosticEvents[0]
	if event.Type != "plugin.csp.violation" ||
		event.PluginID != "com.example.http" ||
		event.SurfaceInstanceID != "surface_http" ||
		event.Details["effective_directive"] != "script-src" ||
		event.Details["sandbox_origin"] != "https://plg-http.sandbox.redevplugin.local" {
		t.Fatalf("diagnostic event mismatch: %#v", event)
	}
}

func TestHandlerCSPReportRejectsUnsupportedContentType(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/csp-report", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing content-type status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrInvalidRequest) {
		t.Fatalf("missing content-type envelope mismatch: %#v", envelope)
	}
}

func TestHandlerCSPReportAppliesJSONLimitDetails(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/csp-report", strings.NewReader(strings.Repeat(" ", maxCSPReportBytes+1)))
	req.Header.Set("Content-Type", "application/csp-report")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized report status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrJSONLimitExceeded) || envelope.ErrorDetails["reason"] != string(jsonLimitReasonPayloadBytes) {
		t.Fatalf("oversized report envelope mismatch: %#v", envelope)
	}
}

func TestHandlerCSPReportRateLimitsBySandboxFingerprintAndSourceIP(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, CSPReportLimiter: NewMemoryCSPReportLimiter(1, time.Minute)}
	body := []byte(`{
		"plugin_id": "com.example.http",
		"plugin_instance_id": "plugin_http",
		"surface_id": "http.activity",
		"surface_instance_id": "surface_http",
		"sandbox_origin": "https://plg-http.sandbox.redevplugin.local",
		"active_fingerprint": "sha256:fingerprint",
		"csp-report": {
			"blocked-uri": "inline",
			"effective-directive": "script-src"
		}
	}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/_redevplugin/csp-report", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/csp-report")
		req.RemoteAddr = "203.0.113.7:51111"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if i == 0 && rec.Code != http.StatusOK {
			t.Fatalf("first report status = %d body = %s", rec.Code, rec.Body.String())
		}
		if i == 1 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("second report status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope Envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.ErrorCode != string(security.ErrNetworkRateLimited) {
				t.Fatalf("rate limit envelope mismatch: %#v", envelope)
			}
		}
	}
}

func TestHandlerListsAuditEvents(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"trust_state":    registry.TrustVerified,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})

	listed := getJSON[struct {
		AuditEvents []host.AuditEvent `json:"audit_events"`
	}](t, handler, "/_redevplugin/api/plugins/audit?plugin_instance_id="+installed.PluginInstanceID+"&type=plugin.enabled&limit=5")
	if len(listed.AuditEvents) != 1 {
		t.Fatalf("audit events = %#v", listed.AuditEvents)
	}
	event := listed.AuditEvents[0]
	if event.Type != "plugin.enabled" || event.PluginID != installed.PluginID || event.PluginInstanceID != installed.PluginInstanceID || event.OccurredAt.IsZero() {
		t.Fatalf("audit event mismatch: %#v", event)
	}
}

func TestHandlerRuntimeLifecycleFlow(t *testing.T) {
	supervisor := &httpRecordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", Ready: true},
	}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeSupervisor: supervisor})
	handler := Handler{Host: h}

	health := postJSON[runtimeclient.Health](t, handler, "/_redevplugin/api/plugins/runtime/start", map[string]any{
		"target": map[string]any{"os": "test-os", "arch": "test-arch"},
	})
	if health.RuntimeInstanceID != "runtime_http" || supervisor.startedTarget.OS != "test-os" || supervisor.startedTarget.Arch != "test-arch" {
		t.Fatalf("runtime start mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	health = getJSON[runtimeclient.Health](t, handler, "/_redevplugin/api/plugins/runtime/health")
	if !health.Ready || health.RuntimeGenerationID != "runtime_gen_http" {
		t.Fatalf("runtime health mismatch: %#v", health)
	}
	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/runtime/stop", map[string]any{})
	if supervisor.stopCalls != 1 {
		t.Fatalf("Stop calls = %d, want 1", supervisor.stopCalls)
	}
}

func TestHandlerRefreshEnabledRuntimeState(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install", map[string]any{
		"package_base64": base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"trust_state":    registry.TrustVerified,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})

	refreshed := postJSON[struct {
		RefreshedPlugins []registry.PluginRecord `json:"refreshed_plugins"`
	}](t, handler, "/_redevplugin/api/plugins/runtime/refresh-enabled", map[string]any{})
	if len(refreshed.RefreshedPlugins) != 1 || refreshed.RefreshedPlugins[0].PluginInstanceID != enabled.PluginInstanceID {
		t.Fatalf("refreshed plugins mismatch: %#v", refreshed.RefreshedPlugins)
	}

	audit := getJSON[struct {
		AuditEvents []host.AuditEvent `json:"audit_events"`
	}](t, handler, "/_redevplugin/api/plugins/audit?plugin_instance_id="+enabled.PluginInstanceID+"&type=plugin.runtime_state.refreshed&limit=5")
	if len(audit.AuditEvents) != 1 {
		t.Fatalf("runtime refresh audit events = %#v", audit.AuditEvents)
	}
}

func postJSON[T any](t *testing.T, handler http.Handler, path string, body any) T {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
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

func postJSONError(t *testing.T, handler http.Handler, path string, body any, wantStatus int) Envelope {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("POST %s status = %d, want %d body = %s", path, rec.Code, wantStatus, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK {
		t.Fatalf("POST %s returned ok for expected error: %s", path, rec.Body.String())
	}
	return envelope
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

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func samplePathForRoute(path string) string {
	switch path {
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bootstrap":
		return "/_redevplugin/api/plugins/surfaces/surface_test/bootstrap"
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token":
		return "/_redevplugin/api/plugins/surfaces/surface_test/bridge-token"
	case "/_redevplugin/api/plugins/operations/{operation_id}":
		return "/_redevplugin/api/plugins/operations/op_test"
	case "/_redevplugin/api/plugins/operations/{operation_id}/cancel":
		return "/_redevplugin/api/plugins/operations/op_test/cancel"
	case "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema":
		return "/_redevplugin/api/plugins/plugini_test/settings/schema"
	case "/_redevplugin/api/plugins/{plugin_instance_id}/settings":
		return "/_redevplugin/api/plugins/plugini_test/settings"
	case "/_redevplugin/assets/{asset_session_id}/{asset_path...}":
		return "/_redevplugin/assets/assetsession_test/ui/index.html"
	case "/_redevplugin/stream/{stream_id}":
		return "/_redevplugin/stream/stream_test"
	default:
		return path
	}
}

func readOpenAPIContract(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "spec", "openapi", "plugin-platform-v1.yaml"),
		filepath.Join("spec", "openapi", "plugin-platform-v1.yaml"),
	}
	var lastErr error
	for _, candidate := range candidates {
		raw, err := os.ReadFile(candidate)
		if err == nil {
			return string(raw)
		}
		lastErr = err
	}
	t.Fatalf("read OpenAPI contract: %v", lastErr)
	return ""
}

func openAPIOperationBlock(spec, routePath, method string) (string, bool) {
	lines := strings.Split(spec, "\n")
	pathLine := "  " + routePath + ":"
	methodLine := "    " + strings.ToLower(method) + ":"
	pathStart := -1
	for i, line := range lines {
		if line == pathLine {
			pathStart = i
			break
		}
	}
	if pathStart == -1 {
		return "", false
	}
	pathEnd := len(lines)
	for i := pathStart + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  /") || lines[i] == "components:" {
			pathEnd = i
			break
		}
	}
	methodStart := -1
	for i := pathStart + 1; i < pathEnd; i++ {
		if lines[i] == methodLine {
			methodStart = i
			break
		}
	}
	if methodStart == -1 {
		return "", false
	}
	methodEnd := pathEnd
	for i := methodStart + 1; i < pathEnd; i++ {
		if strings.TrimSpace(lines[i]) != "" && leadingSpaces(lines[i]) <= 4 {
			methodEnd = i
			break
		}
	}
	return strings.Join(lines[methodStart:methodEnd], "\n"), true
}

func leadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func newHTTPTestHost(t *testing.T) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{})
}

func newHTTPTestHostWithStorage(t *testing.T, storageBroker storage.Broker) *host.Host {
	return newHTTPTestHostWithOptions(t, httpTestHostOptions{storageBroker: storageBroker})
}

type httpTestHostOptions struct {
	storageBroker     storage.Broker
	browserSite       browsersite.Store
	secrets           host.SecretStoreAdapter
	diagnostics       host.DiagnosticsSink
	permissions       permissions.Store
	runtimeSupervisor runtimeclient.Supervisor
	capabilityID      string
	capabilityAdapter capability.Adapter
	coreActions       host.CoreActionAdapter
}

func newHTTPTestHostWithOptions(t *testing.T, opts httpTestHostOptions) *host.Host {
	t.Helper()
	capabilities := capability.NewRegistry()
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		capabilities.Register(opts.capabilityID, opts.capabilityAdapter)
	}
	h, err := host.New(host.Adapters{
		SessionResolver:      httpTestSessionResolver{},
		Policy:               httpTestPolicy{},
		PackageTrustVerifier: httpTestPackageTrustVerifier{},
		Storage:              opts.storageBroker,
		BrowserSite:          opts.browserSite,
		Secrets:              opts.secrets,
		Diagnostics:          opts.diagnostics,
		Permissions:          opts.permissions,
		RuntimeSupervisor:    opts.runtimeSupervisor,
		Capabilities:         capabilities,
		CoreActions:          opts.coreActions,
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

func buildHTTPRawPackage(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entryPath, content := range entries {
		writer, err := zw.Create(entryPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPVersionedFixturePackage(t *testing.T, version string, title string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpVersionedFixtureManifestJSON(version, title))
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>"+title+"</title>")
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

func buildHTTPIntentFixturePackage(t *testing.T, dangerous bool) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := httpRPCFixtureManifestJSON()
	if dangerous {
		manifestJSON = httpDangerousRPCFixtureManifestJSON()
	}
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), addHTTPIntentToManifestJSON(t, manifestJSON, dangerous))
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Intent</title>")
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

func buildHTTPSubscriptionRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpSubscriptionRPCFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Subscription</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPCoreActionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpCoreActionFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Core Action</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPWorkerFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpWorkerFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Worker</title>")
	writeHTTPBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalHTTPWorkerWASMForTest("redevplugin_worker_invoke"))
	writeHTTPFile(t, filepath.Join(dir, "workers", "abi.json"), httpWorkerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildHTTPSettingsFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeHTTPFile(t, filepath.Join(dir, "manifest.json"), httpSettingsFixtureManifestJSON())
	writeHTTPFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>HTTP Settings</title>")
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
	writeHTTPBytes(t, filename, []byte(content))
}

func writeHTTPBytes(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func minimalHTTPWorkerWASMForTest(exportName string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07,
	}
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x00)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b)
	return module
}

func httpWorkerFixtureABIJSON(exports ...string) string {
	rawExports, err := json.Marshal(exports)
	if err != nil {
		panic(err)
	}
	return "{\n" +
		"  \"abi_version\": \"redevplugin-wasm-worker-v1\",\n" +
		"  \"exports\": " + string(rawExports) + ",\n" +
		"  \"imports\": [\"redevplugin.log\", \"redevplugin.storage\", \"redevplugin.network\", \"redevplugin.operation\", \"redevplugin.clock\"]\n" +
		"}\n"
}

func httpFixtureManifestJSON() string {
	return httpVersionedFixtureManifestJSON("1.0.0", "HTTP")
}

func httpVersionedFixtureManifestJSON(version string, title string) string {
	if title == "" {
		title = "HTTP"
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
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
		"schema_version": "redevplugin.manifest.v1",
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
		"schema_version": "redevplugin.manifest.v1",
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
		"schema_version": "redevplugin.manifest.v1",
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
		"schema_version": "redevplugin.manifest.v1",
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

func httpSubscriptionRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.subscription",
			"display_name": "HTTP Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.subscription.activity", "kind": "activity", "label": "HTTP Subscription", "entry": "ui/index.html", "method": "logs.tail"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "logs.tail",
				"effect": "read",
				"execution": "subscription",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "orphan",
					"uninstall_behavior": "force_cleanup_allowed",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "logs.tail"}
			}
		]
	}`
}

func httpCoreActionFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.core",
			"display_name": "HTTP Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.core.activity", "kind": "activity", "label": "HTTP Core", "entry": "ui/index.html", "method": "core.open"}
		],
		"methods": [
			{
				"method": "core.open",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "core_action", "action_id": "example.open_settings"}
			}
		]
	}`
}

func httpWorkerFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.worker",
			"display_name": "HTTP Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.worker.activity", "kind": "activity", "label": "HTTP Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{"worker_id": "echo_worker", "mode": "job", "artifact": "workers/echo.wasm", "abi": "redevplugin-wasm-worker-v1", "scope": "user", "memory_limit_bytes": 1048576}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		]
	}`
}

func httpSettingsFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.settings",
			"display_name": "HTTP Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "http.settings.activity", "kind": "activity", "label": "HTTP Settings", "entry": "ui/index.html"}
		],
		"settings": {
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
			},
			"fields": [
				{"key": "default_engine", "type": "select", "scope": "user", "label": "Default engine", "default": "docker", "options": ["docker", "podman"]},
				{"key": "show_stopped", "type": "boolean", "scope": "user", "label": "Show stopped", "default": true},
				{"key": "api_token", "type": "secret", "scope": "user", "label": "API token", "secret_ref": "api_token"}
			]
		}
	}`
}

func httpBlockedNetworkFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
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

func addHTTPIntentToManifestJSON(t *testing.T, manifestJSON string, dangerous bool) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &doc); err != nil {
		t.Fatal(err)
	}
	intent := map[string]any{
		"intent_id":      "example.echo",
		"method":         "echo.ping",
		"payload_schema": map[string]any{"type": "object"},
	}
	if dangerous {
		intent["intent_id"] = "example.danger"
		intent["method"] = "danger.run"
	}
	doc["intents"] = []any{intent}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func patchJSON[T any](t *testing.T, handler http.Handler, path string, body any) T {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code < 200 || rec.Code >= 300 {
		t.Fatalf("PATCH %s status = %d body = %s", path, rec.Code, rec.Body.String())
	}
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("PATCH %s returned not ok: %s", path, rec.Body.String())
	}
	var data T
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
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

type httpTestPackageTrustVerifier struct{}

func (httpTestPackageTrustVerifier) VerifyPackageTrust(_ context.Context, req host.PackageTrustVerificationRequest) (host.PackageTrustVerificationResult, error) {
	return host.PackageTrustVerificationResult{TrustState: req.RequestedTrustState}, nil
}

type httpRecordingCapabilityAdapter struct {
	last   capability.Invocation
	result capability.Result
}

type httpRecordingCoreActionAdapter struct {
	last   capability.Invocation
	result capability.Result
}

type httpRecordingSecretStore struct {
	bind   host.SecretBindRequest
	test   host.SecretTestRequest
	delete host.SecretDeleteRequest
}

type httpRecordingRuntimeSupervisor struct {
	health        runtimeclient.Health
	startedTarget runtimeclient.Target
	stopCalls     int
	err           error
}

type httpTestWebSecurityGuard struct {
	decision        websecurity.OriginDecision
	evaluateErr     error
	csrfErr         error
	evaluateCount   int
	csrfCount       int
	lastSessionHash string
}

func (g *httpTestWebSecurityGuard) Evaluate(r *http.Request) (websecurity.RequestContext, websecurity.OriginDecision, error) {
	g.evaluateCount++
	decision := g.decision
	if decision == "" {
		decision = websecurity.OriginAllow
	}
	return websecurity.RequestContext{
		Origin: r.Header.Get("Origin"),
		Route:  r.URL.Path,
		Method: r.Method,
	}, decision, g.evaluateErr
}

func (g *httpTestWebSecurityGuard) ValidateCSRF(_ *http.Request, sessionHash string) error {
	g.csrfCount++
	g.lastSessionHash = sessionHash
	return g.csrfErr
}

func openHTTPBridge(t *testing.T, handler http.Handler, pluginInstanceID string, surfaceID string, surfaceInstanceID string, bridgeChannelID string) bridge.GatewayTokenResult {
	t.Helper()
	return openHTTPBridgeWithSandboxOrigin(t, handler, pluginInstanceID, surfaceID, surfaceInstanceID, bridgeChannelID, "")
}

func openHTTPBridgeWithSandboxOrigin(t *testing.T, handler http.Handler, pluginInstanceID string, surfaceID string, surfaceInstanceID string, bridgeChannelID string, sandboxOrigin string) bridge.GatewayTokenResult {
	t.Helper()
	openBody := map[string]any{
		"plugin_instance_id":      pluginInstanceID,
		"surface_id":              surfaceID,
		"surface_instance_id":     surfaceInstanceID,
		"owner_session_hash":      "session_hash",
		"owner_user_hash":         "user_hash",
		"session_channel_id_hash": "channel_hash",
	}
	if sandboxOrigin != "" {
		openBody["sandbox_origin"] = sandboxOrigin
	}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", openBody)
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/"+surfaceInstanceID+"/bootstrap", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	return postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/"+surfaceInstanceID+"/bridge-token", map[string]any{
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

func grantHTTPDeclaredPermissions(t *testing.T, h *host.Host, record registry.PluginRecord) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, binding := range record.Manifest.CapabilityBindings {
		for _, permissionID := range binding.RequiredPermissions {
			if permissionID == "" {
				continue
			}
			if _, ok := seen[permissionID]; ok {
				continue
			}
			seen[permissionID] = struct{}{}
			if _, err := h.GrantPermission(context.Background(), host.GrantPermissionRequest{
				PluginInstanceID: record.PluginInstanceID,
				PermissionID:     permissionID,
				GrantedBy:        "test",
			}); err != nil {
				t.Fatalf("GrantPermission(%s) error = %v", permissionID, err)
			}
		}
	}
}

func (a *httpRecordingCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.last = req
	return a.result, nil
}

func (a *httpRecordingCoreActionAdapter) InvokeCoreAction(_ context.Context, req capability.Invocation) (capability.Result, error) {
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

func (s *httpRecordingRuntimeSupervisor) Start(_ context.Context, target runtimeclient.Target) error {
	s.startedTarget = target
	if s.health == (runtimeclient.Health{}) {
		s.health = runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", Ready: true}
	}
	return nil
}

func (s *httpRecordingRuntimeSupervisor) Stop(context.Context) error {
	s.stopCalls++
	s.health.Ready = false
	return nil
}

func (s *httpRecordingRuntimeSupervisor) Health(context.Context) (runtimeclient.Health, error) {
	return s.health, nil
}

func (s *httpRecordingRuntimeSupervisor) Heartbeat(context.Context) (runtimeclient.HeartbeatResult, error) {
	if s.err != nil {
		return runtimeclient.HeartbeatResult{}, s.err
	}
	return runtimeclient.HeartbeatResult{
		RuntimeGenerationID:  s.health.RuntimeGenerationID,
		RuntimeUnixNano:      time.Now().UnixNano(),
		MaxStalenessMillis:   5000,
		HostSentUnixNanoEcho: time.Now().UnixNano(),
	}, nil
}

func (s *httpRecordingRuntimeSupervisor) InvokeWorker(context.Context, runtimeclient.Lease, string, []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return nil, runtimeclient.ErrRuntimeIPCUnavailable
}

func (s *httpRecordingRuntimeSupervisor) Revoke(_ context.Context, pluginInstanceID string, revokeEpoch uint64) (runtimeclient.RevokeResult, error) {
	if s.err != nil {
		return runtimeclient.RevokeResult{}, s.err
	}
	return runtimeclient.RevokeResult{
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	}, runtimeclient.ErrRuntimeIPCUnavailable
}
