package httpadapter

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
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

func mustPluginStateVersion(t testing.TB, h *host.Host, pluginInstanceID string) uint64 {
	t.Helper()
	records, err := h.ListPlugins(context.Background())
	if err != nil {
		t.Fatalf("ListPlugins() for state version: %v", err)
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			if record.ManagementRevision == 0 {
				t.Fatalf("plugin %q has zero management revision", pluginInstanceID)
			}
			return record.ManagementRevision
		}
	}
	t.Fatalf("plugin %q not found while resolving state version", pluginInstanceID)
	return 0
}

func TestRouteSetHasManagementAndSandboxRoutes(t *testing.T) {
	routes := RouteSet()
	want := map[string]bool{
		"POST /_redevplugin/api/plugins/install-release-ref":                              false,
		"POST /_redevplugin/api/plugins/enable":                                           false,
		"POST /_redevplugin/api/plugins/surfaces/open":                                    false,
		"POST /_redevplugin/api/plugins/surfaces/revoke-scope":                            false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare":           false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token":      false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read":       false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read":      false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/operations/cancel": false,
		"POST /_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose":           false,
		"POST /_redevplugin/api/plugins/rpc":                                              false,
		"POST /_redevplugin/api/plugins/data/export":                                      false,
		"GET /_redevplugin/api/plugins/retained-data":                                     false,
		"POST /_redevplugin/api/plugins/retained-data/delete":                             false,
		"POST /_redevplugin/api/plugins/retained-data/cleanup-expired":                    false,
		"GET /_redevplugin/api/plugins/intents":                                           false,
		"POST /_redevplugin/api/plugins/intents/invoke":                                   false,
		"GET /_redevplugin/api/plugins/platform/compatibility":                            false,
		"POST /_redevplugin/api/plugins/update-release-ref":                               false,
		"GET /_redevplugin/api/plugins/permissions":                                       false,
		"POST /_redevplugin/api/plugins/permissions/grant":                                false,
		"POST /_redevplugin/api/plugins/permissions/revoke":                               false,
		"GET /_redevplugin/api/plugins/audit":                                             false,
		"GET /_redevplugin/api/plugins/diagnostics":                                       false,
		"GET /_redevplugin/api/plugins/runtime/health":                                    false,
		"POST /_redevplugin/api/plugins/runtime/refresh-enabled":                          false,
		"POST /_redevplugin/api/plugins/runtime/start":                                    false,
		"POST /_redevplugin/api/plugins/runtime/stop":                                     false,
		"GET /_redevplugin/api/plugins/{plugin_instance_id}/settings":                     false,
		"PATCH /_redevplugin/api/plugins/{plugin_instance_id}/settings":                   false,
		"GET /_redevplugin/api/plugins/{plugin_instance_id}/settings/schema":              false,
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

func TestRouteSetExcludesLocalImportRoutesByDefault(t *testing.T) {
	for _, route := range RouteSet() {
		if strings.Contains(route.Path, "/local-import/") {
			t.Fatalf("default RouteSet() must not expose local-import route: %#v", route)
		}
	}
}

func TestRouteSetWithLocalImportRoutesRequiresExplicitOption(t *testing.T) {
	routes := RouteSetWithOptions(RouteSetOptions{EnableLocalImportRoutes: true})
	want := map[string]bool{
		"POST /_redevplugin/api/plugins/local-import/install": false,
		"POST /_redevplugin/api/plugins/local-import/update":  false,
	}
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("RouteSetWithOptions(local import) missing %s", key)
		}
	}
}

func TestRouteSetRoutesAreHandled(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
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

func TestHandlerLocalImportRoutesAreDisabledByDefault(t *testing.T) {
	for _, path := range []string{
		"/_redevplugin/api/plugins/local-import/install",
		"/_redevplugin/api/plugins/local-import/update",
	} {
		t.Run(path, func(t *testing.T) {
			handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandlerLocalImportRoutesRequireExplicitEnable(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "install",
			path: "/_redevplugin/api/plugins/local-import/install",
			body: `{"package_base64":"not-base64"}`,
		},
		{
			name: "update",
			path: "/_redevplugin/api/plugins/local-import/update",
			body: `{"plugin_instance_id":"plugini_test","package_base64":"not-base64"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusNotFound {
				t.Fatalf("local-import route fell through to 404 when explicitly enabled: body = %s", rec.Body.String())
			}
		})
	}
}

func TestHandlerCompatibilityManifest(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
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

	if got.SchemaVersion != "redevplugin.compatibility.v2" {
		t.Fatalf("schema_version = %q", got.SchemaVersion)
	}
	if got.Matrix.PluginHostProtocolVersion != "plugin-host-v2" || got.Matrix.PluginPlatformOpenAPI != "plugin-platform-v2" {
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
	if openapi.Path != "spec/openapi/plugin-platform-v2.yaml" || openapi.SHA256 == "" {
		t.Fatalf("plugin-platform-openapi contract mismatch: %#v", openapi)
	}
}

func TestHandlerJSONLimitErrorsExposeReason(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
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
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
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

func TestHandlerWebSecurityRejectsHostSpecificOriginDecision(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginDecision("plugin_sandbox")}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard, EnableLocalImportRoutes: true}
	for _, path := range []string{
		"/_redevplugin/api/plugins/install-release-ref",
		"/_redevplugin/api/plugins/local-import/install",
		"/_redevplugin/api/plugins/enable",
		"/_redevplugin/api/plugins/surfaces/surface_test/prepare",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
			req.Header.Set("Origin", "https://plugin.sandbox.example")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("sandbox route status = %d, want 403 body = %s", rec.Code, rec.Body.String())
			}
		})
	}
	if guard.csrfCount != 0 {
		t.Fatalf("CSRF count = %d, want 0 for rejected sandbox routes", guard.csrfCount)
	}
}

func TestHandlerWebSecurityFailsClosedWithoutGuard(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t)}
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerWebSecurityRejectsIncompleteTrustedScope(t *testing.T) {
	guard := &httpTestWebSecurityGuard{scope: websecurity.RequestScope{OwnerSessionHash: "session_hash"}}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerWebSecurityRequiresCSRFForUnsafeProxyRoutes(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginTrustedParent, csrfErr: websecurity.ErrCSRFRequired}
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ErrorCode != string(security.ErrCSRFRequired) {
		t.Fatalf("csrf error_code = %q, want %q", envelope.ErrorCode, security.ErrCSRFRequired)
	}
	if guard.evaluateCount != 1 || guard.csrfCount != 1 || guard.lastSessionHash != "session_hash" {
		t.Fatalf("guard calls = evaluate:%d csrf:%d session:%q", guard.evaluateCount, guard.csrfCount, guard.lastSessionHash)
	}
}

func TestHandlerWebSecurityAllowsSafeProxyRouteWithoutCSRF(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: websecurity.OriginTrustedParent, csrfErr: websecurity.ErrCSRFRequired}
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

func TestHandlerWebSecurityCSRFClassificationCoversRouteSet(t *testing.T) {
	for _, route := range RouteSet() {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			guard := &httpTestWebSecurityGuard{decision: websecurity.OriginTrustedParent}
			handler := Handler{Host: newHTTPTestHost(t), WebSecurity: guard}
			body := ""
			if route.Method == http.MethodPost || route.Method == http.MethodPatch || route.Method == http.MethodPut {
				body = `{}`
			}
			req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path), bytes.NewBufferString(body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if guard.evaluateCount != 1 {
				t.Fatalf("Evaluate count = %d, want 1", guard.evaluateCount)
			}
			wantCSRF := route.Method != http.MethodGet &&
				route.Method != http.MethodHead &&
				route.Method != http.MethodOptions
			if wantCSRF && guard.csrfCount != 1 {
				t.Fatalf("CSRF count = %d, want 1 for %s", guard.csrfCount, route.Path)
			}
			if !wantCSRF && guard.csrfCount != 0 {
				t.Fatalf("CSRF count = %d, want 0 for %s", guard.csrfCount, route.Path)
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

func TestHandlerInstallReleaseRefRequiresHostTrustVerifier(t *testing.T) {
	packageBytes := buildHTTPSignedReleasePackageBytes(t, buildHTTPFixturePackage(t), "official")
	pkg := readHTTPTestPackage(t, packageBytes)
	ref := httpReleaseRefForPackage(t, "official", pkg)
	resolver := &httpRecordingReleaseArtifactResolver{
		artifact: httpResolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, err := host.New(host.Adapters{
		SessionResolver:         httpTestSessionResolver{},
		Policy:                  httpTestPolicy{},
		ReleaseSourcePolicy:     &httpRecordingReleaseSourcePolicyResolver{snapshot: httpSourcePolicyForRelease(ref)},
		ReleaseArtifactResolver: resolver,
		ReleaseMetadataVerifier: httpTestReleaseMetadataVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	raw, err := json.Marshal(map[string]any{
		"release_ref":          ref,
		"plugin_state_version": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/install-release-ref", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("install status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.ErrorCode != string(security.ErrTrustVerificationRequired) {
		t.Fatalf("install envelope = %#v", envelope)
	}
}

func TestHandlerManagementLifecycleFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	packageBytes := buildHTTPFixturePackage(t)

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(packageBytes),
		"plugin_state_version": 0,
	})
	if installed.PluginInstanceID == "" || installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install response mismatch: %#v", installed)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
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
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"reason":               "test",
	})
	if disabled.EnableState != registry.EnableDisabled || disabled.DisabledReason != "test" {
		t.Fatalf("disable response mismatch: %#v", disabled)
	}

	uninstalled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": disabled.ManagementRevision,
		"delete_data":          true,
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

func TestHandlerManagementStateVersionContractFailsClosed(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"plugin_state_version": 0,
	})

	for _, body := range []map[string]any{
		{"plugin_instance_id": installed.PluginInstanceID},
		{"plugin_instance_id": installed.PluginInstanceID, "plugin_state_version": 0},
	} {
		envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/enable", body, http.StatusBadRequest)
		if envelope.ErrorCode != string(security.ErrInvalidRequest) {
			t.Fatalf("missing/zero state version error_code = %q, want %q", envelope.ErrorCode, security.ErrInvalidRequest)
		}
	}

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision + 1,
	}, http.StatusConflict)
	if envelope.ErrorCode != string(security.ErrStateVersionMismatch) {
		t.Fatalf("stale enable error_code = %q, want %q", envelope.ErrorCode, security.ErrStateVersionMismatch)
	}
	catalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog")
	if len(catalog.Plugins) != 1 || catalog.Plugins[0].EnableState != registry.EnableDisabled || catalog.Plugins[0].ManagementRevision != installed.ManagementRevision {
		t.Fatalf("failed enable mutated catalog: %#v", catalog.Plugins)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
	})
	staleOpen := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   enabled.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_state_version",
	}, http.StatusConflict)
	if staleOpen.ErrorCode != string(security.ErrStateVersionMismatch) {
		t.Fatalf("stale open error_code = %q, want %q", staleOpen.ErrorCode, security.ErrStateVersionMismatch)
	}
	opened := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   enabled.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_state_version",
	})
	if opened.SurfaceInstanceID != "surface_state_version" {
		t.Fatalf("open after stale request = %#v", opened)
	}
}

func TestHandlerInstallReleaseRefUsesResolverWithoutPackageBase64(t *testing.T) {
	packageBytes := buildHTTPSignedReleasePackageBytes(t, buildHTTPVersionedFixturePackage(t, "1.0.0", "HTTP"), "official")
	pkg := readHTTPTestPackage(t, packageBytes)
	ref := httpReleaseRefForPackage(t, "official", pkg)
	resolver := &httpRecordingReleaseArtifactResolver{
		artifact: httpResolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		releaseSourcePolicy:     &httpRecordingReleaseSourcePolicyResolver{snapshot: httpSourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install-release-ref", map[string]any{
		"release_ref":          ref,
		"plugin_state_version": 0,
	})

	if installed.PackageHash != pkg.PackageHash || installed.TrustState != registry.TrustVerified {
		t.Fatalf("install release ref response mismatch: %#v", installed)
	}
	wantMetadataSignatureRef := "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/release.json.sig"
	wantPackageSignatureBundleRef := "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.sigbundle"
	if installed.Metadata["source_id"] != "official" ||
		installed.Metadata["source.type"] != string(host.PackageSourceRegistry) ||
		installed.Metadata["source.class"] != string(host.PackageSourceClassOfficial) ||
		installed.Metadata["source.distribution"] != string(host.PackageDistributionRegistryRef) ||
		installed.Metadata["source.install_policy"] != string(host.PackageInstallAllow) ||
		installed.Metadata["source.unsigned_policy"] != string(host.PackageUnsignedBlock) ||
		installed.Metadata["source.downgrade_policy"] != string(host.PackageDowngradeBlock) ||
		installed.Metadata["source.policy_epoch"] != "1" ||
		installed.Metadata["source.key_rotation_epoch"] != "1" ||
		installed.Metadata["source.revocation_epoch"] != "1" ||
		installed.Metadata["source.assessed_at"] != "2026-07-07T00:00:00Z" ||
		installed.Metadata["release.metadata_signature_algorithm"] != "ed25519" ||
		installed.Metadata["release.metadata_signature_key_id"] != "official" ||
		installed.Metadata["release.metadata_signature_ref"] != wantMetadataSignatureRef ||
		installed.Metadata["release.package_signature_algorithm"] != "ed25519" ||
		installed.Metadata["release.package_signature_key_id"] != "official" ||
		installed.Metadata["release.package_signature_bundle_ref"] != wantPackageSignatureBundleRef {
		t.Fatalf("metadata = %#v", installed.Metadata)
	}
	if resolver.last.Action != host.PackageTrustActionInstall || resolver.last.ReleaseRef.PluginID != pkg.Manifest.PluginID() {
		t.Fatalf("resolver request mismatch: %#v", resolver.last)
	}
	if resolver.last.SourcePolicySnapshot.SourceClass != host.PackageSourceClassOfficial || !resolver.last.SourcePolicySnapshot.RequireSignature {
		t.Fatalf("resolver source policy mismatch: %#v", resolver.last.SourcePolicySnapshot)
	}
}

func TestHandlerInstallReleaseRefPolicyDeniedUsesReleaseRefErrorCode(t *testing.T) {
	packageBytes := buildHTTPSignedReleasePackageBytes(t, buildHTTPVersionedFixturePackage(t, "1.0.0", "HTTP"), "official")
	pkg := readHTTPTestPackage(t, packageBytes)
	ref := httpReleaseRefForPackage(t, "official", pkg)
	sourcePolicy := httpSourcePolicyForRelease(ref)
	sourcePolicy.InstallPolicy = host.PackageInstallBlock
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		releaseSourcePolicy:     &httpRecordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: &httpRecordingReleaseArtifactResolver{artifact: httpResolvedArtifactForPackage(t, ref, pkg, packageBytes)},
	})
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/install-release-ref", map[string]any{
		"release_ref":          ref,
		"plugin_state_version": 0,
	}, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrReleaseRefPolicyDenied) {
		t.Fatalf("error_code = %q, want %q body = %#v", envelope.ErrorCode, security.ErrReleaseRefPolicyDenied, envelope)
	}
}

func TestHandlerUpdateAndDowngradeFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	v1 := buildHTTPVersionedFixturePackage(t, "1.0.0", "HTTP")
	v2 := buildHTTPVersionedFixturePackage(t, "2.0.0", "HTTP v2")

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(v1),
		"plugin_state_version": 0,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
	})
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable response mismatch: %#v", enabled)
	}

	updated := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/update", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"package_base64":       base64.StdEncoding.EncodeToString(v2),
	})
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("update response mismatch: %#v", updated)
	}

	downgraded := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/downgrade", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": updated.ManagementRevision,
		"version":              "1.0.0",
	})
	if downgraded.Version != "1.0.0" || downgraded.ActiveFingerprint != installed.ActiveFingerprint || len(downgraded.VersionHistory) != 1 || downgraded.VersionHistory[0].Version != "2.0.0" {
		t.Fatalf("downgrade response mismatch: %#v", downgraded)
	}
}

func TestHandlerManagementRejectsInvalidInstallAndTrustStateInput(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/local-import/install", bytes.NewBufferString(`{"package_base64":"not-base64","plugin_state_version":0}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid install status = %d body = %s", rec.Code, rec.Body.String())
	}

	raw, err := json.Marshal(map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"plugin_state_version": 0,
		"trust_state":          "verified",
	})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/local-import/install", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trust_state input status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerInstallMapsPackageValidationErrorDetails(t *testing.T) {
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
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
				"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPRawPackage(t, tt.entries)),
				"plugin_state_version": 0,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/local-import/install", bytes.NewReader(raw))
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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPBlockedNetworkFixturePackage(t)),
		"plugin_state_version": 0,
	})
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID, "plugin_state_version": installed.ManagementRevision})
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
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http",
		"plugin_state_version": 2,
	})
	if openResp.AssetTicket == "" || openResp.BridgeNonce == "" {
		t.Fatalf("open response missing ticket/nonce: %#v", openResp)
	}
	postJSON[host.PrepareSurfaceResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})

	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http"))
	if bridgeResp.GatewayToken == "" || bridgeResp.AssetSession == "" {
		t.Fatalf("bridge token response is empty: %#v", bridgeResp)
	}
	renewalBody := bridgeTokenRequestBody(openResp, "bridge_http")
	renewalBody["previous_plugin_gateway_token"] = bridgeResp.GatewayToken
	renewed := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http/bridge-token", renewalBody)
	if renewed.GatewayToken == bridgeResp.GatewayToken || renewed.AssetSession == bridgeResp.AssetSession {
		t.Fatalf("bridge token renewal did not rotate credentials: first=%#v renewed=%#v", bridgeResp, renewed)
	}
}

func TestHandlerRevokesAllSurfacesForCurrentSessionChannel(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	first := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_scope_first",
		"plugin_state_version": 2,
	})
	postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_scope_second",
		"plugin_state_version": 2,
	})
	result := postJSON[struct {
		RevokedSurfaceCount int `json:"revoked_surface_count"`
	}](t, handler, "/_redevplugin/api/plugins/surfaces/revoke-scope", map[string]any{})
	if result.RevokedSurfaceCount != 2 {
		t.Fatalf("revoked_surface_count = %d, want 2", result.RevokedSurfaceCount)
	}
	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_scope_first/prepare", map[string]any{
		"asset_ticket": first.AssetTicket,
	}, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("prepare after scope revoke error_code = %q", envelope.ErrorCode)
	}
}

func TestOpenSurfaceErrorsUseStableRecoverySemantics(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   security.ErrorCode
	}{
		{name: "session limit", err: bridge.ErrSurfaceSessionLimitReached, wantStatus: http.StatusServiceUnavailable, wantCode: security.ErrRuntimeUnavailable},
		{name: "duplicate session", err: bridge.ErrSurfaceSessionAlreadyExists, wantStatus: http.StatusConflict, wantCode: security.ErrContractMismatch},
		{name: "policy denial", err: errors.New("denied"), wantStatus: http.StatusForbidden, wantCode: security.ErrPermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpStatusForOpenSurfaceError(tt.err); got != tt.wantStatus {
				t.Fatalf("httpStatusForOpenSurfaceError() = %d, want %d", got, tt.wantStatus)
			}
			if got := errorCodeForOpenSurfaceError(tt.err); got != tt.wantCode {
				t.Fatalf("errorCodeForOpenSurfaceError() = %s, want %s", got, tt.wantCode)
			}
		})
	}
}

func TestHandlerBridgeTokenRejectsInvalidHandshakeType(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http_bad_type",
		"plugin_state_version": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_type/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	wrongType := "redevplugin.bridge.call"
	for _, tc := range []struct {
		name      string
		typeValue *string
	}{
		{name: "wrong", typeValue: &wrongType},
		{name: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bridgeTokenRequestBody(openResp, "bridge_http")
			handshake := body["handshake"].(map[string]any)
			if tc.typeValue == nil {
				delete(handshake, "type")
			} else {
				handshake["type"] = *tc.typeValue
			}
			envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_type/bridge-token", body, http.StatusBadRequest)
			if envelope.OK || envelope.ErrorCode != string(security.ErrInvalidRequest) {
				t.Fatalf("bridge token envelope = %#v", envelope)
			}
		})
	}
}

func TestHandlerBridgeTokenRejectsTranscriptMismatch(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http_bad_transcript",
		"plugin_state_version": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_transcript/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	body := bridgeTokenRequestBody(openResp, "bridge_http_transcript")
	body["handshake_transcript_sha256"] = bridge.HandshakeTranscriptSHA256(bridgeHandshakeFromBootstrap(openResp), "bridge_http_other")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_transcript/bridge-token", body, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("transcript mismatch error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestHandlerPrepareAndPrivateAssetFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http_asset",
		"plugin_state_version": 2,
	})
	preparePath := "/_redevplugin/api/plugins/surfaces/surface_http_asset/prepare"
	prepareResp := postJSON[host.PrepareSurfaceResult](t, handler, preparePath, map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	if prepareResp.AssetSession == "" || prepareResp.Document.EntryPath != "ui/index.html" {
		t.Fatalf("prepare response mismatch: %#v", prepareResp)
	}
	if len(prepareResp.Document.Assets) != 1 {
		t.Fatalf("prepare response assets = %#v, want one lazy asset", prepareResp.Document.Assets)
	}
	preparedAsset := prepareResp.Document.Assets[0]

	replay := postJSONError(t, handler, preparePath, map[string]any{"asset_ticket": openResp.AssetTicket}, http.StatusForbidden)
	if replay.ErrorCode != string(security.ErrTokenReplay) {
		t.Fatalf("asset ticket replay error_code = %s body = %#v", replay.ErrorCode, replay)
	}

	asset := postJSON[struct {
		Path          string `json:"path"`
		SHA256        string `json:"sha256"`
		ContentType   string `json:"content_type"`
		ContentBase64 string `json:"content_base64"`
	}](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_asset/assets/read", map[string]any{
		"asset_session":    prepareResp.AssetSession,
		"asset_session_id": prepareResp.AssetSessionID,
		"binding_id":       preparedAsset.BindingID,
	})
	content, err := base64.StdEncoding.DecodeString(asset.ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	if asset.Path != preparedAsset.Path || asset.SHA256 != preparedAsset.SHA256 || string(content) != "http-status" {
		t.Fatalf("asset response mismatch: %#v content=%q", asset, string(content))
	}

	rawPathBypass := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_asset/assets/read", map[string]any{
		"asset_session":    prepareResp.AssetSession,
		"asset_session_id": prepareResp.AssetSessionID,
		"asset_path":       "ui/app.js",
	}, http.StatusBadRequest)
	if rawPathBypass.ErrorCode != string(security.ErrInvalidRequest) {
		t.Fatalf("raw asset path bypass error_code = %s body = %#v", rawPathBypass.ErrorCode, rawPathBypass)
	}

	wrongSurface := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_other/assets/read", map[string]any{
		"asset_session":    prepareResp.AssetSession,
		"asset_session_id": prepareResp.AssetSessionID,
		"binding_id":       preparedAsset.BindingID,
	}, http.StatusForbidden)
	if wrongSurface.ErrorCode != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("cross-surface asset error_code = %s body = %#v", wrongSurface.ErrorCode, wrongSurface)
	}
}

func TestHandlerRPCFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.rpc.view",
		"surface_instance_id":  "surface_http_rpc",
		"plugin_state_version": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_rpc/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_rpc/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_rpc"))

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_rpc",
		"bridge_channel_id":    "bridge_http_rpc",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
		"params":               map[string]any{"message": "hello"},
	})
	if result.Data == nil {
		t.Fatalf("rpc result missing data: %#v", result)
	}
	if adapter.last.Execution.PluginInstanceID != installed.PluginInstanceID || adapter.last.Execution.Method != "echo.ping" {
		t.Fatalf("capability invocation mismatch: %#v", adapter.last)
	}
}

func TestHandlerRPCSchemaErrorsUseStableCodes(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_schema", "bridge_http_schema")
	baseBody := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_schema",
		"bridge_channel_id":    "bridge_http_schema",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
	}

	invalidRequest := cloneMap(baseBody)
	invalidRequest["params"] = map[string]any{"unknown": true}
	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", invalidRequest, http.StatusBadRequest)
	if envelope.ErrorCode != string(security.ErrInvalidRequest) {
		t.Fatalf("request schema error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}

	adapter.result = capability.Result{Data: map[string]any{"unknown": true}}
	invalidResponse := cloneMap(baseBody)
	invalidResponse["params"] = map[string]any{"message": "hello"}
	envelope = postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", invalidResponse, http.StatusBadGateway)
	if envelope.ErrorCode != string(security.ErrContractMismatch) {
		t.Fatalf("response schema error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestHandlerRPCDoesNotExposeAdapterErrorDetails(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{err: errors.New("dial /private/runtime.sock with bearer super-secret")}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_redaction", "bridge_http_redaction")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_redaction",
		"bridge_channel_id":    "bridge_http_redaction",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
		"params":               map[string]any{"message": "hello"},
	}, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("adapter error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
	if strings.Contains(envelope.Error, "runtime.sock") || strings.Contains(envelope.Error, "super-secret") {
		t.Fatalf("adapter details leaked to plugin: %#v", envelope)
	}
}

func TestHandlerOpenSurfaceOmitsTrustedScopeHashes(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bootstrap := postJSON[map[string]any](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http_public_bootstrap",
		"plugin_state_version": mustPluginStateVersion(t, h, installed.PluginInstanceID),
	})
	for _, field := range []string{"owner_session_hash", "owner_user_hash", "session_channel_id_hash"} {
		if _, present := bootstrap[field]; present {
			t.Fatalf("public surface bootstrap exposed %s: %#v", field, bootstrap)
		}
	}
}

func TestHandlerRPCFlowRedactsCapabilityResponseData(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{
		"containers": []any{
			map[string]any{
				"id":    "container_http_1",
				"image": "redis:7",
				"env": []any{
					"PATH=/usr/bin",
					"REDIS_PASSWORD=plaintext-password",
				},
				"labels": map[string]any{
					"com.example.owner": "platform",
					"secret_token":      "label-secret",
				},
				"mounts": []any{
					map[string]any{"source": "/srv/cache", "target": "/cache"},
					map[string]any{"source": "/run/secrets/redis_password", "target": "/run/secrets/redis_password"},
				},
			},
		},
	}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_redaction", "bridge_http_redaction")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_redaction",
		"bridge_channel_id":    "bridge_http_redaction",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
	})
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, leaked := range []string{"plaintext-password", "label-secret", "/run/secrets/redis_password"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("http rpc response leaked %q: %s", leaked, body)
		}
	}
	for _, kept := range []string{"PATH=/usr/bin", "platform", "/srv/cache"} {
		if !strings.Contains(body, kept) {
			t.Fatalf("http rpc response dropped safe value %q: %s", kept, body)
		}
	}
}

func TestHandlerRPCGatewayTokenErrorsUseStableCodes(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_gateway_errors", "bridge_http_gateway")
	baseBody := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_gateway_errors",
		"bridge_channel_id":    "bridge_http_gateway",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.view",
		"surface_instance_id":  "surface_http_duplicate_channel",
		"plugin_state_version": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_a"))

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_b"), http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrGatewayTokenChannelMismatch) {
		t.Fatalf("duplicate bridge channel error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestRPCErrorCodeMapsGatewayTokenReplay(t *testing.T) {
	if got := errorCodeForRPCError(bridge.ErrTokenReplay); got != security.ErrGatewayTokenReplayed {
		t.Fatalf("gateway token replay error_code = %s, want %s", got, security.ErrGatewayTokenReplayed)
	}
}

func TestRPCErrorMapsValidatedCapabilityBusinessError(t *testing.T) {
	err := &capability.BusinessError{
		CapabilityID: "example.capability.documents", CapabilityVersion: "1.0.0", DetailSchemaSHA256: strings.Repeat("a", 64),
		Code: "DOCUMENT_NOT_FOUND", Message: "Document not found", Details: map[string]any{"document_id": "doc-1"},
	}
	if got := errorCodeForRPCError(err); got != security.ErrCapabilityError {
		t.Fatalf("errorCodeForRPCError() = %s, want %s", got, security.ErrCapabilityError)
	}
	if got := httpStatusForRPCError(err); got != http.StatusUnprocessableEntity {
		t.Fatalf("httpStatusForRPCError() = %d, want %d", got, http.StatusUnprocessableEntity)
	}
	if got := publicPluginErrorMessage(security.ErrCapabilityError); got != "host capability request failed" {
		t.Fatalf("publicPluginErrorMessage() = %q", got)
	}
	details := errorDetailsForRPCError(err)
	if details["business_error_code"] != "DOCUMENT_NOT_FOUND" {
		t.Fatalf("business error details = %#v", details)
	}
	if details["capability_id"] != "example.capability.documents" || details["capability_version"] != "1.0.0" || details["detail_schema_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("business error contract identity = %#v", details)
	}
	payload, ok := details["business_error_details"].(map[string]any)
	if !ok || payload["document_id"] != "doc-1" {
		t.Fatalf("business error payload = %#v", details)
	}
}

func TestBridgeTokenRenewalErrorsUseGatewayTokenCodes(t *testing.T) {
	tests := []struct {
		err  error
		want security.ErrorCode
	}{
		{err: bridge.ErrTokenInvalid, want: security.ErrGatewayTokenInvalid},
		{err: bridge.ErrTokenExpired, want: security.ErrGatewayTokenInvalid},
		{err: bridge.ErrTokenReplay, want: security.ErrGatewayTokenReplayed},
		{err: bridge.ErrTokenAudience, want: security.ErrGatewayTokenChannelMismatch},
		{err: bridge.ErrTokenAlreadyBound, want: security.ErrGatewayTokenChannelMismatch},
	}
	for _, tt := range tests {
		if got := errorCodeForBridgeTokenError(tt.err, true); got != tt.want {
			t.Fatalf("errorCodeForBridgeTokenError(%v) = %s, want %s", tt.err, got, tt.want)
		}
	}
}

func TestHandlerPermissionGrantRevokeFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_permissions", "bridge_http_permissions")
	callBody := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_permissions",
		"bridge_channel_id":    "bridge_http_permissions",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
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

	bridgeResp = openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_permissions", "bridge_http_permissions")
	callBody["plugin_gateway_token"] = bridgeResp.GatewayToken
	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", callBody)
	if result.Data == nil || adapter.last.Execution.Method != "echo.ping" {
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
	bridgeResp = openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_permissions", "bridge_http_permissions")
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
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPDangerousRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_id":           "http.danger.view",
		"surface_instance_id":  "surface_http_danger",
		"plugin_state_version": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_danger/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	bridgeResp := postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_danger/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_danger"))
	body := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_danger",
		"bridge_channel_id":    "bridge_http_danger",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "danger.run",
		"params":               map[string]any{"target": "db"},
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
	if adapter.last.Execution.Method != "" {
		t.Fatalf("capability adapter should not be called before confirmation: %#v", adapter.last)
	}

	confirmation := postJSON[host.ConfirmMethodResult](t, handler, "/_redevplugin/api/plugins/confirm", body)
	if confirmation.ConfirmationID == "" || confirmation.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", confirmation)
	}
	body["confirmation_id"] = confirmation.ConfirmationID
	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", body)
	if result.Data == nil || adapter.last.Execution.Method != "danger.run" {
		t.Fatalf("confirmed rpc mismatch: result=%#v invocation=%#v", result, adapter.last)
	}
}

func TestHandlerRPCConfirmationRejectionFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"done": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPDangerousRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.danger.view", "surface_http_danger", "bridge_http_danger")
	body := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_danger",
		"bridge_channel_id":    "bridge_http_danger",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "danger.run",
		"params":               map[string]any{"target": "db"},
	}
	confirmation := postJSON[host.ConfirmMethodResult](t, handler, "/_redevplugin/api/plugins/confirm", body)

	rejected := postJSON[host.RejectMethodConfirmationResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_danger/confirmations/reject", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"bridge_channel_id":    "bridge_http_danger",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"confirmation_id":      confirmation.ConfirmationID,
	})
	if !rejected.Rejected {
		t.Fatalf("confirmation rejection response mismatch: %#v", rejected)
	}
	if adapter.last.Execution.Method != "" {
		t.Fatalf("confirmation rejection dispatched adapter: %#v", adapter.last)
	}
	body["confirmation_id"] = confirmation.ConfirmationID
	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", body, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrConfirmationInvalid) {
		t.Fatalf("rejected confirmation replay error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
}

func TestHandlerIntentListAndInvokeFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

	listed := getJSON[struct {
		Intents []host.IntentRecord `json:"intents"`
	}](t, handler, "/_redevplugin/api/plugins/intents?intent_id=example.echo&plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Intents) != 1 || listed.Intents[0].IntentID != "example.echo" || listed.Intents[0].Method != "echo.ping" || listed.Intents[0].PayloadSchema["type"] != "object" {
		t.Fatalf("intent list mismatch: %#v", listed)
	}

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/intents/invoke", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"intent_id":          "example.echo",
		"params":             map[string]any{"message": "from http intent"},
	})
	if result.Data == nil || adapter.last.Execution.PluginInstanceID != installed.PluginInstanceID || adapter.last.Execution.Method != "echo.ping" || adapter.last.Arguments["message"] != "from http intent" {
		t.Fatalf("intent invoke mismatch: result=%#v invocation=%#v", result, adapter.last)
	}
}

func TestHandlerIntentInvokeRequiresPermission(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
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
	if adapter.last.Execution.Method != "" {
		t.Fatalf("capability adapter should not be called without grant: %#v", adapter.last)
	}
}

func TestHandlerIntentInvokeDangerousFailsClosed(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"done": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPIntentFixturePackage(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
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
	if adapter.last.Execution.Method != "" {
		t.Fatalf("capability adapter should not be called for dangerous intent: %#v", adapter.last)
	}
}

func TestHandlerOperationManagementFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_operation", "bridge_http_operation")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})
	if result.OperationID == "" || adapter.last.Execution.Operation == nil || result.OperationID != adapter.last.Execution.Operation.ID() {
		t.Fatalf("rpc operation result mismatch: %#v", result)
	}

	listed := getJSON[struct {
		Operations []operation.Record `json:"operations"`
	}](t, handler, "/_redevplugin/api/plugins/operations?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Operations) != 1 || listed.Operations[0].OperationID != result.OperationID {
		t.Fatalf("operation list mismatch: %#v", listed)
	}

	detail := getJSON[operation.Record](t, handler, "/_redevplugin/api/plugins/operations/"+result.OperationID)
	if detail.Method != "documents.archive" || detail.Status != operation.StatusRunning {
		t.Fatalf("operation detail mismatch: %#v", detail)
	}

	canceled := postJSON[operation.Record](t, handler, "/_redevplugin/api/plugins/operations/"+result.OperationID+"/cancel", map[string]any{
		"reason": "user",
	})
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel response mismatch: %#v", canceled)
	}
	if adapter.cancelCalls != 1 ||
		adapter.lastCancellation.OperationID != result.OperationID ||
		adapter.lastCancellation.Execution.Method != "documents.archive" ||
		adapter.lastCancellation.Execution.SurfaceInstanceID != "surface_http_operation" ||
		adapter.lastCancellation.Execution.BridgeChannelID != "bridge_http_operation" ||
		adapter.lastCancellation.Reason != "user" {
		t.Fatalf("operation canceler request mismatch: calls=%d req=%#v", adapter.cancelCalls, adapter.lastCancellation)
	}
}

func TestHandlerOperationCancelDispatchFailure(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}, cancellationError: errors.New("runtime is down")}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_operation", "bridge_http_operation")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})
	if result.OperationID == "" {
		t.Fatalf("rpc operation result mismatch: %#v", result)
	}

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/operations/"+result.OperationID+"/cancel", map[string]any{
		"reason": "user",
	}, http.StatusServiceUnavailable)
	if envelope.ErrorCode != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("cancel dispatch error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
	if adapter.cancelCalls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", adapter.cancelCalls)
	}
	stored, err := h.GetOperation(context.Background(), result.OperationID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if stored.Status != operation.StatusCancelRequested || stored.Reason != "user" {
		t.Fatalf("stored operation after failed dispatch mismatch: %#v", stored)
	}
}

func TestHandlerSurfaceOperationCancelRequiresMatchingBridgeScope(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_operation", "bridge_http_operation")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})
	if result.OperationID == "" {
		t.Fatalf("rpc operation result mismatch: %#v", result)
	}

	cancelPath := "/_redevplugin/api/plugins/surfaces/surface_http_operation/operations/cancel"
	envelope := postJSONError(t, handler, cancelPath, map[string]any{
		"operation_id":      result.OperationID,
		"bridge_channel_id": "bridge_other",
		"reason":            "user",
	}, http.StatusForbidden)
	if envelope.ErrorCode != string(security.ErrPermissionDenied) {
		t.Fatalf("scope mismatch error_code = %s body = %#v", envelope.ErrorCode, envelope)
	}
	if adapter.cancelCalls != 0 {
		t.Fatalf("scope mismatch reached operation canceler %d times", adapter.cancelCalls)
	}

	canceled := postJSON[operation.Record](t, handler, cancelPath, map[string]any{
		"operation_id":      result.OperationID,
		"bridge_channel_id": "bridge_http_operation",
		"reason":            "user",
	})
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("surface cancel response mismatch: %#v", canceled)
	}
	if adapter.cancelCalls != 1 || adapter.lastCancellation.OperationID != result.OperationID ||
		adapter.lastCancellation.Execution.SurfaceInstanceID != "surface_http_operation" ||
		adapter.lastCancellation.Execution.BridgeChannelID != "bridge_http_operation" {
		t.Fatalf("surface operation canceler request mismatch: calls=%d req=%#v", adapter.cancelCalls, adapter.lastCancellation)
	}
}

func TestHandlerPrivateSurfaceStreamFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPSubscriptionRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.subscription.view", "surface_http_stream", "bridge_http_stream")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_stream",
		"bridge_channel_id":    "bridge_http_stream",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "logs.tail",
	})
	if result.StreamID == "" || adapter.last.Execution.Stream == nil || result.StreamID != adapter.last.Execution.Stream.ID() || result.StreamTicket == "" {
		t.Fatalf("rpc stream result mismatch: %#v", result)
	}
	if err := adapter.last.Execution.Stream.Append(context.Background(), map[string]any{"line": "line 1"}); err != nil {
		t.Fatal(err)
	}

	readPath := "/_redevplugin/api/plugins/surfaces/surface_http_stream/streams/read"
	read := postJSON[struct {
		Events []struct {
			StreamID string `json:"stream_id"`
			Sequence uint64 `json:"sequence"`
			Data     []byte `json:"data"`
		} `json:"events"`
	}](t, handler, readPath, map[string]any{
		"stream_id":     result.StreamID,
		"stream_ticket": result.StreamTicket,
	})
	if len(read.Events) != 1 || read.Events[0].StreamID != result.StreamID || string(read.Events[0].Data) != `{"line":"line 1"}` {
		t.Fatalf("stream response mismatch: %#v", read)
	}

	replay := postJSONError(t, handler, readPath, map[string]any{
		"stream_id":     result.StreamID,
		"stream_ticket": result.StreamTicket,
	}, http.StatusForbidden)
	if replay.ErrorCode != string(security.ErrStreamTicketInvalid) {
		t.Fatalf("stream replay error_code = %s body = %#v", replay.ErrorCode, replay)
	}
	if strings.Contains(readPath, "ticket") {
		t.Fatalf("stream bearer leaked into URL: %s", readPath)
	}
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

func TestHandlerCoreActionRPCFlow(t *testing.T) {
	coreAdapter := &httpRecordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{coreActions: coreAdapter})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPCoreActionFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.core.view", "surface_http_core", "bridge_http_core")

	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_core",
		"bridge_channel_id":    "bridge_http_core",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "core.open",
		"params":               map[string]any{"target": "settings"},
	})
	if result.Data == nil {
		t.Fatalf("core action rpc result missing data: %#v", result)
	}
	if coreAdapter.last.Execution.TargetMethod != "example.open_settings" || coreAdapter.last.Arguments["target"] != "settings" {
		t.Fatalf("core action invocation mismatch: %#v", coreAdapter.last)
	}
}

func TestHandlerWorkerRuntimeErrorMapsToRuntimeUnavailable(t *testing.T) {
	runtime := &httpRecordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", IPCChannelID: "ipc_http", ConnectionNonce: "connection_nonce_http_1234567890", Ready: true},
		err:    runtimeclient.ErrRuntimeRequestFailed,
	}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeSupervisor: runtime})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.worker.view", "surface_http_worker", "bridge_http_worker")

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_worker",
		"bridge_channel_id":    "bridge_http_worker",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "worker.echo",
		"params":               map[string]any{"message": "hello"},
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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_block_delete", "bridge_http_block_delete")
	postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_block_delete",
		"bridge_channel_id":    "bridge_http_block_delete",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": 2,
		"delete_data":          true,
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
	Handler{Host: h, WebSecurity: allowHTTPTestGuard()}.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerDataExportImportFlow(t *testing.T) {
	storageBroker := storage.NewMemoryBroker()
	h := newHTTPTestHostWithStorage(t, storageBroker)
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if err := storageBroker.SetUsage(context.Background(), installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t)),
		"plugin_state_version": 0,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
	})
	if err := storageBroker.SetUsage(ctx, installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatalf("SetUsage() error = %v", err)
	}
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"delete_data":          false,
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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	packageBase64 := base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t))
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       packageBase64,
		"plugin_state_version": 0,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
	})
	if err := storageBroker.SetUsage(ctx, installed.PluginInstanceID, "db", 1024); err != nil {
		t.Fatal(err)
	}
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"delete_data":          false,
	})
	listed := getJSON[struct {
		RetainedData []retaineddata.Record `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?source_plugin_instance_id="+installed.PluginInstanceID)
	target := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       packageBase64,
		"plugin_instance_id":   "plugini_http_storage_rebind_target",
		"plugin_state_version": 0,
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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPStorageFixturePackage(t)),
		"plugin_state_version": 0,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": enabled.ManagementRevision,
		"delete_data":          false,
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
	handler := Handler{Host: newHTTPTestHost(t), WebSecurity: allowHTTPTestGuard()}
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
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PatchPluginSettings(context.Background(), host.PatchSettingsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Values:           map[string]any{"default_engine": "podman"},
	}); err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

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
	installed, err := host.ImportLocalPackageBytes(context.Background(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

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

func TestHandlerListsAuditEvents(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"plugin_state_version": 0,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
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
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", IPCChannelID: "ipc_http", ConnectionNonce: "connection_nonce_http_1234567890", Ready: true},
	}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeSupervisor: supervisor})
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard()}

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
	handler := Handler{Host: h, WebSecurity: allowHTTPTestGuard(), EnableLocalImportRoutes: true}
	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/local-import/install", map[string]any{
		"package_base64":       base64.StdEncoding.EncodeToString(buildHTTPFixturePackage(t)),
		"plugin_state_version": 0,
	})
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"plugin_state_version": installed.ManagementRevision,
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
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare":
		return "/_redevplugin/api/plugins/surfaces/surface_test/prepare"
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token":
		return "/_redevplugin/api/plugins/surfaces/surface_test/bridge-token"
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read":
		return "/_redevplugin/api/plugins/surfaces/surface_test/assets/read"
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read":
		return "/_redevplugin/api/plugins/surfaces/surface_test/streams/read"
	case "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose":
		return "/_redevplugin/api/plugins/surfaces/surface_test/dispose"
	case "/_redevplugin/api/plugins/operations/{operation_id}":
		return "/_redevplugin/api/plugins/operations/op_test"
	case "/_redevplugin/api/plugins/operations/{operation_id}/cancel":
		return "/_redevplugin/api/plugins/operations/op_test/cancel"
	case "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema":
		return "/_redevplugin/api/plugins/plugini_test/settings/schema"
	case "/_redevplugin/api/plugins/{plugin_instance_id}/settings":
		return "/_redevplugin/api/plugins/plugini_test/settings"
	default:
		return path
	}
}

func readOpenAPIContract(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "spec", "openapi", "plugin-platform-v2.yaml"),
		filepath.Join("spec", "openapi", "plugin-platform-v2.yaml"),
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
	storageBroker           storage.Broker
	secrets                 host.SecretStoreAdapter
	diagnostics             host.DiagnosticsSink
	permissions             permissions.Store
	runtimeSupervisor       runtimeclient.Supervisor
	releaseSourcePolicy     host.ReleaseSourcePolicyResolver
	releaseArtifactResolver host.ReleaseArtifactResolver
	releaseMetadataVerifier host.ReleaseMetadataVerifier
	capabilityID            string
	capabilityAdapter       interface {
		capability.Adapter
		capability.TargetProjector
	}
	coreActions host.CoreActionAdapter
}

func newHTTPTestHostWithOptions(t *testing.T, opts httpTestHostOptions) *host.Host {
	t.Helper()
	capabilities := capability.NewRegistry()
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		verified := httpVerifiedCapabilityContract(t)
		if err := capabilities.Register(capability.Registration{Contract: verified, TargetProjector: opts.capabilityAdapter, Adapter: opts.capabilityAdapter}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := host.New(host.Adapters{
		SessionResolver:         httpTestSessionResolver{},
		Policy:                  httpTestPolicy{},
		PackageTrustVerifier:    httpTestPackageTrustVerifier{},
		ReleaseSourcePolicy:     opts.releaseSourcePolicy,
		ReleaseArtifactResolver: opts.releaseArtifactResolver,
		ReleaseMetadataVerifier: firstNonNilReleaseMetadataVerifier(opts.releaseMetadataVerifier, httpTestReleaseMetadataVerifier{}),
		Storage:                 opts.storageBroker,
		Secrets:                 opts.secrets,
		Diagnostics:             opts.diagnostics,
		Permissions:             opts.permissions,
		RuntimeSupervisor:       opts.runtimeSupervisor,
		Capabilities:            capabilities,
		CoreActions:             opts.coreActions,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func httpVerifiedCapabilityContract(t *testing.T) capabilitycontract.VerifiedContract {
	t.Helper()
	contract := httpCapabilityContract()
	bundle, publicKey, err := httpCapabilityBundle(contract)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle: bundle, ExpectedPin: bundle.Pin,
		TrustedKey: capabilitycontract.TrustedKey{
			PublisherID: contract.PublisherID, KeyID: "fixture-key", PublicKey: publicKey, PolicyEpoch: "1", RevocationEpoch: "1",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func httpCapabilityContract() capabilitycontract.Contract {
	empty := map[string]any{"type": "object", "additionalProperties": false}
	request := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"message": map[string]any{"type": "string"}}}
	response := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
		"pong": map[string]any{"type": "boolean"}, "ok": map[string]any{"type": "boolean"},
		"containers": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"id": map[string]any{"type": "string"}, "image": map[string]any{"type": "string"},
			"env":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"labels": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"com.example.owner": map[string]any{"type": "string"}, "secret_token": map[string]any{"type": "string"}}},
			"mounts": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"source": map[string]any{"type": "string"}, "target": map[string]any{"type": "string"}}}},
		}}},
	}}
	method := func(name, effect, execution string, permissions []string, requestSchema, responseSchema map[string]any) capabilitycontract.Method {
		return capabilitycontract.Method{
			Name: name, ClientMethod: httpFixtureIdentifier(name), Effect: effect, Execution: execution,
			RequiredPermissions: permissions, TargetFields: []string{}, TargetSchema: empty,
			RequestTypeName: httpFixtureTypeName(name) + "Request", ResponseTypeName: httpFixtureTypeName(name) + "Response",
			RequestSchema: requestSchema, ResponseSchema: responseSchema,
		}
	}
	methods := []capabilitycontract.Method{
		method("echo.ping", "read", "sync", []string{"read"}, request, response),
		method("danger.run", "execute", "sync", []string{"execute"}, map[string]any{"type": "object", "additionalProperties": false, "required": []string{"target"}, "properties": map[string]any{"target": map[string]any{"type": "string"}}}, map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"done": map[string]any{"type": "boolean"}}}),
		method("documents.archive", "execute", "operation", []string{"execute"}, empty, empty),
		method("logs.tail", "read", "subscription", []string{"read"}, empty, empty),
	}
	methods[1].TargetFields = []string{"target"}
	methods[1].TargetSchema = methods[1].RequestSchema
	methods[1].Confirmation = &capabilitycontract.Confirmation{Mode: "required", RequestHashFields: []string{"target"}}
	methods[2].CancelPolicy = &capabilitycontract.CancelPolicy{Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel_then_block_delete", AckTimeoutMS: 2000}
	methods[3].EventTypeName = "HTTPLogEvent"
	methods[3].EventSchema = map[string]any{"type": "object", "additionalProperties": false, "required": []string{"line"}, "properties": map[string]any{"line": map[string]any{"type": "string"}}}
	methods[3].CancelPolicy = &capabilitycontract.CancelPolicy{Cancelable: true, DisableBehavior: "orphan", UninstallBehavior: "force_cleanup_allowed", AckTimeoutMS: 2000}
	return capabilitycontract.Contract{
		SchemaVersion: capabilitycontract.SchemaVersion, ContractID: "example.capability.echo.v1", ContractVersion: "1.0.0",
		PublisherID: "example.contracts", CapabilityID: "example.capability.echo", CapabilityVersion: "1.0.0",
		ClientName: "HTTPFixtureCapabilityClient", Methods: methods,
	}
}

func httpCapabilityBundle(contract capabilitycontract.Contract) (capabilitycontract.Bundle, ed25519.PublicKey, error) {
	raw, err := json.Marshal(contract)
	if err != nil {
		return capabilitycontract.Bundle{}, nil, err
	}
	seed := sha256.Sum256(raw)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/http-fixture/1.0.0",
		GeneratedAt:     time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC), SourceCommit: strings.Repeat("f", 40),
		MinReDevPluginVersion: "0.3.0", SignatureKeyID: "fixture-key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	return bundle, publicKey, err
}

func httpCapabilityPinJSON() string {
	bundle, _, err := httpCapabilityBundle(httpCapabilityContract())
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal(bundle.Pin)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func httpCloneMap(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	var cloned map[string]any
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func httpFixtureIdentifier(value string) string {
	parts := strings.Split(value, ".")
	return parts[0] + httpFixtureTypeName(strings.Join(parts[1:], "."))
}

func httpFixtureTypeName(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	var builder strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		builder.WriteString(strings.ToUpper(part[:1]))
		builder.WriteString(part[1:])
	}
	return builder.String()
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
	if filepath.Base(filename) == "index.html" && filepath.Base(filepath.Dir(filename)) == "ui" {
		content += `<body><main>Fixture</main><img src="status.png" alt="Status"><script type="text/redevplugin-worker" src="app.js"></script></body>`
		writeHTTPBytes(t, filepath.Join(filepath.Dir(filename), "app.js"), []byte(`globalThis.__redevpluginFixture = true;`))
		writeHTTPBytes(t, filepath.Join(filepath.Dir(filename), "status.png"), []byte("http-status"))
	}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.view", "kind": "view", "label": "HTTP", "entry": "ui/index.html"}
		]
	}`
}

func httpStorageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.storage",
			"display_name": "HTTP Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.storage.view", "kind": "view", "label": "HTTP Storage", "entry": "ui/index.html"}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.rpc",
			"display_name": "HTTP RPC",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.rpc.view", "kind": "view", "label": "HTTP RPC", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + httpCapabilityPinJSON() + `}
		],
		"methods": [
			{
				"method": "echo.ping",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "echo.ping"}
			}
		]
	}`
}

func httpDangerousRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.danger",
			"display_name": "HTTP Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.danger.view", "kind": "view", "label": "HTTP Danger", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + httpCapabilityPinJSON() + `}
		],
		"methods": [
			{
				"method": "danger.run",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "danger.run"}
			}
		]
	}`
}

func httpOperationRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.operation",
			"display_name": "HTTP Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.operation.view", "kind": "view", "label": "HTTP Operation", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + httpCapabilityPinJSON() + `}
		],
		"methods": [
			{
				"method": "documents.archive",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "documents.archive"}
			}
		]
	}`
}

func httpSubscriptionRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.subscription",
			"display_name": "HTTP Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.subscription.view", "kind": "view", "label": "HTTP Subscription", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + httpCapabilityPinJSON() + `}
		],
		"methods": [
			{
				"method": "logs.tail",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "logs.tail"}
			}
		]
	}`
}

func httpCoreActionFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.core",
			"display_name": "HTTP Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.core.view", "kind": "view", "label": "HTTP Core", "entry": "ui/index.html"}
		],
		"methods": [
			{
				"method": "core.open",
				"effect": "read",
				"execution": "sync",
				"request_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"target": {"type": "string"}}
				},
				"response_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"opened": {"type": "boolean"}}
				},
				"route": {"kind": "core_action", "action_id": "example.open_settings"}
			}
		]
	}`
}

func httpWorkerFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.worker",
			"display_name": "HTTP Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.worker.view", "kind": "view", "label": "HTTP Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{"worker_id": "echo_worker", "mode": "job", "artifact": "workers/echo.wasm", "abi": "redevplugin-wasm-worker-v1", "scope": "user", "memory_limit_bytes": 1048576}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"request_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"message": {"type": "string"}}
				},
				"response_schema": {"type": "object", "additionalProperties": false},
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		]
	}`
}

func httpSettingsFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.settings",
			"display_name": "HTTP Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.settings.view", "kind": "view", "label": "HTTP Settings", "entry": "ui/index.html"}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.network",
			"display_name": "HTTP Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "http.network.view", "kind": "view", "label": "HTTP Network", "entry": "ui/index.html"}
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
	if req.LocalImport {
		if req.Package.PackageSignature != nil {
			return host.PackageTrustVerificationResult{TrustState: registry.TrustVerified}, nil
		}
		return host.PackageTrustVerificationResult{TrustState: registry.TrustUnsignedLocal}, nil
	}
	if req.SourcePolicySnapshot != nil {
		return host.PackageTrustVerificationResult{TrustState: registry.TrustVerified}, nil
	}
	return host.PackageTrustVerificationResult{TrustState: registry.TrustUntrusted}, nil
}

type httpRecordingReleaseArtifactResolver struct {
	artifact host.ResolvedPackageArtifact
	err      error
	last     host.ReleaseArtifactResolveRequest
}

type httpRecordingReleaseSourcePolicyResolver struct {
	snapshot host.SourcePolicySnapshot
	err      error
	last     host.ReleaseSourcePolicyRequest
}

type httpTestReleaseMetadataVerifier struct{}

func firstNonNilReleaseMetadataVerifier(primary host.ReleaseMetadataVerifier, fallback host.ReleaseMetadataVerifier) host.ReleaseMetadataVerifier {
	if primary != nil {
		return primary
	}
	return fallback
}

func (r *httpRecordingReleaseSourcePolicyResolver) ResolveReleaseSourcePolicy(_ context.Context, req host.ReleaseSourcePolicyRequest) (host.SourcePolicySnapshot, error) {
	r.last = req
	if r.err != nil {
		return host.SourcePolicySnapshot{}, r.err
	}
	return r.snapshot, nil
}

func (r *httpRecordingReleaseArtifactResolver) ResolveReleaseArtifact(_ context.Context, req host.ReleaseArtifactResolveRequest) (host.ResolvedPackageArtifact, error) {
	r.last = req
	if r.err != nil {
		return host.ResolvedPackageArtifact{}, r.err
	}
	return r.artifact, nil
}

func (httpTestReleaseMetadataVerifier) VerifyReleaseMetadata(_ context.Context, req host.ReleaseMetadataVerificationRequest) (host.ReleaseMetadataVerificationResult, error) {
	if req.Release.ReleaseMetadataSignature == nil {
		return host.ReleaseMetadataVerificationResult{}, errors.New("release metadata signature is required")
	}
	return host.ReleaseMetadataVerificationResult{Metadata: map[string]string{"key_id": req.Release.ReleaseMetadataSignature.KeyID}}, nil
}

func (httpTestReleaseMetadataVerifier) VerifySourceRevocationEvidence(_ context.Context, req host.SourceRevocationEvidenceVerificationRequest) (host.SourceRevocationEvidenceVerificationResult, error) {
	return host.SourceRevocationEvidenceVerificationResult{
		Metadata: map[string]string{"key_id": req.RevocationEvidence.SignatureKeyID},
	}, nil
}

func httpResolvedArtifactForPackage(t *testing.T, ref host.PluginReleaseRef, pkg pluginpkg.Package, packageBytes []byte) host.ResolvedPackageArtifact {
	t.Helper()
	return host.ResolvedPackageArtifact{
		ReleaseMetadataBytes:     httpReleaseMetadataBytesForPackage(t, ref, pkg),
		ReleaseMetadataSignature: []byte("release-metadata-signature"),
		Reader:                   bytes.NewReader(packageBytes),
		Size:                     int64(len(packageBytes)),
	}
}

func readHTTPTestPackage(t *testing.T, data []byte) pluginpkg.Package {
	t.Helper()
	pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func buildHTTPSignedReleasePackageBytes(t *testing.T, data []byte, keyID string) []byte {
	t.Helper()
	pkg := readHTTPTestPackage(t, data)
	pkg.PackageSignature = &pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion,
		Algorithm:     pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:         keyID,
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "test-signature",
		SignedAt:      "2026-07-07T00:00:00Z",
	}
	var buf bytes.Buffer
	if err := pluginpkg.WritePackage(context.Background(), &buf, pkg); err != nil {
		t.Fatalf("WritePackage() error = %v", err)
	}
	return buf.Bytes()
}

func httpReleaseRefForPackage(t *testing.T, sourceID string, pkg pluginpkg.Package) host.PluginReleaseRef {
	t.Helper()
	releaseMetadataRef := "plugins/" + pkg.Manifest.Publisher.PublisherID + "/" + pkg.Manifest.PluginID() + "/" + pkg.Manifest.Version() + "/release.json"
	metadataBytes := httpReleaseMetadataBytesForPackage(t, host.PluginReleaseRef{
		SourceID:           sourceID,
		ReleaseMetadataRef: releaseMetadataRef,
		PublisherID:        pkg.Manifest.Publisher.PublisherID,
		PluginID:           pkg.Manifest.PluginID(),
		Version:            pkg.Manifest.Version(),
	}, pkg)
	metadataHash := sha256.Sum256(metadataBytes)
	return host.PluginReleaseRef{
		SourceID:              sourceID,
		ReleaseMetadataRef:    releaseMetadataRef,
		ReleaseMetadataSHA256: hex.EncodeToString(metadataHash[:]),
		PublisherID:           pkg.Manifest.Publisher.PublisherID,
		PluginID:              pkg.Manifest.PluginID(),
		Version:               pkg.Manifest.Version(),
		ExpectedHashes: host.PackageHashSet{
			PackageSHA256:  pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash,
			EntriesSHA256:  pkg.EntriesHash,
		},
	}
}

func httpReleaseMetadataBytesForPackage(t *testing.T, ref host.PluginReleaseRef, pkg pluginpkg.Package) []byte {
	t.Helper()
	release := httpReleaseForPackage(ref, pkg)
	raw, err := json.Marshal(map[string]any{
		"schema_version":             "redevplugin.release_metadata.v2",
		"source_id":                  release.SourceID,
		"release_metadata_ref":       ref.ReleaseMetadataRef,
		"publisher_id":               release.PublisherID,
		"plugin_id":                  release.PluginID,
		"version":                    release.Version,
		"distribution_ref":           release.DistributionRef,
		"hashes":                     release.Hashes,
		"release_metadata_signature": release.ReleaseMetadataSignature,
		"package_signature":          release.PackageSignature,
		"compatibility":              release.Compatibility,
		"host_requirements":          release.HostRequirements,
		"release_evidence":           release.ReleaseEvidence,
		"metadata":                   release.Metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func httpReleaseForPackage(ref host.PluginReleaseRef, pkg pluginpkg.Package) host.PluginPackageRelease {
	return host.PluginPackageRelease{
		SourceID:    ref.SourceID,
		PublisherID: ref.PublisherID,
		PluginID:    ref.PluginID,
		Version:     ref.Version,
		DistributionRef: host.PackageDistributionRef{
			Distribution: host.PackageDistributionRegistryRef,
			ArtifactRef:  "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.redevplugin",
		},
		ReleaseMetadataSHA256: ref.ReleaseMetadataSHA256,
		ReleaseMetadataSignature: &host.ReleaseMetadataSignature{
			Algorithm:         "ed25519",
			KeyID:             "official",
			SignatureRef:      "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/release.json.sig",
			SourcePolicyEpoch: "1",
			RevocationEpoch:   "1",
		},
		Hashes: host.PackageHashSet{
			PackageSHA256:  pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash,
			EntriesSHA256:  pkg.EntriesHash,
		},
		PackageSignature: &host.PackageReleaseSignature{
			Algorithm:          "ed25519",
			KeyID:              "official",
			SignatureBundleRef: "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.sigbundle",
			SourcePolicyEpoch:  "1",
			RevocationEpoch:    "1",
		},
		Compatibility: &host.ReleaseCompatibility{
			MinReDevPluginVersion: "0.1.0",
			MinRuntimeVersion:     pkg.Manifest.Plugin.MinRuntimeVersion,
			UIProtocolVersion:     string(pkg.Manifest.Plugin.UIProtocolVersion),
		},
	}
}

func httpRevocationMetadataBytesForSource(sourceID string, epoch string) []byte {
	raw, err := json.Marshal(host.SourceRevocationMetadata{
		SchemaVersion:    "redevplugin.source_revocations.v1",
		SourceID:         sourceID,
		HighestSeenEpoch: epoch,
		GeneratedAt:      "2026-07-07T00:00:00Z",
		ExpiresAt:        "2027-01-01T00:00:00Z",
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func httpSourcePolicyForRelease(ref host.PluginReleaseRef) host.SourcePolicySnapshot {
	revocationMetadata := httpRevocationMetadataBytesForSource(ref.SourceID, "1")
	revocationHash := sha256.Sum256(revocationMetadata)
	return host.SourcePolicySnapshot{
		SchemaVersion:     "redevplugin.source_policy.v1",
		SourceID:          ref.SourceID,
		SourceType:        host.PackageSourceRegistry,
		SourceClass:       host.PackageSourceClassOfficial,
		AllowedPublishers: []string{ref.PublisherID},
		TrustedKeyIDs:     []string{"official"},
		TrustedKeys: []host.SourcePolicyTrustedKey{{
			Algorithm:       pluginpkg.PackageSignatureAlgorithmEd25519,
			KeyID:           "official",
			PublicKeySHA256: strings.Repeat("a", 64),
			Usage:           []string{"release_metadata", "package_signature", "revocation_metadata"},
			ValidFrom:       "2026-01-01T00:00:00Z",
			ValidUntil:      "2027-01-01T00:00:00Z",
			RevocationEpoch: "1",
		}},
		RevocationEvidence: &host.SourcePolicyRevocationEvidence{
			MetadataRef:      "sources/" + ref.SourceID + "/revocations.json",
			MetadataSHA256:   hex.EncodeToString(revocationHash[:]),
			SignatureRef:     "sources/" + ref.SourceID + "/revocations.json.sig",
			SignatureKeyID:   "official",
			VerifiedAt:       "2026-07-07T00:00:00Z",
			ExpiresAt:        "2027-01-01T00:00:00Z",
			HighestSeenEpoch: "1",
			MetadataBytes:    revocationMetadata,
			SignatureBytes:   []byte("source-revocation-signature"),
		},
		RequireSignature: true,
		InstallPolicy:    host.PackageInstallAllow,
		UnsignedPolicy:   host.PackageUnsignedBlock,
		DowngradePolicy:  host.PackageDowngradeBlock,
		PolicyEpoch:      "1",
		KeyRotationEpoch: "1",
		RevocationEpoch:  "1",
		AssessedAt:       "2026-07-07T00:00:00Z",
	}
}

type httpRecordingCapabilityAdapter struct {
	last              capability.Invocation
	lastTarget        capability.TargetResolutionRequest
	result            capability.Result
	err               error
	cancelCalls       int
	lastCancellation  capability.OperationCancellation
	cancellationError error
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
	scope           websecurity.RequestScope
	evaluateErr     error
	csrfErr         error
	evaluateCount   int
	csrfCount       int
	lastSessionHash string
}

func allowHTTPTestGuard() *httpTestWebSecurityGuard {
	return &httpTestWebSecurityGuard{}
}

func (g *httpTestWebSecurityGuard) Evaluate(r *http.Request) (websecurity.RequestContext, websecurity.OriginDecision, error) {
	g.evaluateCount++
	decision := g.decision
	if decision == "" {
		decision = websecurity.OriginTrustedParent
	}
	scope := g.scope
	if scope == (websecurity.RequestScope{}) {
		scope = websecurity.RequestScope{
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			SessionChannelIDHash: "channel_hash",
		}
	}
	return websecurity.RequestContext{
		Origin: r.Header.Get("Origin"),
		Route:  r.URL.Path,
		Method: r.Method,
		Scope:  scope,
	}, decision, g.evaluateErr
}

func (g *httpTestWebSecurityGuard) ValidateCSRF(_ *http.Request, sessionHash string) error {
	g.csrfCount++
	g.lastSessionHash = sessionHash
	return g.csrfErr
}

func openHTTPBridge(t *testing.T, handler http.Handler, pluginInstanceID string, surfaceID string, surfaceInstanceID string, bridgeChannelID string) bridge.GatewayTokenResult {
	t.Helper()
	openBody := map[string]any{
		"plugin_instance_id":   pluginInstanceID,
		"surface_id":           surfaceID,
		"surface_instance_id":  surfaceInstanceID,
		"plugin_state_version": 2,
	}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", openBody)
	postJSON[host.PrepareSurfaceResult](t, handler, "/_redevplugin/api/plugins/surfaces/"+surfaceInstanceID+"/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	return postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/"+surfaceInstanceID+"/bridge-token", bridgeTokenRequestBody(openResp, bridgeChannelID))
}

func bridgeTokenRequestBody(openResp bridge.SurfaceBootstrap, bridgeChannelID string) map[string]any {
	handshake := bridgeHandshakeFromBootstrap(openResp)
	return map[string]any{
		"bridge_channel_id":           bridgeChannelID,
		"handshake":                   bridgeHandshakeBody(handshake),
		"handshake_transcript_sha256": bridge.HandshakeTranscriptSHA256(handshake, bridgeChannelID),
	}
}

func bridgeHandshakeFromBootstrap(openResp bridge.SurfaceBootstrap) bridge.Handshake {
	return bridge.Handshake{
		PluginID:           openResp.PluginID,
		SurfaceID:          openResp.SurfaceID,
		SurfaceInstanceID:  openResp.SurfaceInstanceID,
		ActiveFingerprint:  openResp.ActiveFingerprint,
		BridgeNonce:        openResp.BridgeNonce,
		AssetSessionNonce:  openResp.AssetSessionNonce,
		PluginStateVersion: openResp.PluginStateVersion,
		RevokeEpoch:        openResp.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}
}

func bridgeHandshakeBody(handshake bridge.Handshake) map[string]any {
	return map[string]any{
		"type":                 "redevplugin.bridge.handshake",
		"plugin_id":            handshake.PluginID,
		"surface_id":           handshake.SurfaceID,
		"surface_instance_id":  handshake.SurfaceInstanceID,
		"active_fingerprint":   handshake.ActiveFingerprint,
		"bridge_nonce":         handshake.BridgeNonce,
		"asset_session_nonce":  handshake.AssetSessionNonce,
		"plugin_state_version": handshake.PluginStateVersion,
		"revoke_epoch":         handshake.RevokeEpoch,
		"ui_protocol_version":  handshake.UIProtocolVersion,
	}
}

func grantHTTPDeclaredPermissions(t *testing.T, h *host.Host, record registry.PluginRecord) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, binding := range record.Manifest.CapabilityBindings {
		verified, err := h.Capabilities().RequireContract(binding.Contract)
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range verified.Contract.Methods {
			for _, permissionID := range method.RequiredPermissions {
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
}

func (a *httpRecordingCapabilityAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	a.lastTarget = req
	return capability.TargetDescriptor{Kind: "http_fixture", Fields: httpCloneMap(req.TargetInput)}, nil
}

func (a *httpRecordingCapabilityAdapter) Invoke(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.last = req
	return a.result, a.err
}

func (a *httpRecordingCapabilityAdapter) CancelOperation(_ context.Context, req capability.OperationCancellation) error {
	a.cancelCalls++
	a.lastCancellation = req
	return a.cancellationError
}

func (a *httpRecordingCoreActionAdapter) InvokeCoreAction(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.last = req
	return a.result, nil
}

func (a *httpRecordingCoreActionAdapter) ResolveCoreActionTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{Kind: "core_action", Fields: httpCloneMap(req.TargetInput)}, nil
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
		s.health = runtimeclient.Health{RuntimeInstanceID: "runtime_http", RuntimeGenerationID: "runtime_gen_http", IPCChannelID: "ipc_http", ConnectionNonce: "connection_nonce_http_1234567890", Ready: true}
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
