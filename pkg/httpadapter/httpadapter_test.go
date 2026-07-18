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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/stream"
	platformversion "github.com/floegence/redevplugin/pkg/version"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

func mustManagementRevision(t testing.TB, h *host.Host, pluginInstanceID string) uint64 {
	t.Helper()
	records, err := h.ListPlugins(httpTestContext())
	if err != nil {
		t.Fatalf("ListPlugins() for management revision: %v", err)
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			if record.ManagementRevision == 0 {
				t.Fatalf("plugin %q has zero management revision", pluginInstanceID)
			}
			return record.ManagementRevision
		}
	}
	t.Fatalf("plugin %q not found while resolving management revision", pluginInstanceID)
	return 0
}

func mustAuthorizationRevisions(t testing.TB, h *host.Host, pluginInstanceID string) registry.AuthorizationRevisions {
	t.Helper()
	records, err := h.ListPlugins(httpTestContext())
	if err != nil {
		t.Fatalf("ListPlugins() for authorization revisions: %v", err)
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			return registry.AuthorizationRevisionsFromRecord(record)
		}
	}
	t.Fatalf("plugin %q not found while resolving authorization revisions", pluginInstanceID)
	return registry.AuthorizationRevisions{}
}

func TestErrorResponseEncodesEmptyDetailsObject(t *testing.T) {
	payload, err := json.Marshal(errorResponse{
		OK:      false,
		Code:    security.ErrRuntimeUnavailable,
		Message: "plugin runtime is unavailable",
	})
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	var envelope struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("Unmarshal() error = %v payload = %s", err, payload)
	}
	if envelope.Error.Details == nil || len(envelope.Error.Details) != 0 {
		t.Fatalf("error.details = %#v, want empty object payload = %s", envelope.Error.Details, payload)
	}
}

func TestWriteJSONRejectsHTTPStatusEnvelopeMismatch(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		payload any
	}{
		{name: "success with error status", status: http.StatusInternalServerError, payload: successResponse{OK: true, Data: map[string]bool{"ready": true}}},
		{name: "error with success status", status: http.StatusOK, payload: errorResponse{OK: false, Code: security.ErrRuntimeUnavailable, Message: "runtime unavailable"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeJSON(recorder, tt.status, tt.payload)
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
			}
			var envelope struct {
				OK    bool `json:"ok"`
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Error.Code != string(security.ErrContractMismatch) {
				t.Fatalf("envelope = %#v", envelope)
			}
		})
	}
}

func TestErrorResponseRejectsMismatchedTypedDetails(t *testing.T) {
	zeroValuesRevision := uint64(0)
	tests := []errorResponse{
		{
			OK:      false,
			Code:    security.ErrorCode("PLUGIN_UNKNOWN"),
			Message: "unknown error",
		},
		{
			OK:      false,
			Code:    security.ErrManagementRevisionMismatch,
			Message: "management revision changed",
		},
		{
			OK:      false,
			Code:    security.ErrCapabilityError,
			Message: "capability failed",
			Details: errorDetails{
				PluginInstanceID:           "plugini_test",
				ExpectedManagementRevision: 1,
				ActualManagementRevision:   2,
			},
		},
		{
			OK:      false,
			Code:    security.ErrBindingRevisionMismatch,
			Message: "binding changed",
		},
		{
			OK:      false,
			Code:    security.ErrValuesRevisionMismatch,
			Message: "settings changed",
		},
		{
			OK:      false,
			Code:    security.ErrValuesRevisionMismatch,
			Message: "settings changed",
			Details: errorDetails{PluginInstanceID: "plugini_test", ExpectedValuesRevision: &zeroValuesRevision, ActualValuesRevision: &zeroValuesRevision},
		},
		{
			OK:      false,
			Code:    security.ErrRuntimeUnavailable,
			Message: "runtime unavailable",
			Details: errorDetails{Reason: "json_depth"},
		},
		{
			OK:      false,
			Code:    security.ErrJSONLimitExceeded,
			Message: "JSON limit exceeded",
			Details: errorDetails{Reason: "manifest_field"},
		},
		{
			OK:      true,
			Code:    security.ErrRuntimeUnavailable,
			Message: "runtime unavailable",
		},
		{
			OK:      false,
			Code:    security.ErrCapabilityError,
			Message: "capability failed",
			Details: errorDetails{CapabilityID: "capability", CapabilityVersion: "1.0.0", DetailSchemaSHA256: "not-a-hash", BusinessErrorCode: "lowercase"},
		},
		{
			OK:      false,
			Code:    security.ErrWorkerError,
			Message: "worker failed",
			Details: errorDetails{WorkerErrorCode: "lowercase", WorkerErrorMessage: strings.Repeat("x", 4097), WorkerErrorOrigin: runtimeclient.WorkerErrorOriginPlugin},
		},
	}
	for _, response := range tests {
		if _, err := json.Marshal(response); err == nil {
			t.Fatalf("json.Marshal(%s) accepted mismatched details", response.Code)
		}
	}

	if _, err := json.Marshal(errorResponse{
		OK:      false,
		Code:    security.ErrManagementRevisionMismatch,
		Message: "management revision changed",
		Details: errorDetails{
			PluginInstanceID:           "plugini_test",
			ExpectedManagementRevision: 1,
			ActualManagementRevision:   2,
		},
	}); err != nil {
		t.Fatalf("json.Marshal(valid management revision details) error = %v", err)
	}

	if _, err := json.Marshal(errorResponse{
		OK:      false,
		Code:    security.ErrBindingRevisionMismatch,
		Message: "binding changed",
		Details: errorDetails{PluginInstanceID: "plugini_test", ExpectedBindingRevision: 1, ActualBindingRevision: 2},
	}); err != nil {
		t.Fatalf("json.Marshal(valid binding revision details) error = %v", err)
	}
	expectedValuesRevision := uint64(1)
	actualValuesRevision := uint64(2)
	if _, err := json.Marshal(errorResponse{
		OK:      false,
		Code:    security.ErrValuesRevisionMismatch,
		Message: "settings changed",
		Details: errorDetails{PluginInstanceID: "plugini_test", ExpectedValuesRevision: &expectedValuesRevision, ActualValuesRevision: &actualValuesRevision},
	}); err != nil {
		t.Fatalf("json.Marshal(valid settings values revision details) error = %v", err)
	}
}

func TestDataLifecycleErrorMappingKeepsConflictSemanticsDistinct(t *testing.T) {
	revisionConflict := &plugindata.BindingRevisionConflictError{
		PluginInstanceID: "plugini_test",
		Expected:         3,
		Actual:           4,
	}
	if got := errorCodeForDataLifecycleError(revisionConflict); got != security.ErrBindingRevisionMismatch {
		t.Fatalf("revision conflict code = %q", got)
	}
	if got := httpStatusForDataLifecycleError(revisionConflict); got != http.StatusConflict {
		t.Fatalf("revision conflict status = %d", got)
	}
	if got := bindingRevisionDetails(revisionConflict); got.PluginInstanceID != "plugini_test" || got.ExpectedBindingRevision != 3 || got.ActualBindingRevision != 4 {
		t.Fatalf("revision conflict details = %#v", got)
	}

	shapeMismatch := fmt.Errorf("%w: import object shape differs", plugindata.ErrShapeMismatch)
	if got := errorCodeForDataLifecycleError(shapeMismatch); got != security.ErrInvalidRequest {
		t.Fatalf("shape mismatch code = %q", got)
	}
	if got := httpStatusForDataLifecycleError(shapeMismatch); got != http.StatusBadRequest {
		t.Fatalf("shape mismatch status = %d", got)
	}

	internalConflict := fmt.Errorf("%w: destination already exists", plugindata.ErrBindingConflict)
	if got := errorCodeForDataLifecycleError(internalConflict); got != security.ErrContractMismatch {
		t.Fatalf("internal binding conflict code = %q", got)
	}
	if got := httpStatusForDataLifecycleError(internalConflict); got != http.StatusInternalServerError {
		t.Fatalf("internal binding conflict status = %d", got)
	}
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
		"GET /_redevplugin/api/plugins/security-policies":                                 false,
		"GET /_redevplugin/api/plugins/security-policies/{plugin_instance_id}":            false,
		"PUT /_redevplugin/api/plugins/security-policies/{plugin_instance_id}":            false,
		"DELETE /_redevplugin/api/plugins/security-policies/{plugin_instance_id}":         false,
		"GET /_redevplugin/api/plugins/diagnostics":                                       false,
		"GET /_redevplugin/api/plugins/runtime/health":                                    false,
		"POST /_redevplugin/api/plugins/runtime/refresh-enabled":                          false,
		"POST /_redevplugin/api/plugins/data/export/delete":                               false,
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

func TestRouteSetIncludesLocalImportRoutes(t *testing.T) {
	want := map[string]bool{
		"POST /_redevplugin/api/plugins/local-imports":                    false,
		"PUT /_redevplugin/api/plugins/{plugin_instance_id}/local-import": false,
	}
	for _, route := range RouteSet() {
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
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	for _, route := range RouteSet() {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			path := samplePathForRoute(route.Path)
			body := ""
			if route.Method == http.MethodPost || route.Method == http.MethodPut || route.Method == http.MethodPatch || route.Method == http.MethodDelete {
				body = `{}`
			}
			req := httptest.NewRequest(route.Method, path, bytes.NewBufferString(body))
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("declared route fell through to 404: %s %s body = %s", route.Method, route.Path, rec.Body.String())
			}
		})
	}
}

func TestRequestIsMutationClassifiesPutAndDelete(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{method: http.MethodGet, path: "/_redevplugin/api/plugins/security-policies", want: false},
		{method: http.MethodPut, path: "/_redevplugin/api/plugins/security-policies/plugini_test", want: true},
		{method: http.MethodDelete, path: "/_redevplugin/api/plugins/security-policies/plugini_test", want: true},
		{method: http.MethodPost, path: "/_redevplugin/api/plugins/surfaces/surface_test/streams/read", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if got := requestIsMutation(req); got != tt.want {
				t.Fatalf("requestIsMutation(%s %s) = %t, want %t", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestHandlerLocalImportRoutesAreAlwaysMounted(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		method string
		body   []byte
	}{
		{
			name:   "install",
			method: http.MethodPost,
			path:   "/_redevplugin/api/plugins/local-imports",
			body:   []byte("not-a-zip"),
		},
		{
			name:   "update",
			method: http.MethodPut,
			path:   "/_redevplugin/api/plugins/plugini_test/local-import?expected_management_revision=1",
			body:   []byte("not-a-zip"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewReader(tt.body))
			req.Header.Set("Content-Type", localImportContentType)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusNotFound {
				t.Fatalf("local-import route fell through to 404: body = %s", rec.Body.String())
			}
		})
	}
}

func TestHandlerCompatibilityManifest(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
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

	if got.SchemaVersion != "redevplugin.compatibility.v6" {
		t.Fatalf("schema_version = %q", got.SchemaVersion)
	}
	if got.Matrix.PluginHostProtocolVersion != "plugin-host-v4" || got.Matrix.PluginPlatformOpenAPI != "plugin-platform-v6" {
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
	if openapi.Path != "spec/openapi/plugin-platform-v6.yaml" || openapi.SHA256 == "" {
		t.Fatalf("plugin-platform-openapi contract mismatch: %#v", openapi)
	}
}

func TestHandlerJSONLimitErrorsExposeReason(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
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
			req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Code != string(security.ErrJSONLimitExceeded) {
				t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
			}
			if got := envelope.Details["reason"]; got != tt.wantReason {
				t.Fatalf("error_details.reason = %#v, want %q body = %s", got, tt.wantReason, rec.Body.String())
			}
		})
	}
}

func TestHandlerMalformedJSONRemainsInvalidRequest(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(`{"plugin_instance_id":`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) || len(envelope.Details) != 0 {
		t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
	}
}

func TestHandlerRejectsAmbiguousJSONObjectKeys(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "duplicate top-level key",
			path: "/_redevplugin/api/plugins/enable",
			body: `{"plugin_instance_id":"plugini_a","plugin_instance_id":"plugini_b","expected_management_revision":1}`,
		},
		{
			name: "case-folded struct field collision",
			path: "/_redevplugin/api/plugins/enable",
			body: `{"plugin_instance_id":"plugini_a","PLUGIN_INSTANCE_ID":"plugini_b","expected_management_revision":1}`,
		},
		{
			name: "duplicate nested params key",
			path: "/_redevplugin/api/plugins/confirmations/prepare",
			body: `{"plugin_instance_id":"plugini_a","surface_instance_id":"surface_a","bridge_channel_id":"bridge_a","plugin_gateway_token":"token_a","method":"example.run","params":{"target":"one","target":"two"}}`,
		},
		{
			name: "duplicate key in array object",
			path: "/_redevplugin/api/plugins/confirmations/prepare",
			body: `{"plugin_instance_id":"plugini_a","surface_instance_id":"surface_a","bridge_channel_id":"bridge_a","plugin_gateway_token":"token_a","method":"example.run","params":{"items":[{"target":"one","target":"two"}]}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := newJSONHTTPRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) {
				t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
			}
		})
	}
}

func TestDecodeJSONPreservesCaseSensitiveDynamicMapKeys(t *testing.T) {
	req := newJSONHTTPRequest(http.MethodPost, "/", strings.NewReader(`{"method":"example.run","params":{"Name":"upper","name":"lower"}}`))
	var decoded rpcRequest
	if err := decodeJSON(req, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Params["Name"] != "upper" || decoded.Params["name"] != "lower" {
		t.Fatalf("params = %#v", decoded.Params)
	}
}

func TestHandlerRequiresApplicationJSONForJSONBodies(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	tests := []struct {
		name         string
		contentTypes []string
		wantStatus   int
	}{
		{name: "application json", contentTypes: []string{"application/json"}, wantStatus: http.StatusOK},
		{name: "utf-8 charset", contentTypes: []string{"application/json; charset=UTF-8"}, wantStatus: http.StatusOK},
		{name: "missing", wantStatus: http.StatusBadRequest},
		{name: "text plain", contentTypes: []string{"text/plain"}, wantStatus: http.StatusBadRequest},
		{name: "form", contentTypes: []string{"application/x-www-form-urlencoded"}, wantStatus: http.StatusBadRequest},
		{name: "unsupported charset", contentTypes: []string{"application/json; charset=iso-8859-1"}, wantStatus: http.StatusBadRequest},
		{name: "unsupported parameter", contentTypes: []string{"application/json; profile=example"}, wantStatus: http.StatusBadRequest},
		{name: "duplicate header", contentTypes: []string{"application/json", "text/plain"}, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/retained-data/cleanup-expired", strings.NewReader(`{}`))
			for _, contentType := range test.contentTypes {
				req.Header.Add("Content-Type", contentType)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d body = %s", rec.Code, test.wantStatus, rec.Body.String())
			}
			if test.wantStatus == http.StatusBadRequest {
				var envelope decodedErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) {
					t.Fatalf("envelope = %#v body = %s", envelope, rec.Body.String())
				}
			}
		})
	}
}

func TestHandlerRuntimeEmptyRequestsRequireClosedJSON(t *testing.T) {
	for _, path := range []string{
		"/_redevplugin/api/plugins/runtime/stop",
		"/_redevplugin/api/plugins/runtime/refresh-enabled",
	} {
		t.Run(path, func(t *testing.T) {
			invalidRequests := []struct {
				name        string
				body        string
				contentType string
			}{
				{name: "empty body", contentType: "application/json"},
				{name: "null", body: `null`, contentType: "application/json"},
				{name: "array", body: `[]`, contentType: "application/json"},
				{name: "unknown field", body: `{"unexpected":true}`, contentType: "application/json"},
				{name: "duplicate field", body: `{"value":1,"value":2}`, contentType: "application/json"},
				{name: "trailing value", body: `{} {}`, contentType: "application/json"},
				{name: "missing content type", body: `{}`},
				{name: "wrong content type", body: `{}`, contentType: "text/plain"},
			}
			for _, test := range invalidRequests {
				t.Run(test.name, func(t *testing.T) {
					handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
					req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(test.body))
					if test.contentType != "" {
						req.Header.Set("Content-Type", test.contentType)
					}
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("status = %d, want %d response = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
					}
					var envelope decodedErrorResponse
					if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
						t.Fatal(err)
					}
					if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) || envelope.MutationOutcome != string(mutation.OutcomeNotCommitted) {
						t.Fatalf("invalid empty request envelope = %#v body = %s", envelope, rec.Body.String())
					}
				})
			}
		})
	}
}

func TestHandlerRejectsQueryParametersOutsideRouteContract(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	for _, route := range routes {
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			path := strings.NewReplacer(
				"{surface_instance_id}", "surface_test",
				"{operation_id}", "operation_test",
				"{plugin_instance_id}", "plugin_test",
			).Replace(route.Path)
			req := httptest.NewRequest(route.Method, path+"?unknown=value", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d response = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			wantOutcome := ""
			if requestIsMutation(req) {
				wantOutcome = string(mutation.OutcomeNotCommitted)
			}
			if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) || envelope.MutationOutcome != wantOutcome {
				t.Fatalf("unknown query envelope = %#v, want mutation_outcome %q", envelope, wantOutcome)
			}
		})
	}
}

func TestHandlerRejectsDuplicateQueryParameters(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	for _, route := range routes {
		if len(route.queryKeys) == 0 {
			continue
		}
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			key := route.queryKeys[0]
			req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path)+"?"+key+"=first&"+key+"=second", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d response = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			wantOutcome := ""
			if requestIsMutation(req) {
				wantOutcome = string(mutation.OutcomeNotCommitted)
			}
			if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) || envelope.MutationOutcome != wantOutcome {
				t.Fatalf("duplicate query envelope = %#v, want mutation_outcome %q", envelope, wantOutcome)
			}
		})
	}
}

func TestHandlerWebSecurityRejectsDeniedOrigin(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: "deny"}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied origin status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrOriginDenied) {
		t.Fatalf("origin error code = %q, want %q", envelope.Code, security.ErrOriginDenied)
	}
	if guard.authenticateCount != 1 || guard.originCount != 1 {
		t.Fatalf("guard calls = authenticate:%d origin:%d", guard.authenticateCount, guard.originCount)
	}
	if guard.csrfCount != 0 || guard.authorizeCount != 0 {
		t.Fatalf("later guard stages ran after denied origin: csrf=%d authorize=%d", guard.csrfCount, guard.authorizeCount)
	}
}

func TestHandlerWebSecurityRejectsHostSpecificOriginDecision(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: "plugin_sandbox"}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	for _, path := range []string{
		"/_redevplugin/api/plugins/install-release-ref",
		"/_redevplugin/api/plugins/local-imports",
		"/_redevplugin/api/plugins/enable",
		"/_redevplugin/api/plugins/surfaces/surface_test/prepare",
	} {
		t.Run(path, func(t *testing.T) {
			req := newJSONHTTPRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
			req.Header.Set("Origin", "https://plugin.sandbox.example")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("sandbox route status = %d, want 403 body = %s", rec.Code, rec.Body.String())
			}
		})
	}
	if guard.csrfCount != 0 || guard.authorizeCount != 0 {
		t.Fatalf("later guard stages ran after rejected sandbox origin: csrf=%d authorize=%d", guard.csrfCount, guard.authorizeCount)
	}
}

func TestHandlerWebSecurityFailsClosedWithoutGuard(t *testing.T) {
	if _, err := NewHandler(Dependencies{Host: newHTTPTestHost(t)}); err == nil {
		t.Fatal("NewHandler() expected missing guard error")
	} else {
		var configErr *host.HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, host.ErrHostConfig) {
			t.Fatalf("NewHandler() error = %v, want HostConfigError", err)
		}
	}
}

func TestHandlerWebSecurityFailsClosedWithTypedNilGuard(t *testing.T) {
	var guard *httpTestWebSecurityGuard
	_, err := NewHandler(Dependencies{Host: newHTTPTestHost(t), Guard: guard})
	var configErr *host.HostConfigError
	if !errors.As(err, &configErr) || !errors.Is(err, host.ErrHostConfig) {
		t.Fatalf("NewHandler() error = %v, want HostConfigError", err)
	}
	if configErr.Module != "http" || configErr.Adapter != "web security guard" {
		t.Fatalf("HostConfigError = %#v", configErr)
	}
}

func TestHandlerWebSecurityRejectsIncompleteTrustedScope(t *testing.T) {
	guard := &httpTestWebSecurityGuard{scope: sessionctx.Context{OwnerSessionHash: "session_hash"}}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerWebSecurityRequiresCSRFForUnsafeProxyRoutes(t *testing.T) {
	for _, path := range []string{
		"/_redevplugin/api/plugins/enable",
		"/_redevplugin/api/plugins/surfaces/surface_test/assets/read",
		"/_redevplugin/api/plugins/surfaces/surface_test/streams/read",
	} {
		t.Run(path, func(t *testing.T) {
			guard := &httpTestWebSecurityGuard{decision: "trusted", csrfErr: websecurity.ErrCSRFRequired}
			handler := mustNewHandler(t, newHTTPTestHost(t), guard)
			req := newJSONHTTPRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("missing csrf status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Code != string(security.ErrCSRFRequired) {
				t.Fatalf("csrf error_code = %q, want %q", envelope.Code, security.ErrCSRFRequired)
			}
			if guard.authenticateCount != 1 || guard.originCount != 1 || guard.csrfCount != 1 || guard.authorizeCount != 0 || guard.lastSessionHash != "session_hash" {
				t.Fatalf("guard calls = authenticate:%d origin:%d csrf:%d authorize:%d session:%q", guard.authenticateCount, guard.originCount, guard.csrfCount, guard.authorizeCount, guard.lastSessionHash)
			}
		})
	}
}

func TestHandlerWebSecurityAllowsSafeProxyRouteWithoutCSRF(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: "trusted", csrfErr: websecurity.ErrCSRFRequired}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("catalog status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.authenticateCount != 1 || guard.originCount != 1 || guard.csrfCount != 1 || guard.authorizeCount != 1 {
		t.Fatalf("guard calls = authenticate:%d origin:%d csrf:%d authorize:%d", guard.authenticateCount, guard.originCount, guard.csrfCount, guard.authorizeCount)
	}
	if guard.lastCSRFPolicy != websecurity.CSRFPolicyNotRequired || guard.lastAction != websecurity.RouteActionListPlugins {
		t.Fatalf("safe route contract = csrf:%q action:%q", guard.lastCSRFPolicy, guard.lastAction)
	}
	if got := strings.Join(guard.callOrder, ","); got != "authenticate,origin,csrf,authorize" {
		t.Fatalf("guard call order = %q", got)
	}
}

func TestHandlerWebSecurityRejectsUnauthorizedRouteAction(t *testing.T) {
	guard := &httpTestWebSecurityGuard{authorizeErr: errors.New("route denied")}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrActionDenied) {
		t.Fatalf("error code = %q, want %q", envelope.Code, security.ErrActionDenied)
	}
	if guard.lastAction != websecurity.RouteActionListPlugins || guard.authorizeCount != 1 {
		t.Fatalf("authorization action = %q count = %d", guard.lastAction, guard.authorizeCount)
	}
}

func TestHandlerMapsHostDirectAuthorizationDenialToStableActionCode(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{authorization: httpDenyAuthorization{}})
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	req := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/catalog", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || envelope.Code != string(security.ErrActionDenied) {
		t.Fatalf("host authorization denial = status:%d envelope:%#v", rec.Code, envelope)
	}
}

func TestHandlerWebSecurityDistinguishesInvalidCSRF(t *testing.T) {
	guard := &httpTestWebSecurityGuard{csrfErr: websecurity.ErrCSRFInvalid}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || envelope.Code != string(security.ErrCSRFInvalid) {
		t.Fatalf("invalid csrf response = status:%d envelope:%#v", rec.Code, envelope)
	}
}

func TestHandlerWebSecurityCSRFClassificationCoversRouteSet(t *testing.T) {
	actions := make(map[websecurity.RouteAction]Route, len(routes))
	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			guard := &httpTestWebSecurityGuard{decision: "trusted"}
			handler := mustNewHandler(t, newHTTPTestHost(t), guard)
			body := ""
			if route.Method == http.MethodPost || route.Method == http.MethodPatch || route.Method == http.MethodPut {
				body = `{}`
			}
			req := httptest.NewRequest(route.Method, samplePathForRoute(route.Path), bytes.NewBufferString(body))
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if guard.authenticateCount != 1 || guard.originCount != 1 || guard.csrfCount != 1 || guard.authorizeCount != 1 {
				t.Fatalf("guard calls = authenticate:%d origin:%d csrf:%d authorize:%d", guard.authenticateCount, guard.originCount, guard.csrfCount, guard.authorizeCount)
			}
			wantCSRF := route.Method != http.MethodGet &&
				route.Method != http.MethodHead &&
				route.Method != http.MethodOptions
			wantPolicy := websecurity.CSRFPolicyNotRequired
			if wantCSRF {
				wantPolicy = websecurity.CSRFPolicyRequired
			}
			if guard.lastCSRFPolicy != wantPolicy {
				t.Fatalf("CSRF policy = %q, want %q for %s", guard.lastCSRFPolicy, wantPolicy, route.Path)
			}
			if guard.lastOriginPolicy != websecurity.OriginPolicyTrustedHost {
				t.Fatalf("origin policy = %q, want trusted host", guard.lastOriginPolicy)
			}
			if guard.lastAction != route.action || !route.action.Valid() {
				t.Fatalf("route action = %q, want %q", guard.lastAction, route.action)
			}
		})
		if previous, exists := actions[route.action]; exists {
			t.Fatalf("route action %q is shared by %s %s and %s %s", route.action, previous.Method, previous.Path, route.Method, route.Path)
		}
		actions[route.action] = route.Route
	}
}

func TestOpenAPIConfirmationPreparationResponseBelongsToPreparationRoute(t *testing.T) {
	spec := readOpenAPIContract(t)
	rpcBlock, ok := openAPIOperationBlock(spec, "/_redevplugin/api/plugins/rpc", http.MethodPost)
	if !ok {
		t.Fatal("OpenAPI missing rpc operation")
	}
	if !strings.Contains(rpcBlock, `#/components/responses/RPCResponse`) {
		t.Fatalf("rpc operation must use RPCResponse; block:\n%s", rpcBlock)
	}
	prepareBlock, ok := openAPIOperationBlock(spec, "/_redevplugin/api/plugins/confirmations/prepare", http.MethodPost)
	if !ok {
		t.Fatal("OpenAPI missing method confirmation preparation operation")
	}
	if !strings.Contains(prepareBlock, `#/components/responses/PluginMethodConfirmationPreparationResponse`) {
		t.Fatalf("method confirmation preparation operation has the wrong response; block:\n%s", prepareBlock)
	}
	if !strings.Contains(prepareBlock, `#/components/requestBodies/PrepareMethodConfirmationRequest`) ||
		strings.Contains(prepareBlock, `#/components/requestBodies/RPCRequest`) {
		t.Fatalf("method confirmation preparation operation must use its dedicated request schema; block:\n%s", prepareBlock)
	}
}

func TestOpenAPIOperationRecordOmitsOwnerScopeHashes(t *testing.T) {
	spec := readOpenAPIContract(t)
	for _, schemaName := range []string{"ExecutionBinding", "OperationRecord"} {
		block, ok := openAPISchemaContractBlock(spec, schemaName)
		if !ok {
			t.Fatalf("OpenAPI schema %s is missing", schemaName)
		}
		for _, forbidden := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
			if strings.Contains(block, forbidden) {
				t.Fatalf("OpenAPI schema %s exposes %s:\n%s", schemaName, forbidden, block)
			}
		}
	}
}

func TestPublicOperationRecordOmitsOwnerScopeHashes(t *testing.T) {
	record := operation.Record{
		OperationID: "operation_public_1",
		ExecutionBinding: capability.ExecutionBinding{
			InvocationID: "invocation_public_1", AuditCorrelationID: "audit_public_1",
			PluginInstanceID: "plugini_public_1", OwnerSessionHash: "session_secret",
			OwnerUserHash: "user_secret", OwnerEnvHash: "env_secret", SessionChannelIDHash: "channel_secret",
		},
	}
	raw, err := json.Marshal(publicOperationRecord(record))
	if err != nil {
		t.Fatalf("Marshal(publicOperationRecord()) error = %v", err)
	}
	var public map[string]any
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatalf("Unmarshal(public operation) error = %v", err)
	}
	if public["operation_id"] != "operation_public_1" || public["invocation_id"] != "invocation_public_1" {
		t.Fatalf("public operation identity = %#v", public)
	}
	for _, forbidden := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if _, present := public[forbidden]; present || strings.Contains(string(raw), "secret") {
			t.Fatalf("public operation exposed owner scope through %s: %s", forbidden, raw)
		}
	}
}

func TestHandlerGenericErrorEnvelopesConformToOpenAPI(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		responseSchema string
		errorSchema    string
	}{
		{
			name:           "read error",
			method:         http.MethodGet,
			path:           "/_redevplugin/api/plugins/intents?unknown=value",
			responseSchema: "PlatformErrorResponse",
			errorSchema:    "GenericPlatformError",
		},
		{
			name:           "mutation error",
			method:         http.MethodPost,
			path:           "/_redevplugin/api/plugins/confirmations/prepare",
			body:           "{",
			responseSchema: "MutationPlatformErrorResponse",
			errorSchema:    "MutationGenericPlatformError",
		},
	}
	spec := readOpenAPIContract(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code < http.StatusBadRequest {
				t.Fatalf("status = %d, want non-success; body = %s", rec.Code, rec.Body.String())
			}
			var envelope map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			assertJSONFieldsMatchOpenAPISchema(t, spec, tt.responseSchema, envelope)
			errorValue, ok := envelope["error"].(map[string]any)
			if !ok {
				t.Fatalf("error field = %#v, want object", envelope["error"])
			}
			assertJSONFieldsMatchOpenAPISchema(t, spec, tt.errorSchema, errorValue)
		})
	}
}

func TestHandlerWebSecurityIgnoresNonPluginPaths(t *testing.T) {
	guard := &httpTestWebSecurityGuard{decision: "deny", csrfErr: websecurity.ErrCSRFRequired}
	handler := mustNewHandler(t, newHTTPTestHost(t), guard)
	req := httptest.NewRequest(http.MethodPost, "/healthz", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-plugin path status = %d body = %s", rec.Code, rec.Body.String())
	}
	if guard.authenticateCount != 0 || guard.originCount != 0 || guard.csrfCount != 0 || guard.authorizeCount != 0 {
		t.Fatalf("guard should not run for non-plugin path: %#v", guard)
	}
}

func TestHandlerManagementLifecycleFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	packageBytes := buildHTTPFixturePackage(t)

	installed := postLocalImport[registry.PluginRecord](t, handler, packageBytes)
	if installed.PluginInstanceID == "" || installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install response mismatch: %#v", installed)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
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
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": enabled.ManagementRevision,
		"reason":                       "test",
	})
	if disabled.EnableState != registry.EnableDisabled || disabled.DisabledReason != "test" {
		t.Fatalf("disable response mismatch: %#v", disabled)
	}

	uninstalled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": disabled.ManagementRevision,
		"delete_data":                  true,
	})
	if uninstalled.DeletedAt == nil {
		t.Fatalf("uninstall response mismatch: %#v", uninstalled)
	}

	emptyCatalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog")
	if len(emptyCatalog.Plugins) != 0 {
		t.Fatalf("catalog after uninstall mismatch: %#v", emptyCatalog)
	}
}

func TestHandlerReportsUnknownMutationOutcomeAfterCommit(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{surfaceCatalog: httpFailingSurfaceCatalogSink{}})
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed := postLocalImport[registry.PluginRecord](t, handler, buildHTTPFixturePackage(t))

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	}, http.StatusForbidden)
	if envelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("mutation_outcome = %q, want %q body = %#v", envelope.MutationOutcome, mutation.OutcomeUnknown, envelope)
	}
	records, err := h.ListPlugins(httpTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EnableState != registry.EnableEnabled {
		t.Fatalf("committed plugin state = %#v", records)
	}
}

func TestHandlerManagementRevisionContractFailsClosed(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed := postLocalImport[registry.PluginRecord](t, handler, buildHTTPFixturePackage(t))

	for _, tc := range []struct {
		body     map[string]any
		wantCode security.ErrorCode
	}{
		{body: map[string]any{"plugin_instance_id": installed.PluginInstanceID}, wantCode: security.ErrInvalidRequest},
		{body: map[string]any{"plugin_instance_id": installed.PluginInstanceID, "expected_management_revision": 0}, wantCode: security.ErrInvalidRequest},
		{body: map[string]any{"plugin_instance_id": installed.PluginInstanceID, "expected_management_revision": uint64(maxJSONSafeInteger) + 1}, wantCode: security.ErrJSONLimitExceeded},
	} {
		envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/enable", tc.body, http.StatusBadRequest)
		if envelope.Code != string(tc.wantCode) {
			t.Fatalf("invalid management revision error_code = %q, want %q", envelope.Code, tc.wantCode)
		}
	}

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision + 1,
	}, http.StatusConflict)
	if envelope.Code != string(security.ErrManagementRevisionMismatch) {
		t.Fatalf("stale enable error_code = %q, want %q", envelope.Code, security.ErrManagementRevisionMismatch)
	}
	catalog := getJSON[struct {
		Plugins []registry.PluginRecord `json:"plugins"`
	}](t, handler, "/_redevplugin/api/plugins/catalog")
	if len(catalog.Plugins) != 1 || catalog.Plugins[0].EnableState != registry.EnableDisabled || catalog.Plugins[0].ManagementRevision != installed.ManagementRevision {
		t.Fatalf("failed enable mutated catalog: %#v", catalog.Plugins)
	}

	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	})
	staleOpen := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           enabled.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_revision_check",
	}, http.StatusConflict)
	if staleOpen.Code != string(security.ErrManagementRevisionMismatch) {
		t.Fatalf("stale open error_code = %q, want %q", staleOpen.Code, security.ErrManagementRevisionMismatch)
	}
	opened := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           enabled.PluginInstanceID,
		"expected_management_revision": enabled.ManagementRevision,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_revision_check",
	})
	if opened.SurfaceInstanceID != "surface_revision_check" {
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
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	installed := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/install-release-ref", map[string]any{
		"release_ref": ref,
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
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/install-release-ref", map[string]any{
		"release_ref": ref,
	}, http.StatusForbidden)
	if envelope.Code != string(security.ErrReleaseRefPolicyDenied) {
		t.Fatalf("error_code = %q, want %q body = %#v", envelope.Code, security.ErrReleaseRefPolicyDenied, envelope)
	}
}

func TestHandlerUpdateAndDowngradeFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	v1 := buildHTTPVersionedFixturePackage(t, "1.0.0", "HTTP")
	v2 := buildHTTPVersionedFixturePackage(t, "2.0.0", "HTTP v2")

	installed := postLocalImport[registry.PluginRecord](t, handler, v1)
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	})
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable response mismatch: %#v", enabled)
	}

	updated := putLocalImport[registry.PluginRecord](t, handler, installed.PluginInstanceID, enabled.ManagementRevision, v2)
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("update response mismatch: %#v", updated)
	}

	downgraded := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/downgrade", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": updated.ManagementRevision,
		"version":                      "1.0.0",
	})
	if downgraded.Version != "1.0.0" || downgraded.ActiveFingerprint != installed.ActiveFingerprint || len(downgraded.VersionHistory) != 1 || downgraded.VersionHistory[0].Version != "2.0.0" {
		t.Fatalf("downgrade response mismatch: %#v", downgraded)
	}
}

func TestHandlerManagementRejectsInvalidInstallAndTrustStateInput(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/local-imports", bytes.NewBufferString("not-a-zip"))
	req.Header.Set("Content-Type", localImportContentType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid install status = %d body = %s", rec.Code, rec.Body.String())
	}

	req = newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/local-imports", bytes.NewBufferString(`{"unexpected":true}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("trust_state input status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerInstallMapsPackageValidationErrorDetails(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
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
			req := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/local-imports", bytes.NewReader(buildHTTPRawPackage(t, tt.entries)))
			req.Header.Set("Content-Type", localImportContentType)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("install status = %d body = %s", rec.Code, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Code != string(tt.wantCode) {
				t.Fatalf("install envelope = %#v, want code %s", envelope, tt.wantCode)
			}
			if got := envelope.Details["reason"]; got != tt.wantReason {
				t.Fatalf("error_details.reason = %#v, want %q body = %s", got, tt.wantReason, rec.Body.String())
			}
			if got := envelope.Details["path"]; got != tt.wantPath {
				t.Fatalf("error_details.path = %#v, want %q body = %s", got, tt.wantPath, rec.Body.String())
			}
			if tt.wantPointer != "" {
				if got := envelope.Details["pointer"]; got != tt.wantPointer {
					t.Fatalf("error_details.pointer = %#v, want %q body = %s", got, tt.wantPointer, rec.Body.String())
				}
			}
		})
	}
}

func TestHandlerEnableMapsBlockedNetworkTarget(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed := postLocalImport[registry.PluginRecord](t, handler, buildHTTPBlockedNetworkFixturePackage(t))
	raw, err := json.Marshal(map[string]any{"plugin_instance_id": installed.PluginInstanceID, "expected_management_revision": installed.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/enable", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked network enable status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrNetworkTargetDenied) {
		t.Fatalf("error_code = %q body = %s", envelope.Code, rec.Body.String())
	}
}

func TestHandlerSurfaceBridgeFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http",
		"expected_management_revision": 2,
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	first := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_scope_first",
		"expected_management_revision": 2,
	})
	postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_scope_second",
		"expected_management_revision": 2,
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
	if envelope.Code != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("prepare after scope revoke error_code = %q", envelope.Code)
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_bad_type",
		"expected_management_revision": 2,
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
			if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) {
				t.Fatalf("bridge token envelope = %#v", envelope)
			}
		})
	}
}

func TestHandlerBridgeTokenRejectsTranscriptMismatch(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_bad_transcript",
		"expected_management_revision": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_transcript/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	body := bridgeTokenRequestBody(openResp, "bridge_http_transcript")
	body["handshake_transcript_sha256"] = bridge.HandshakeTranscriptSHA256(bridgeHandshakeFromBootstrap(openResp), "bridge_http_other")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_bad_transcript/bridge-token", body, http.StatusForbidden)
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("transcript mismatch error_code = %s body = %#v", envelope.Code, envelope)
	}
}

func TestHandlerPrepareAndPrivateAssetFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_asset",
		"expected_management_revision": 2,
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
	if replay.Code != string(security.ErrTokenReplay) {
		t.Fatalf("asset ticket replay error_code = %s body = %#v", replay.Code, replay)
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
	if asset.Path != preparedAsset.Path ||
		asset.SHA256 != preparedAsset.SHA256 ||
		asset.ContentType != "image/png" ||
		!bytes.Equal(content, minimalHTTPPNGForTest()) {
		t.Fatalf("asset response mismatch: %#v content=%q", asset, string(content))
	}

	rawPathBypass := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_asset/assets/read", map[string]any{
		"asset_session":    prepareResp.AssetSession,
		"asset_session_id": prepareResp.AssetSessionID,
		"asset_path":       "ui/app.js",
	}, http.StatusBadRequest)
	if rawPathBypass.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("raw asset path bypass error_code = %s body = %#v", rawPathBypass.Code, rawPathBypass)
	}

	wrongSurface := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_other/assets/read", map[string]any{
		"asset_session":    prepareResp.AssetSession,
		"asset_session_id": prepareResp.AssetSessionID,
		"binding_id":       preparedAsset.BindingID,
	}, http.StatusForbidden)
	if wrongSurface.Code != string(security.ErrAssetSessionInvalid) {
		t.Fatalf("cross-surface asset error_code = %s body = %#v", wrongSurface.Code, wrongSurface)
	}
}

func TestHandlerRPCFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.rpc.view",
		"surface_instance_id":          "surface_http_rpc",
		"expected_management_revision": 2,
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	if envelope.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("request schema error_code = %s body = %#v", envelope.Code, envelope)
	}

	adapter.result = capability.Result{Data: map[string]any{"unknown": true}}
	invalidResponse := cloneMap(baseBody)
	invalidResponse["params"] = map[string]any{"message": "hello"}
	envelope = postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", invalidResponse, http.StatusBadGateway)
	if envelope.Code != string(security.ErrContractMismatch) {
		t.Fatalf("response schema error_code = %s body = %#v", envelope.Code, envelope)
	}
}

func TestHandlerRPCDoesNotExposeAdapterErrorDetails(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{err: errors.New("dial /private/runtime.sock with bearer super-secret")}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_redaction", "bridge_http_redaction")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_redaction",
		"bridge_channel_id":    "bridge_http_redaction",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
		"params":               map[string]any{"message": "hello"},
	}, http.StatusForbidden)
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("adapter error_code = %s body = %#v", envelope.Code, envelope)
	}
	if strings.Contains(envelope.Message, "runtime.sock") || strings.Contains(envelope.Message, "super-secret") {
		t.Fatalf("adapter details leaked to plugin: %#v", envelope)
	}
}

func TestHandlerOpenSurfaceOmitsTrustedScopeHashes(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bootstrap := postJSON[map[string]any](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_public_bootstrap",
		"expected_management_revision": mustManagementRevision(t, h, installed.PluginInstanceID),
	})
	for _, field := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if _, present := bootstrap[field]; present {
			t.Fatalf("public surface bootstrap exposed %s: %#v", field, bootstrap)
		}
	}
	injected := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_owner_injection",
		"expected_management_revision": mustManagementRevision(t, h, installed.PluginInstanceID),
		"owner_env_hash":               "attacker_controlled_env",
	}, http.StatusBadRequest)
	if injected.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("owner injection error = %#v", injected)
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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

func TestHandlerRPCExposesHostAttestedCapabilityBusinessError(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{err: &capability.BusinessError{
		CapabilityID:       "adapter.forged",
		CapabilityVersion:  "9.9.9",
		DetailSchemaSHA256: strings.Repeat("f", 64),
		Code:               "DOCUMENT_NOT_FOUND",
		Message:            "adapter controlled message",
		Details: map[string]any{
			"document_id":  "doc-1",
			"secret_token": "adapter-secret",
		},
	}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_business_error", "bridge_http_business_error")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_business_error",
		"bridge_channel_id":    "bridge_http_business_error",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "echo.ping",
	}, http.StatusUnprocessableEntity)
	if envelope.Code != string(security.ErrCapabilityError) {
		t.Fatalf("business error envelope = %#v", envelope)
	}
	if envelope.Details["capability_id"] != "example.capability.echo" || envelope.Details["capability_version"] != "1.0.0" {
		t.Fatalf("business error did not use published identity: %#v", envelope.Details)
	}
	details, ok := envelope.Details["business_error_details"].(map[string]any)
	if !ok || details["document_id"] != "doc-1" || details["secret_token"] != capability.ResponseRedactedValue {
		t.Fatalf("business error details were not attested and redacted: %#v", envelope.Details)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "adapter-secret") || strings.Contains(string(raw), "adapter.forged") || strings.Contains(string(raw), "adapter controlled") {
		t.Fatalf("adapter-owned business error fields leaked: %s", raw)
	}
}

func TestHandlerRPCGatewayTokenErrorsUseStableCodes(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	if envelope.Code != string(security.ErrGatewayTokenInvalid) {
		t.Fatalf("invalid gateway token error_code = %s body = %#v", envelope.Code, envelope)
	}

	wrongChannelBody := cloneMap(baseBody)
	wrongChannelBody["bridge_channel_id"] = "bridge_http_other"
	envelope = postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", wrongChannelBody, http.StatusForbidden)
	if envelope.Code != string(security.ErrGatewayTokenChannelMismatch) {
		t.Fatalf("gateway token channel mismatch error_code = %s body = %#v", envelope.Code, envelope)
	}
}

func TestHandlerBridgeTokenDuplicateChannelUsesGatewayMismatchCode(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.view",
		"surface_instance_id":          "surface_http_duplicate_channel",
		"expected_management_revision": 2,
	})
	postJSON[bridge.AssetSessionResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/prepare", map[string]any{
		"asset_ticket": openResp.AssetTicket,
	})
	postJSON[bridge.GatewayTokenResult](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_a"))

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_duplicate_channel/bridge-token", bridgeTokenRequestBody(openResp, "bridge_http_b"), http.StatusForbidden)
	if envelope.Code != string(security.ErrGatewayTokenChannelMismatch) {
		t.Fatalf("duplicate bridge channel error_code = %s body = %#v", envelope.Code, envelope)
	}
}

func TestRPCErrorCodeMapsGatewayTokenReplay(t *testing.T) {
	if got := errorCodeForRPCError(bridge.ErrTokenReplay); got != security.ErrGatewayTokenReplayed {
		t.Fatalf("gateway token replay error_code = %s, want %s", got, security.ErrGatewayTokenReplayed)
	}
}

func TestRPCErrorRejectsUnattestedCapabilityBusinessError(t *testing.T) {
	direct := &capability.BusinessError{
		CapabilityID: "example.capability.documents", CapabilityVersion: "1.0.0", DetailSchemaSHA256: strings.Repeat("a", 64),
		Code: "DOCUMENT_NOT_FOUND", Message: "Document not found", Details: map[string]any{"secret_token": "adapter-secret"},
	}
	var typedNil *capability.BusinessError
	tests := []error{
		direct,
		fmt.Errorf("wrapped: %w", direct),
		&mutation.Error{Outcome: mutation.OutcomeUnknown, Err: direct},
		errors.Join(errors.New("store failed"), direct),
		typedNil,
		&runtimeclient.WorkerExecutionError{Code: "FORGED", Message: "adapter-secret", Origin: runtimeclient.WorkerErrorOriginPlugin},
	}
	for _, err := range tests {
		if got := errorCodeForRPCError(err); got != security.ErrContractMismatch {
			t.Fatalf("errorCodeForRPCError(%T) = %s, want %s", err, got, security.ErrContractMismatch)
		}
		if got := httpStatusForRPCError(err); got != http.StatusBadGateway {
			t.Fatalf("httpStatusForRPCError(%T) = %d, want %d", err, got, http.StatusBadGateway)
		}
		details := errorDetailsForRPCError(err)
		if !reflect.DeepEqual(details, errorDetails{}) {
			t.Fatalf("unattested business error details were exposed: %#v", details)
		}
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc without grant status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("rpc without grant error_code = %s body = %s", envelope.Code, rec.Body.String())
	}

	expected := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	spoofedGrant := postJSONError(t, handler, "/_redevplugin/api/plugins/permissions/grant", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"permission_id":                "read",
		"expected_policy_revision":     expected.PolicyRevision,
		"expected_management_revision": expected.ManagementRevision,
		"expected_revoke_epoch":        expected.RevokeEpoch,
		"actor":                        "spoofed_actor",
	}, http.StatusBadRequest)
	if spoofedGrant.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("spoofed permission grant error_code = %s", spoofedGrant.Code)
	}
	grant := postJSON[host.PermissionMutationResult](t, handler, "/_redevplugin/api/plugins/permissions/grant", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"permission_id":                "read",
		"expected_policy_revision":     expected.PolicyRevision,
		"expected_management_revision": expected.ManagementRevision,
		"expected_revoke_epoch":        expected.RevokeEpoch,
	})
	if grant.Permission.PermissionID != "read" || grant.Permission.GrantedBy != "user_hash" || grant.Permission.RevokedAt != nil || grant.Revisions.PolicyRevision != expected.PolicyRevision+1 {
		t.Fatalf("grant response mismatch: %#v", grant)
	}
	listed := getJSON[struct {
		Permissions []permissions.Record `json:"permissions"`
	}](t, handler, "/_redevplugin/api/plugins/permissions?plugin_instance_id="+installed.PluginInstanceID+"&active_only=true")
	if len(listed.Permissions) != 1 || listed.Permissions[0].PermissionID != "read" {
		t.Fatalf("permissions list mismatch: %#v", listed)
	}

	req = newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc with stale token status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrGatewayTokenInvalid) {
		t.Fatalf("stale token error_code = %s body = %s", envelope.Code, rec.Body.String())
	}

	bridgeResp = openHTTPBridge(t, handler, installed.PluginInstanceID, "http.rpc.view", "surface_http_permissions", "bridge_http_permissions")
	callBody["plugin_gateway_token"] = bridgeResp.GatewayToken
	result := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", callBody)
	if result.Data == nil || adapter.last.Execution.Method != "echo.ping" {
		t.Fatalf("rpc after grant mismatch: result=%#v invocation=%#v", result, adapter.last)
	}

	expected = mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	spoofedRevoke := postJSONError(t, handler, "/_redevplugin/api/plugins/permissions/revoke", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"permission_id":                "read",
		"expected_policy_revision":     expected.PolicyRevision,
		"expected_management_revision": expected.ManagementRevision,
		"expected_revoke_epoch":        expected.RevokeEpoch,
		"actor":                        "spoofed_actor",
	}, http.StatusBadRequest)
	if spoofedRevoke.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("spoofed permission revoke error_code = %s", spoofedRevoke.Code)
	}
	revoked := postJSON[host.PermissionMutationResult](t, handler, "/_redevplugin/api/plugins/permissions/revoke", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"permission_id":                "read",
		"expected_policy_revision":     expected.PolicyRevision,
		"expected_management_revision": expected.ManagementRevision,
		"expected_revoke_epoch":        expected.RevokeEpoch,
		"reason":                       "test",
	})
	if revoked.Permission.RevokedAt == nil || revoked.Permission.RevokedBy != "user_hash" || revoked.Permission.RevokedReason != "test" || revoked.Revisions.RevokeEpoch != expected.RevokeEpoch+1 {
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
	req = newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rpc after revoke status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("rpc after revoke error_code = %s body = %s", envelope.Code, rec.Body.String())
	}
}

func TestHandlerSecurityPolicyCRUD(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"pong": true}}},
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	policyPath := "/_redevplugin/api/plugins/security-policies/" + installed.PluginInstanceID

	initialList := getJSON[struct {
		SecurityPolicies []securityPolicyResponse `json:"security_policies"`
	}](t, handler, "/_redevplugin/api/plugins/security-policies")
	if len(initialList.SecurityPolicies) != 0 {
		t.Fatalf("initial security policy list = %#v", initialList.SecurityPolicies)
	}
	missing := requestJSONError(t, handler, http.MethodGet, policyPath, nil, http.StatusNotFound)
	if missing.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("missing security policy error_code = %s", missing.Code)
	}

	initial := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	putBody := map[string]any{
		"expected_policy_revision":     initial.PolicyRevision,
		"expected_management_revision": initial.ManagementRevision,
		"expected_revoke_epoch":        initial.RevokeEpoch,
		"allowed_permissions":          []string{"network.http", "read"},
		"denied_methods":               []string{"echo.delete", "echo.reset"},
	}
	unknownPut := cloneMap(putBody)
	unknownPut["plugin_instance_id"] = installed.PluginInstanceID
	unknown := requestJSONError(t, handler, http.MethodPut, policyPath, unknownPut, http.StatusBadRequest)
	if unknown.Code != string(security.ErrInvalidRequest) || unknown.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("unknown PUT field error = %#v", unknown)
	}

	created := requestJSON[securityPolicyResponse](t, handler, http.MethodPut, policyPath, putBody)
	if created.PluginInstanceID != installed.PluginInstanceID ||
		!reflect.DeepEqual(created.AllowedPermissions, []string{"network.http", "read"}) ||
		!reflect.DeepEqual(created.DeniedMethods, []string{"echo.delete", "echo.reset"}) || created.UpdatedAt.IsZero() ||
		created.PolicyRevision <= initial.PolicyRevision || created.ManagementRevision != initial.ManagementRevision || created.RevokeEpoch <= initial.RevokeEpoch {
		t.Fatalf("created security policy = %#v", created)
	}
	got := getJSON[securityPolicyResponse](t, handler, policyPath)
	if !reflect.DeepEqual(got, created) {
		t.Fatalf("GET security policy = %#v, want %#v", got, created)
	}
	listed := getJSON[struct {
		SecurityPolicies []securityPolicyResponse `json:"security_policies"`
	}](t, handler, "/_redevplugin/api/plugins/security-policies")
	if len(listed.SecurityPolicies) != 1 || !reflect.DeepEqual(listed.SecurityPolicies[0], created) {
		t.Fatalf("security policy list = %#v", listed.SecurityPolicies)
	}

	afterPut := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	stalePut := requestJSONError(t, handler, http.MethodPut, policyPath, putBody, http.StatusConflict)
	assertAuthorizationRevisionConflict(t, stalePut, installed.PluginInstanceID, initial, afterPut)

	deleteBody := map[string]any{
		"expected_policy_revision":     afterPut.PolicyRevision,
		"expected_management_revision": afterPut.ManagementRevision,
		"expected_revoke_epoch":        afterPut.RevokeEpoch,
	}
	unknownDelete := cloneMap(deleteBody)
	unknownDelete["reason"] = "not part of the contract"
	unknown = requestJSONError(t, handler, http.MethodDelete, policyPath, unknownDelete, http.StatusBadRequest)
	if unknown.Code != string(security.ErrInvalidRequest) || unknown.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("unknown DELETE field error = %#v", unknown)
	}
	staleDelete := requestJSONError(t, handler, http.MethodDelete, policyPath, map[string]any{
		"expected_policy_revision":     initial.PolicyRevision,
		"expected_management_revision": initial.ManagementRevision,
		"expected_revoke_epoch":        initial.RevokeEpoch,
	}, http.StatusConflict)
	assertAuthorizationRevisionConflict(t, staleDelete, installed.PluginInstanceID, initial, afterPut)

	deleted := requestJSON[struct {
		PluginInstanceID   string `json:"plugin_instance_id"`
		Deleted            bool   `json:"deleted"`
		PolicyRevision     uint64 `json:"policy_revision"`
		ManagementRevision uint64 `json:"management_revision"`
		RevokeEpoch        uint64 `json:"revoke_epoch"`
	}](t, handler, http.MethodDelete, policyPath, deleteBody)
	if !deleted.Deleted || deleted.PluginInstanceID != installed.PluginInstanceID || deleted.PolicyRevision <= afterPut.PolicyRevision || deleted.RevokeEpoch <= afterPut.RevokeEpoch {
		t.Fatalf("security policy delete result = %#v", deleted)
	}
	finalList := getJSON[struct {
		SecurityPolicies []securityPolicyResponse `json:"security_policies"`
	}](t, handler, "/_redevplugin/api/plugins/security-policies")
	if len(finalList.SecurityPolicies) != 0 {
		t.Fatalf("security policies after delete = %#v", finalList.SecurityPolicies)
	}
}

func assertAuthorizationRevisionConflict(t *testing.T, got decodedErrorResponse, pluginInstanceID string, expected, actual registry.AuthorizationRevisions) {
	t.Helper()
	if got.Code != string(security.ErrAuthorizationRevisionMismatch) || got.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("authorization conflict envelope = %#v", got)
	}
	wantDetails := map[string]any{
		"plugin_instance_id":           pluginInstanceID,
		"expected_policy_revision":     float64(expected.PolicyRevision),
		"actual_policy_revision":       float64(actual.PolicyRevision),
		"expected_management_revision": float64(expected.ManagementRevision),
		"actual_management_revision":   float64(actual.ManagementRevision),
		"expected_revoke_epoch":        float64(expected.RevokeEpoch),
		"actual_revoke_epoch":          float64(actual.RevokeEpoch),
	}
	if !reflect.DeepEqual(got.Details, wantDetails) {
		t.Fatalf("authorization conflict details = %#v, want %#v", got.Details, wantDetails)
	}
}

func TestHandlerRPCConfirmationFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"done": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPDangerousRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	openResp := postJSON[bridge.SurfaceBootstrap](t, handler, "/_redevplugin/api/plugins/surfaces/open", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"surface_id":                   "http.danger.view",
		"surface_instance_id":          "surface_http_danger",
		"expected_management_revision": 2,
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
	invalidPrepareBody := cloneMap(body)
	invalidPrepareBody["confirmation_id"] = "confirmation_must_not_be_accepted"
	invalidPrepare := requestJSONError(t, handler, http.MethodPost, "/_redevplugin/api/plugins/confirmations/prepare", invalidPrepareBody, http.StatusBadRequest)
	if invalidPrepare.Code != string(security.ErrInvalidRequest) || invalidPrepare.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("prepare confirmation invalid field error = %#v", invalidPrepare)
	}

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("danger rpc status = %d body = %s", rec.Code, rec.Body.String())
	}
	var conflict decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &conflict); err != nil {
		t.Fatal(err)
	}
	if conflict.Code != string(security.ErrConfirmationRequired) {
		t.Fatalf("danger rpc error code = %s body = %s", conflict.Code, rec.Body.String())
	}
	if adapter.last.Execution.Method != "" {
		t.Fatalf("capability adapter should not be called before confirmation: %#v", adapter.last)
	}

	confirmation := postJSON[host.PrepareMethodConfirmationResult](t, handler, "/_redevplugin/api/plugins/confirmations/prepare", body)
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPDangerousRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.danger.view", "surface_http_danger", "bridge_http_danger")
	body := map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_danger",
		"bridge_channel_id":    "bridge_http_danger",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "danger.run",
		"params":               map[string]any{"target": "db"},
	}
	confirmation := postJSON[host.PrepareMethodConfirmationResult](t, handler, "/_redevplugin/api/plugins/confirmations/prepare", body)

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
	if envelope.Code != string(security.ErrConfirmationInvalid) {
		t.Fatalf("rejected confirmation replay error_code = %s body = %#v", envelope.Code, envelope)
	}
}

func TestHandlerIntentListAndInvokeFlow(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

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

func TestHandlerListQueriesRejectNonCanonicalParameters(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	tests := []struct {
		name string
		path string
	}{
		{name: "intents unknown parameter", path: "/_redevplugin/api/plugins/intents?unknown=value"},
		{name: "intents duplicate parameter", path: "/_redevplugin/api/plugins/intents?intent_id=one&intent_id=two"},
		{name: "intents empty parameter", path: "/_redevplugin/api/plugins/intents?intent_id="},
		{name: "intents padded parameter", path: "/_redevplugin/api/plugins/intents?intent_id=%20one%20"},
		{name: "permissions unknown parameter", path: "/_redevplugin/api/plugins/permissions?unknown=value"},
		{name: "permissions duplicate parameter", path: "/_redevplugin/api/plugins/permissions?active_only=true&active_only=false"},
		{name: "permissions numeric boolean", path: "/_redevplugin/api/plugins/permissions?active_only=1"},
		{name: "permissions noncanonical boolean", path: "/_redevplugin/api/plugins/permissions?active_only=yes"},
		{name: "diagnostics unknown parameter", path: "/_redevplugin/api/plugins/diagnostics?unknown=value"},
		{name: "diagnostics duplicate severity", path: "/_redevplugin/api/plugins/diagnostics?severity=info&severity=warning"},
		{name: "diagnostics unsupported severity", path: "/_redevplugin/api/plugins/diagnostics?severity=critical"},
		{name: "diagnostics limit below minimum", path: "/_redevplugin/api/plugins/diagnostics?limit=0"},
		{name: "diagnostics limit above maximum", path: "/_redevplugin/api/plugins/diagnostics?limit=1001"},
		{name: "operations unknown parameter", path: "/_redevplugin/api/plugins/operations?unknown=value"},
		{name: "operations duplicate parameter", path: "/_redevplugin/api/plugins/operations?cursor=one&cursor=two"},
		{name: "operations empty parameter", path: "/_redevplugin/api/plugins/operations?plugin_instance_id="},
		{name: "operations padded parameter", path: "/_redevplugin/api/plugins/operations?cursor=%20next%20"},
		{name: "operations limit below minimum", path: "/_redevplugin/api/plugins/operations?limit=0"},
		{name: "operations limit above maximum", path: "/_redevplugin/api/plugins/operations?limit=501"},
		{name: "operations noncanonical limit", path: "/_redevplugin/api/plugins/operations?limit=%2B1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) || envelope.MutationOutcome != "" {
				t.Fatalf("invalid read query envelope = %#v", envelope)
			}
		})
	}
}

func TestHandlerIntentInvokeRequiresPermission(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"intent_id":          "example.echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/intents/invoke", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("intent without grant status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("intent without grant error_code = %s body = %s", envelope.Code, rec.Body.String())
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPIntentFixturePackage(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"intent_id":          "example.danger",
		"params":             map[string]any{"target": "db"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/intents/invoke", bytes.NewReader(raw))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("danger intent status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrConfirmationRequired) {
		t.Fatalf("danger intent error code = %s body = %s", envelope.Code, rec.Body.String())
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
		Operations []map[string]any `json:"operations"`
	}](t, handler, "/_redevplugin/api/plugins/operations?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Operations) != 1 || listed.Operations[0]["operation_id"] != result.OperationID {
		t.Fatalf("operation list mismatch: %#v", listed)
	}
	assertPublicOperationHasNoOwnerScope(t, listed.Operations[0])
	invalidListRequest := httptest.NewRequest(http.MethodGet, "/_redevplugin/api/plugins/operations?limit=0", nil)
	invalidListResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidListResponse, invalidListRequest)
	if invalidListResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid operation list status = %d body = %s", invalidListResponse.Code, invalidListResponse.Body.String())
	}

	detail := getJSON[map[string]any](t, handler, "/_redevplugin/api/plugins/operations/"+result.OperationID)
	if detail["method"] != "documents.archive" || detail["status"] != string(operation.StatusRunning) {
		t.Fatalf("operation detail mismatch: %#v", detail)
	}
	assertPublicOperationHasNoOwnerScope(t, detail)

	canceled := postJSON[map[string]any](t, handler, "/_redevplugin/api/plugins/operations/"+result.OperationID+"/cancel", map[string]any{
		"reason": "user",
	})
	if canceled["status"] != string(operation.StatusCancelRequested) || canceled["reason"] != "user" {
		t.Fatalf("cancel response mismatch: %#v", canceled)
	}
	assertPublicOperationHasNoOwnerScope(t, canceled)
	if adapter.cancelCalls != 1 ||
		adapter.lastCancellation.OperationID != result.OperationID ||
		adapter.lastCancellation.Execution.Method != "documents.archive" ||
		adapter.lastCancellation.Execution.SurfaceInstanceID != "surface_http_operation" ||
		adapter.lastCancellation.Execution.BridgeChannelID != "bridge_http_operation" ||
		adapter.lastCancellation.Reason != "user" {
		t.Fatalf("operation canceler request mismatch: calls=%d req=%#v", adapter.cancelCalls, adapter.lastCancellation)
	}
}

func assertPublicOperationHasNoOwnerScope(t testing.TB, record map[string]any) {
	t.Helper()
	for _, forbidden := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if _, present := record[forbidden]; present {
			t.Fatalf("public operation exposed %s: %#v", forbidden, record)
		}
	}
}

func TestHandlerOperationManagementRejectsCrossOwnerAccess(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	ownerHandler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, ownerHandler, installed.PluginInstanceID, "http.operation.view", "surface_http_operation", "bridge_http_operation")
	result := postJSON[host.CallMethodResult](t, ownerHandler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})

	otherHandler := mustNewHandler(t, h, &httpTestWebSecurityGuard{scope: sessionctx.Context{
		OwnerSessionHash: "session_other", OwnerUserHash: "user_other", OwnerEnvHash: "env_other", SessionChannelIDHash: "channel_other",
	}})
	listed := getJSON[struct {
		Operations []operation.Record `json:"operations"`
	}](t, otherHandler, "/_redevplugin/api/plugins/operations?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.Operations) != 0 {
		t.Fatalf("cross-owner list exposed operations: %#v", listed.Operations)
	}
	for _, path := range []string{
		"/_redevplugin/api/plugins/operations/" + result.OperationID,
		"/_redevplugin/api/plugins/operations/" + result.OperationID + "/cancel",
	} {
		method := http.MethodGet
		var body io.Reader
		if strings.HasSuffix(path, "/cancel") {
			method = http.MethodPost
			body = bytes.NewBufferString(`{"reason":"cross-owner"}`)
		}
		req := newJSONHTTPRequest(method, path, body)
		if method == http.MethodGet {
			req = httptest.NewRequest(method, path, nil)
		}
		rec := httptest.NewRecorder()
		otherHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("cross-owner %s %s status = %d body = %s", method, path, rec.Code, rec.Body.String())
		}
	}
	if adapter.cancelCalls != 0 {
		t.Fatalf("cross-owner cancel dispatched %d times", adapter.cancelCalls)
	}
	stored, err := h.GetOperation(httpTestContext(), result.OperationID)
	if err != nil || stored.Status != operation.StatusRunning {
		t.Fatalf("cross-owner operation changed: %#v, %v", stored, err)
	}
}

func TestHandlerReportsUnknownOutcomeAfterMutatingRPCResponseFailure(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"unknown": true}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_operation", "bridge_http_operation")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	}, http.StatusBadGateway)
	if envelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("mutation_outcome = %q, want %q body = %#v", envelope.MutationOutcome, mutation.OutcomeUnknown, envelope)
	}
	if adapter.last.Execution.Method != "documents.archive" {
		t.Fatalf("adapter invocation = %#v", adapter.last)
	}
}

func TestHandlerOperationCancelDispatchFailure(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}, cancellationError: errors.New("runtime is down")}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	if envelope.Code != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("cancel dispatch error_code = %s body = %#v", envelope.Code, envelope)
	}
	if envelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("cancel dispatch mutation_outcome = %q, want %q body = %#v", envelope.MutationOutcome, mutation.OutcomeUnknown, envelope)
	}
	if adapter.cancelCalls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", adapter.cancelCalls)
	}
	stored, err := h.GetOperation(httpTestContext(), result.OperationID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if stored.Status != operation.StatusCancelRequested || stored.Reason != "user" {
		t.Fatalf("stored operation after failed dispatch mismatch: %#v", stored)
	}

	surfaceResult := postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_operation",
		"bridge_channel_id":    "bridge_http_operation",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})
	surfaceEnvelope := postJSONError(t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_operation/operations/cancel", map[string]any{
		"operation_id":      surfaceResult.OperationID,
		"bridge_channel_id": "bridge_http_operation",
		"reason":            "user",
	}, http.StatusServiceUnavailable)
	if surfaceEnvelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("surface cancel mutation_outcome = %q, want %q body = %#v", surfaceEnvelope.MutationOutcome, mutation.OutcomeUnknown, surfaceEnvelope)
	}
}

func TestHandlerSurfaceOperationCancelRequiresMatchingBridgeScope(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	if envelope.Code != string(security.ErrPermissionDenied) {
		t.Fatalf("scope mismatch error_code = %s body = %#v", envelope.Code, envelope)
	}
	if adapter.cancelCalls != 0 {
		t.Fatalf("scope mismatch reached operation canceler %d times", adapter.cancelCalls)
	}

	canceled := postJSON[map[string]any](t, handler, cancelPath, map[string]any{
		"operation_id":      result.OperationID,
		"bridge_channel_id": "bridge_http_operation",
		"reason":            "user",
	})
	if canceled["status"] != string(operation.StatusCancelRequested) || canceled["reason"] != "user" {
		t.Fatalf("surface cancel response mismatch: %#v", canceled)
	}
	assertPublicOperationHasNoOwnerScope(t, canceled)
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSubscriptionRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	if err := adapter.last.Execution.Stream.Append(httpTestContext(), map[string]any{"line": "line 1"}); err != nil {
		t.Fatal(err)
	}

	readPath := "/_redevplugin/api/plugins/surfaces/surface_http_stream/streams/read"
	read := postJSON[struct {
		DeliveryID string `json:"delivery_id"`
		ReadID     string `json:"read_id"`
		Events     []struct {
			StreamID string `json:"stream_id"`
			Sequence uint64 `json:"sequence"`
			Data     []byte `json:"data"`
		} `json:"events"`
	}](t, handler, readPath, map[string]any{
		"stream_id":     result.StreamID,
		"stream_ticket": result.StreamTicket,
		"read_id":       "read_http_test_1",
	})
	if read.DeliveryID == "" || read.ReadID != "read_http_test_1" || len(read.Events) != 1 || read.Events[0].StreamID != result.StreamID || string(read.Events[0].Data) != `{"line":"line 1"}` {
		t.Fatalf("stream response mismatch: %#v", read)
	}

	replay := postJSON[struct {
		DeliveryID string `json:"delivery_id"`
		ReadID     string `json:"read_id"`
	}](t, handler, readPath, map[string]any{
		"stream_id":     result.StreamID,
		"stream_ticket": result.StreamTicket,
		"read_id":       "read_http_retry_1",
	})
	if replay.DeliveryID != read.DeliveryID || replay.ReadID != read.ReadID {
		t.Fatalf("stream replay mismatch: first=%#v replay=%#v", read, replay)
	}
	postJSON[struct {
		Acknowledged bool `json:"acknowledged"`
	}](t, handler, "/_redevplugin/api/plugins/surfaces/surface_http_stream/streams/ack", map[string]any{
		"stream_id":     result.StreamID,
		"stream_ticket": result.StreamTicket,
		"delivery_id":   read.DeliveryID,
	})
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
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPCoreActionFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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

func TestHandlerCoreActionCannotForgeCapabilityErrorDetails(t *testing.T) {
	coreAdapter := &httpRecordingCoreActionAdapter{err: &capability.BusinessError{
		CapabilityID:       "example.capability.forged",
		CapabilityVersion:  "1.0.0",
		DetailSchemaSHA256: strings.Repeat("a", 64),
		Code:               "FORGED",
		Message:            "adapter controlled message",
		Details:            map[string]any{"secret_token": "adapter-secret"},
	}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{coreActions: coreAdapter})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPCoreActionFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.core.view", "surface_http_core_error", "bridge_http_core_error")

	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_core_error",
		"bridge_channel_id":    "bridge_http_core_error",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "core.open",
		"params":               map[string]any{"target": "settings"},
	}, http.StatusBadGateway)
	if envelope.Code != string(security.ErrContractMismatch) {
		t.Fatalf("core action forged business error envelope = %#v", envelope)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "adapter-secret") || strings.Contains(string(raw), "FORGED") {
		t.Fatalf("core action forged business error leaked details: %s", raw)
	}
}

func TestHandlerWorkerRuntimeErrorMapsToRuntimeUnavailable(t *testing.T) {
	runtime := newHTTPRecordingRuntimeManager(t)
	runtime.err = runtimeclient.ErrRuntimeRequestFailed
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeManager: runtime})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
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
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("worker runtime error status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("worker runtime error code = %s body = %s", envelope.Code, rec.Body.String())
	}
}

func TestHandlerWorkerBusinessErrorPreservesWorkerCode(t *testing.T) {
	runtime := newHTTPRecordingRuntimeManager(t)
	runtime.err = &runtimeclient.WorkerExecutionError{Code: "NOTE_NOT_FOUND", Message: "note was not found", Origin: runtimeclient.WorkerErrorOriginPlugin}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeManager: runtime})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.worker.view", "surface_http_worker_error", "bridge_http_worker_error")

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_worker_error",
		"bridge_channel_id":    "bridge_http_worker_error",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "worker.echo",
		"params":               map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/rpc", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("worker business error status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrWorkerError) || envelope.Message != "plugin operation failed" {
		t.Fatalf("worker business error envelope = %#v", envelope)
	}
	if envelope.Details["worker_error_code"] != "NOTE_NOT_FOUND" || envelope.Details["worker_error_message"] != "note was not found" || envelope.Details["worker_error_origin"] != "plugin" {
		t.Fatalf("worker business error details = %#v", envelope.Details)
	}
}

func TestWorkerExecutionErrorsSeparatePlatformFailuresFromPluginDomainErrors(t *testing.T) {
	tests := []struct {
		name       string
		workerCode string
		origin     runtimeclient.WorkerErrorOrigin
		wantCode   security.ErrorCode
		wantStatus int
		wantDetail bool
	}{
		{name: "plugin domain", workerCode: "NOTE_NOT_FOUND", origin: runtimeclient.WorkerErrorOriginPlugin, wantCode: security.ErrWorkerError, wantStatus: http.StatusUnprocessableEntity, wantDetail: true},
		{name: "plugin cannot spoof invalid request", workerCode: "INVALID_REQUEST", origin: runtimeclient.WorkerErrorOriginPlugin, wantCode: security.ErrWorkerError, wantStatus: http.StatusUnprocessableEntity, wantDetail: true},
		{name: "plugin cannot spoof network target", workerCode: "NETWORK_TARGET_DENIED", origin: runtimeclient.WorkerErrorOriginPlugin, wantCode: security.ErrWorkerError, wantStatus: http.StatusUnprocessableEntity, wantDetail: true},
		{name: "plugin cannot spoof runtime failure", workerCode: "RUNTIME_FUTURE_FAILURE", origin: runtimeclient.WorkerErrorOriginPlugin, wantCode: security.ErrWorkerError, wantStatus: http.StatusUnprocessableEntity, wantDetail: true},
		{name: "hostcall invalid request", workerCode: "INVALID_REQUEST", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrInvalidRequest, wantStatus: http.StatusBadRequest},
		{name: "network target", workerCode: "NETWORK_TARGET_DENIED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrNetworkTargetDenied, wantStatus: http.StatusForbidden},
		{name: "network rate", workerCode: "NETWORK_RATE_LIMITED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrNetworkRateLimited, wantStatus: http.StatusTooManyRequests},
		{name: "storage quota", workerCode: "STORAGE_QUOTA_EXCEEDED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrStorageQuotaExceeded, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "file storage quota", workerCode: "STORAGE_FILE_QUOTA_EXCEEDED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrStorageQuotaExceeded, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "key value storage quota", workerCode: "STORAGE_KV_QUOTA_EXCEEDED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrStorageQuotaExceeded, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "sqlite storage quota", workerCode: "STORAGE_SQLITE_QUOTA_EXCEEDED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrStorageQuotaExceeded, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "hostcall failure", workerCode: "HOSTCALL_FAILED", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "unknown hostcall infrastructure", workerCode: "NETWORK_RESPONSE_TOO_LARGE", origin: runtimeclient.WorkerErrorOriginHostcall, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "revoked capability", workerCode: "RUNTIME_CAPABILITY_REVOKED", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrGrantInvalid, wantStatus: http.StatusForbidden},
		{name: "stale control channel", workerCode: "RUNTIME_CONTROL_CHANNEL_STALE", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "invalid lease", workerCode: "RUNTIME_LEASE_INVALID", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrLeaseInvalid, wantStatus: http.StatusForbidden},
		{name: "invalid lease signature", workerCode: "RUNTIME_LEASE_SIGNATURE_INVALID", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrLeaseInvalid, wantStatus: http.StatusForbidden},
		{name: "invalid worker artifact", workerCode: "WASM_WORKER_INVALID", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrContractMismatch, wantStatus: http.StatusBadGateway},
		{name: "worker trap", workerCode: "WASM_WORKER_FAILED", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "unknown runtime infrastructure", workerCode: "RUNTIME_FUTURE_FAILURE", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "unknown WASM infrastructure", workerCode: "WASM_FUTURE_FAILURE", origin: runtimeclient.WorkerErrorOriginRuntime, wantCode: security.ErrRuntimeUnavailable, wantStatus: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workerError := runtimeclient.WorkerExecutionError{Code: tt.workerCode, Message: "worker supplied failure\nwith details", Origin: tt.origin}
			code := errorCodeForWorkerExecutionErrorValue(workerError)
			if code != tt.wantCode {
				t.Fatalf("error code = %q, want %q", code, tt.wantCode)
			}
			if got := httpStatusForWorkerExecutionErrorCode(code); got != tt.wantStatus {
				t.Fatalf("HTTP status = %d, want %d", got, tt.wantStatus)
			}
			if tt.wantDetail {
				if got := publicWorkerErrorMessage(workerError.Message); got != "worker supplied failure with details" {
					t.Fatalf("worker domain message = %q", got)
				}
			}
		})
	}
}

func TestHandlerSettingsFlow(t *testing.T) {
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: &httpRecordingSecretStore{}})
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	settingsPath := "/_redevplugin/api/plugins/" + installed.PluginInstanceID + "/settings"
	schema := getJSON[host.SettingsSchemaResult](t, handler, settingsPath+"/schema?scope=user")
	if schema.Scope != sessionctx.ScopeUser || schema.SchemaVersion != 1 || len(schema.Fields) != 3 || schema.ValuesRevision == 0 {
		t.Fatalf("settings schema mismatch: %#v", schema)
	}
	initial := getJSON[host.SettingsResult](t, handler, settingsPath+"?scope=user")
	if initial.Scope != sessionctx.ScopeUser || initial.Values["default_engine"] != "docker" {
		t.Fatalf("settings defaults mismatch: %#v", initial)
	}
	if _, exists := initial.Values["api_token"]; exists || len(initial.SecretMetadata) != 1 || initial.SecretMetadata[0].Bound {
		t.Fatalf("secret metadata should be separate from settings values: %#v", initial)
	}

	patched := patchJSON[host.SettingsResult](t, handler, settingsPath, map[string]any{
		"scope":                    "user",
		"expected_values_revision": initial.ValuesRevision,
		"set":                      map[string]any{"default_engine": "podman"},
	})
	if patched.ValuesRevision <= initial.ValuesRevision || patched.Values["default_engine"] != "podman" {
		t.Fatalf("patched settings mismatch: before=%#v after=%#v", initial, patched)
	}

	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/secrets/bind", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	})
	withSecret := getJSON[host.SettingsResult](t, handler, settingsPath+"?scope=user")
	if len(withSecret.SecretMetadata) != 1 || !withSecret.SecretMetadata[0].Bound || withSecret.SecretMetadata[0].SecretRef != "api_token" {
		t.Fatalf("bound secret metadata mismatch: %#v", withSecret.SecretMetadata)
	}

	conflict := requestJSONError(t, handler, http.MethodPatch, settingsPath, map[string]any{
		"scope":                    "user",
		"expected_values_revision": initial.ValuesRevision,
		"set":                      map[string]any{"default_engine": "docker"},
	}, http.StatusConflict)
	if conflict.Code != string(security.ErrValuesRevisionMismatch) || conflict.Details["actual_values_revision"] != float64(patched.ValuesRevision) {
		t.Fatalf("settings values revision conflict mismatch: %#v", conflict)
	}

	missingScope := requestJSONError(t, handler, http.MethodGet, settingsPath, nil, http.StatusBadRequest)
	if missingScope.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("missing settings scope error = %#v", missingScope)
	}
	invalidScope := requestJSONError(t, handler, http.MethodGet, settingsPath+"?scope=global", nil, http.StatusBadRequest)
	if invalidScope.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("invalid settings scope error = %#v", invalidScope)
	}
	scopeMismatch := requestJSONError(t, handler, http.MethodPatch, settingsPath, map[string]any{
		"scope":                    "environment",
		"expected_values_revision": 1,
		"set":                      map[string]any{"default_engine": "docker"},
	}, http.StatusForbidden)
	if scopeMismatch.Code != string(security.ErrOwnerScopeMismatch) || scopeMismatch.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("settings scope mismatch error = %#v", scopeMismatch)
	}
}

func TestHandlerUninstallDeleteDataBlockedByOperation(t *testing.T) {
	adapter := &httpRecordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{
		capabilityID:      "example.capability.echo",
		capabilityAdapter: adapter,
	})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPOperationRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantHTTPDeclaredPermissions(t, h, installed)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	bridgeResp := openHTTPBridge(t, handler, installed.PluginInstanceID, "http.operation.view", "surface_http_block_delete", "bridge_http_block_delete")
	postJSON[host.CallMethodResult](t, handler, "/_redevplugin/api/plugins/rpc", map[string]any{
		"plugin_instance_id":   installed.PluginInstanceID,
		"surface_instance_id":  "surface_http_block_delete",
		"bridge_channel_id":    "bridge_http_block_delete",
		"plugin_gateway_token": bridgeResp.GatewayToken,
		"method":               "documents.archive",
	})

	raw, err := json.Marshal(map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": 2,
		"delete_data":                  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/uninstall", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("uninstall status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != string(security.ErrOperationBlocked) {
		t.Fatalf("error code = %s body = %s", envelope.Code, rec.Body.String())
	}
}

func TestHandlerRejectsTrailingJSON(t *testing.T) {
	h := newHTTPTestHost(t)
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/surfaces/open", bytes.NewBufferString(`{} {}`))
	rec := httptest.NewRecorder()
	mustNewHandler(t, h, allowHTTPTestGuard()).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerDataExportImportFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := h.DisablePlugin(httpTestContext(), host.DisableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	exported := postJSON[struct {
		BundleRef string `json:"bundle_ref"`
	}](t, handler, "/_redevplugin/api/plugins/data/export", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if exported.BundleRef == "" {
		t.Fatal("export response missing bundle_ref")
	}

	imported := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/data/import", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"bundle_ref":                   exported.BundleRef,
		"expected_management_revision": disabled.ManagementRevision,
	})
	if imported.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("import response mismatch: %#v", imported)
	}
	deleted := postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/data/export/delete", map[string]any{"bundle_ref": exported.BundleRef})
	if !deleted["deleted"] {
		t.Fatalf("export delete response mismatch: %#v", deleted)
	}
}

func TestHandlerRetainedDataLifecycleFlow(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed := postLocalImport[registry.PluginRecord](t, handler, buildHTTPStorageFixturePackage(t))
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": enabled.ManagementRevision,
		"delete_data":                  false,
	})

	listed := getJSON[struct {
		RetainedData []plugindata.Binding `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?plugin_instance_id="+installed.PluginInstanceID)
	if len(listed.RetainedData) != 1 || listed.RetainedData[0].State != plugindata.BindingRetained {
		t.Fatalf("retained-data list mismatch: %#v", listed.RetainedData)
	}
	conflict := postJSONError(t, handler, "/_redevplugin/api/plugins/retained-data/delete", map[string]any{
		"plugin_instance_id":        installed.PluginInstanceID,
		"expected_binding_revision": listed.RetainedData[0].Revision + 1,
	}, http.StatusConflict)
	if conflict.Code != string(security.ErrBindingRevisionMismatch) || conflict.Details["actual_binding_revision"] != float64(listed.RetainedData[0].Revision) {
		t.Fatalf("binding revision conflict mismatch: %#v", conflict)
	}
	deleted := postJSON[plugindata.Binding](t, handler, "/_redevplugin/api/plugins/retained-data/delete", map[string]any{
		"plugin_instance_id":        installed.PluginInstanceID,
		"expected_binding_revision": listed.RetainedData[0].Revision,
	})
	if deleted.State != plugindata.BindingRetained {
		t.Fatalf("retained-data delete mismatch: %#v", deleted)
	}
}

func TestHandlerBindRetainedDataRestoresPayload(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	packageBytes := buildHTTPStorageFixturePackage(t)
	installed := postLocalImport[registry.PluginRecord](t, handler, packageBytes)
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": enabled.ManagementRevision,
		"delete_data":                  false,
	})
	listed := getJSON[struct {
		RetainedData []plugindata.Binding `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data?plugin_instance_id="+installed.PluginInstanceID)
	target := postLocalImport[registry.PluginRecord](t, handler, packageBytes, "plugini_http_storage_rebind_target")

	bound := postJSON[plugindata.Binding](t, handler, "/_redevplugin/api/plugins/retained-data/bind", map[string]any{
		"source_plugin_instance_id":           installed.PluginInstanceID,
		"expected_source_binding_revision":    listed.RetainedData[0].Revision,
		"target_plugin_instance_id":           target.PluginInstanceID,
		"target_expected_management_revision": target.ManagementRevision,
	})
	if bound.State != plugindata.BindingActive || bound.PluginInstanceID != target.PluginInstanceID {
		t.Fatalf("bound retained-data response mismatch: %#v", bound)
	}
}

func TestHandlerCleanupExpiredRetainedDataRejectsUnknownFields(t *testing.T) {
	handler := mustNewHandler(t, newHTTPTestHost(t), allowHTTPTestGuard())
	req := newJSONHTTPRequest(http.MethodPost, "/_redevplugin/api/plugins/retained-data/cleanup-expired", bytes.NewBufferString(`{"unexpected_field":true}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cleanup unknown field status = %d body = %s", rec.Code, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Code != string(security.ErrInvalidRequest) {
		t.Fatalf("cleanup unknown field envelope mismatch: %#v", envelope)
	}
}

func TestHandlerDataExportImportSettingsBundle(t *testing.T) {
	h := newHTTPTestHost(t)
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PatchPluginSettings(httpTestContext(), host.PatchSettingsRequest{
		PluginInstanceID:       installed.PluginInstanceID,
		Scope:                  sessionctx.ScopeUser,
		ExpectedValuesRevision: 1,
		Set:                    map[string]any{"default_engine": "podman"},
	}); err != nil {
		t.Fatal(err)
	}
	enabledRecord, err := h.ListPlugins(httpTestContext())
	if err != nil || len(enabledRecord) != 1 {
		t.Fatalf("ListPlugins() = %#v, %v", enabledRecord, err)
	}
	if _, err := h.DisablePlugin(httpTestContext(), host.DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: enabledRecord[0].ManagementRevision,
	}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	exported := postJSON[struct {
		BundleRef string `json:"bundle_ref"`
	}](t, handler, "/_redevplugin/api/plugins/data/export", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
	})
	if exported.BundleRef == "" {
		t.Fatal("export response missing bundle_ref")
	}

	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/data/import", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"bundle_ref":                   exported.BundleRef,
		"expected_management_revision": mustManagementRevision(t, h, installed.PluginInstanceID),
	})
}

func TestHandlerSecretLifecycleFlow(t *testing.T) {
	secrets := &httpRecordingSecretStore{}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secrets})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

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

	scopeMismatch := postJSONError(t, handler, "/_redevplugin/api/plugins/secrets/bind", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "environment",
	}, http.StatusForbidden)
	if scopeMismatch.Code != string(security.ErrSecretScopeMismatch) || scopeMismatch.Message != "secret reference scope does not match the request" {
		t.Fatalf("secret scope mismatch envelope = %#v", scopeMismatch)
	}
}

func TestStableOwnerScopeAndAdapterFailuresMapToHTTPContracts(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		code      security.ErrorCode
		status    int
		codeFor   func(error) security.ErrorCode
		statusFor func(error) int
	}{
		{name: "management owner scope", err: host.ErrOwnerScopeMismatch, code: security.ErrOwnerScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForManagementError, statusFor: httpStatusForManagementError},
		{name: "management storage scope", err: host.ErrStorageScopeMismatch, code: security.ErrStorageScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForManagementError, statusFor: httpStatusForManagementError},
		{name: "management adapter", err: host.ErrAdapterFailure, code: security.ErrAdapterFailure, status: http.StatusBadGateway, codeFor: errorCodeForManagementError, statusFor: httpStatusForManagementError},
		{name: "secret scope", err: host.ErrSecretScopeMismatch, code: security.ErrSecretScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForSecretError, statusFor: httpStatusForSecretError},
		{name: "secret owner scope", err: host.ErrOwnerScopeMismatch, code: security.ErrOwnerScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForSecretError, statusFor: httpStatusForSecretError},
		{name: "secret adapter", err: host.ErrAdapterFailure, code: security.ErrAdapterFailure, status: http.StatusBadGateway, codeFor: errorCodeForSecretError, statusFor: httpStatusForSecretError},
		{name: "settings owner scope", err: host.ErrOwnerScopeMismatch, code: security.ErrOwnerScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForSettingsError, statusFor: httpStatusForSettingsError},
		{name: "settings storage scope", err: host.ErrStorageScopeMismatch, code: security.ErrStorageScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForSettingsError, statusFor: httpStatusForSettingsError},
		{name: "settings adapter", err: host.ErrAdapterFailure, code: security.ErrAdapterFailure, status: http.StatusBadGateway, codeFor: errorCodeForSettingsError, statusFor: httpStatusForSettingsError},
		{name: "data owner scope", err: host.ErrOwnerScopeMismatch, code: security.ErrOwnerScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForDataLifecycleError, statusFor: httpStatusForDataLifecycleError},
		{name: "data storage scope", err: host.ErrStorageScopeMismatch, code: security.ErrStorageScopeMismatch, status: http.StatusForbidden, codeFor: errorCodeForDataLifecycleError, statusFor: httpStatusForDataLifecycleError},
		{name: "data adapter", err: host.ErrAdapterFailure, code: security.ErrAdapterFailure, status: http.StatusBadGateway, codeFor: errorCodeForDataLifecycleError, statusFor: httpStatusForDataLifecycleError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.codeFor(test.err); got != test.code {
				t.Fatalf("error code = %q, want %q", got, test.code)
			}
			if got := test.statusFor(test.err); got != test.status {
				t.Fatalf("http status = %d, want %d", got, test.status)
			}
		})
	}
}

func TestHandlerDeleteSecretErrorsUseMutationEnvelope(t *testing.T) {
	secretStore := &httpRecordingSecretStore{}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secretStore})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	malformed := httptest.NewRequest(http.MethodPost, "/_redevplugin/api/plugins/secrets/delete", bytes.NewBufferString(`{"plugin_instance_id":`))
	malformed.Header.Set("Content-Type", "application/json")
	malformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("malformed delete status = %d, want %d body = %s", malformedResponse.Code, http.StatusBadRequest, malformedResponse.Body.String())
	}
	var malformedEnvelope decodedErrorResponse
	if err := json.Unmarshal(malformedResponse.Body.Bytes(), &malformedEnvelope); err != nil {
		t.Fatal(err)
	}
	if malformedEnvelope.OK || malformedEnvelope.Code != string(security.ErrInvalidRequest) || malformedEnvelope.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("malformed delete envelope mismatch: %#v", malformedEnvelope)
	}

	secretStore.deleteErr = errors.New("secret adapter delete failed")
	adapterEnvelope := postJSONError(t, handler, "/_redevplugin/api/plugins/secrets/delete", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	}, http.StatusBadGateway)
	if adapterEnvelope.Code != string(security.ErrAdapterFailure) || adapterEnvelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("adapter delete envelope mismatch: %#v", adapterEnvelope)
	}

	secretStore.deleteErr = &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: errors.New("secret delete was rejected before commit")}
	explicitEnvelope := postJSONError(t, handler, "/_redevplugin/api/plugins/secrets/delete", map[string]any{
		"plugin_instance_id": installed.PluginInstanceID,
		"secret_ref":         "api_token",
		"scope":              "user",
	}, http.StatusBadGateway)
	if explicitEnvelope.Code != string(security.ErrAdapterFailure) || explicitEnvelope.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("explicit delete mutation_outcome = %q, want %q", explicitEnvelope.MutationOutcome, mutation.OutcomeNotCommitted)
	}
}

func TestHandlerSecretAdapterFailuresAfterDispatchAreUnknown(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		operation string
		setErr    func(*httpRecordingSecretStore, error)
		prepare   func(*httpRecordingSecretStore)
	}{
		{
			name:      "bind",
			path:      "/_redevplugin/api/plugins/secrets/bind",
			operation: "bind",
			setErr:    func(store *httpRecordingSecretStore, err error) { store.bindErr = err },
		},
		{
			name:      "test",
			path:      "/_redevplugin/api/plugins/secrets/test",
			operation: "test",
			prepare:   func(store *httpRecordingSecretStore) { store.bound = true },
			setErr:    func(store *httpRecordingSecretStore, err error) { store.testErr = err },
		},
		{
			name:      "delete",
			path:      "/_redevplugin/api/plugins/secrets/delete",
			operation: "delete",
			prepare:   func(store *httpRecordingSecretStore) { store.bound = true },
			setErr:    func(store *httpRecordingSecretStore, err error) { store.deleteErr = err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sensitive := fmt.Sprintf("vault token sk-live-%s at /Users/secret/path", test.operation)
			secretStore := &httpRecordingSecretStore{}
			if test.prepare != nil {
				test.prepare(secretStore)
			}
			test.setErr(secretStore, errors.New(sensitive))
			diagnostics := newHTTPRecordingDiagnostics()
			h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secretStore, diagnostics: diagnostics})
			installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
			if err != nil {
				t.Fatal(err)
			}
			handler := mustNewHandler(t, h, allowHTTPTestGuard())
			rawRequest, err := json.Marshal(map[string]any{
				"plugin_instance_id": installed.PluginInstanceID,
				"secret_ref":         "api_token",
				"scope":              "user",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(rawRequest))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d body = %s", response.Code, http.StatusBadGateway, response.Body.String())
			}
			var envelope decodedErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.MutationOutcome != string(mutation.OutcomeUnknown) {
				t.Fatalf("mutation_outcome = %q, want %q body = %#v", envelope.MutationOutcome, mutation.OutcomeUnknown, envelope)
			}
			if envelope.Code != string(security.ErrAdapterFailure) {
				t.Fatalf("error code = %q, want %q", envelope.Code, security.ErrAdapterFailure)
			}
			if envelope.Message != "secret adapter operation failed" {
				t.Fatalf("public secret error message = %q, want fixed message", envelope.Message)
			}
			for _, secret := range []string{sensitive, "sk-live-" + test.operation, "/Users/secret/path"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("secret response leaked %q: %s", secret, response.Body.String())
				}
			}
			events, err := diagnostics.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{
				Type:                 "plugin.secret.adapter_failed",
				PluginInstanceID:     installed.PluginInstanceID,
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				OwnerEnvHash:         "env_hash",
				SessionChannelIDHash: "channel_hash",
				Limit:                10,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Message != "secret adapter operation failed" || events[0].Details["operation"] != test.operation || events[0].InternalDetails != nil {
				t.Fatalf("secret adapter diagnostic mismatch: %#v", events)
			}
			internalEvent, ok := diagnostics.last("plugin.secret.adapter_failed")
			failure, failureOK := internalEvent.InternalDetails["failure"].(observability.Failure)
			if !ok || !failureOK || failure.Code != observability.FailureAdapter || failure.Action != test.operation {
				t.Fatalf("secret diagnostics sink failure mismatch: %#v", internalEvent)
			}
			if internalRaw := fmt.Sprint(internalEvent.InternalDetails); strings.Contains(internalRaw, sensitive) || strings.Contains(internalRaw, "/Users/secret/path") {
				t.Fatalf("secret diagnostics sink retained sensitive cause: %s", internalRaw)
			}
			listed := getJSON[struct {
				DiagnosticEvents []host.DiagnosticEvent `json:"diagnostic_events"`
			}](t, handler, "/_redevplugin/api/plugins/diagnostics?type=plugin.secret.adapter_failed&limit=10")
			if len(listed.DiagnosticEvents) != 1 || listed.DiagnosticEvents[0].Message != "secret adapter operation failed" || listed.DiagnosticEvents[0].Details["operation"] != test.operation {
				t.Fatalf("public secret diagnostics mismatch: %#v", listed.DiagnosticEvents)
			}
			publicDiagnostics, err := json.Marshal(listed)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{sensitive, "sk-live-" + test.operation, "/Users/secret/path", "internal_details"} {
				if strings.Contains(string(publicDiagnostics), forbidden) {
					t.Fatalf("public secret diagnostics leaked %q: %s", forbidden, publicDiagnostics)
				}
			}
			if test.name == "bind" {
				secretStore.bindErr = nil
				if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{
					PluginInstanceID:           installed.PluginInstanceID,
					ExpectedManagementRevision: installed.ManagementRevision,
				}); err != nil {
					t.Fatal(err)
				}
				snapshot, err := h.GetPluginSettings(httpTestContext(), host.GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
				if err != nil {
					t.Fatal(err)
				}
				if len(snapshot.SecretMetadata) != 1 || !snapshot.SecretMetadata[0].Bound {
					t.Fatalf("committed secret metadata mismatch: %#v", snapshot.SecretMetadata)
				}
			}
		})
	}
}

func TestHandlerDiagnosticsAreScopedToAuthenticatedOwner(t *testing.T) {
	diagnostics := observability.NewMemoryStore()
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{diagnostics: diagnostics})
	if err := diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type: "plugin.runtime.hostcall.failed", Severity: "warning", Message: "background raw failure",
		Details: map[string]any{"error": "vault token at /Users/secret/path"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type: "plugin.owner.failure", Severity: "warning", Message: "current owner failure",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}); err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type: "plugin.owner.failure", Severity: "warning", Message: "other owner failure",
		OwnerSessionHash: "session_other", OwnerUserHash: "user_other", OwnerEnvHash: "env_other", SessionChannelIDHash: "channel_other",
	}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	listed := getJSON[struct {
		DiagnosticEvents []host.DiagnosticEvent `json:"diagnostic_events"`
	}](t, handler, "/_redevplugin/api/plugins/diagnostics?severity=warning&limit=10")
	if len(listed.DiagnosticEvents) != 1 || listed.DiagnosticEvents[0].Message != "current owner failure" {
		t.Fatalf("owner-scoped diagnostics mismatch: %#v", listed.DiagnosticEvents)
	}
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"background raw failure", "/Users/secret/path", "other owner failure", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("diagnostics route leaked %q: %s", forbidden, raw)
		}
	}
}

func TestHandlerInternalErrorsUseStableMessagesAndOwnerScopedDiagnostics(t *testing.T) {
	const sensitive = "launch /Users/secret/path/redevplugin-runtime with vault-token-super-secret"
	diagnostics := newHTTPRecordingDiagnostics()
	runtimeManager := newHTTPRecordingRuntimeManager(t)
	runtimeManager.startErr = errors.New(sensitive)
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{diagnostics: diagnostics, runtimeManager: runtimeManager})
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	envelope := postJSONError(t, handler, "/_redevplugin/api/plugins/runtime/start", map[string]any{
		"target": map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH},
	}, http.StatusServiceUnavailable)
	if envelope.Code != string(security.ErrRuntimeUnavailable) || envelope.Message != "plugin runtime is unavailable" || envelope.MutationOutcome != string(mutation.OutcomeNotCommitted) {
		t.Fatalf("runtime public error mismatch: %#v", envelope)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), sensitive) || strings.Contains(string(encoded), "/Users/secret/path") || strings.Contains(string(encoded), "vault-token-super-secret") {
		t.Fatalf("runtime response leaked internal error: %s", encoded)
	}
	events, err := diagnostics.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{
		Type: "plugin.http.operation_failed", OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Message != "plugin HTTP operation failed" || events[0].Details["operation"] != "runtime.start" || events[0].InternalDetails != nil {
		t.Fatalf("runtime failure diagnostic mismatch: %#v", events)
	}
	internalRuntimeEvent, ok := diagnostics.last("plugin.http.operation_failed")
	failure, failureOK := internalRuntimeEvent.InternalDetails["failure"].(observability.Failure)
	if !ok || !failureOK || failure.Code != observability.FailureAction || failure.Action != "runtime.start" {
		t.Fatalf("runtime diagnostics sink failure mismatch: %#v", internalRuntimeEvent)
	}
	if internalRaw := fmt.Sprint(internalRuntimeEvent.InternalDetails); strings.Contains(internalRaw, sensitive) || strings.Contains(internalRaw, "/Users/secret/path") {
		t.Fatalf("runtime diagnostics sink retained sensitive cause: %s", internalRaw)
	}
	rawEvent, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawEvent), "owner_session_hash") || strings.Contains(string(rawEvent), "owner_user_hash") || strings.Contains(string(rawEvent), "owner_env_hash") || strings.Contains(string(rawEvent), "session_channel_id_hash") {
		t.Fatalf("diagnostic owner scope was serialized: %s", rawEvent)
	}
	if strings.Contains(string(encoded), "plugin HTTP operation failed") {
		t.Fatalf("public response exposed diagnostic-only message: %s", encoded)
	}
	listed := getJSON[struct {
		DiagnosticEvents []host.DiagnosticEvent `json:"diagnostic_events"`
	}](t, handler, "/_redevplugin/api/plugins/diagnostics?type=plugin.http.operation_failed&limit=10")
	publicDiagnostics, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.DiagnosticEvents) != 1 || listed.DiagnosticEvents[0].Details["operation"] != "runtime.start" || listed.DiagnosticEvents[0].Details["code"] != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("public runtime diagnostics mismatch: %#v", listed.DiagnosticEvents)
	}
	for _, forbidden := range []string{sensitive, "/Users/secret/path", "vault-token-super-secret", "internal_details"} {
		if strings.Contains(string(publicDiagnostics), forbidden) {
			t.Fatalf("public runtime diagnostics leaked %q: %s", forbidden, publicDiagnostics)
		}
	}

	stopSensitive := "stop /Users/secret/path/redevplugin-runtime with vault-token-stop-secret"
	runtimeManager.stopErr = errors.New(stopSensitive)
	stopEnvelope := postJSONError(t, handler, "/_redevplugin/api/plugins/runtime/stop", map[string]any{}, http.StatusServiceUnavailable)
	if stopEnvelope.Code != string(security.ErrRuntimeUnavailable) || stopEnvelope.Message != "plugin runtime is unavailable" || stopEnvelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("runtime stop public error mismatch: %#v", stopEnvelope)
	}
	stopEvents, err := diagnostics.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{
		Type: "plugin.runtime.stop_failed", OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stopEvents) != 1 || stopEvents[0].InternalDetails != nil {
		t.Fatalf("runtime stop internal diagnostic mismatch: %#v", stopEvents)
	}
	internalStopEvent, ok := diagnostics.last("plugin.runtime.stop_failed")
	stopFailure, failureOK := internalStopEvent.InternalDetails["failure"].(observability.Failure)
	if !ok || !failureOK || stopFailure.Code != observability.FailureAdapter || stopFailure.Action != "runtime.stop" {
		t.Fatalf("runtime stop diagnostics sink failure mismatch: %#v", internalStopEvent)
	}
	if internalRaw := fmt.Sprint(internalStopEvent.InternalDetails); strings.Contains(internalRaw, stopSensitive) || strings.Contains(internalRaw, "/Users/secret/path") {
		t.Fatalf("runtime stop diagnostics sink retained sensitive cause: %s", internalRaw)
	}
	listedStop := getJSON[struct {
		DiagnosticEvents []host.DiagnosticEvent `json:"diagnostic_events"`
	}](t, handler, "/_redevplugin/api/plugins/diagnostics?type=plugin.runtime.stop_failed&limit=10")
	publicStopDiagnostics, err := json.Marshal(listedStop)
	if err != nil {
		t.Fatal(err)
	}
	if len(listedStop.DiagnosticEvents) != 1 || listedStop.DiagnosticEvents[0].Message != "plugin runtime stop failed" || strings.Contains(string(publicStopDiagnostics), stopSensitive) || strings.Contains(string(publicStopDiagnostics), "/Users/secret/path") {
		t.Fatalf("public runtime stop diagnostics leaked internal cause: %s", publicStopDiagnostics)
	}
}

func TestHandlerPatchSettingsReportsUnknownWhenMetadataReadFailsAfterCommit(t *testing.T) {
	secretStore := &httpRecordingSecretStore{listErr: errors.New("secret metadata unavailable")}
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{secrets: secretStore})
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, buildHTTPSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	}); err != nil {
		t.Fatal(err)
	}
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	envelope := requestJSONError(t, handler, http.MethodPatch, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings", map[string]any{
		"scope":                    "user",
		"expected_values_revision": 1,
		"set":                      map[string]any{"default_engine": "podman"},
	}, http.StatusForbidden)
	if envelope.MutationOutcome != string(mutation.OutcomeUnknown) {
		t.Fatalf("settings mutation_outcome = %q, want %q body = %#v", envelope.MutationOutcome, mutation.OutcomeUnknown, envelope)
	}

	secretStore.listErr = nil
	snapshot := getJSON[host.SettingsResult](t, handler, "/_redevplugin/api/plugins/"+installed.PluginInstanceID+"/settings?scope=user")
	if snapshot.ValuesRevision != 2 || snapshot.Values["default_engine"] != "podman" {
		t.Fatalf("committed settings snapshot mismatch: %#v", snapshot)
	}
}

func TestHandlerRuntimeLifecycleFlow(t *testing.T) {
	supervisor := newHTTPRecordingRuntimeManager(t)
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{runtimeManager: supervisor})
	handler := mustNewHandler(t, h, allowHTTPTestGuard())

	health := postJSON[runtimeclient.ManagerHealth](t, handler, "/_redevplugin/api/plugins/runtime/start", map[string]any{
		"target": map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH},
	})
	if !health.Ready || len(health.Shards) != 1 || health.Shards[0].RuntimeInstanceID != "runtime_http" || supervisor.startedTarget != (runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}) {
		t.Fatalf("runtime start mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	if health.Descriptor != supervisor.health.Descriptor || health.Shards[0].Descriptor != health.Descriptor {
		t.Fatalf("runtime start descriptor mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	health = getJSON[runtimeclient.ManagerHealth](t, handler, "/_redevplugin/api/plugins/runtime/health")
	if !health.Ready || len(health.Shards) != 1 || health.Shards[0].RuntimeGenerationID != "runtime_gen_http" || health.Descriptor != supervisor.health.Descriptor || health.Shards[0].Descriptor != health.Descriptor {
		t.Fatalf("runtime health mismatch: %#v", health)
	}
	postJSON[map[string]bool](t, handler, "/_redevplugin/api/plugins/runtime/stop", map[string]any{})
	if supervisor.stopCalls != 1 {
		t.Fatalf("Stop calls = %d, want 1", supervisor.stopCalls)
	}
}

func TestHandlerRefreshEnabledRuntimeState(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	installed := postLocalImport[registry.PluginRecord](t, handler, buildHTTPFixturePackage(t))
	enabled := postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/enable", map[string]any{
		"plugin_instance_id":           installed.PluginInstanceID,
		"expected_management_revision": installed.ManagementRevision,
	})

	refreshed := postJSON[struct {
		Results []host.RefreshEnabledPluginResult `json:"results"`
	}](t, handler, "/_redevplugin/api/plugins/runtime/refresh-enabled", map[string]any{})
	if len(refreshed.Results) != 1 || refreshed.Results[0].PluginInstanceID != enabled.PluginInstanceID || refreshed.Results[0].Status != host.RefreshEnabledPluginStatusRefreshed || refreshed.Results[0].Error != nil {
		t.Fatalf("runtime refresh results mismatch: %#v", refreshed.Results)
	}
}

func postJSON[T any](t *testing.T, handler http.Handler, path string, body any) T {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, path, bytes.NewReader(raw))
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

func postLocalImport[T any](t *testing.T, handler http.Handler, packageBytes []byte, pluginInstanceID ...string) T {
	path := "/_redevplugin/api/plugins/local-imports"
	if len(pluginInstanceID) > 0 && pluginInstanceID[0] != "" {
		path += "?plugin_instance_id=" + url.QueryEscape(pluginInstanceID[0])
	}
	return requestBinary[T](t, handler, http.MethodPost, path, packageBytes, http.StatusOK)
}

func putLocalImport[T any](t *testing.T, handler http.Handler, pluginInstanceID string, revision uint64, packageBytes []byte) T {
	path := "/_redevplugin/api/plugins/" + url.PathEscape(pluginInstanceID) + "/local-import?expected_management_revision=" + strconv.FormatUint(revision, 10)
	return requestBinary[T](t, handler, http.MethodPut, path, packageBytes, http.StatusOK)
}

func requestBinary[T any](t *testing.T, handler http.Handler, method, path string, body []byte, wantStatus int) T {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", localImportContentType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d body = %s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("%s %s returned not ok: %s", method, path, rec.Body.String())
	}
	var data T
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func requestJSON[T any](t *testing.T, handler http.Handler, method, path string, body any) T {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s status = %d body = %s", method, path, rec.Code, rec.Body.String())
	}
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("%s %s returned not ok: %s", method, path, rec.Body.String())
	}
	var data T
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

type decodedErrorResponse struct {
	OK              bool
	Code            string
	Message         string
	Details         map[string]any
	MutationOutcome string
}

func (r *decodedErrorResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		OK    bool `json:"ok"`
		Error struct {
			Code            string         `json:"code"`
			Message         string         `json:"message"`
			Details         map[string]any `json:"details"`
			MutationOutcome string         `json:"mutation_outcome"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.OK = wire.OK
	r.Code = wire.Error.Code
	r.Message = wire.Error.Message
	r.Details = wire.Error.Details
	r.MutationOutcome = wire.Error.MutationOutcome
	return nil
}

func postJSONError(t *testing.T, handler http.Handler, path string, body any, wantStatus int) decodedErrorResponse {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := newJSONHTTPRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("POST %s status = %d, want %d body = %s", path, rec.Code, wantStatus, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK {
		t.Fatalf("POST %s returned ok for expected error: %s", path, rec.Body.String())
	}
	return envelope
}

func requestJSONError(t *testing.T, handler http.Handler, method, path string, body any, wantStatus int) decodedErrorResponse {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d body = %s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	var envelope decodedErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK {
		t.Fatalf("%s %s returned ok for expected error: %s", method, path, rec.Body.String())
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

func newJSONHTTPRequest(method string, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	return req
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
	case "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}":
		return "/_redevplugin/api/plugins/security-policies/plugini_test"
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
		filepath.Join("..", "..", "spec", "openapi", "plugin-platform-v6.yaml"),
		filepath.Join("spec", "openapi", "plugin-platform-v6.yaml"),
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

func assertJSONFieldsMatchOpenAPISchema(t *testing.T, spec, schemaName string, value map[string]any) {
	t.Helper()
	block, ok := openAPISchemaContractBlock(spec, schemaName)
	if !ok {
		t.Fatalf("OpenAPI schema %s is missing", schemaName)
	}
	if !strings.Contains(block, "additionalProperties: false") {
		t.Fatalf("OpenAPI schema %s is not closed", schemaName)
	}
	requiredMarker := "required: ["
	requiredStart := strings.Index(block, requiredMarker)
	if requiredStart < 0 {
		t.Fatalf("OpenAPI schema %s has no inline required fields", schemaName)
	}
	requiredStart += len(requiredMarker)
	requiredEnd := strings.Index(block[requiredStart:], "]")
	if requiredEnd < 0 {
		t.Fatalf("OpenAPI schema %s has malformed required fields", schemaName)
	}
	required := strings.Split(block[requiredStart:requiredStart+requiredEnd], ",")
	want := make(map[string]struct{}, len(required))
	for _, field := range required {
		want[strings.TrimSpace(field)] = struct{}{}
	}
	if len(value) != len(want) {
		t.Fatalf("JSON fields for %s = %#v, want exactly %#v", schemaName, reflect.ValueOf(value).MapKeys(), required)
	}
	for field := range want {
		if _, ok := value[field]; !ok {
			t.Fatalf("JSON for %s is missing required field %q: %#v", schemaName, field, value)
		}
	}
}

func openAPISchemaContractBlock(spec, schemaName string) (string, bool) {
	lines := strings.Split(spec, "\n")
	marker := "    " + schemaName + ":"
	start := -1
	for i, line := range lines {
		if line == marker {
			start = i
		}
	}
	if start < 0 {
		return "", false
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if leadingSpaces(lines[i]) == 4 && strings.HasSuffix(lines[i], ":") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n"), true
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

type httpTestHostOptions struct {
	authorization           host.AuthorizationAdapter
	secrets                 host.SecretStoreAdapter
	diagnostics             host.DiagnosticsSink
	runtimeManager          runtimeclient.Manager
	surfaceCatalog          host.SurfaceCatalogSink
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
	observabilityStore := observability.NewMemoryStore()
	diagnostics := opts.diagnostics
	if diagnostics == nil {
		diagnostics = observabilityStore
	}
	authorization := opts.authorization
	if authorization == nil {
		authorization = httpTestAuthorization{}
	}
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		verified := httpVerifiedCapabilityContract(t)
		if err := capabilities.Register(capability.Registration{Contract: verified, TargetProjector: opts.capabilityAdapter, Adapter: opts.capabilityAdapter}); err != nil {
			t.Fatal(err)
		}
	}
	secretStore := opts.secrets
	if secretStore == nil {
		secretStore = secrets.NewMemoryStore()
	}
	runtimeManager := opts.runtimeManager
	if runtimeManager == nil {
		runtimeManager = newHTTPRecordingRuntimeManager(t)
	}
	releaseSourcePolicy := opts.releaseSourcePolicy
	if releaseSourcePolicy == nil {
		releaseSourcePolicy = &httpRecordingReleaseSourcePolicyResolver{}
	}
	releaseArtifactResolver := opts.releaseArtifactResolver
	if releaseArtifactResolver == nil {
		releaseArtifactResolver = &httpRecordingReleaseArtifactResolver{}
	}
	releaseMetadataVerifier := firstNonNilReleaseMetadataVerifier(opts.releaseMetadataVerifier, httpTestReleaseMetadataVerifier{})
	revocationVerifier, ok := releaseMetadataVerifier.(host.SourceRevocationEvidenceVerifier)
	if !ok {
		revocationVerifier = httpTestReleaseMetadataVerifier{}
	}
	coreActions := opts.coreActions
	if coreActions == nil {
		coreActions = &httpRecordingCoreActionAdapter{}
	}
	surfaceCatalog := opts.surfaceCatalog
	if surfaceCatalog == nil {
		surfaceCatalog = httpSurfaceCatalogSink{}
	}
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(httpTestContext(), t.TempDir(), registryStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pluginData.Close(); err != nil {
			t.Errorf("PluginData.Close() error = %v", err)
		}
	})
	h, err := host.Open(httpTestContext(), host.Config{
		Core: host.CoreAdapters{
			Policy:               httpTestPolicy{},
			Authorization:        authorization,
			PackageTrustVerifier: httpTestPackageTrustVerifier{},
			Registry:             registryStore,
			Audit:                observabilityStore,
			SecurityAudit:        observabilityStore,
			Diagnostics:          diagnostics,
			SurfaceCatalog:       surfaceCatalog,
			Assets:               pluginpkg.NewMemoryAssetStore(),
			InstallStages:        installstage.NewMemoryStore(),
			SurfaceTokens:        bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{}),
			Operations:           operation.NewMemoryStore(),
			ConfirmationIntents:  security.NewMemoryConfirmationIntentStore(),
			PluginData:           pluginData,
			Streams:              stream.NewMemoryStore(),
		},
		Release: &host.ReleaseModule{
			ReleaseMetadataVerifier:     releaseMetadataVerifier,
			RevocationVerifier:          revocationVerifier,
			ReleaseSourcePolicy:         releaseSourcePolicy,
			ReleaseArtifactResolver:     releaseArtifactResolver,
			HostRequirements:            httpHostRequirementPolicy{},
			CapabilityContractArtifacts: httpCapabilityContractArtifactResolver{},
			CapabilityContractKeys:      httpCapabilityContractKeyResolver{},
		},
		Runtime:      &host.RuntimeModule{Manager: runtimeManager},
		Capability:   &host.CapabilityModule{Registry: capabilities},
		Connectivity: &host.ConnectivityModule{Broker: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})},
		Secrets:      &host.SecretsModule{Store: secretStore},
		CoreAction:   &host.CoreActionModule{Adapter: coreActions},
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
		Errors: []capabilitycontract.BusinessError{{
			Code: "DOCUMENT_NOT_FOUND", Message: "Document not found",
			DetailsSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []string{"document_id", "secret_token"},
				"properties": map[string]any{
					"document_id":  map[string]any{"type": "string", "minLength": 1},
					"secret_token": map[string]any{"type": "string", "const": capability.ResponseRedactedValue},
				},
			},
		}},
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeHTTPFile(t *testing.T, filename string, content string) {
	t.Helper()
	if filepath.Base(filename) == "index.html" && filepath.Base(filepath.Dir(filename)) == "ui" {
		content += `<body><main>Fixture</main><img src="status.png" alt="Status"><script type="text/redevplugin-worker" src="app.js"></script></body>`
		writeHTTPBytes(t, filepath.Join(filepath.Dir(filename), "app.js"), []byte(`globalThis.__redevpluginFixture = true;`))
		writeHTTPBytes(t, filepath.Join(filepath.Dir(filename), "status.png"), minimalHTTPPNGForTest())
	}
	writeHTTPBytes(t, filename, []byte(content))
}

func minimalHTTPPNGForTest() []byte {
	raw, err := hex.DecodeString("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")
	if err != nil {
		panic(err)
	}
	return raw
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
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x11, 0x03,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
		0x60, 0x02, 0x7f, 0x7f, 0x00,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
		0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
		0x05, 0x03, 0x01, 0x00, 0x01,
	}
	exportPayload := []byte{0x04}
	for _, export := range []struct {
		name  string
		kind  byte
		index byte
	}{
		{name: "memory", kind: 0x02, index: 0x00},
		{name: "redevplugin_worker_alloc", kind: 0x00, index: 0x00},
		{name: "redevplugin_worker_dealloc", kind: 0x00, index: 0x01},
		{name: exportName, kind: 0x00, index: 0x02},
	} {
		exportPayload = append(exportPayload, byte(len(export.name)))
		exportPayload = append(exportPayload, export.name...)
		exportPayload = append(exportPayload, export.kind, export.index)
	}
	module = append(module, 0x07, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module,
		0x0a, 0x0f, 0x03,
		0x05, 0x00, 0x41, 0x80, 0x08, 0x0b,
		0x02, 0x00, 0x0b,
		0x04, 0x00, 0x42, 0x00, 0x0b,
	)
	return module
}

func httpFixtureManifestJSON() string {
	return httpVersionedFixtureManifestJSON("1.0.0", "HTTP")
}

func httpVersionedFixtureManifestJSON(version string, title string) string {
	if title == "" {
		title = "HTTP"
	}
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "http.view", "kind": "view", "label": "HTTP", "entry": "ui/index.html"}
		]
	}`
}

func httpStorageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.storage",
			"display_name": "HTTP Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
					"schema_version": 1
				}
			]
		}
	}`
}

func httpRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.rpc",
			"display_name": "HTTP RPC",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.danger",
			"display_name": "HTTP Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.operation",
			"display_name": "HTTP Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.subscription",
			"display_name": "HTTP Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.core",
			"display_name": "HTTP Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.worker",
			"display_name": "HTTP Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "http.worker.view", "kind": "view", "label": "HTTP Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{"worker_id": "echo_worker", "mode": "job", "artifact": "workers/echo.wasm", "abi": "redevplugin-wasm-worker-v2", "scope": "user", "memory_limit_bytes": 1048576}
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
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		]
	}`
}

func httpSettingsFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.settings",
			"display_name": "HTTP Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "http.settings.view", "kind": "view", "label": "HTTP Settings", "entry": "ui/index.html"}
		],
		"settings": {
			"schema_version": 1,
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.http.network",
			"display_name": "HTTP Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
					"schema_version": 1
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
	req := newJSONHTTPRequest(http.MethodPatch, path, bytes.NewReader(raw))
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

type httpTestPolicy struct{}

type httpTestAuthorization struct{}

func (httpTestAuthorization) Authorize(_ context.Context, req host.AuthorizationRequest) error {
	if !req.Session.Valid() || !req.Action.Valid() || !req.Resource.Valid() || req.Resource != req.Action.Resource() {
		return host.ErrActionDenied
	}
	return nil
}

type httpDenyAuthorization struct{}

func (httpDenyAuthorization) Authorize(context.Context, host.AuthorizationRequest) error {
	return errors.New("private host authorization denial")
}

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

func artifactSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type httpRecordingReleaseSourcePolicyResolver struct {
	snapshot host.SourcePolicySnapshot
	err      error
	last     host.ReleaseSourcePolicyRequest
}

type httpTestReleaseMetadataVerifier struct{}

type httpHostRequirementPolicy struct{}

func (httpHostRequirementPolicy) SelectHostRequirement(context.Context, host.HostRequirementSelectionRequest) (host.HostRequirementSelection, error) {
	return host.HostRequirementSelection{HostID: "test-host"}, nil
}

type httpCapabilityContractArtifactResolver struct{}

func (httpCapabilityContractArtifactResolver) ResolveCapabilityContract(context.Context, host.CapabilityContractResolveRequest) (host.ResolvedCapabilityContractArtifact, error) {
	return host.ResolvedCapabilityContractArtifact{}, errors.New("capability contract artifact is not configured for this test")
}

type httpCapabilityContractKeyResolver struct{}

func (httpCapabilityContractKeyResolver) ResolveCapabilityContractKey(context.Context, host.CapabilityContractKeyRequest) ([]byte, error) {
	return nil, errors.New("capability contract key is not configured for this test")
}

type httpSurfaceCatalogSink struct{}

func (httpSurfaceCatalogSink) PublishSurfaces(context.Context, host.SurfaceSnapshot) error {
	return nil
}

type httpFailingSurfaceCatalogSink struct{}

func (httpFailingSurfaceCatalogSink) PublishSurfaces(context.Context, host.SurfaceSnapshot) error {
	return errors.New("surface catalog unavailable")
}

func firstNonNilReleaseMetadataVerifier(primary host.ReleaseMetadataVerifier, defaultVerifier host.ReleaseMetadataVerifier) host.ReleaseMetadataVerifier {
	if primary != nil {
		return primary
	}
	return defaultVerifier
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
		ArtifactSHA256:           artifactSHA256(packageBytes),
	}
}

func readHTTPTestPackage(t *testing.T, data []byte) pluginpkg.Package {
	t.Helper()
	pkg, err := pluginpkg.Read(httpTestContext(), bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadLimits())
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
	if err := pluginpkg.WritePackage(httpTestContext(), &buf, pkg); err != nil {
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
		"schema_version":             "redevplugin.release_metadata.v5",
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
	err    error
}

type httpRecordingSecretStore struct {
	bind      host.SecretBindRequest
	test      host.SecretTestRequest
	delete    host.SecretDeleteRequest
	bound     bool
	bindErr   error
	testErr   error
	deleteErr error
	listErr   error
}

type httpRecordingRuntimeManager struct {
	health        runtimeclient.Health
	startedTarget runtimeclient.Target
	stopCalls     int
	startErr      error
	stopErr       error
	err           error
	hostServices  runtimeclient.RuntimeHostServices
}

func newHTTPRecordingRuntimeManager(t testing.TB) *httpRecordingRuntimeManager {
	t.Helper()
	runtimeVersion, err := platformversion.ParseSemVer("0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := runtimeclient.NewRuntimeDescriptor(
		runtimeVersion,
		runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH},
		platformversion.RustIPCVersion,
		platformversion.WASMABIVersion,
		strings.Repeat("a", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &httpRecordingRuntimeManager{health: runtimeclient.Health{
		RuntimeInstanceID:   "runtime_http",
		RuntimeGenerationID: "runtime_gen_http",
		IPCChannelID:        "ipc_http",
		ConnectionNonce:     "connection_nonce_http_1234567890",
		Descriptor:          descriptor,
		Ready:               true,
	}}
}

type httpRecordingDiagnostics struct {
	store  *observability.MemoryStore
	events []observability.DiagnosticEvent
}

func newHTTPRecordingDiagnostics() *httpRecordingDiagnostics {
	return &httpRecordingDiagnostics{store: observability.NewMemoryStore()}
}

func (s *httpRecordingDiagnostics) AppendPluginDiagnostic(ctx context.Context, event observability.DiagnosticEvent) error {
	s.events = append(s.events, event)
	return s.store.AppendPluginDiagnostic(ctx, event)
}

func (s *httpRecordingDiagnostics) ListPluginDiagnostics(ctx context.Context, req observability.ListDiagnosticRequest) ([]observability.DiagnosticEvent, error) {
	return s.store.ListPluginDiagnostics(ctx, req)
}

func (s *httpRecordingDiagnostics) last(eventType string) (observability.DiagnosticEvent, bool) {
	for index := len(s.events) - 1; index >= 0; index-- {
		if s.events[index].Type == eventType {
			return s.events[index], true
		}
	}
	return observability.DiagnosticEvent{}, false
}

type httpTestWebSecurityGuard struct {
	decision          string
	scope             sessionctx.Context
	authenticateErr   error
	csrfErr           error
	authorizeErr      error
	authenticateCount int
	originCount       int
	csrfCount         int
	authorizeCount    int
	lastSessionHash   string
	lastOriginPolicy  websecurity.OriginPolicy
	lastCSRFPolicy    websecurity.CSRFPolicy
	lastAction        websecurity.RouteAction
	callOrder         []string
}

func allowHTTPTestGuard() *httpTestWebSecurityGuard {
	return &httpTestWebSecurityGuard{}
}

func httpTestContext() context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	})
}

func mustNewHandler(t *testing.T, pluginHost *host.Host, guard websecurity.Guard) *Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{
		Host:  pluginHost,
		Guard: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func (g *httpTestWebSecurityGuard) Authenticate(r *http.Request) (sessionctx.Context, error) {
	g.authenticateCount++
	g.callOrder = append(g.callOrder, "authenticate")
	if g.authenticateErr != nil {
		return sessionctx.Context{}, g.authenticateErr
	}
	scope := g.scope
	if scope == (sessionctx.Context{}) {
		scope = sessionctx.Context{
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
		}
	}
	return scope, nil
}

func (g *httpTestWebSecurityGuard) ValidateOrigin(_ *http.Request, session sessionctx.Context, policy websecurity.OriginPolicy) error {
	g.originCount++
	g.callOrder = append(g.callOrder, "origin")
	g.lastOriginPolicy = policy
	g.lastSessionHash = session.OwnerSessionHash
	if !policy.Valid() {
		return websecurity.ErrOriginPolicyInvalid
	}
	if g.decision != "" && g.decision != "trusted" {
		return websecurity.ErrOriginDenied
	}
	return nil
}

func (g *httpTestWebSecurityGuard) ValidateCSRF(_ *http.Request, session sessionctx.Context, policy websecurity.CSRFPolicy) error {
	g.csrfCount++
	g.callOrder = append(g.callOrder, "csrf")
	g.lastCSRFPolicy = policy
	g.lastSessionHash = session.OwnerSessionHash
	if !policy.Valid() {
		return websecurity.ErrCSRFPolicyInvalid
	}
	if policy == websecurity.CSRFPolicyRequired && g.csrfErr != nil {
		return g.csrfErr
	}
	return nil
}

func (g *httpTestWebSecurityGuard) AuthorizeRoute(_ *http.Request, session sessionctx.Context, action websecurity.RouteAction) error {
	g.authorizeCount++
	g.callOrder = append(g.callOrder, "authorize")
	g.lastAction = action
	g.lastSessionHash = session.OwnerSessionHash
	if !action.Valid() {
		return websecurity.ErrRouteActionInvalid
	}
	return g.authorizeErr
}

func openHTTPBridge(t *testing.T, handler http.Handler, pluginInstanceID string, surfaceID string, surfaceInstanceID string, bridgeChannelID string) bridge.GatewayTokenResult {
	t.Helper()
	openBody := map[string]any{
		"plugin_instance_id":           pluginInstanceID,
		"surface_id":                   surfaceID,
		"surface_instance_id":          surfaceInstanceID,
		"expected_management_revision": 2,
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
		ManagementRevision: openResp.ManagementRevision,
		RevokeEpoch:        openResp.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
}

func bridgeHandshakeBody(handshake bridge.Handshake) map[string]any {
	return map[string]any{
		"type":                "redevplugin.bridge.handshake",
		"plugin_id":           handshake.PluginID,
		"surface_id":          handshake.SurfaceID,
		"surface_instance_id": handshake.SurfaceInstanceID,
		"active_fingerprint":  handshake.ActiveFingerprint,
		"bridge_nonce":        handshake.BridgeNonce,
		"asset_session_nonce": handshake.AssetSessionNonce,
		"management_revision": handshake.ManagementRevision,
		"revoke_epoch":        handshake.RevokeEpoch,
		"ui_protocol_version": handshake.UIProtocolVersion,
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
				expected := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
				if _, err := h.GrantPermission(httpTestContext(), host.GrantPermissionRequest{
					PluginInstanceID:           record.PluginInstanceID,
					PermissionID:               permissionID,
					ExpectedPolicyRevision:     expected.PolicyRevision,
					ExpectedManagementRevision: expected.ManagementRevision,
					ExpectedRevokeEpoch:        expected.RevokeEpoch,
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
	return a.result, a.err
}

func (a *httpRecordingCoreActionAdapter) ResolveCoreActionTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{Kind: "core_action", Fields: httpCloneMap(req.TargetInput)}, nil
}

func (s *httpRecordingSecretStore) BindSecretRef(_ context.Context, req host.SecretBindRequest) error {
	s.bind = req
	s.bound = true
	return s.bindErr
}

func (s *httpRecordingSecretStore) TestSecretRef(_ context.Context, req host.SecretTestRequest) error {
	s.test = req
	return s.testErr
}

func (s *httpRecordingSecretStore) DeleteSecretRef(_ context.Context, req host.SecretDeleteRequest) error {
	s.delete = req
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.bound = false
	return nil
}

func (s *httpRecordingSecretStore) List(_ context.Context, req secrets.ListRequest) ([]secrets.Record, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	if s.bind.PluginInstanceID == "" || (req.PluginInstanceID != "" && req.PluginInstanceID != s.bind.PluginInstanceID) || (req.BoundOnly && !s.bound) {
		return nil, nil
	}
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	return []secrets.Record{{
		PluginInstanceID: s.bind.PluginInstanceID,
		SecretRef:        s.bind.SecretRef,
		Scope:            s.bind.Scope,
		Bound:            s.bound,
		UpdatedAt:        now,
	}}, nil
}

func (s *httpRecordingSecretStore) DeletePlugin(_ context.Context, pluginInstanceID string) error {
	if s.bind.PluginInstanceID == pluginInstanceID {
		s.bound = false
	}
	return nil
}

func (s *httpRecordingRuntimeManager) Preflight(ctx context.Context, target runtimeclient.Target) (runtimeclient.RuntimeDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return runtimeclient.RuntimeDescriptor{}, err
	}
	descriptor := s.health.Descriptor
	if descriptor.Version().String() == "" {
		return runtimeclient.RuntimeDescriptor{}, runtimeclient.ErrRuntimeDescriptorInvalid
	}
	if target != descriptor.Target() {
		return runtimeclient.RuntimeDescriptor{}, runtimeclient.ErrRuntimeDescriptorMismatch
	}
	return descriptor, nil
}

func (s *httpRecordingRuntimeManager) Start(ctx context.Context, target runtimeclient.Target) (runtimeclient.ManagerHealth, error) {
	s.startedTarget = target
	if _, err := s.Preflight(ctx, target); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	if s.startErr != nil {
		return runtimeclient.ManagerHealth{}, s.startErr
	}
	return s.managerHealth(), nil
}

func (s *httpRecordingRuntimeManager) BindHostServices(services runtimeclient.RuntimeHostServices) error {
	if services.StreamSink == nil {
		return runtimeclient.ErrRuntimeHostServicesInvalid
	}
	s.hostServices = services
	return nil
}

func (s *httpRecordingRuntimeManager) Stop(context.Context) error {
	s.stopCalls++
	s.health.Ready = false
	return s.stopErr
}

func (s *httpRecordingRuntimeManager) Health(context.Context) (runtimeclient.ManagerHealth, error) {
	return s.managerHealth(), nil
}

func (s *httpRecordingRuntimeManager) managerHealth() runtimeclient.ManagerHealth {
	return runtimeclient.ManagerHealth{
		Ready:      s.health.Ready,
		Descriptor: s.health.Descriptor,
		Shards:     []runtimeclient.ShardHealth{{RuntimeShardID: "runtime_shard_00", Health: s.health}},
	}
}

func (s *httpRecordingRuntimeManager) BindPlugin(context.Context, string) (runtimeclient.RuntimeBinding, error) {
	return runtimeclient.RuntimeBinding{
		RuntimeShardID:      "runtime_shard_00",
		RuntimeInstanceID:   s.health.RuntimeInstanceID,
		RuntimeGenerationID: s.health.RuntimeGenerationID,
		IPCChannelID:        s.health.IPCChannelID,
		ConnectionNonce:     s.health.ConnectionNonce,
		Descriptor:          s.health.Descriptor,
	}, nil
}

func (s *httpRecordingRuntimeManager) InvokeWorker(context.Context, runtimeclient.RuntimeBinding, runtimeclient.Lease, string, []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return nil, runtimeclient.ErrRuntimeIPCUnavailable
}

func (s *httpRecordingRuntimeManager) Revoke(_ context.Context, req runtimeclient.RevokeRequest) (runtimeclient.RevokeResult, error) {
	if s.err != nil {
		return runtimeclient.RevokeResult{}, s.err
	}
	return runtimeclient.RevokeResult{
		ResourceScope:    req.ResourceScope,
		PluginInstanceID: req.PluginInstanceID,
		RevokeEpoch:      req.RevokeEpoch,
	}, nil
}
