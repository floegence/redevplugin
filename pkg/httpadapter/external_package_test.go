package httpadapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

func TestExternalPackageRoutesDeclareClosedSecurityContracts(t *testing.T) {
	want := map[string]struct {
		method string
		action websecurity.RouteAction
		effect websecurity.RouteEffect
	}{
		"/_redevplugin/api/plugins/external-packages/inspect":                             {http.MethodPost, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/upload/inspect":                      {http.MethodPost, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/{plugin_instance_id}/external-packages/upload/inspect": {http.MethodPut, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/install-operations":                  {http.MethodPost, websecurity.RouteActionInstallInspectedPackage, websecurity.RouteEffectMutation},
	}
	for _, route := range routes {
		expected, ok := want[route.Path]
		if !ok {
			continue
		}
		if route.Method != expected.method || route.action != expected.action || route.Effect != expected.effect || route.originPolicy != websecurity.OriginPolicyTrustedHost || route.csrfPolicy != websecurity.CSRFPolicyRequired {
			t.Fatalf("route %s contract = %#v", route.Path, route)
		}
		delete(want, route.Path)
	}
	if len(want) != 0 {
		t.Fatalf("missing external package routes: %v", want)
	}
}

func TestExternalPackageUploadInspectInstallAndUpdate(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	pluginHost := newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module})
	handler := mustNewHandler(t, pluginHost, allowHTTPTestGuard())
	raw := buildHTTPFixturePackage(t)

	installRaw := externalPackageUploadRequest(t, handler, http.MethodPost,
		"/_redevplugin/api/plugins/external-packages/upload/inspect", raw, nil, int64(len(raw)), http.StatusOK)
	var inspection host.ExternalPackageInspection
	decodeExternalPackageData(t, installRaw, &inspection)
	if inspection.SourceProvenance.Kind != "package_upload" || !strings.HasPrefix(inspection.SourceProvenance.UploadID, "upload_") ||
		inspection.UpdateEligibility.State != "manual_only" {
		t.Fatalf("upload inspection=%#v", inspection)
	}
	commitRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations", map[string]any{
		"request_id": "install-http-test", "inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusOK)
	var operation host.InspectedInstallOperation
	decodeExternalPackageData(t, commitRaw, &operation)
	waitHTTPInstall(t, handler, operation.RequestID)
	listed := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations/list", map[string]any{"limit": 1}, http.StatusOK)
	var receipts host.InspectedInstallList
	decodeExternalPackageData(t, listed, &receipts)
	if len(receipts.Operations) != 1 || receipts.NextCursor != 0 || receipts.Operations[0].RequestID != operation.RequestID || receipts.Operations[0].PluginID != inspection.PluginID {
		t.Fatalf("installation list lost receipt identity: %+v", receipts)
	}
	externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations/list", map[string]any{"limit": 501}, http.StatusBadRequest)
	installed, err := pluginHost.ListPlugins(httpTestContext())
	if err != nil || len(installed) != 1 {
		t.Fatalf("installed: %+v %v", installed, err)
	}
	committed := struct{ Plugin *registry.PluginRecord }{Plugin: &installed[0]}
	if committed.Plugin.PackageSourceProvenance.UploadID != inspection.SourceProvenance.UploadID {
		t.Fatal("source changed")
	}

	revision := strconv.FormatUint(committed.Plugin.ManagementRevision, 10)
	updateRaw := externalPackageUploadRequest(t, handler, http.MethodPut,
		"/_redevplugin/api/plugins/"+committed.Plugin.PluginInstanceID+"/external-packages/upload/inspect", raw,
		http.Header{localImportRevisionHeader: []string{revision}, allowSourceChangeHeader: []string{"true"}, "Content-Type": []string{localImportContentType}}, -1, http.StatusOK)
	var updateInspection host.ExternalPackageInspection
	decodeExternalPackageData(t, updateRaw, &updateInspection)
	if !updateInspection.Intent.AllowSourceChange || updateInspection.Intent.Action != "update" || updateInspection.Intent.PluginInstanceID != committed.Plugin.PluginInstanceID ||
		updateInspection.Intent.ExpectedManagementRevision != committed.Plugin.ManagementRevision {
		t.Fatalf("update inspection=%#v", updateInspection)
	}
}

func TestExternalPackageUploadHeadersAndLimitsRejectBeforeStage(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	tests := []struct {
		name          string
		headers       http.Header
		contentLength int64
		wantStatus    int
	}{
		{name: "missing content type", headers: http.Header{}, contentLength: 1, wantStatus: http.StatusUnsupportedMediaType},
		{name: "content type parameter", headers: http.Header{"Content-Type": []string{localImportContentType + "; charset=utf-8"}}, contentLength: 1, wantStatus: http.StatusUnsupportedMediaType},
		{name: "duplicate content type", headers: http.Header{"Content-Type": []string{localImportContentType, localImportContentType}}, contentLength: 1, wantStatus: http.StatusUnsupportedMediaType},
		{name: "compressed", headers: http.Header{"Content-Type": []string{localImportContentType}, "Content-Encoding": []string{"gzip"}}, contentLength: 1, wantStatus: http.StatusUnsupportedMediaType},
		{name: "multiple encodings", headers: http.Header{"Content-Type": []string{localImportContentType}, "Content-Encoding": []string{"identity", "identity"}}, contentLength: 1, wantStatus: http.StatusUnsupportedMediaType},
		{name: "install source consent", headers: http.Header{"Content-Type": []string{localImportContentType}, allowSourceChangeHeader: []string{"true"}}, contentLength: 1, wantStatus: http.StatusBadRequest},
		{name: "empty", headers: http.Header{"Content-Type": []string{localImportContentType}}, contentLength: 0, wantStatus: http.StatusBadRequest},
		{name: "oversize", headers: http.Header{"Content-Type": []string{localImportContentType}}, contentLength: externalsource.MaxArtifactBytes + 1, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			externalPackageUploadRequest(t, handler, http.MethodPost,
				"/_redevplugin/api/plugins/external-packages/upload/inspect", []byte("x"), test.headers, test.contentLength, test.wantStatus)
		})
	}
}

func TestExternalPackageUploadErrorDoesNotDefaultToPermissionDenied(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	raw := externalPackageUploadRequest(t, handler, http.MethodPost,
		"/_redevplugin/api/plugins/external-packages/upload/inspect", []byte("chunk"), nil, externalsource.MaxArtifactBytes+1, http.StatusRequestEntityTooLarge)
	assertExternalPackageErrorCode(t, raw, security.ErrPackageTooLarge)
}

func TestExternalPackageUploadUpdateRejectsSlashPluginInstanceIDs(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	for _, path := range []string{
		"/_redevplugin/api/plugins/plugin/bad/external-packages/upload/inspect",
		"/_redevplugin/api/plugins/plugin%2Fbad/external-packages/upload/inspect",
	} {
		externalPackageUploadRequest(t, handler, http.MethodPut, path, []byte("x"),
			http.Header{localImportRevisionHeader: []string{"1"}}, 1, http.StatusNotFound)
	}
}

func TestExternalPackageRoutesBindInspectionToSessionAndHideOwnerHashes(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	pluginHost := newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module})
	original := mustNewHandler(t, pluginHost, allowHTTPTestGuard())

	rawPackage := buildHTTPFixturePackage(t)
	inspectRaw := externalPackageUploadRequest(t, original, http.MethodPost,
		"/_redevplugin/api/plugins/external-packages/upload/inspect", rawPackage, nil, int64(len(rawPackage)), http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, inspectRaw)
	var inspectEnvelope struct {
		Data struct {
			SourceProvenance map[string]json.RawMessage `json:"source_provenance"`
		} `json:"data"`
	}
	if err := json.Unmarshal(inspectRaw, &inspectEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, ok := inspectEnvelope.Data.SourceProvenance["redirect_chain"]; ok {
		t.Fatalf("package upload provenance unexpectedly contains redirect_chain; response=%s", inspectRaw)
	}
	var inspection host.ExternalPackageInspection
	decodeExternalPackageData(t, inspectRaw, &inspection)
	if inspection.InspectionID == "" || inspection.InspectedHashes.PackageSHA256 == "" || inspection.ExecutionApproval.State != "pending" {
		t.Fatalf("inspection = %#v", inspection)
	}

	crossSessionGuard := &httpTestWebSecurityGuard{scope: sessionctx.Context{
		OwnerSessionHash: "other_session", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "other_channel",
	}}
	crossSession := mustNewHandler(t, pluginHost, crossSessionGuard)
	crossCommit := externalPackageRequest(t, crossSession, "/_redevplugin/api/plugins/external-packages/install-operations", map[string]any{
		"request_id": "install-http-test", "inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusBadRequest)
	assertExternalPackageErrorCode(t, crossCommit, security.ErrInvalidRequest)
	assertExternalPackageJSONHasNoOwnerHashes(t, crossCommit)

	commitRaw := externalPackageRequest(t, original, "/_redevplugin/api/plugins/external-packages/install-operations", map[string]any{
		"request_id": "install-http-test", "inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, commitRaw)
	var operation host.InspectedInstallOperation
	decodeExternalPackageData(t, commitRaw, &operation)
	waitHTTPInstall(t, original, operation.RequestID)

}

func newHTTPExternalPackageModule(t *testing.T) *host.ExternalPackageModule {
	t.Helper()
	return &host.ExternalPackageModule{}
}

func externalPackageRequest(t *testing.T, handler http.Handler, path string, body any, wantStatus int) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newJSONHTTPRequest(http.MethodPost, path, bytes.NewReader(raw)))
	if recorder.Code != wantStatus {
		t.Fatalf("POST %s status=%d want=%d body=%s", path, recorder.Code, wantStatus, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

func externalPackageUploadRequest(t *testing.T, handler http.Handler, method, path string, body []byte, headers http.Header, contentLength int64, wantStatus int) []byte {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header = make(http.Header)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if len(req.Header.Values("Content-Type")) == 0 && headers == nil {
		req.Header.Set("Content-Type", localImportContentType)
	}
	req.ContentLength = contentLength
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != wantStatus {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, recorder.Code, wantStatus, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

func decodeExternalPackageData(t *testing.T, raw []byte, destination any) {
	t.Helper()
	var envelope struct {
		OK   bool            `json:"ok"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("response is not successful: %s", raw)
	}
	if err := json.Unmarshal(envelope.Data, destination); err != nil {
		t.Fatal(err)
	}
}

func assertExternalPackageErrorCode(t *testing.T, raw []byte, want security.ErrorCode) {
	t.Helper()
	var envelope decodedErrorResponse
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Code != string(want) {
		t.Fatalf("error response=%#v want code=%q body=%s", envelope, want, raw)
	}
}

func assertExternalPackageJSONHasNoOwnerHashes(t *testing.T, raw []byte) {
	t.Helper()
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"owner_env_hash", "owner_user_hash", "owner_session_hash", "session_channel_id_hash", "env_hash", "user_hash", "session_hash", "channel_hash"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("public external package JSON contains private owner material %q: %s", forbidden, raw)
		}
	}
}

func TestInspectedInstallOperationHTTPRecoversSameRequest(t *testing.T) {
	module := newHTTPExternalPackageModule(t)
	platform := newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module})
	handler := mustNewHandler(t, platform, allowHTTPTestGuard())
	raw := buildHTTPFixturePackage(t)
	inspectRaw := externalPackageUploadRequest(t, handler, http.MethodPost, "/_redevplugin/api/plugins/external-packages/upload/inspect", raw, nil, int64(len(raw)), http.StatusOK)
	var inspection host.ExternalPackageInspection
	decodeExternalPackageData(t, inspectRaw, &inspection)
	request := map[string]any{"request_id": "reviewed-preview", "inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256}
	started := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations", request, http.StatusOK)
	var first host.InspectedInstallOperation
	decodeExternalPackageData(t, started, &first)
	for deadline := time.Now().Add(3 * time.Second); ; {
		queried := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations/query", map[string]any{"request_id": "reviewed-preview"}, http.StatusOK)
		var current host.InspectedInstallOperation
		decodeExternalPackageData(t, queried, &current)
		if current.Execution.ID != first.Execution.ID {
			t.Fatal("receipt identity changed")
		}
		if strings.Contains(string(queried), "owner_user_hash") || strings.Contains(string(queried), "owner_session_hash") {
			t.Fatal("owner authority leaked")
		}
		if current.Execution.Status == "completed" {
			if current.MutationOutcome != "committed" {
				t.Fatal("false success")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("install did not complete: %+v", current)
		}
		time.Sleep(time.Millisecond)
	}
	externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations", request, http.StatusOK)
	request["expected_package_sha256"] = "sha256:" + strings.Repeat("a", 64)
	externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations", request, http.StatusBadRequest)
}

func waitHTTPInstall(t *testing.T, handler http.Handler, requestID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install-operations/query", map[string]any{"request_id": requestID}, http.StatusOK)
		var op host.InspectedInstallOperation
		decodeExternalPackageData(t, raw, &op)
		if op.Execution.Status != "running" {
			if op.Execution.Status != "completed" {
				t.Fatalf("installation failed: %+v", op)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("installation timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUpdateReviewUsesStableConfirmationError(t *testing.T) {
	if got := errorCodeForManagementError(host.ErrUpdateReviewRequired); got != security.ErrConfirmationRequired {
		t.Fatalf("code=%s", got)
	}
	if got := httpStatusForManagementError(host.ErrUpdateReviewRequired); got != http.StatusConflict {
		t.Fatalf("status=%d", got)
	}
}

type repositoryQueryTransport func(*http.Request) (*http.Response, error)

func (f repositoryQueryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRepositoryPluginQueryUsesPlatformIndexAndHostSelection(t *testing.T) {
	index := `{"schema_version":"redevplugin.repository-index.v1","targets":[{"ecosystem":"redevplugin","host":"redeven","plugins":[{"plugin_id":"example.zulu","path":"zulu","manifest":"manifest.json","release":{"tag_template":"zulu-v{version}","package_asset_template":"plugin.redevplugin"}},{"plugin_id":"example.alpha","path":"alpha","manifest":"manifest.json","release":{"tag_template":"alpha-v{version}","package_asset_template":"plugin.redevplugin"}}]}]}`
	sha := strings.Repeat("a", 40)
	calls := 0
	module := newHTTPExternalPackageModule(t)
	module.GitHub.Transport = repositoryQueryTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body string
		switch r.URL.Path {
		case "/repos/example/plugins":
			body = `{"id":1,"name":"plugins","owner":{"login":"example"},"default_branch":"main"}`
		case "/repos/example/plugins/commits/main":
			body = `{"sha":"` + sha + `"}`
		case "/repos/example/plugins/contents/.redevplugin/index.json":
			if r.URL.Query().Get("ref") != sha {
				t.Fatal("unbound index read")
			}
			raw, err := json.Marshal(map[string]any{"type": "file", "encoding": "base64", "path": repositoryindex.IndexPath, "size": len(index), "content": base64.StdEncoding.EncodeToString([]byte(index))})
			if err != nil {
				t.Fatal(err)
			}
			body = string(raw)
		default:
			t.Fatalf("unexpected GitHub path %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	path := "/_redevplugin/api/plugins/repository/plugins/query"
	raw := externalPackageRequest(t, handler, path, map[string]any{"url": "https://github.com/example/plugins", "host": "redeven"}, http.StatusOK)
	var result []repositoryindex.Plugin
	decodeExternalPackageData(t, raw, &result)
	if len(result) != 2 || result[0].PluginID != "example.alpha" || result[1].PluginID != "example.zulu" || calls != 3 {
		t.Fatalf("repository selection: %+v calls=%d", result, calls)
	}
	raw = externalPackageRequest(t, handler, path, map[string]any{"url": "https://github.com/example/plugins", "host": "another-host"}, http.StatusOK)
	decodeExternalPackageData(t, raw, &result)
	if len(result) != 0 {
		t.Fatal("returned plugins for another host")
	}
	before := calls
	externalPackageRequest(t, handler, path, map[string]any{"url": "https://example.com/example/plugins"}, http.StatusBadRequest)
	if calls != before {
		t.Fatal("invalid repository URL reached provider")
	}
}
