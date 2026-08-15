package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v2/pkg/externalsource"
	"github.com/floegence/redevplugin/v2/pkg/host"
	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/security"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
	"github.com/floegence/redevplugin/v2/pkg/websecurity"
)

type httpExternalPackageAssessor struct {
	status registry.SignatureAssessmentStatus
}

func (assessor httpExternalPackageAssessor) AssessExternalPackageSignature(context.Context, host.ExternalPackageSignatureAssessmentRequest) (registry.SignatureAssessment, error) {
	return registry.SignatureAssessment{Status: assessor.status, ReasonCodes: []string{"test_" + string(assessor.status)}}, nil
}

func (httpExternalPackageAssessor) AssessExternalPackageSignatureFreshness(_ context.Context, req host.ExternalPackageSignatureFreshnessRequest) (registry.SignatureAssessment, error) {
	return req.Assessment, nil
}

func TestExternalPackageRoutesDeclareClosedSecurityContracts(t *testing.T) {
	want := map[string]struct {
		method string
		action websecurity.RouteAction
		effect websecurity.RouteEffect
	}{
		"/_redevplugin/api/plugins/external-packages/inspect":                             {http.MethodPost, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/upload/inspect":                      {http.MethodPost, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/{plugin_instance_id}/external-packages/upload/inspect": {http.MethodPut, websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/install":                             {http.MethodPost, websecurity.RouteActionInstallInspectedPackage, websecurity.RouteEffectMutation},
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
	module := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	raw := buildHTTPFixturePackage(t)

	installRaw := externalPackageUploadRequest(t, handler, http.MethodPost,
		"/_redevplugin/api/plugins/external-packages/upload/inspect", raw, nil, int64(len(raw)), http.StatusOK)
	var inspection host.ExternalPackageInspection
	decodeExternalPackageData(t, installRaw, &inspection)
	if inspection.SourceProvenance.Kind != "package_upload" || !strings.HasPrefix(inspection.SourceProvenance.UploadID, "upload_") ||
		inspection.UpdateEligibility.State != "manual_only" {
		t.Fatalf("upload inspection=%#v", inspection)
	}
	commitRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install", map[string]any{
		"inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusOK)
	var committed installedExternalPackageResponse
	decodeExternalPackageData(t, commitRaw, &committed)
	if committed.Plugin == nil || committed.SourceProvenance == nil || committed.SourceProvenance.UploadID != inspection.SourceProvenance.UploadID {
		t.Fatalf("committed upload = %#v", committed)
	}

	revision := strconv.FormatUint(committed.Plugin.ManagementRevision, 10)
	updateRaw := externalPackageUploadRequest(t, handler, http.MethodPut,
		"/_redevplugin/api/plugins/"+committed.Plugin.PluginInstanceID+"/external-packages/upload/inspect", raw,
		http.Header{localImportRevisionHeader: []string{revision}, "Content-Type": []string{localImportContentType}}, -1, http.StatusOK)
	var updateInspection host.ExternalPackageInspection
	decodeExternalPackageData(t, updateRaw, &updateInspection)
	if updateInspection.Intent.Action != "update" || updateInspection.Intent.PluginInstanceID != committed.Plugin.PluginInstanceID ||
		updateInspection.Intent.ExpectedManagementRevision != committed.Plugin.ManagementRevision {
		t.Fatalf("update inspection=%#v", updateInspection)
	}
}

func TestExternalPackageUploadHeadersAndLimitsRejectBeforeStage(t *testing.T) {
	module := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
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
	module := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
	handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
	raw := externalPackageUploadRequest(t, handler, http.MethodPost,
		"/_redevplugin/api/plugins/external-packages/upload/inspect", []byte("chunk"), nil, externalsource.MaxArtifactBytes+1, http.StatusRequestEntityTooLarge)
	assertExternalPackageErrorCode(t, raw, security.ErrPackageTooLarge)
}

func TestExternalPackageUploadSignatureStatesPreserveAdmissionPolicy(t *testing.T) {
	for _, status := range []registry.SignatureAssessmentStatus{
		registry.SignatureAbsent, registry.SignatureUnknownSigner, registry.SignatureUnavailable,
		registry.SignatureVerified, registry.SignatureInvalid, registry.SignatureRevoked,
	} {
		t.Run(string(status), func(t *testing.T) {
			module := newHTTPExternalPackageModule(t, status)
			handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
			packageBytes := buildHTTPExternalPackage(t, status)
			raw := externalPackageUploadRequest(t, handler, http.MethodPost,
				"/_redevplugin/api/plugins/external-packages/upload/inspect", packageBytes, nil, int64(len(packageBytes)), http.StatusOK)
			var inspection host.ExternalPackageInspection
			decodeExternalPackageData(t, raw, &inspection)
			if inspection.SignatureAssessment.State != string(status) || inspection.UpdateEligibility.State != "manual_only" {
				t.Fatalf("inspection = %#v", inspection)
			}
			blocked := status == registry.SignatureInvalid || status == registry.SignatureRevoked
			wantApproval := "pending"
			wantStatus := http.StatusOK
			if blocked {
				wantApproval = "policy_blocked"
				wantStatus = http.StatusForbidden
			}
			if inspection.ExecutionApproval.State != wantApproval {
				t.Fatalf("approval = %#v", inspection.ExecutionApproval)
			}
			commitRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install", map[string]any{
				"inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
			}, wantStatus)
			if blocked {
				assertExternalPackageErrorCode(t, commitRaw, security.ErrSignatureInvalid)
			}
		})
	}
}

func TestInstalledExternalPackageWireProjectionContainsNoReceiptLifecycle(t *testing.T) {
	projected, err := publicInstalledExternalPackage(host.InstalledExternalPackage{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("receipt")) || bytes.Contains(raw, []byte("commit_id")) || bytes.Contains(raw, []byte("failure_code")) {
		t.Fatalf("installed package projection retained durable commit lifecycle: %s", raw)
	}
}

func TestExternalPackageUploadUpdateRejectsSlashPluginInstanceIDs(t *testing.T) {
	module := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
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
	module := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
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
	crossCommit := externalPackageRequest(t, crossSession, "/_redevplugin/api/plugins/external-packages/install", map[string]any{
		"inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusBadRequest)
	assertExternalPackageErrorCode(t, crossCommit, security.ErrInvalidRequest)
	assertExternalPackageJSONHasNoOwnerHashes(t, crossCommit)

	commitRaw := externalPackageRequest(t, original, "/_redevplugin/api/plugins/external-packages/install", map[string]any{
		"inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
	}, http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, commitRaw)
	var committed installedExternalPackageResponse
	decodeExternalPackageData(t, commitRaw, &committed)
	if committed.Plugin == nil {
		t.Fatalf("commit = %#v", committed)
	}
}

func TestExternalPackageInvalidAndRevokedCommitErrorsAreStable(t *testing.T) {
	for _, status := range []registry.SignatureAssessmentStatus{registry.SignatureInvalid, registry.SignatureRevoked} {
		t.Run(string(status), func(t *testing.T) {
			module := newHTTPExternalPackageModule(t, status)
			handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
			rawPackage := buildHTTPExternalPackage(t, status)
			inspectRaw := externalPackageUploadRequest(t, handler, http.MethodPost,
				"/_redevplugin/api/plugins/external-packages/upload/inspect", rawPackage, nil, int64(len(rawPackage)), http.StatusOK)
			var inspection host.ExternalPackageInspection
			decodeExternalPackageData(t, inspectRaw, &inspection)
			if inspection.SignatureAssessment.State != string(status) || inspection.ExecutionApproval.State != "policy_blocked" {
				t.Fatalf("inspection = %#v", inspection)
			}
			commitRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/install", map[string]any{
				"inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256,
			}, http.StatusForbidden)
			assertExternalPackageErrorCode(t, commitRaw, security.ErrSignatureInvalid)
			var envelope decodedErrorResponse
			if err := json.Unmarshal(commitRaw, &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Message != "plugin trust verification failed" || envelope.MutationOutcome != "not_committed" {
				t.Fatalf("blocked commit error is unstable: %#v", envelope)
			}
			assertExternalPackageJSONHasNoOwnerHashes(t, commitRaw)
		})
	}
}

func newHTTPExternalPackageModule(t *testing.T, status registry.SignatureAssessmentStatus) *host.ExternalPackageModule {
	t.Helper()
	return &host.ExternalPackageModule{SignatureAssessor: httpExternalPackageAssessor{status: status}}
}

func buildHTTPExternalPackage(t *testing.T, status registry.SignatureAssessmentStatus) []byte {
	t.Helper()
	raw := buildHTTPFixturePackage(t)
	if status == registry.SignatureAbsent {
		return raw
	}
	pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	pkg.PackageSignature = &pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion,
		Algorithm:     pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:         "test-key",
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.Plugin.PluginID,
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "invalid-test-signature",
	}
	var signed bytes.Buffer
	if err := pluginpkg.WritePackage(context.Background(), &signed, pkg); err != nil {
		t.Fatal(err)
	}
	return signed.Bytes()
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
