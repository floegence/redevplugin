package httpadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

type httpExternalPackageStage struct {
	pkg     pluginpkg.Package
	removed int
}

func (stage *httpExternalPackageStage) VerifyPackage(context.Context, externalsource.StagedArtifact, pluginpkg.ReadLimits) (pluginpkg.Package, error) {
	return stage.pkg, nil
}

func (stage *httpExternalPackageStage) Remove(externalsource.StagedArtifact) error {
	stage.removed++
	return nil
}

type httpExternalPackageFetcher struct {
	result externalsource.FetchResult
}

func (fetcher httpExternalPackageFetcher) FetchPackage(context.Context, externalsource.FetchRequest) (externalsource.FetchResult, error) {
	return fetcher.result, nil
}

type httpExternalPackageGitHubResolver struct{}

func (httpExternalPackageGitHubResolver) ResolvePackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.ResolvedGitHubAsset, error) {
	return externalsource.ResolvedGitHubAsset{}, errors.New("unexpected GitHub resolution")
}

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
		action websecurity.RouteAction
		effect websecurity.RouteEffect
	}{
		"/_redevplugin/api/plugins/external-packages/inspect":      {websecurity.RouteActionInspectExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/commit":       {websecurity.RouteActionCommitExternalPackage, websecurity.RouteEffectMutation},
		"/_redevplugin/api/plugins/external-packages/commit/query": {websecurity.RouteActionQueryExternalPackageCommit, websecurity.RouteEffectQuery},
	}
	for _, route := range routes {
		expected, ok := want[route.Path]
		if !ok {
			continue
		}
		if route.Method != http.MethodPost || route.action != expected.action || route.Effect != expected.effect || route.originPolicy != websecurity.OriginPolicyTrustedHost || route.csrfPolicy != websecurity.CSRFPolicyRequired {
			t.Fatalf("route %s contract = %#v", route.Path, route)
		}
		delete(want, route.Path)
	}
	if len(want) != 0 {
		t.Fatalf("missing external package routes: %v", want)
	}
}

func TestExternalPackageRoutesBindInspectionToSessionAndHideOwnerHashes(t *testing.T) {
	module, stage := newHTTPExternalPackageModule(t, registry.SignatureAbsent)
	pluginHost := newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module})
	original := mustNewHandler(t, pluginHost, allowHTTPTestGuard())

	inspectRaw := externalPackageRequest(t, original, "/_redevplugin/api/plugins/external-packages/inspect", map[string]any{
		"intent": map[string]any{"action": "install"},
		"source": map[string]any{"kind": "package_url", "url": "https://plugins.example.test/example.redevplugin"},
	}, http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, inspectRaw)
	var inspection host.ExternalPackageInspection
	decodeExternalPackageData(t, inspectRaw, &inspection)
	if inspection.InspectionID == "" || inspection.ConfirmationDigest == "" || inspection.ExecutionApproval.State != "pending" {
		t.Fatalf("inspection = %#v", inspection)
	}

	crossSessionGuard := &httpTestWebSecurityGuard{scope: sessionctx.Context{
		OwnerSessionHash: "other_session", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "other_channel",
	}}
	crossSession := mustNewHandler(t, pluginHost, crossSessionGuard)
	crossCommit := externalPackageRequest(t, crossSession, "/_redevplugin/api/plugins/external-packages/commit", map[string]any{
		"inspection_id": inspection.InspectionID, "confirmation_digest": inspection.ConfirmationDigest,
	}, http.StatusBadRequest)
	assertExternalPackageErrorCode(t, crossCommit, security.ErrInvalidRequest)
	assertExternalPackageJSONHasNoOwnerHashes(t, crossCommit)

	commitRaw := externalPackageRequest(t, original, "/_redevplugin/api/plugins/external-packages/commit", map[string]any{
		"inspection_id": inspection.InspectionID, "confirmation_digest": inspection.ConfirmationDigest,
	}, http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, commitRaw)
	var committed externalPackageCommitResultResponse
	decodeExternalPackageData(t, commitRaw, &committed)
	if committed.Status != "committed" || committed.Receipt == nil || committed.Plugin == nil || stage.removed != 1 {
		t.Fatalf("commit = %#v removed=%d", committed, stage.removed)
	}

	queryRaw := externalPackageRequest(t, original, "/_redevplugin/api/plugins/external-packages/commit/query", map[string]any{
		"inspection_id": inspection.InspectionID, "commit_id": committed.Receipt.CommitID,
	}, http.StatusOK)
	assertExternalPackageJSONHasNoOwnerHashes(t, queryRaw)

	crossOwnerGuard := &httpTestWebSecurityGuard{scope: sessionctx.Context{
		OwnerSessionHash: "foreign_session", OwnerUserHash: "foreign_user", OwnerEnvHash: "foreign_env", SessionChannelIDHash: "foreign_channel",
	}}
	crossOwner := mustNewHandler(t, pluginHost, crossOwnerGuard)
	crossQuery := externalPackageRequest(t, crossOwner, "/_redevplugin/api/plugins/external-packages/commit/query", map[string]any{
		"inspection_id": inspection.InspectionID, "commit_id": committed.Receipt.CommitID,
	}, http.StatusBadRequest)
	assertExternalPackageErrorCode(t, crossQuery, security.ErrInvalidRequest)
	assertExternalPackageJSONHasNoOwnerHashes(t, crossQuery)
}

func TestExternalPackageInvalidAndRevokedCommitErrorsAreStable(t *testing.T) {
	for _, status := range []registry.SignatureAssessmentStatus{registry.SignatureInvalid, registry.SignatureRevoked} {
		t.Run(string(status), func(t *testing.T) {
			module, _ := newHTTPExternalPackageModule(t, status)
			handler := mustNewHandler(t, newHTTPTestHostWithOptions(t, httpTestHostOptions{external: module}), allowHTTPTestGuard())
			inspectRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/inspect", map[string]any{
				"intent": map[string]any{"action": "install"},
				"source": map[string]any{"kind": "package_url", "url": "https://plugins.example.test/blocked.redevplugin"},
			}, http.StatusOK)
			var inspection host.ExternalPackageInspection
			decodeExternalPackageData(t, inspectRaw, &inspection)
			if inspection.SignatureAssessment.State != string(status) || inspection.ExecutionApproval.State != "policy_blocked" {
				t.Fatalf("inspection = %#v", inspection)
			}
			commitRaw := externalPackageRequest(t, handler, "/_redevplugin/api/plugins/external-packages/commit", map[string]any{
				"inspection_id": inspection.InspectionID, "confirmation_digest": inspection.ConfirmationDigest,
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

func newHTTPExternalPackageModule(t *testing.T, status registry.SignatureAssessmentStatus) (*host.ExternalPackageModule, *httpExternalPackageStage) {
	t.Helper()
	raw := buildHTTPFixturePackage(t)
	pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	if status != registry.SignatureAbsent {
		pkg.PackageSignature = &pluginpkg.PackageSignature{
			SchemaVersion: pluginpkg.PackageSignatureSchemaVersion,
			Algorithm:     pluginpkg.PackageSignatureAlgorithmEd25519,
			KeyID:         "test-key",
			Signature:     "invalid-test-signature",
		}
	}
	stage := &httpExternalPackageStage{pkg: pkg}
	digest := sha256.Sum256(raw)
	artifact := externalsource.StagedArtifact{ID: "0123456789abcdef0123456789abcdef", Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
	return &host.ExternalPackageModule{
		StageStore: stage,
		PackageFetcher: httpExternalPackageFetcher{result: externalsource.FetchResult{
			Artifact: artifact,
			Source:   "https://plugins.example.test:443/example.redevplugin",
			Final:    "https://plugins.example.test:443/example.redevplugin",
		}},
		GitHubResolver:    httpExternalPackageGitHubResolver{},
		SignatureAssessor: httpExternalPackageAssessor{status: status},
	}, stage
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
