package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
)

type externalPackageTestStage struct {
	mu                 sync.Mutex
	pkg                pluginpkg.Package
	removed            int
	removeErr          error
	uploaded           externalsource.StagedArtifact
	uploadOwner        string
	uploadDeclaredSize int64
}

func (s *externalPackageTestStage) StageUpload(_ context.Context, owner string, source io.Reader, declaredSize int64) (externalsource.StagedArtifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == nil {
		return externalsource.StagedArtifact{}, errors.New("upload source is required")
	}
	s.uploadOwner = owner
	s.uploadDeclaredSize = declaredSize
	return s.uploaded, nil
}

func (s *externalPackageTestStage) VerifyPackage(context.Context, externalsource.StagedArtifact, pluginpkg.ReadLimits) (pluginpkg.Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pkg, nil
}

func (s *externalPackageTestStage) Remove(externalsource.StagedArtifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed++
	return s.removeErr
}

func (s *externalPackageTestStage) setPackage(pkg pluginpkg.Package) {
	s.mu.Lock()
	s.pkg = pkg
	s.mu.Unlock()
}

func (s *externalPackageTestStage) removedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removed
}

func (s *externalPackageTestStage) setRemoveError(err error) {
	s.mu.Lock()
	s.removeErr = err
	s.mu.Unlock()
}

type externalPackageTestFetcher struct {
	result      externalsource.FetchResult
	lastRequest externalsource.FetchRequest
}

type blockingExternalPackageTestFetcher struct {
	result  externalsource.FetchResult
	entered chan struct{}
	release chan struct{}
}

func (f *blockingExternalPackageTestFetcher) FetchPackage(ctx context.Context, _ externalsource.FetchRequest) (externalsource.FetchResult, error) {
	close(f.entered)
	select {
	case <-f.release:
		return f.result, nil
	case <-ctx.Done():
		return externalsource.FetchResult{}, ctx.Err()
	}
}

func (f *externalPackageTestFetcher) FetchPackage(_ context.Context, request externalsource.FetchRequest) (externalsource.FetchResult, error) {
	f.lastRequest = request
	return f.result, nil
}

type externalPackageTestGitHubResolver struct{}

func (externalPackageTestGitHubResolver) ResolvePackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.ResolvedGitHubAsset, error) {
	return externalsource.ResolvedGitHubAsset{}, errors.New("unexpected GitHub resolution")
}

type externalPackageTestAssessor struct {
	assessment registry.SignatureAssessment
}

type mutableExternalPackageTestAssessor struct {
	mu             sync.Mutex
	assessment     registry.SignatureAssessment
	freshness      registry.SignatureAssessment
	freshnessCalls int
	freshnessErr   error
}

func (a externalPackageTestAssessor) AssessExternalPackageSignature(context.Context, ExternalPackageSignatureAssessmentRequest) (registry.SignatureAssessment, error) {
	return a.assessment, nil
}

func (a externalPackageTestAssessor) AssessExternalPackageSignatureFreshness(_ context.Context, req ExternalPackageSignatureFreshnessRequest) (registry.SignatureAssessment, error) {
	return req.Assessment, nil
}

func (a *mutableExternalPackageTestAssessor) AssessExternalPackageSignature(context.Context, ExternalPackageSignatureAssessmentRequest) (registry.SignatureAssessment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.assessment, nil
}

func (a *mutableExternalPackageTestAssessor) AssessExternalPackageSignatureFreshness(_ context.Context, req ExternalPackageSignatureFreshnessRequest) (registry.SignatureAssessment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.freshnessCalls++
	if a.freshness.Status == "" {
		return req.Assessment, a.freshnessErr
	}
	return a.freshness, a.freshnessErr
}

func (a *mutableExternalPackageTestAssessor) setAssessment(assessment registry.SignatureAssessment) {
	a.mu.Lock()
	a.assessment = assessment
	a.mu.Unlock()
}

func (a *mutableExternalPackageTestAssessor) setFreshness(assessment registry.SignatureAssessment, err error) {
	a.mu.Lock()
	a.freshness = assessment
	a.freshnessErr = err
	a.mu.Unlock()
}

func (a *mutableExternalPackageTestAssessor) freshnessCallCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.freshnessCalls
}

func TestExternalPackageUnsignedInspectInstallInstallsDisabledWithoutGrants(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	stage := &externalPackageTestStage{pkg: pkg}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/example.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatalf("InspectExternalPackage() error = %v", err)
	}
	if fetcher := h.adapters.ExternalPackageFetcher.(*externalPackageTestFetcher); fetcher.lastRequest.QuotaKey != "env_hash" {
		t.Fatalf("fetch quota key = %q, want authenticated environment hash", fetcher.lastRequest.QuotaKey)
	}
	if inspection.SignatureAssessment.State != "absent" || inspection.ExecutionApproval.State != "pending" || inspection.UpdateEligibility.State != "manual_only" {
		t.Fatalf("inspection facts = %#v", inspection)
	}
	if inspection.Intent.PluginInstanceID == "" || inspection.InspectedHashes.PackageSHA256 == "" {
		t.Fatalf("inspection identity is incomplete: %#v", inspection)
	}

	committed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("InstallInspectedPackage() error = %v", err)
	}
	if committed.Plugin == nil || committed.Plugin.EnableState != registry.EnableDisabled {
		t.Fatalf("commit result = %#v", committed)
	}
	if committed.Plugin.ExecutionApproval.Status != registry.ExecutionApprovalUserApproved || committed.Plugin.UpdateEligibility != registry.UpdateManualOnly {
		t.Fatalf("committed facts = %#v", committed.Plugin)
	}
	authorization, err := h.getAuthorizationSnapshot(hostTestContext(), committed.Plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorization.Grants) != 0 {
		t.Fatalf("new external install has grants: %#v", authorization.Grants)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("staged artifact remove count = %d, want 1", stage.removedCount())
	}

	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: now.Add(2 * time.Minute),
	}); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("consumed inspection replay error = %v", err)
	}
}

func TestStateRootExternalInstallNeedsNoCallerRegistryOrInstallStages(t *testing.T) {
	config := modularTestConfig(t)
	config.StateRoot = filepath.Join(t.TempDir(), "state")
	pkg := readTestPackage(t, buildFixturePackage(t))
	stage := &externalPackageTestStage{pkg: pkg}
	rawDigest := sha256.Sum256([]byte("state-root-external-artifact"))
	artifact := externalsource.StagedArtifact{ID: "abcdef0123456789abcdef0123456789", Size: 1, SHA256: hex.EncodeToString(rawDigest[:])}
	stage.uploaded = artifact
	config.ExternalPackage = &ExternalPackageModule{
		stageStore: stage,
		packageFetcher: &externalPackageTestFetcher{result: externalsource.FetchResult{
			Artifact: artifact, Source: "https://plugins.example.test/example.redevplugin", Final: "https://plugins.example.test/example.redevplugin",
		}},
		githubResolver:    externalPackageTestGitHubResolver{},
		SignatureAssessor: externalPackageTestAssessor{},
	}
	h, err := Open(hostTestContext(), config)
	if err != nil {
		t.Fatalf("Open() with Host-owned persistence error = %v", err)
	}
	defer h.Close()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/example.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Plugin == nil || installed.Plugin.EnableState != registry.EnableDisabled {
		t.Fatalf("installed plugin = %#v", installed.Plugin)
	}
	records, err := h.ListPlugins(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PluginInstanceID != installed.Plugin.PluginInstanceID {
		t.Fatalf("Host control readback = %#v", records)
	}
}

func TestSQLiteExternalPackageCallPluginMethodKeepsExecutionAuthorized(t *testing.T) {
	ctx := hostTestContext()
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true,
		capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildRPCFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := stableRecentTestNow()

	inspection, err := h.InspectExternalPackage(ctx, InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/sqlite.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatalf("InspectExternalPackage() error = %v", err)
	}
	committed, err := h.InstallInspectedPackage(ctx, InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("InstallInspectedPackage() error = %v", err)
	}
	if committed.Plugin == nil {
		t.Fatal("InstallInspectedPackage() returned no plugin")
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: committed.Plugin.PluginInstanceID,
		Now:              now.Add(2 * time.Second),
		ExpectedManagementRevision: mustManagementRevision(t, h,
			committed.Plugin.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	grantDeclaredPermissions(t, h, enabled)
	_, gateway := openSurfaceAndMintGateway(t, h, enabled.PluginInstanceID, "rpc.view")

	result, err := h.CallPluginMethod(ctx, CallMethodRequest{
		PluginInstanceID: enabled.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
		Now: stableRecentTestNow(),
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok || data["ok"] != true || adapter.calls != 1 {
		t.Fatalf("CallPluginMethod() result = %#v, adapter calls = %d", result, adapter.calls)
	}
}

func TestUploadedExternalPackageUsesOwnerScopedStageAndPersistsManualOnlyProvenance(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle v1"))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := time.Date(2026, 7, 23, 13, 0, 0, 0, time.UTC)

	inspection, err := h.InspectUploadedExternalPackage(hostTestContext(), InspectUploadedExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7, Now: now,
	})
	if err != nil {
		t.Fatalf("InspectUploadedExternalPackage() error = %v", err)
	}
	stage.mu.Lock()
	uploadOwner, uploadDeclaredSize := stage.uploadOwner, stage.uploadDeclaredSize
	stage.mu.Unlock()
	if uploadOwner != "env_hash" || uploadDeclaredSize != 7 {
		t.Fatalf("upload staging owner=%q size=%d", uploadOwner, uploadDeclaredSize)
	}
	if inspection.SourceProvenance.Kind != "package_upload" || !strings.HasPrefix(inspection.SourceProvenance.UploadID, "upload_") ||
		inspection.SourceProvenance.SourceOrigin != "" || inspection.SourceProvenance.RepositoryURL != "" {
		t.Fatalf("upload provenance = %#v", inspection.SourceProvenance)
	}
	if inspection.UpdateEligibility.State != "manual_only" || inspection.SignatureAssessment.State != "absent" {
		t.Fatalf("upload security facts = %#v", inspection)
	}

	committed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("InstallInspectedPackage() error = %v", err)
	}
	if committed.Plugin == nil || committed.Plugin.PackageSourceProvenance.Kind != registry.PackageSourcePackageUpload ||
		committed.Plugin.PackageSourceProvenance.UploadID != inspection.SourceProvenance.UploadID ||
		committed.Plugin.UpdateEligibility != registry.UpdateManualOnly || committed.Plugin.EnableState != registry.EnableDisabled {
		t.Fatalf("committed upload = %#v", committed.Plugin)
	}
	stage.setPackage(readTestPackage(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")))
	updatedInspection, err := h.InspectUploadedExternalPackage(hostTestContext(), InspectUploadedExternalPackageRequest{
		Intent: ExternalPackageIntent{
			Action: "update", PluginInstanceID: committed.Plugin.PluginInstanceID,
			ExpectedManagementRevision: committed.Plugin.ManagementRevision,
		},
		Package: strings.NewReader("package-v2"), DeclaredSize: 10, Now: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("InspectUploadedExternalPackage(update) error = %v", err)
	}
	updated, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: updatedInspection.InspectionID, ExpectedPackageSHA256: updatedInspection.InspectedHashes.PackageSHA256, Now: now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("InstallInspectedPackage(update) error = %v", err)
	}
	if updated.Plugin == nil || len(updated.Plugin.VersionHistory) != 1 ||
		updated.Plugin.VersionHistory[0].PackageSourceProvenance.Kind != registry.PackageSourcePackageUpload ||
		updated.Plugin.VersionHistory[0].PackageSourceProvenance.UploadID != inspection.SourceProvenance.UploadID ||
		updated.Plugin.PackageSourceProvenance.UploadID != updatedInspection.SourceProvenance.UploadID {
		t.Fatalf("uploaded version history = %#v", updated.Plugin)
	}
}

func TestExternalPackageInspectionBindsExactSessionAndBlocksInvalidSignature(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	pkg.PackageSignature = &pluginpkg.PackageSignature{SchemaVersion: pluginpkg.PackageSignatureSchemaVersion, Algorithm: "ed25519", KeyID: "known", Signature: "invalid"}
	stage := &externalPackageTestStage{pkg: pkg}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{Status: registry.SignatureInvalid, ReasonCodes: []string{"signature_verification_failed"}})

	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/invalid.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.SignatureAssessment.State != "invalid" || inspection.ExecutionApproval.State != "policy_blocked" {
		t.Fatalf("blocked inspection = %#v", inspection)
	}
	otherSession := hostTestContextWith("other_session", "user_hash", "env_hash", "other_channel")
	if _, err := h.InstallInspectedPackage(otherSession, InstallInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256}); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("cross-session commit error = %v", err)
	}
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256}); !errors.Is(err, ErrExternalPackageInstallBlocked) {
		t.Fatalf("invalid signature commit error = %v", err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("blocked commit staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageInspectRemovesExpiredPendingStageBeforeFetching(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	stage := &externalPackageTestStage{pkg: pkg}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	first, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/first.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ExpiresAt != now.Add(externalPackageInspectionTTL) {
		t.Fatalf("first expiry = %v", first.ExpiresAt)
	}
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/second.redevplugin"},
		Now:    first.ExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("expired stage remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageExpiredCleanupFailureRetainsInspectionForRetry(t *testing.T) {
	cleanupErr := errors.New("stage cleanup failed")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t)), removeErr: cleanupErr}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	first, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/retry-cleanup.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/blocked-by-cleanup.redevplugin"},
		Now:    first.ExpiresAt,
	}); !errors.Is(err, cleanupErr) {
		t.Fatalf("InspectExternalPackage() cleanup error = %v", err)
	}
	session, err := requireUserSession(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.externalInspections.get(first.InspectionID, scope); err != nil {
		t.Fatalf("expired inspection was lost after failed deletion: %v", err)
	}
	stage.setRemoveError(nil)
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/after-cleanup.redevplugin"},
		Now:    first.ExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if stage.removedCount() != 2 {
		t.Fatalf("stage remove attempts = %d, want failed attempt plus retry", stage.removedCount())
	}
	if _, err := h.externalInspections.get(first.InspectionID, scope); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("successfully cleaned inspection remains registered: %v", err)
	}
}

func TestExternalPackageInspectReservationLetsSessionRevokeDrainRegisteredStage(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	baseFetcher := h.adapters.ExternalPackageFetcher.(*externalPackageTestFetcher)
	blocking := &blockingExternalPackageTestFetcher{result: baseFetcher.result, entered: make(chan struct{}), release: make(chan struct{})}
	h.adapters.ExternalPackageFetcher = blocking

	inspectionDone := make(chan error, 1)
	go func() {
		_, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
			Intent: ExternalPackageIntent{Action: "install"},
			Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/session-race.redevplugin"},
		})
		inspectionDone <- err
	}()
	<-blocking.entered
	revokeDone := make(chan error, 1)
	go func() {
		_, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
		revokeDone <- err
	}()
	select {
	case err := <-revokeDone:
		t.Fatalf("session revoke passed active inspection reservation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocking.release)
	if err := <-inspectionDone; err != nil {
		t.Fatal(err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatal(err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("session revoke removed staged artifact %d times, want 1", stage.removedCount())
	}
}

func TestExternalPackageSessionRevokeCleanupFailureIsFencedAndRetryable(t *testing.T) {
	cleanupErr := errors.New("session stage cleanup failed")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/revoke-cleanup-retry.redevplugin"},
	}); err != nil {
		t.Fatal(err)
	}
	session, err := requireUserSession(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(hostTestContext(), scope)
	if err != nil {
		t.Fatal(err)
	}
	stage.setRemoveError(cleanupErr)
	first, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) || !first.Fenced || first.Complete {
		t.Fatalf("first revoke = %#v, %v", first, err)
	}
	stage.setRemoveError(nil)
	second, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Identity: identity, Now: time.Now().UTC()})
	if err != nil || !second.Fenced || !second.Complete {
		t.Fatalf("retried revoke = %#v, %v", second, err)
	}
	if stage.removedCount() != 2 {
		t.Fatalf("session cleanup attempts = %d, want failed attempt plus retry", stage.removedCount())
	}
}

func TestExternalPackageCommitReassessesSignatureAndBlocksNewRevocation(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	pkg.PackageSignature = &pluginpkg.PackageSignature{SchemaVersion: pluginpkg.PackageSignatureSchemaVersion, Algorithm: "ed25519", KeyID: "known", Signature: "test"}
	stage := &externalPackageTestStage{pkg: pkg}
	assessor := &mutableExternalPackageTestAssessor{assessment: registry.SignatureAssessment{
		Status: registry.SignatureVerified, EvidenceReference: "sha256:key", KeyringGeneration: "1", RevocationGeneration: "1",
	}}
	configureExternalPackageTestModuleWithAssessor(h, stage, assessor)

	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/revoked-after-inspect.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assessor.setAssessment(registry.SignatureAssessment{Status: registry.SignatureRevoked, ReasonCodes: []string{"signing_key_revoked"}})
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
	}); !errors.Is(err, ErrExternalPackageInstallBlocked) {
		t.Fatalf("InstallInspectedPackage() error = %v, want blocked", err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("revoked commit staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageExpiredInspectionRemovesStagedArtifact(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/expired.redevplugin"},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, Now: inspection.ExpiresAt,
	}); !errors.Is(err, ErrExternalPackageInspectionExpired) {
		t.Fatalf("InstallInspectedPackage() error = %v, want expired", err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("expired inspection staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageInstallBindsConfirmedHashAndReverifiedBytes(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle v1"))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/exact.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: "sha256:other",
	}); !errors.Is(err, ErrExternalPackageConfirmation) {
		t.Fatalf("mismatched confirmation hash error = %v", err)
	}

	stage.setPackage(readTestPackage(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")))
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
	}); err == nil || !strings.Contains(err.Error(), "changed after inspection") {
		t.Fatalf("changed staged bytes error = %v", err)
	}
	if _, err := h.getPluginRecord(hostTestContext(), inspection.Intent.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("changed package was installed: %v", err)
	}
}

func TestExternalPackageInspectionExpiresAcrossHostRestart(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/restart.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.externalInspections = newExternalPackageInspectionStore()
	if _, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
	}); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("inspection survived Host restart: %v", err)
	}
}

func TestExternalPackageFreshnessPolicyDisablesRevokedButAllowsUnavailable(t *testing.T) {
	h, _, audits := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	pkg.PackageSignature = &pluginpkg.PackageSignature{SchemaVersion: pluginpkg.PackageSignatureSchemaVersion, Algorithm: "ed25519", KeyID: "known", Signature: "test"}
	stage := &externalPackageTestStage{pkg: pkg}
	assessor := &mutableExternalPackageTestAssessor{assessment: registry.SignatureAssessment{
		Status: registry.SignatureVerified, EvidenceReference: "sha256:key", KeyringGeneration: "1", RevocationGeneration: "1",
	}}
	configureExternalPackageTestModuleWithAssessor(h, stage, assessor)
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/freshness.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := *committed.Plugin

	assessor.setFreshness(registry.SignatureAssessment{Status: registry.SignatureUnavailable}, errors.New("keyring offline"))
	if err := h.canRun(hostTestContext(), record); err != nil {
		t.Fatalf("canRun() unavailable freshness error = %v", err)
	}
	assessor.setFreshness(registry.SignatureAssessment{Status: registry.SignatureRevoked}, nil)
	if err := h.validateExecutionBinding(hostTestContext(), capability.ExecutionBinding{PluginInstanceID: record.PluginInstanceID}); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("validateExecutionBinding() revoked freshness error = %v, want execution revoked", err)
	}
	disabled, err := h.getPluginRecord(hostTestContext(), record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("enable state = %q, want disabled_by_policy", disabled.EnableState)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatal("revoked freshness did not revoke runtime capabilities")
	}
}

func TestExternalPackageFreshnessDoesNotAffectLocalPlugins(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	assessor := &mutableExternalPackageTestAssessor{}
	h.adapters.ExternalPackageSignatureAssessor = assessor
	if err := h.canRun(hostTestContext(), installed); err != nil {
		t.Fatalf("canRun() local plugin error = %v", err)
	}
	if assessor.freshnessCallCount() != 0 {
		t.Fatalf("local plugin freshness calls = %d, want 0", assessor.freshnessCallCount())
	}
}

func TestExternalPackageHostCloseDrainsPendingStagedArtifacts(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/pending-close.redevplugin"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("Host.Close() staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageHostCloseReturnsStageCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("stage cleanup failed")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, expectCloseErr: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t)), removeErr: cleanupErr}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/cleanup-failure.redevplugin"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Host.Close() error = %v, want stage cleanup failure", err)
	}
}

func TestExternalPackageUnverifiedUpdateDisablesWithoutRefreshingNewBytes(t *testing.T) {
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle v1"))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/lifecycle-v1.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.Plugin.PluginInstanceID,
		ExpectedManagementRevision: installed.Plugin.ManagementRevision,
		Now:                        time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeSnapshots := len(surfaces.snapshots)
	stage.setPackage(readTestPackage(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")))
	updateInspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{
			Action: "update", PluginInstanceID: enabled.PluginInstanceID,
			ExpectedManagementRevision: enabled.ManagementRevision,
		},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/lifecycle-v2.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := h.InstallInspectedPackage(hostTestContext(), InstallInspectedPackageRequest{
		InspectionID: updateInspection.InspectionID, ExpectedPackageSHA256: updateInspection.InspectedHashes.PackageSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Plugin == nil || updated.Plugin.Version != "2.0.0" || updated.Plugin.EnableState != registry.EnableDisabled || updated.Plugin.UpdateEligibility != registry.UpdateManualOnly {
		t.Fatalf("updated plugin = %#v", updated.Plugin)
	}
	if len(surfaces.snapshots) != beforeSnapshots {
		t.Fatalf("unverified update refreshed new package bytes: snapshots before=%d after=%d", beforeSnapshots, len(surfaces.snapshots))
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatal("external update did not revoke old runtime capabilities")
	}
	authorization, err := h.getAuthorizationSnapshot(hostTestContext(), updated.Plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorization.Grants) != 0 {
		t.Fatalf("unverified update retained grants: %#v", authorization.Grants)
	}
}

func configureExternalPackageTestModule(h *Host, stage *externalPackageTestStage, assessment registry.SignatureAssessment) {
	configureExternalPackageTestModuleWithAssessor(h, stage, externalPackageTestAssessor{assessment: assessment})
}

func configureExternalPackageTestModuleWithAssessor(h *Host, stage *externalPackageTestStage, assessor ExternalPackageSignatureAssessor) {
	rawDigest := sha256.Sum256([]byte("external-package-test-artifact"))
	artifact := externalsource.StagedArtifact{ID: "0123456789abcdef0123456789abcdef", Size: 1, SHA256: hex.EncodeToString(rawDigest[:])}
	stage.uploaded = artifact
	h.adapters.ExternalPackageStageStore = stage
	h.adapters.ExternalPackageFetcher = &externalPackageTestFetcher{result: externalsource.FetchResult{
		Artifact: artifact, Source: "https://plugins.example.test/example.redevplugin", Final: "https://plugins.example.test/example.redevplugin",
	}}
	h.adapters.ExternalPackageGitHubResolver = externalPackageTestGitHubResolver{}
	h.adapters.ExternalPackageSignatureAssessor = assessor
	h.features[FeatureExternalPackage] = struct{}{}
}
