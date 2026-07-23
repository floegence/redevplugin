package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/mutation"
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

type externalPackageCommitErrorStore struct {
	registry.Store
	cause    error
	injected bool
}

func (s *externalPackageCommitErrorStore) CommitExternalPackage(ctx context.Context, req registry.CommitExternalPackageRequest) (registry.ExternalPackageCommitResult, error) {
	result, err := s.Store.CommitExternalPackage(ctx, req)
	if err == nil && !s.injected {
		s.injected = true
		return result, mutation.Unknown(s.cause)
	}
	return result, err
}

type externalPackageResumableCommitStore struct {
	registry.Store
	firstRequest *registry.CommitExternalPackageRequest
	commitCalls  int
}

type externalPackageFailedCommitStore struct {
	registry.Store
	commitCalls int
}

type externalPackageMalformedCommitStore struct {
	registry.Store
	mutate func(*registry.ExternalPackageCommitResult)
	result registry.ExternalPackageCommitResult
}

type externalPackageReplayTamperStore struct {
	registry.Store
	mutate func(*registry.ExternalPackageCommitResult)
}

func (s *externalPackageReplayTamperStore) QueryExternalPackageCommit(ctx context.Context, req registry.QueryExternalPackageCommitRequest) (registry.ExternalPackageCommitResult, error) {
	result, err := s.Store.QueryExternalPackageCommit(ctx, req)
	if err == nil {
		s.mutate(&result)
	}
	return result, err
}

func (s *externalPackageMalformedCommitStore) CommitExternalPackage(_ context.Context, req registry.CommitExternalPackageRequest) (registry.ExternalPackageCommitResult, error) {
	s.result = registry.ExternalPackageCommitResult{
		InspectionID: req.InspectionID, CommitID: req.CommitID, Intent: req.Intent,
		PluginInstanceID: req.Record.PluginInstanceID, ExpectedManagementRevision: req.ExpectedManagementRevision,
		IntendedFingerprint: req.IntendedFingerprint, IntendedPackageSHA256: req.IntendedPackageSHA256,
		Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
		CreatedAt: req.Now, UpdatedAt: req.Now,
	}
	s.mutate(&s.result)
	return s.result, nil
}

func (s *externalPackageMalformedCommitStore) QueryExternalPackageCommit(context.Context, registry.QueryExternalPackageCommitRequest) (registry.ExternalPackageCommitResult, error) {
	return s.result, nil
}

func (s *externalPackageFailedCommitStore) CommitExternalPackage(_ context.Context, req registry.CommitExternalPackageRequest) (registry.ExternalPackageCommitResult, error) {
	s.commitCalls++
	return registry.ExternalPackageCommitResult{
		InspectionID: req.InspectionID, CommitID: req.CommitID, Intent: req.Intent,
		PluginInstanceID: req.Record.PluginInstanceID, ExpectedManagementRevision: req.ExpectedManagementRevision,
		IntendedFingerprint: req.IntendedFingerprint, IntendedPackageSHA256: req.IntendedPackageSHA256,
		Status: registry.ExternalPackageFailed, MutationOutcome: mutation.OutcomeNotCommitted,
		FailureCode: registry.ExternalPackageFailureHostRestarted,
		CreatedAt:   req.Now, UpdatedAt: req.Now,
	}, nil
}

func (s *externalPackageResumableCommitStore) CommitExternalPackage(ctx context.Context, req registry.CommitExternalPackageRequest) (registry.ExternalPackageCommitResult, error) {
	s.commitCalls++
	if s.commitCalls == 1 {
		copyReq := req
		s.firstRequest = &copyReq
		return registry.ExternalPackageCommitResult{
			InspectionID: req.InspectionID, CommitID: req.CommitID, Intent: req.Intent,
			PluginInstanceID: req.Record.PluginInstanceID, ExpectedManagementRevision: req.ExpectedManagementRevision,
			IntendedFingerprint: req.IntendedFingerprint, IntendedPackageSHA256: req.IntendedPackageSHA256,
			Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
			CreatedAt: req.Now, UpdatedAt: req.Now,
		}, mutation.Unknown(errors.New("commit result unavailable"))
	}
	if s.firstRequest == nil || req.CommitID != s.firstRequest.CommitID {
		return registry.ExternalPackageCommitResult{}, fmt.Errorf("commit id changed across retry")
	}
	return s.Store.CommitExternalPackage(ctx, req)
}

func (s *externalPackageResumableCommitStore) QueryExternalPackageCommit(ctx context.Context, req registry.QueryExternalPackageCommitRequest) (registry.ExternalPackageCommitResult, error) {
	if s.commitCalls == 1 && s.firstRequest != nil {
		return registry.ExternalPackageCommitResult{
			InspectionID: s.firstRequest.InspectionID, CommitID: s.firstRequest.CommitID, Intent: s.firstRequest.Intent,
			PluginInstanceID: s.firstRequest.Record.PluginInstanceID, ExpectedManagementRevision: s.firstRequest.ExpectedManagementRevision,
			IntendedFingerprint: s.firstRequest.IntendedFingerprint, IntendedPackageSHA256: s.firstRequest.IntendedPackageSHA256,
			Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
			CreatedAt: s.firstRequest.Now, UpdatedAt: s.firstRequest.Now,
		}, nil
	}
	return s.Store.QueryExternalPackageCommit(ctx, req)
}

type externalPackageAssetStore struct {
	pluginpkg.AssetStore
	deleteCalls int
}

func (s *externalPackageAssetStore) DeletePackage(ctx context.Context, packageHash string) error {
	s.deleteCalls++
	return s.AssetStore.DeletePackage(ctx, packageHash)
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

func TestExternalPackageUnsignedInspectCommitInstallsDisabledWithoutGrants(t *testing.T) {
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
	if inspection.Intent.PluginInstanceID == "" || inspection.ConfirmationDigest == "" {
		t.Fatalf("inspection identity is incomplete: %#v", inspection)
	}

	committed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("CommitExternalPackage() error = %v", err)
	}
	if committed.Status != "committed" || committed.Plugin == nil || committed.Plugin.EnableState != registry.EnableDisabled {
		t.Fatalf("commit result = %#v", committed)
	}
	if committed.Plugin.ExecutionApproval.Status != registry.ExecutionApprovalUserApproved || committed.Plugin.UpdateEligibility != registry.UpdateManualOnly {
		t.Fatalf("committed facts = %#v", committed.Plugin)
	}
	authorization, err := h.adapters.Registry.GetAuthorization(hostTestContext(), committed.Plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorization.Grants) != 0 {
		t.Fatalf("new external install has grants: %#v", authorization.Grants)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("staged artifact remove count = %d, want 1", stage.removedCount())
	}

	replayed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest, Now: now.Add(2 * time.Minute),
	})
	if err != nil || replayed.Receipt == nil || replayed.Receipt.CommitID != committed.Receipt.CommitID {
		t.Fatalf("commit replay = %#v, %v", replayed, err)
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

	committed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("CommitExternalPackage() error = %v", err)
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
	updated, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: updatedInspection.InspectionID, ConfirmationDigest: updatedInspection.ConfirmationDigest, Now: now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CommitExternalPackage(update) error = %v", err)
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
	if _, err := h.CommitExternalPackage(otherSession, CommitExternalPackageRequest{InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest}); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("cross-session commit error = %v", err)
	}
	if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest}); !errors.Is(err, ErrExternalPackageCommitBlocked) {
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
	h.adapters.SessionLifecycle = &recordingSessionLifecycleAdapter{}

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
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter
	if _, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/revoke-cleanup-retry.redevplugin"},
	}); err != nil {
		t.Fatal(err)
	}
	stage.setRemoveError(cleanupErr)
	first, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) || !first.Fenced || first.Complete {
		t.Fatalf("first revoke = %#v, %v", first, err)
	}
	stage.setRemoveError(nil)
	second, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Identity: adapter.identity, Now: time.Now().UTC()})
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
	if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	}); !errors.Is(err, ErrExternalPackageCommitBlocked) {
		t.Fatalf("CommitExternalPackage() error = %v, want blocked", err)
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
	if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest, Now: inspection.ExpiresAt,
	}); !errors.Is(err, ErrExternalPackageInspectionExpired) {
		t.Fatalf("CommitExternalPackage() error = %v, want expired", err)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("expired inspection staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageCommitReconcilesCommittedReceiptWithoutDeletingAssets(t *testing.T) {
	h, _, audits := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	registryStore := &externalPackageCommitErrorStore{Store: h.adapters.Registry, cause: errors.New("commit acknowledgement lost")}
	assets := &externalPackageAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Registry = registryStore
	h.adapters.Assets = assets
	pkg := readTestPackage(t, buildFixturePackage(t))
	stage := &externalPackageTestStage{pkg: pkg}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})

	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/reconciled.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	committed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	})
	if err != nil || committed.Status != "committed" || committed.Plugin == nil {
		t.Fatalf("CommitExternalPackage() = %#v, %v", committed, err)
	}
	if assets.deleteCalls != 0 {
		t.Fatalf("asset delete calls = %d, want 0", assets.deleteCalls)
	}
	if _, err := assets.ReadPackageMetadata(hostTestContext(), committed.Plugin.PackageHash); err != nil {
		t.Fatalf("committed package asset is unavailable: %v", err)
	}

	// A restarted Host has no in-memory inspection, but the owner-scoped
	// registry receipt remains the query authority.
	h.externalInspections = newExternalPackageInspectionStore()
	queried, err := h.QueryExternalPackageCommit(hostTestContext(), QueryExternalPackageCommitRequest{
		InspectionID: inspection.InspectionID, CommitID: committed.Receipt.CommitID,
	})
	if err != nil || queried.Status != "committed" || queried.Plugin == nil {
		t.Fatalf("QueryExternalPackageCommit() after inspection loss = %#v, %v", queried, err)
	}
	if event, ok := audits.lastEvent("plugin.external_package.committed"); !ok || event.Details["status"] != "committed" {
		t.Fatalf("commit audit = %#v, found=%v", event, ok)
	}
}

func TestExternalPackageCommittedReplayRejectsTamperedRegistryIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*registry.ExternalPackageCommitResult)
	}{
		{name: "plugin instance", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.PluginInstanceID = "other_plugin"
			result.RecordSnapshot.PluginInstanceID = "other_plugin"
		}},
		{name: "fingerprint", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.IntendedFingerprint = "sha256:other"
			result.RecordSnapshot.ActiveFingerprint = "sha256:other"
		}},
		{name: "package", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.IntendedPackageSHA256 = "sha256:other"
			result.RecordSnapshot.PackageHash = "sha256:other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanupErr := errors.New("stage cleanup failed")
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
			registryStore := &externalPackageReplayTamperStore{Store: h.adapters.Registry, mutate: test.mutate}
			h.adapters.Registry = registryStore
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t)), removeErr: cleanupErr}
			configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
			inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
				Intent: ExternalPackageIntent{Action: "install"},
				Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/replay.redevplugin"},
			})
			if err != nil {
				t.Fatal(err)
			}
			committed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
				InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
			})
			if committed.Status != "committed" || mutation.ForError(err) != mutation.OutcomeCommitted || !errors.Is(err, cleanupErr) {
				t.Fatalf("initial commit = %#v, error=%v", committed, err)
			}
			if stage.removedCount() != 1 {
				t.Fatalf("initial cleanup attempts = %d", stage.removedCount())
			}
			if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
				InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
			}); !errors.Is(err, ErrAdapterFailure) || mutation.ForError(err) != mutation.OutcomeNotCommitted {
				t.Fatalf("tampered replay error = %v, outcome=%q", err, mutation.ForError(err))
			}
			if stage.removedCount() != 1 {
				t.Fatalf("tampered replay cleanup attempts = %d", stage.removedCount())
			}
		})
	}
}

func TestExternalPackageCommitRetriesSameDurableCommit(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	registryStore := &externalPackageResumableCommitStore{Store: h.adapters.Registry}
	h.adapters.Registry = registryStore
	pkg := readTestPackage(t, buildFixturePackage(t))
	stage := &externalPackageTestStage{pkg: pkg}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/retry.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	})
	if mutation.ForError(err) != mutation.OutcomeUnknown || first.Status != "in_progress" {
		t.Fatalf("first commit = %#v, error=%v, outcome=%q", first, err, mutation.ForError(err))
	}
	if stage.removedCount() != 0 {
		t.Fatalf("in-progress commit removed staged artifact %d times", stage.removedCount())
	}
	second, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	})
	if err != nil || second.Status != "committed" || registryStore.commitCalls != 2 {
		t.Fatalf("retried commit = %#v, error=%v, calls=%d", second, err, registryStore.commitCalls)
	}
	if stage.removedCount() != 1 {
		t.Fatalf("committed retry staged artifact remove count = %d, want 1", stage.removedCount())
	}
}

func TestExternalPackageCommitKeepsDurableFailedReceiptTerminal(t *testing.T) {
	h, _, audits := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	registryStore := &externalPackageFailedCommitStore{Store: h.adapters.Registry}
	h.adapters.Registry = registryStore
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/failed.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	})
	if err != nil || failed.Status != "failed" || failed.FailureCode != registry.ExternalPackageFailureHostRestarted {
		t.Fatalf("CommitExternalPackage() = %#v, %v", failed, err)
	}
	if failed.Intent.Action != "install" || failed.Intent.PluginInstanceID == "" || failed.Intent.ExpectedManagementRevision != 0 {
		t.Fatalf("failed intent = %#v", failed.Intent)
	}
	if registryStore.commitCalls != 1 || stage.removedCount() != 1 {
		t.Fatalf("failed terminal calls: commit=%d remove=%d", registryStore.commitCalls, stage.removedCount())
	}
	if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	}); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
		t.Fatalf("terminal failed inspection retry error = %v", err)
	}
	if event, ok := audits.lastEvent("plugin.external_package.committed"); !ok || event.Details["status"] != "failed" {
		t.Fatalf("failed commit audit = %#v, found=%v", event, ok)
	}
}

func TestExternalPackageCommitFailsClosedForMalformedRegistryResults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*registry.ExternalPackageCommitResult)
	}{
		{name: "future status", mutate: func(result *registry.ExternalPackageCommitResult) { result.Status = "future" }},
		{name: "committed without snapshot", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageCommitted
			result.MutationOutcome = mutation.OutcomeCommitted
		}},
		{name: "committed zero lifecycle", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageCommitted
			result.MutationOutcome = mutation.OutcomeCommitted
			result.CreatedAt = time.Time{}
			result.UpdatedAt = time.Time{}
			result.RecordSnapshot = &registry.PluginRecord{
				PluginInstanceID: result.PluginInstanceID, ManagementRevision: 1,
				ActiveFingerprint: result.IntendedFingerprint, PackageHash: result.IntendedPackageSHA256,
			}
		}},
		{name: "committed backwards lifecycle", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageCommitted
			result.MutationOutcome = mutation.OutcomeCommitted
			result.UpdatedAt = result.CreatedAt.Add(-time.Second)
			result.RecordSnapshot = &registry.PluginRecord{
				PluginInstanceID: result.PluginInstanceID, ManagementRevision: 1,
				ActiveFingerprint: result.IntendedFingerprint, PackageHash: result.IntendedPackageSHA256,
				UpdatedAt: result.UpdatedAt,
			}
		}},
		{name: "committed wrong fingerprint", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageCommitted
			result.MutationOutcome = mutation.OutcomeCommitted
			result.RecordSnapshot = &registry.PluginRecord{
				PluginInstanceID: result.PluginInstanceID, ManagementRevision: 1,
				ActiveFingerprint: "sha256:wrong", PackageHash: result.IntendedPackageSHA256,
				UpdatedAt: result.UpdatedAt,
			}
		}},
		{name: "committed wrong package", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageCommitted
			result.MutationOutcome = mutation.OutcomeCommitted
			result.RecordSnapshot = &registry.PluginRecord{
				PluginInstanceID: result.PluginInstanceID, ManagementRevision: 1,
				ActiveFingerprint: result.IntendedFingerprint, PackageHash: "sha256:wrong",
				UpdatedAt: result.UpdatedAt,
			}
		}},
		{name: "failed wrong code", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageFailed
			result.MutationOutcome = mutation.OutcomeNotCommitted
			result.FailureCode = "future_failure"
		}},
		{name: "failed wrong identity", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageFailed
			result.MutationOutcome = mutation.OutcomeNotCommitted
			result.FailureCode = registry.ExternalPackageFailureHostRestarted
			result.InspectionID = "other_inspection"
		}},
		{name: "failed wrong outcome", mutate: func(result *registry.ExternalPackageCommitResult) {
			result.Status = registry.ExternalPackageFailed
			result.MutationOutcome = mutation.OutcomeUnknown
			result.FailureCode = registry.ExternalPackageFailureHostRestarted
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
			registryStore := &externalPackageMalformedCommitStore{Store: h.adapters.Registry, mutate: test.mutate}
			h.adapters.Registry = registryStore
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
			configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
			inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
				Intent: ExternalPackageIntent{Action: "install"},
				Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/malformed.redevplugin"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
				InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
			}); !errors.Is(err, ErrAdapterFailure) || mutation.ForError(err) != mutation.OutcomeUnknown {
				t.Fatalf("malformed commit error = %v, outcome=%q", err, mutation.ForError(err))
			}
			if stage.removedCount() != 0 {
				t.Fatalf("malformed commit removed staged artifact %d times", stage.removedCount())
			}
			if _, err := h.QueryExternalPackageCommit(hostTestContext(), QueryExternalPackageCommitRequest{
				InspectionID: inspection.InspectionID, CommitID: registryStore.result.CommitID,
			}); !errors.Is(err, ErrAdapterFailure) {
				t.Fatalf("malformed query error = %v", err)
			}
		})
	}
}

func TestExternalPackageFailedReceiptProjectsTerminalNotCommittedStatus(t *testing.T) {
	now := time.Now().UTC()
	projected, err := publicExternalPackageCommitResult(registry.ExternalPackageCommitResult{
		InspectionID: "inspection_restart", CommitID: "commit_restart", Intent: registry.ExternalPackageInstall,
		PluginInstanceID:    "plugin_instance_restart",
		IntendedFingerprint: "sha256:fingerprint", IntendedPackageSHA256: "sha256:package",
		Status: registry.ExternalPackageFailed, MutationOutcome: mutation.OutcomeNotCommitted,
		FailureCode: registry.ExternalPackageFailureHostRestarted,
		CreatedAt:   now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if projected.Status != "failed" || projected.FailureCode != registry.ExternalPackageFailureHostRestarted || projected.RetryAfterMS != 0 {
		t.Fatalf("projected failed receipt = %#v", projected)
	}
	if projected.Intent.Action != "install" || projected.Intent.PluginInstanceID != "plugin_instance_restart" || projected.Intent.ExpectedManagementRevision != 0 {
		t.Fatalf("projected failed intent = %#v", projected.Intent)
	}
}

func TestExternalPackageInProgressReceiptProjectsResolvedUpdateIntent(t *testing.T) {
	now := time.Now().UTC()
	projected, err := publicExternalPackageCommitResult(registry.ExternalPackageCommitResult{
		InspectionID: "inspection_update", CommitID: "commit_update", Intent: registry.ExternalPackageUpdate,
		PluginInstanceID: "plugin_instance_update", ExpectedManagementRevision: 7,
		IntendedFingerprint: "sha256:fingerprint", IntendedPackageSHA256: "sha256:package",
		Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if projected.Status != "in_progress" || projected.RetryAfterMS != 250 {
		t.Fatalf("projected in-progress receipt = %#v", projected)
	}
	if projected.Intent.Action != "update" || projected.Intent.PluginInstanceID != "plugin_instance_update" || projected.Intent.ExpectedManagementRevision != 7 {
		t.Fatalf("projected in-progress intent = %#v", projected.Intent)
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
	committed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
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
	disabled, err := h.adapters.Registry.GetPlugin(hostTestContext(), record.PluginInstanceID)
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

func TestExternalPackageHostClosePreservesUnknownCommitStagedArtifact(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	registryStore := &externalPackageResumableCommitStore{Store: h.adapters.Registry}
	h.adapters.Registry = registryStore
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildFixturePackage(t))}
	configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
	inspection, err := h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
		Intent: ExternalPackageIntent{Action: "install"},
		Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/unknown-close.redevplugin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
	})
	if mutation.ForError(err) != mutation.OutcomeUnknown || result.Status != "in_progress" {
		t.Fatalf("CommitExternalPackage() = %#v, %v", result, err)
	}
	if stage.removedCount() != 0 {
		t.Fatalf("unknown commit removed staged artifact %d times before close", stage.removedCount())
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if stage.removedCount() != 0 {
		t.Fatalf("Host.Close() removed a committing staged artifact %d times", stage.removedCount())
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

func TestExternalPackageUpdateRefreshesEnabledSurfaceAndRevokesOldCapabilities(t *testing.T) {
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
	installed, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: inspection.InspectionID, ConfirmationDigest: inspection.ConfirmationDigest,
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
	updated, err := h.CommitExternalPackage(hostTestContext(), CommitExternalPackageRequest{
		InspectionID: updateInspection.InspectionID, ConfirmationDigest: updateInspection.ConfirmationDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Plugin == nil || updated.Plugin.Version != "2.0.0" || updated.Plugin.EnableState != registry.EnableEnabled {
		t.Fatalf("updated plugin = %#v", updated.Plugin)
	}
	if len(surfaces.snapshots) <= beforeSnapshots || surfaces.snapshots[len(surfaces.snapshots)-1].ActiveFingerprint != updated.Plugin.ActiveFingerprint {
		t.Fatalf("updated surfaces = %#v", surfaces.snapshots)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatal("external update did not revoke old runtime capabilities")
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
