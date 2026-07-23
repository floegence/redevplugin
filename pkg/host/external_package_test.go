package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	mu        sync.Mutex
	pkg       pluginpkg.Package
	removed   int
	removeErr error
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

type externalPackageTestFetcher struct {
	result      externalsource.FetchResult
	lastRequest externalsource.FetchRequest
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

func (s *externalPackageResumableCommitStore) CommitExternalPackage(ctx context.Context, req registry.CommitExternalPackageRequest) (registry.ExternalPackageCommitResult, error) {
	s.commitCalls++
	if s.commitCalls == 1 {
		copyReq := req
		s.firstRequest = &copyReq
		return registry.ExternalPackageCommitResult{
			InspectionID: req.InspectionID, CommitID: req.CommitID, Intent: req.Intent,
			Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
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
			Status: registry.ExternalPackageCommitting, MutationOutcome: mutation.OutcomeUnknown,
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

func TestExternalPackageHostCloseDrainsUnknownCommitStagedArtifact(t *testing.T) {
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
	h.adapters.ExternalPackageStageStore = stage
	h.adapters.ExternalPackageFetcher = &externalPackageTestFetcher{result: externalsource.FetchResult{
		Artifact: artifact, Source: "https://plugins.example.test/example.redevplugin", Final: "https://plugins.example.test/example.redevplugin",
	}}
	h.adapters.ExternalPackageGitHubResolver = externalPackageTestGitHubResolver{}
	h.adapters.ExternalPackageSignatureAssessor = assessor
	h.features[FeatureExternalPackage] = struct{}{}
}
