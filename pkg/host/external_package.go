package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v2/internal/controlstore"
	"github.com/floegence/redevplugin/v2/pkg/externalsource"
	"github.com/floegence/redevplugin/v2/pkg/manifest"
	"github.com/floegence/redevplugin/v2/pkg/mutation"
	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
)

const externalPackageInspectionTTL = 15 * time.Minute

var (
	ErrExternalPackageInspectionNotFound = errors.New("external package inspection not found")
	ErrExternalPackageInspectionExpired  = errors.New("external package inspection expired")
	ErrExternalPackageConfirmation       = errors.New("external package hash does not match inspection")
	ErrExternalPackageInstallBlocked     = errors.New("external package install is blocked by integrity assessment")
	ErrExternalPackageInstallInProgress  = errors.New("external package install is in progress")
	ErrExternalPackageInspectionStale    = errors.New("external package signature assessment changed after inspection")
	ErrExternalPackageRequestInvalid     = errors.New("external package request is invalid")
)

type externalPackageStageStore interface {
	StageUpload(context.Context, string, io.Reader, int64) (externalsource.StagedArtifact, error)
	VerifyPackage(context.Context, externalsource.StagedArtifact, pluginpkg.ReadLimits) (pluginpkg.Package, error)
	Remove(externalsource.StagedArtifact) error
}

type externalPackageFetcher interface {
	FetchPackage(context.Context, externalsource.FetchRequest) (externalsource.FetchResult, error)
}

type externalPackageGitHubResolver interface {
	ResolvePackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.ResolvedGitHubAsset, error)
}

type ExternalPackageSignatureAssessmentRequest struct {
	Package pluginpkg.Package `json:"package"`
	Now     time.Time         `json:"-"`
}

// ExternalPackageSignatureAssessor returns a closed signature fact. Expected
// outcomes such as unknown signer, invalid signature, and revocation belong in
// the result; errors are reserved for unavailable assessment dependencies.
type ExternalPackageSignatureAssessor interface {
	AssessExternalPackageSignature(context.Context, ExternalPackageSignatureAssessmentRequest) (registry.SignatureAssessment, error)
}

type ExternalPackageSignatureFreshnessRequest struct {
	PublisherID    string                       `json:"publisher_id"`
	PluginID       string                       `json:"plugin_id"`
	PackageSHA256  string                       `json:"package_sha256"`
	ManifestSHA256 string                       `json:"manifest_sha256"`
	EntriesSHA256  string                       `json:"entries_sha256"`
	Assessment     registry.SignatureAssessment `json:"assessment"`
	Now            time.Time                    `json:"-"`
}

// ExternalPackageSignatureFreshnessAssessor checks mutable keyring and
// revocation facts without requiring the package payload again.
type ExternalPackageSignatureFreshnessAssessor interface {
	AssessExternalPackageSignatureFreshness(context.Context, ExternalPackageSignatureFreshnessRequest) (registry.SignatureAssessment, error)
}

type ExternalPackageSource struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
	Tag  string `json:"tag,omitempty"`
}

type InspectExternalPackageRequest struct {
	Intent ExternalPackageIntent `json:"intent"`
	Source ExternalPackageSource `json:"source"`
	Now    time.Time             `json:"-"`
}

type InspectUploadedExternalPackageRequest struct {
	Intent       ExternalPackageIntent `json:"intent"`
	Package      io.Reader             `json:"-"`
	DeclaredSize int64                 `json:"-"`
	Now          time.Time             `json:"-"`
}

type InstallInspectedPackageRequest struct {
	InspectionID          string    `json:"inspection_id"`
	ExpectedPackageSHA256 string    `json:"expected_package_sha256"`
	ActivateAfterInstall  *bool     `json:"activate_after_install,omitempty"`
	ApprovedPermissionIDs []string  `json:"approved_permission_ids,omitempty"`
	Now                   time.Time `json:"-"`
}

type externalPackageInspectionState string

const (
	externalPackagePending    externalPackageInspectionState = "pending"
	externalPackageCleaning   externalPackageInspectionState = "cleaning"
	externalPackageCommitting externalPackageInspectionState = "installing"
	externalPackageFailed     externalPackageInspectionState = "failed"
)

type externalPackagePendingInspection struct {
	Scope      sessionctx.SessionScope
	Artifact   externalsource.StagedArtifact
	Inspection ExternalPackageInspection
	Record     registry.PluginRecord
	State      externalPackageInspectionState
}

type externalPackageInspectionStore struct {
	mu      sync.Mutex
	records map[string]externalPackagePendingInspection
}

func newExternalPackageInspectionStore() *externalPackageInspectionStore {
	return &externalPackageInspectionStore{records: make(map[string]externalPackagePendingInspection)}
}

func (s *externalPackageInspectionStore) put(record externalPackagePendingInspection) {
	s.mu.Lock()
	s.records[record.Inspection.InspectionID] = record
	s.mu.Unlock()
}

func (s *externalPackageInspectionStore) get(id string, scope sessionctx.SessionScope) (externalPackagePendingInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok || !record.Scope.Matches(scope) {
		return externalPackagePendingInspection{}, ErrExternalPackageInspectionNotFound
	}
	return record, nil
}

func (s *externalPackageInspectionStore) begin(id string, scope sessionctx.SessionScope, expectedPackageSHA256 string, now time.Time) (externalPackagePendingInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok || !record.Scope.Matches(scope) {
		return externalPackagePendingInspection{}, ErrExternalPackageInspectionNotFound
	}
	if record.Inspection.InspectedHashes.PackageSHA256 != expectedPackageSHA256 {
		return externalPackagePendingInspection{}, ErrExternalPackageConfirmation
	}
	if record.State == externalPackageCommitting {
		return record, ErrExternalPackageInstallInProgress
	}
	if record.State != externalPackagePending {
		return externalPackagePendingInspection{}, ErrExternalPackageInspectionNotFound
	}
	if !now.Before(record.Inspection.ExpiresAt) {
		return record, ErrExternalPackageInspectionExpired
	}
	record.State = externalPackageCommitting
	s.records[id] = record
	return record, nil
}

func (s *externalPackageInspectionStore) artifact(id string) (externalsource.StagedArtifact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok || strings.TrimSpace(record.Artifact.ID) == "" {
		return externalsource.StagedArtifact{}, false
	}
	return record.Artifact, true
}

func (s *externalPackageInspectionStore) clearArtifact(id string) {
	s.mu.Lock()
	record, ok := s.records[id]
	if ok {
		record.Artifact = externalsource.StagedArtifact{}
		s.records[id] = record
	}
	s.mu.Unlock()
}

func (s *externalPackageInspectionStore) take(id string) (externalPackagePendingInspection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if ok {
		delete(s.records, id)
	}
	return record, ok
}

func (s *externalPackageInspectionStore) claimCleanup(scope *sessionctx.SessionScope, expiredAt *time.Time) []externalPackagePendingInspection {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]externalPackagePendingInspection, 0, len(s.records))
	for id, record := range s.records {
		if record.State != externalPackagePending && record.State != externalPackageFailed {
			continue
		}
		if scope != nil && !record.Scope.Matches(*scope) {
			continue
		}
		if expiredAt != nil && (record.State != externalPackagePending || expiredAt.Before(record.Inspection.ExpiresAt)) {
			continue
		}
		claimed := record
		record.State = externalPackageCleaning
		s.records[id] = record
		records = append(records, claimed)
	}
	return records
}

func (s *externalPackageInspectionStore) finishCleanup(record externalPackagePendingInspection, removed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := record.Inspection.InspectionID
	current, ok := s.records[id]
	if !ok || current.State != externalPackageCleaning || current.Artifact != record.Artifact {
		return
	}
	if removed {
		delete(s.records, id)
		return
	}
	current.State = record.State
	s.records[id] = current
}

func (s *externalPackageInspectionStore) finish(id string, state externalPackageInspectionState) {
	s.mu.Lock()
	record, ok := s.records[id]
	if ok {
		record.State = state
		s.records[id] = record
	}
	s.mu.Unlock()
}

func (h *Host) InspectExternalPackage(ctx context.Context, req InspectExternalPackageRequest) (result ExternalPackageInspection, retErr error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return ExternalPackageInspection{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	intent, err := normalizeExternalPackageIntent(req.Intent)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	authorization, err := h.authorizeManagementSession(ctx, session, ManagementActionInspectExternalPackage,
		scopedAuthorizationTargetOrCollection(ResourcePlugin, intent.PluginInstanceID, sessionctx.ScopeEnvironment),
	)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	ctx, releaseReservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	defer releaseReservation()
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := h.removeExpiredExternalPackageInspectionArtifacts(now); err != nil {
		return ExternalPackageInspection{}, err
	}

	fetched, provenance, err := h.fetchExternalPackage(ctx, req.Source, scope.OwnerEnvHash, now)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	return h.inspectStagedExternalPackage(ctx, scope, intent, fetched.Artifact, provenance, now)
}

func (h *Host) InspectUploadedExternalPackage(ctx context.Context, req InspectUploadedExternalPackageRequest) (ExternalPackageInspection, error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return ExternalPackageInspection{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	intent, err := normalizeExternalPackageIntent(req.Intent)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	authorization, err := h.authorizeManagementSession(ctx, session, ManagementActionInspectExternalPackage,
		scopedAuthorizationTargetOrCollection(ResourcePlugin, intent.PluginInstanceID, sessionctx.ScopeEnvironment),
	)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	ctx, releaseReservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	defer releaseReservation()
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := h.removeExpiredExternalPackageInspectionArtifacts(now); err != nil {
		return ExternalPackageInspection{}, err
	}
	uploadID, err := newExternalPackageID("upload")
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	artifact, err := h.adapters.ExternalPackageStageStore.StageUpload(ctx, scope.OwnerEnvHash, req.Package, req.DeclaredSize)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	return h.inspectStagedExternalPackage(ctx, scope, intent, artifact, registry.PackageSourceProvenance{
		Kind: registry.PackageSourcePackageUpload, UploadID: uploadID, RetrievedAt: now,
	}, now)
}

func (h *Host) inspectStagedExternalPackage(
	ctx context.Context,
	scope sessionctx.SessionScope,
	intent ExternalPackageIntent,
	artifact externalsource.StagedArtifact,
	provenance registry.PackageSourceProvenance,
	now time.Time,
) (result ExternalPackageInspection, retErr error) {
	keepArtifact := false
	defer func() {
		if !keepArtifact {
			retErr = errors.Join(retErr, h.adapters.ExternalPackageStageStore.Remove(artifact))
		}
	}()
	pkg, err := h.adapters.ExternalPackageStageStore.VerifyPackage(ctx, artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	current, instanceID, err := h.resolveExternalPackageIntent(ctx, intent, pkg)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	intent.PluginInstanceID = instanceID
	if err := h.preflightPackageFeatures(pkg.ManifestModel, packageTrustInput{}); err != nil {
		return ExternalPackageInspection{}, err
	}
	runtimeRequirement, err := runtimeRequirementForPackage(pkg.Manifest, packageTrustInput{})
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, registry.PluginRecord{Manifest: pkg.Manifest, RuntimeRequirement: runtimeRequirement}); err != nil {
		return ExternalPackageInspection{}, err
	}
	pins, err := h.resolvePackageCapabilityPins(ctx, pkg.Manifest, packageTrustInput{})
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	signature := h.assessExternalPackageSignature(ctx, pkg, now)
	trust := externalPackageLegacyTrust(pkg, signature)
	record := packageRecord(pkg, trust, instanceID, map[string]string{"source.type": "external"}, pins)
	record.RuntimeRequirement = runtimeRequirement
	if current != nil {
		if err := validateSamePluginIdentity(*current, record); err != nil {
			return ExternalPackageInspection{}, err
		}
		if err := requireStablePluginDataShape(current.Manifest, record.Manifest); err != nil {
			return ExternalPackageInspection{}, err
		}
		record.VersionHistory = append(append([]registry.PluginVersion(nil), current.VersionHistory...), versionSnapshot(*current, now))
		record.EnableState = current.EnableState
		record.DisabledReason = current.DisabledReason
		record.EnabledAt = cloneTimePtr(current.EnabledAt)
	}

	effectiveManifest, required, err := h.externalPackageEffectiveManifest(record)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	securitySummary, err := buildExternalPackageSecuritySummary(effectiveManifest, pins, required)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	provenance.PackageSHA256 = pkg.PackageHash
	record.SignatureAssessment = signature
	record.PackageSourceProvenance = provenance
	record.ExecutionApproval = registry.ExecutionApproval{
		Status: registry.ExecutionApprovalPending, OwnerEnvHash: scope.OwnerEnvHash,
		PackageSHA256: pkg.PackageHash, ReasonCodes: []string{"explicit_confirmation_required"}, AssessedAt: now,
	}
	record.UpdateEligibility = registry.UpdateManualOnly
	record.SecurityCapabilitySummary = registry.SecurityCapabilitySummary{
		SchemaVersion: "redevplugin.external_security_summary.v1",
		Summary:       securitySummary.SummarySHA256, SHA256: securitySummary.SummarySHA256,
	}
	if raw, marshalErr := json.Marshal(securitySummary); marshalErr == nil {
		record.SecurityCapabilitySummary.CanonicalJSON = string(raw)
	} else {
		return ExternalPackageInspection{}, marshalErr
	}
	if signature.Status == registry.SignatureInvalid || signature.Status == registry.SignatureRevoked {
		record.ExecutionApproval.Status = registry.ExecutionApprovalPolicyBlocked
		record.ExecutionApproval.ReasonCodes = []string{"signature_integrity_failure"}
		record.TrustState = registry.TrustBlockedSecurity
		record.TrustAssessment.TrustState = registry.TrustBlockedSecurity
	}

	inspectionID, err := newExternalPackageID("inspection")
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	presentation := pkg.Manifest.PresentationCatalog()
	presentationSHA256, err := manifest.PresentationCatalogSHA256(presentation)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	inspection := ExternalPackageInspection{
		InspectionID: inspectionID, ExpiresAt: now.Add(externalPackageInspectionTTL), Intent: intent,
		PublisherID: record.PublisherID, PluginID: record.PluginID, Version: record.Version,
		Presentation: presentation, PresentationSHA256: presentationSHA256,
		InspectedHashes:     packageHashSetForPackage(pkg),
		SignatureAssessment: publicExternalSignatureAssessment(signature),
		SourceProvenance:    publicExternalSourceProvenance(provenance),
		ExecutionApproval:   publicExternalExecutionApproval(record.ExecutionApproval),
		UpdateEligibility:   publicExternalUpdateEligibility(record.UpdateEligibility, signature, now),
		SecuritySummary:     securitySummary,
	}
	h.externalInspections.put(externalPackagePendingInspection{
		Scope: scope, Artifact: artifact, Inspection: inspection, Record: record, State: externalPackagePending,
	})
	keepArtifact = true
	return inspection, nil
}

func (h *Host) InstallInspectedPackage(ctx context.Context, req InstallInspectedPackageRequest) (result InstalledExternalPackage, retErr error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return InstalledExternalPackage{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	inspectionID := strings.TrimSpace(req.InspectionID)
	preview, err := h.externalInspections.get(inspectionID, scope)
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	req.ApprovedPermissionIDs = normalizeStringSet(req.ApprovedPermissionIDs)
	if req.ActivateAfterInstall != nil && !*req.ActivateAfterInstall && len(req.ApprovedPermissionIDs) != 0 {
		return InstalledExternalPackage{}, fmt.Errorf("%w: approved permissions require activation", ErrExternalPackageRequestInvalid)
	}
	activationRequest := externalPackageActivationRequest(req, preview)
	if activationRequest.Mode != registry.ReleaseInstallActivationDisabled {
		if _, err := h.authorizeManagementSession(ctx, session, ManagementActionEnablePlugin,
			scopedAuthorizationTarget(ResourcePlugin, preview.Record.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
			return InstalledExternalPackage{}, err
		}
		for _, permissionID := range activationRequest.ApprovedPermissionIDs {
			if _, err := h.authorizeManagementSession(ctx, session, ManagementActionGrantPermission,
				scopedAuthorizationTarget(ResourcePermission, permissionID, sessionctx.ScopeEnvironment),
				scopedAuthorizationTarget(ResourcePlugin, preview.Record.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
				return InstalledExternalPackage{}, err
			}
		}
	}
	authorization, err := h.authorizeManagementSession(ctx, session, ManagementActionInstallInspectedPackage,
		scopedAuthorizationTarget(ResourcePlugin, preview.Record.PluginInstanceID, sessionctx.ScopeEnvironment))
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	ctx, releaseReservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return InstalledExternalPackage{}, err
	}
	defer releaseReservation()
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pending, err := h.externalInspections.begin(inspectionID, scope, strings.TrimSpace(req.ExpectedPackageSHA256), now)
	if err != nil {
		if errors.Is(err, ErrExternalPackageInspectionExpired) {
			return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
		}
		return InstalledExternalPackage{}, err
	}
	if pending.Record.SignatureAssessment.Status == registry.SignatureInvalid || pending.Record.SignatureAssessment.Status == registry.SignatureRevoked {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, ErrExternalPackageInstallBlocked)
	}
	unlockLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pending.Record.PluginInstanceID)
	if err != nil {
		h.externalInspections.finish(pending.Inspection.InspectionID, externalPackagePending)
		return InstalledExternalPackage{}, err
	}
	defer unlockLifecycle()
	var previous *registry.PluginRecord
	if pending.Inspection.Intent.Action == string(registry.ExternalPackageUpdate) {
		current, err := h.controlStore.Registry().GetPlugin(ctx, scope.OwnerEnvHash, pending.Record.PluginInstanceID)
		if err != nil {
			return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
		}
		if err := requireManagementRevision(current, pending.Inspection.Intent.ExpectedManagementRevision); err != nil {
			return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
		}
		previous = &current
	}
	// Reopen and parse the staged artifact immediately before install.
	pkg, err := h.adapters.ExternalPackageStageStore.VerifyPackage(ctx, pending.Artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
	}
	if pkg.PackageHash != pending.Record.PackageHash || pkg.ManifestHash != pending.Record.ManifestHash || pkg.EntriesHash != pending.Record.EntriesHash {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, errors.New("external package changed after inspection"))
	}
	reassessedSignature := h.assessExternalPackageSignature(ctx, pkg, now)
	if reassessedSignature.Status == registry.SignatureInvalid || reassessedSignature.Status == registry.SignatureRevoked {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, ErrExternalPackageInstallBlocked)
	}
	if !sameExternalPackageSignatureFreshness(pending.Record.SignatureAssessment, reassessedSignature) {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, ErrExternalPackageInspectionStale)
	}
	record := pending.Record
	record.ExecutionApproval.Status = registry.ExecutionApprovalUserApproved
	record.ExecutionApproval.ReasonCodes = []string{"explicit_user_confirmation"}
	record.ExecutionApproval.ApprovedAt = now
	record.ExecutionApproval.AssessedAt = now
	if record.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, record); err != nil {
			return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
		Type: "plugin.external_package.installed", PluginID: record.PluginID,
		PluginInstanceID: record.PluginInstanceID, RequestID: pending.Inspection.InspectionID,
	})
	if err != nil {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
	}
	auditDetails := map[string]any{"status": "installing"}
	defer func() { retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails) }()
	if err := h.adapters.Assets.PutOwnedPackage(ctx, &pkg); err != nil {
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, err)
	}
	stored, pendingActivation, err := h.installExternalPackageRecord(ctx, session, registry.InstallExternalPackageRequest{
		Intent:                     registry.ExternalPackageInstallIntent(pending.Inspection.Intent.Action),
		ExpectedManagementRevision: pending.Inspection.Intent.ExpectedManagementRevision,
		Record:                     record, Now: now,
	}, activationRequest)
	if err != nil {
		auditDetails["status"] = "failed"
		assetRollbackErr := h.adapters.Assets.DeletePackage(context.WithoutCancel(ctx), record.PackageHash)
		return InstalledExternalPackage{}, h.failExternalPackageInspection(pending, errors.Join(managementMutationError(record, err), assetRollbackErr))
	}
	activation := registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationNotRequested}
	if activationRequest.Mode != registry.ReleaseInstallActivationDisabled {
		activation, stored, err = h.activatePluginInstall(ctx, stored, activationRequest, now)
		if err != nil {
			auditDetails["status"] = "activation_failed"
			activation = registry.ReleaseInstallActivation{
				Status: registry.ReleaseInstallActivationNeedsAttention, NextAction: registry.ReleaseInstallNextActionRetryActivation,
			}
			result = installedExternalPackage(stored, activation, now)
			return result, mutation.Committed(err)
		}
		if err := h.completeExternalInstallActivation(context.WithoutCancel(ctx), *pendingActivation, activation, now); err != nil {
			auditDetails["status"] = "activation_completion_failed"
			result = installedExternalPackage(stored, activation, now)
			return result, mutation.Committed(err)
		}
	}
	auditDetails["status"] = "committed"
	result = installedExternalPackage(stored, activation, now)
	var postCommitErr error
	if previous != nil {
		revokeRecord := stored
		if pluginHasWorkers(previous.Manifest) {
			revokeRecord.Manifest = previous.Manifest
		}
		if err := h.revokePluginRuntimeCapabilities(ctx, revokeRecord, now); err != nil {
			postCommitErr = errors.Join(postCommitErr, err)
		} else if err := h.refreshEnabledRuntimeState(ctx, stored); err != nil {
			postCommitErr = errors.Join(postCommitErr, err)
		}
	}
	if err := h.removeExternalPackageInspectionArtifact(pending.Inspection.InspectionID, true); err != nil {
		h.externalInspections.finish(pending.Inspection.InspectionID, externalPackageFailed)
		postCommitErr = errors.Join(postCommitErr, err)
	}
	if postCommitErr != nil {
		return result, mutation.Committed(postCommitErr)
	}
	return result, nil
}

func (h *Host) installExternalPackageRecord(ctx context.Context, session sessionctx.Context, req registry.InstallExternalPackageRequest, activation registry.ReleaseInstallActivationRequest) (registry.PluginRecord, *controlstore.ExternalInstallActivation, error) {
	if h.controlStore == nil {
		return registry.PluginRecord{}, nil, ErrControlStoreRequired
	}
	if activation.Mode == registry.ReleaseInstallActivationDisabled {
		record, err := h.controlStore.Registry().InstallExternalPackage(ctx, session.OwnerEnvHash, req)
		return record, nil, err
	}
	executionID, err := newExternalPackageID("external_install")
	if err != nil {
		return registry.PluginRecord{}, nil, err
	}
	record, pending, err := h.controlStore.Registry().InstallExternalPackageWithActivation(ctx, session.OwnerEnvHash, req, controlstore.ExternalInstallActivationRequest{
		ExecutionID: executionID, Owner: releaseInstallOwner(session), Activation: activation, Now: req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, nil, err
	}
	return record, &pending, nil
}

func externalPackageActivationRequest(req InstallInspectedPackageRequest, pending externalPackagePendingInspection) registry.ReleaseInstallActivationRequest {
	mode := registry.ReleaseInstallActivationAutomatic
	if pending.Inspection.Intent.Action == string(registry.ExternalPackageUpdate) {
		if pending.Record.EnableState != registry.EnableEnabled {
			mode = registry.ReleaseInstallActivationDisabled
		} else {
			mode = registry.ReleaseInstallActivationRequested
		}
	} else if req.ActivateAfterInstall != nil {
		if *req.ActivateAfterInstall {
			mode = registry.ReleaseInstallActivationRequested
		} else {
			mode = registry.ReleaseInstallActivationDisabled
		}
	}
	return registry.ReleaseInstallActivationRequest{Mode: mode, ApprovedPermissionIDs: append([]string(nil), req.ApprovedPermissionIDs...)}
}

func installedExternalPackage(record registry.PluginRecord, activation registry.ReleaseInstallActivation, now time.Time) InstalledExternalPackage {
	result := InstalledExternalPackage{Plugin: &record, Activation: activation}
	signature := publicExternalSignatureAssessment(record.SignatureAssessment)
	provenance := publicExternalSourceProvenance(record.PackageSourceProvenance)
	approval := publicExternalExecutionApproval(record.ExecutionApproval)
	update := publicExternalUpdateEligibility(record.UpdateEligibility, record.SignatureAssessment, now)
	result.SignatureAssessment, result.SourceProvenance = &signature, &provenance
	result.ExecutionApproval, result.UpdateEligibility = &approval, &update
	if record.SecurityCapabilitySummary.CanonicalJSON != "" {
		var summary ExternalPackageSecuritySummary
		if json.Unmarshal([]byte(record.SecurityCapabilitySummary.CanonicalJSON), &summary) == nil {
			result.SecuritySummary = &summary
		}
	}
	return result
}

func (h *Host) removeExternalPackageInspectionArtifact(inspectionID string, removeInspection bool) error {
	artifact, ok := h.externalInspections.artifact(inspectionID)
	if !ok {
		if removeInspection {
			h.externalInspections.take(inspectionID)
		}
		return nil
	}
	if err := h.adapters.ExternalPackageStageStore.Remove(artifact); err != nil {
		return err
	}
	if removeInspection {
		h.externalInspections.take(inspectionID)
	} else {
		h.externalInspections.clearArtifact(inspectionID)
	}
	return nil
}

func (h *Host) failExternalPackageInspection(pending externalPackagePendingInspection, cause error) error {
	h.externalInspections.finish(pending.Inspection.InspectionID, externalPackageFailed)
	return errors.Join(cause, h.removeExternalPackageInspectionArtifact(pending.Inspection.InspectionID, true))
}

func (h *Host) cleanupExternalPackageInspectionArtifacts(scope *sessionctx.SessionScope, expiredAt *time.Time) error {
	if h == nil || h.externalInspections == nil || h.adapters.ExternalPackageStageStore == nil {
		return nil
	}
	var resultErr error
	for _, pending := range h.externalInspections.claimCleanup(scope, expiredAt) {
		if strings.TrimSpace(pending.Artifact.ID) == "" {
			h.externalInspections.finishCleanup(pending, true)
			continue
		}
		err := h.adapters.ExternalPackageStageStore.Remove(pending.Artifact)
		h.externalInspections.finishCleanup(pending, err == nil)
		resultErr = errors.Join(resultErr, err)
	}
	return resultErr
}

func (h *Host) drainExternalPackageInspectionArtifacts() error {
	return h.cleanupExternalPackageInspectionArtifacts(nil, nil)
}

func (h *Host) cleanupExternalPackageInspectionArtifactsForScope(scope sessionctx.SessionScope) error {
	return h.cleanupExternalPackageInspectionArtifacts(&scope, nil)
}

func (h *Host) removeExpiredExternalPackageInspectionArtifacts(now time.Time) error {
	return h.cleanupExternalPackageInspectionArtifacts(nil, &now)
}

func (h *Host) fetchExternalPackage(ctx context.Context, source ExternalPackageSource, quotaKey string, now time.Time) (externalsource.FetchResult, registry.PackageSourceProvenance, error) {
	switch strings.TrimSpace(source.Kind) {
	case string(registry.PackageSourcePackageURL):
		if strings.TrimSpace(source.Tag) != "" {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, fmt.Errorf("%w: tag is valid only for GitHub repository sources", ErrExternalPackageRequestInvalid)
		}
		fetched, err := h.adapters.ExternalPackageFetcher.FetchPackage(ctx, externalsource.FetchRequest{URL: source.URL, QuotaKey: quotaKey})
		if err != nil {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, err
		}
		provenance, err := directExternalPackageProvenance(fetched, now)
		return fetched, provenance, err
	case string(registry.PackageSourceGitHubRepository):
		resolved, err := h.adapters.ExternalPackageGitHubResolver.ResolvePackage(ctx, externalsource.GitHubRepositorySource{RepositoryURL: source.URL, Tag: source.Tag, QuotaKey: quotaKey})
		if err != nil {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, err
		}
		owner, repository := githubDisplayIdentity(resolved.RepositoryURL)
		return resolved.Fetch, registry.PackageSourceProvenance{
			Kind: registry.PackageSourceGitHubRepository, RepositoryURL: resolved.RepositoryURL,
			GitHubRepositoryID: strconv.FormatInt(resolved.RepositoryID, 10), GitHubReleaseID: strconv.FormatInt(resolved.ReleaseID, 10),
			GitHubAssetID: strconv.FormatInt(resolved.AssetID, 10), GitHubOwner: owner, GitHubRepository: repository,
			ReleaseTag: resolved.Tag, AssetName: resolved.AssetName, ResolvedRevision: resolved.ResolvedCommitSHA, RetrievedAt: now,
		}, nil
	default:
		return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, fmt.Errorf("%w: external package source kind is invalid", ErrExternalPackageRequestInvalid)
	}
}

func (h *Host) resolveExternalPackageIntent(ctx context.Context, intent ExternalPackageIntent, pkg pluginpkg.Package) (*registry.PluginRecord, string, error) {
	if intent.Action == string(registry.ExternalPackageInstall) {
		instanceID, err := newExternalPackageID("plugin")
		return nil, instanceID, err
	}
	current, err := h.getPluginRecord(ctx, intent.PluginInstanceID)
	if err != nil {
		return nil, "", err
	}
	if err := requireManagementRevision(current, intent.ExpectedManagementRevision); err != nil {
		return nil, "", err
	}
	if current.PublisherID != pkg.Manifest.Publisher.PublisherID || current.PluginID != pkg.Manifest.PluginID() {
		return nil, "", fmt.Errorf("%w: external package update identity does not match installed plugin", ErrExternalPackageRequestInvalid)
	}
	return &current, current.PluginInstanceID, nil
}

func (h *Host) externalPackageEffectiveManifest(record registry.PluginRecord) (manifest.Manifest, map[string][]string, error) {
	effective := record.Manifest
	effective.Methods = append([]manifest.MethodSpec(nil), record.Manifest.Methods...)
	required := make(map[string][]string, len(effective.Methods))
	for index, declared := range effective.Methods {
		method, err := h.effectiveMethod(record, declared)
		if err != nil {
			return manifest.Manifest{}, nil, err
		}
		effective.Methods[index] = method
		permissions, err := h.requiredPermissionsForMethod(record, method)
		if err != nil {
			return manifest.Manifest{}, nil, err
		}
		required[method.Method] = permissions
	}
	return effective, required, nil
}

func (h *Host) assessExternalPackageSignature(ctx context.Context, pkg pluginpkg.Package, now time.Time) registry.SignatureAssessment {
	hashes := registry.TrustHashSet{PackageSHA256: pkg.PackageHash, ManifestSHA256: pkg.ManifestHash, EntriesSHA256: pkg.EntriesHash}
	if pkg.PackageSignature == nil {
		return registry.SignatureAssessment{
			Status: registry.SignatureAbsent, AssessedHashes: hashes, PackageSHA256: pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash, EntriesSHA256: pkg.EntriesHash,
			ReasonCodes: []string{"signature_not_present"}, AssessedAt: now,
		}
	}
	assessment, err := h.adapters.ExternalPackageSignatureAssessor.AssessExternalPackageSignature(ctx, ExternalPackageSignatureAssessmentRequest{Package: pkg, Now: now})
	if err != nil {
		assessment = registry.SignatureAssessment{Status: registry.SignatureUnavailable, ReasonCodes: []string{"signature_assessment_unavailable"}}
	}
	assessment.Algorithm = pkg.PackageSignature.Algorithm
	assessment.KeyID = pkg.PackageSignature.KeyID
	assessment.AssessedHashes = hashes
	assessment.PackageSHA256 = pkg.PackageHash
	assessment.ManifestSHA256 = pkg.ManifestHash
	assessment.EntriesSHA256 = pkg.EntriesHash
	assessment.AssessedAt = now
	if assessment.AssessmentEpoch == "" {
		raw := strings.Join([]string{string(assessment.Status), assessment.KeyringGeneration, assessment.RevocationGeneration, pkg.PackageHash}, "\x00")
		digest := sha256.Sum256([]byte(raw))
		assessment.AssessmentEpoch = "sha256:" + hex.EncodeToString(digest[:])
	}
	return assessment
}

func sameExternalPackageSignatureFreshness(inspected, current registry.SignatureAssessment) bool {
	return inspected.Status == current.Status &&
		inspected.Algorithm == current.Algorithm &&
		inspected.KeyID == current.KeyID &&
		inspected.PackageSHA256 == current.PackageSHA256 &&
		inspected.ManifestSHA256 == current.ManifestSHA256 &&
		inspected.EntriesSHA256 == current.EntriesSHA256 &&
		inspected.EvidenceReference == current.EvidenceReference &&
		inspected.KeyringGeneration == current.KeyringGeneration &&
		inspected.RevocationGeneration == current.RevocationGeneration &&
		inspected.AssessmentEpoch == current.AssessmentEpoch
}

func (h *Host) validateExternalPackageSignatureFreshness(ctx context.Context, record registry.PluginRecord) error {
	if record.SignatureAssessment.Status != registry.SignatureVerified || !externalPackageSource(record.PackageSourceProvenance.Kind) {
		return nil
	}
	assessor, ok := h.adapters.ExternalPackageSignatureAssessor.(ExternalPackageSignatureFreshnessAssessor)
	if !ok {
		// Configuration validation prevents this for new hosts. Keep existing
		// callers fail-open for unavailable freshness, matching user-approved
		// unknown/unavailable signature policy.
		return nil
	}
	assessment, err := assessor.AssessExternalPackageSignatureFreshness(ctx, ExternalPackageSignatureFreshnessRequest{
		PublisherID: record.PublisherID, PluginID: record.PluginID,
		PackageSHA256: record.PackageHash, ManifestSHA256: record.ManifestHash, EntriesSHA256: record.EntriesHash,
		Assessment: record.SignatureAssessment, Now: time.Now().UTC(),
	})
	if err != nil {
		return nil
	}
	if assessment.Status == registry.SignatureInvalid || assessment.Status == registry.SignatureRevoked {
		denied := fmt.Errorf("%w: external package signature freshness is %q", ErrPluginTrustDenied, assessment.Status)
		cleanupErr := h.disablePluginForPolicyFailure(ctx, record, "external package signing key is invalid or revoked", time.Now().UTC())
		return errors.Join(denied, cleanupErr)
	}
	return nil
}

func externalPackageSource(kind registry.PackageSourceKind) bool {
	switch kind {
	case registry.PackageSourcePackageURL, registry.PackageSourceGitHubRepository,
		registry.PackageSourcePackageUpload, registry.PackageSourceOfficialCatalog, registry.PackageSourceApprovedCatalog:
		return true
	default:
		return false
	}
}

func normalizeExternalPackageIntent(intent ExternalPackageIntent) (ExternalPackageIntent, error) {
	intent.Action = strings.TrimSpace(intent.Action)
	intent.PluginInstanceID = strings.TrimSpace(intent.PluginInstanceID)
	switch registry.ExternalPackageInstallIntent(intent.Action) {
	case registry.ExternalPackageInstall:
		if intent.PluginInstanceID != "" || intent.ExpectedManagementRevision != 0 {
			return ExternalPackageIntent{}, fmt.Errorf("%w: external package install intent cannot select an instance or revision", ErrExternalPackageRequestInvalid)
		}
	case registry.ExternalPackageUpdate:
		if intent.PluginInstanceID == "" || intent.ExpectedManagementRevision == 0 {
			return ExternalPackageIntent{}, fmt.Errorf("%w: external package update intent requires plugin_instance_id and expected_management_revision", ErrExternalPackageRequestInvalid)
		}
	default:
		return ExternalPackageIntent{}, fmt.Errorf("%w: external package intent is invalid", ErrExternalPackageRequestInvalid)
	}
	return intent, nil
}

func externalPackageLegacyTrust(pkg pluginpkg.Package, assessment registry.SignatureAssessment) registry.TrustAssessment {
	state := registry.TrustNeedsReview
	switch assessment.Status {
	case registry.SignatureVerified:
		state = registry.TrustVerified
	case registry.SignatureAbsent:
		state = registry.TrustUntrusted
	case registry.SignatureInvalid, registry.SignatureRevoked:
		state = registry.TrustBlockedSecurity
	}
	result := registry.TrustAssessment{
		TrustState: state, ReasonCodes: append([]string(nil), assessment.ReasonCodes...),
		VerifiedHashes:       registry.TrustHashSet{PackageSHA256: pkg.PackageHash, ManifestSHA256: pkg.ManifestHash, EntriesSHA256: pkg.EntriesHash},
		TrustAssessmentEpoch: assessment.AssessmentEpoch,
	}
	if assessment.Status == registry.SignatureVerified {
		result.VerifiedSignature = &registry.VerifiedSignature{Algorithm: assessment.Algorithm, KeyID: assessment.KeyID}
	}
	return result
}

func packageHashSetForPackage(pkg pluginpkg.Package) PackageHashSet {
	return PackageHashSet{PackageSHA256: pkg.PackageHash, ManifestSHA256: pkg.ManifestHash, EntriesSHA256: pkg.EntriesHash}
}

func directExternalPackageProvenance(fetched externalsource.FetchResult, now time.Time) (registry.PackageSourceProvenance, error) {
	source, err := url.Parse(fetched.Source)
	if err != nil {
		return registry.PackageSourceProvenance{}, err
	}
	redirects := make([]registry.PackageSourceRedirectHop, 0, len(fetched.Redirects))
	for _, hop := range fetched.Redirects {
		target, parseErr := url.Parse(hop.To)
		if parseErr != nil {
			return registry.PackageSourceProvenance{}, parseErr
		}
		redirects = append(redirects, registry.PackageSourceRedirectHop{Origin: target.Scheme + "://" + target.Host, Path: target.EscapedPath()})
	}
	return registry.PackageSourceProvenance{
		Kind: registry.PackageSourcePackageURL, SourceOrigin: source.Scheme + "://" + source.Host,
		SourceURL: fetched.Source, FinalURL: fetched.Final, SourcePath: source.EscapedPath(), RedirectChain: redirects, RetrievedAt: now,
	}, nil
}

func githubDisplayIdentity(repositoryURL string) (string, string) {
	parsed, err := url.Parse(repositoryURL)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func newExternalPackageID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw), nil
}

func publicExternalSignatureAssessment(value registry.SignatureAssessment) ExternalPackageSignatureAssessment {
	return ExternalPackageSignatureAssessment{
		State: string(value.Status), ReasonCodes: append([]string{}, value.ReasonCodes...),
		AssessedHashes: PackageHashSet{PackageSHA256: value.PackageSHA256, ManifestSHA256: value.ManifestSHA256, EntriesSHA256: value.EntriesSHA256},
		Algorithm:      value.Algorithm, KeyID: value.KeyID, AssessedAt: value.AssessedAt, AssessmentEpoch: value.AssessmentEpoch,
	}
}

func publicExternalSourceProvenance(value registry.PackageSourceProvenance) ExternalPackageSourceProvenance {
	redirects := make([]ExternalPackageRedirectHop, len(value.RedirectChain))
	for index, hop := range value.RedirectChain {
		redirects[index] = ExternalPackageRedirectHop{Origin: hop.Origin, Path: hop.Path}
	}
	return ExternalPackageSourceProvenance{
		Kind: string(value.Kind), UploadID: value.UploadID, SourceOrigin: value.SourceOrigin, SourcePath: value.SourcePath, RedirectChain: redirects,
		RepositoryID: value.GitHubRepositoryID, ReleaseID: value.GitHubReleaseID, AssetID: value.GitHubAssetID,
		RepositoryURL: value.RepositoryURL, Owner: value.GitHubOwner, Repository: value.GitHubRepository,
		ResolvedCommitSHA: value.ResolvedRevision, ReleaseTag: value.ReleaseTag, AssetName: value.AssetName,
		PackageSHA256: value.PackageSHA256, ResolvedAt: value.RetrievedAt,
	}
}

func publicExternalExecutionApproval(value registry.ExecutionApproval) ExternalPackageExecutionApproval {
	var approvedAt *time.Time
	if !value.ApprovedAt.IsZero() {
		approved := value.ApprovedAt
		approvedAt = &approved
	}
	return ExternalPackageExecutionApproval{State: string(value.Status), ReasonCodes: append([]string{}, value.ReasonCodes...), AssessedAt: value.AssessedAt, ApprovedAt: approvedAt}
}

func publicExternalUpdateEligibility(value registry.UpdateEligibility, signature registry.SignatureAssessment, now time.Time) ExternalPackageUpdateEligibility {
	reasons := []string{"manual_confirmation_required"}
	if signature.Status != registry.SignatureVerified {
		reasons = []string{"signature_not_verified"}
	}
	return ExternalPackageUpdateEligibility{State: string(value), ReasonCodes: reasons, AssessedAt: now}
}
