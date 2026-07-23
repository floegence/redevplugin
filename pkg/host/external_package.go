package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const externalPackageInspectionTTL = 15 * time.Minute

var (
	ErrExternalPackageInspectionNotFound = errors.New("external package inspection not found")
	ErrExternalPackageInspectionExpired  = errors.New("external package inspection expired")
	ErrExternalPackageConfirmation       = errors.New("external package confirmation does not match inspection")
	ErrExternalPackageCommitBlocked      = errors.New("external package commit is blocked by integrity assessment")
	ErrExternalPackageCommitInProgress   = errors.New("external package commit is in progress")
	ErrExternalPackageInspectionStale    = errors.New("external package signature assessment changed after inspection")
)

type ExternalPackageStageStore interface {
	VerifyPackage(context.Context, externalsource.StagedArtifact, pluginpkg.ReadLimits) (pluginpkg.Package, error)
	Remove(externalsource.StagedArtifact) error
}

type ExternalPackageFetcher interface {
	FetchPackage(context.Context, externalsource.FetchRequest) (externalsource.FetchResult, error)
}

type ExternalPackageGitHubResolver interface {
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

type CommitExternalPackageRequest struct {
	InspectionID       string    `json:"inspection_id"`
	ConfirmationDigest string    `json:"confirmation_digest"`
	Now                time.Time `json:"-"`
}

type QueryExternalPackageCommitRequest struct {
	InspectionID string `json:"inspection_id"`
	CommitID     string `json:"commit_id,omitempty"`
}

type externalPackageInspectionState string

const (
	externalPackagePending    externalPackageInspectionState = "pending"
	externalPackageCommitting externalPackageInspectionState = "committing"
	externalPackageCommitted  externalPackageInspectionState = "committed"
	externalPackageFailed     externalPackageInspectionState = "failed"
)

type externalPackagePendingInspection struct {
	Scope      sessionctx.SessionScope
	Artifact   externalsource.StagedArtifact
	Inspection ExternalPackageInspection
	Record     registry.PluginRecord
	State      externalPackageInspectionState
	CommitID   string
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

func (s *externalPackageInspectionStore) begin(id string, scope sessionctx.SessionScope, digest, commitID string, now time.Time) (externalPackagePendingInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok || !record.Scope.Matches(scope) {
		return externalPackagePendingInspection{}, ErrExternalPackageInspectionNotFound
	}
	if record.Inspection.ConfirmationDigest != digest {
		return externalPackagePendingInspection{}, ErrExternalPackageConfirmation
	}
	if record.State == externalPackageCommitting {
		return record, ErrExternalPackageCommitInProgress
	}
	if record.State == externalPackageCommitted {
		return record, nil
	}
	if record.State != externalPackagePending {
		return externalPackagePendingInspection{}, ErrExternalPackageInspectionNotFound
	}
	if !now.Before(record.Inspection.ExpiresAt) {
		return record, ErrExternalPackageInspectionExpired
	}
	record.State = externalPackageCommitting
	record.CommitID = commitID
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

func (s *externalPackageInspectionStore) drain() []externalPackagePendingInspection {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]externalPackagePendingInspection, 0, len(s.records))
	for id, record := range s.records {
		records = append(records, record)
		delete(s.records, id)
	}
	return records
}

func (s *externalPackageInspectionStore) takeExpiredPending(now time.Time) []externalPackagePendingInspection {
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []externalPackagePendingInspection
	for id, record := range s.records {
		if record.State != externalPackagePending || now.Before(record.Inspection.ExpiresAt) {
			continue
		}
		expired = append(expired, record)
		delete(s.records, id)
	}
	return expired
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

func (s *externalPackageInspectionStore) updateRecord(id string, record registry.PluginRecord) {
	s.mu.Lock()
	pending, ok := s.records[id]
	if ok {
		pending.Record = record
		s.records[id] = pending
	}
	s.mu.Unlock()
}

func (h *Host) InspectExternalPackage(ctx context.Context, req InspectExternalPackageRequest) (result ExternalPackageInspection, retErr error) {
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
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionInspectExternalPackage,
		scopedAuthorizationTargetOrCollection(ResourcePlugin, intent.PluginInstanceID, sessionctx.ScopeEnvironment),
	); err != nil {
		return ExternalPackageInspection{}, err
	}
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
	keepArtifact := false
	defer func() {
		if !keepArtifact {
			retErr = errors.Join(retErr, h.adapters.ExternalPackageStageStore.Remove(fetched.Artifact))
		}
	}()
	pkg, err := h.adapters.ExternalPackageStageStore.VerifyPackage(ctx, fetched.Artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	current, instanceID, err := h.resolveExternalPackageIntent(ctx, intent, pkg)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	intent.PluginInstanceID = instanceID
	if err := h.preflightPackageFeatures(pkg.Manifest, packageTrustInput{}); err != nil {
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
	inspection := ExternalPackageInspection{
		InspectionID: inspectionID, ExpiresAt: now.Add(externalPackageInspectionTTL), Intent: intent,
		PublisherID: record.PublisherID, PluginID: record.PluginID, Version: record.Version,
		InspectedHashes:     packageHashSetForPackage(pkg),
		SignatureAssessment: publicExternalSignatureAssessment(signature),
		SourceProvenance:    publicExternalSourceProvenance(provenance),
		ExecutionApproval:   publicExternalExecutionApproval(record.ExecutionApproval),
		UpdateEligibility:   publicExternalUpdateEligibility(record.UpdateEligibility, signature, now),
		SecuritySummary:     securitySummary,
	}
	inspection.ConfirmationDigest, err = externalPackageConfirmationDigest(inspection)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	h.externalInspections.put(externalPackagePendingInspection{
		Scope: scope, Artifact: fetched.Artifact, Inspection: inspection, Record: record, State: externalPackagePending,
	})
	keepArtifact = true
	return inspection, nil
}

func (h *Host) CommitExternalPackage(ctx context.Context, req CommitExternalPackageRequest) (result ExternalPackageCommitResult, retErr error) {
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return ExternalPackageCommitResult{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	commitID, err := newExternalPackageID("commit")
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	pending, err := h.externalInspections.begin(strings.TrimSpace(req.InspectionID), scope, strings.TrimSpace(req.ConfirmationDigest), commitID, now)
	if errors.Is(err, ErrExternalPackageCommitInProgress) {
		queried, queryErr := h.QueryExternalPackageCommit(ctx, QueryExternalPackageCommitRequest{InspectionID: req.InspectionID, CommitID: pending.CommitID})
		if queryErr == nil && queried.Status == "committed" {
			if cleanupErr := h.removeExternalPackageInspectionArtifact(pending.Inspection.InspectionID, false); cleanupErr != nil {
				return queried, mutation.Committed(cleanupErr)
			}
			return queried, nil
		}
		if queryErr != nil && !errors.Is(queryErr, registry.ErrExternalPackageCommitNotFound) {
			return ExternalPackageCommitResult{}, queryErr
		}
		err = nil
	}
	if err == nil && pending.State == externalPackageCommitted {
		queried, queryErr := h.QueryExternalPackageCommit(ctx, QueryExternalPackageCommitRequest{InspectionID: req.InspectionID, CommitID: pending.CommitID})
		if queryErr != nil {
			return ExternalPackageCommitResult{}, queryErr
		}
		if cleanupErr := h.removeExternalPackageInspectionArtifact(pending.Inspection.InspectionID, false); cleanupErr != nil {
			return queried, mutation.Committed(cleanupErr)
		}
		return queried, nil
	}
	if err != nil {
		if errors.Is(err, ErrExternalPackageInspectionExpired) {
			return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
		}
		return ExternalPackageCommitResult{}, err
	}
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionCommitExternalPackage,
		scopedAuthorizationTarget(ResourcePlugin, pending.Record.PluginInstanceID, sessionctx.ScopeEnvironment),
	); err != nil {
		h.externalInspections.finish(pending.Inspection.InspectionID, externalPackagePending)
		return ExternalPackageCommitResult{}, err
	}
	if pending.Record.SignatureAssessment.Status == registry.SignatureInvalid || pending.Record.SignatureAssessment.Status == registry.SignatureRevoked {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, ErrExternalPackageCommitBlocked)
	}
	unlockLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pending.Record.PluginInstanceID)
	if err != nil {
		h.externalInspections.finish(pending.Inspection.InspectionID, externalPackagePending)
		return ExternalPackageCommitResult{}, err
	}
	defer unlockLifecycle()

	var previous *registry.PluginRecord
	if pending.Inspection.Intent.Action == string(registry.ExternalPackageUpdate) {
		current, err := h.adapters.Registry.GetPlugin(ctx, pending.Record.PluginInstanceID)
		if err != nil {
			return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
		}
		if err := requireManagementRevision(current, pending.Inspection.Intent.ExpectedManagementRevision); err != nil {
			return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
		}
		previous = &current
	}
	pkg, err := h.adapters.ExternalPackageStageStore.VerifyPackage(ctx, pending.Artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
	}
	if pkg.PackageHash != pending.Record.PackageHash || pkg.ManifestHash != pending.Record.ManifestHash || pkg.EntriesHash != pending.Record.EntriesHash {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, errors.New("external package changed after inspection"))
	}
	reassessedSignature := h.assessExternalPackageSignature(ctx, pkg, now)
	if reassessedSignature.Status == registry.SignatureInvalid || reassessedSignature.Status == registry.SignatureRevoked {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, ErrExternalPackageCommitBlocked)
	}
	if !sameExternalPackageSignatureFreshness(pending.Record.SignatureAssessment, reassessedSignature) {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, ErrExternalPackageInspectionStale)
	}

	record := pending.Record
	if record.ExecutionApproval.Status != registry.ExecutionApprovalUserApproved {
		record.ExecutionApproval.Status = registry.ExecutionApprovalUserApproved
		record.ExecutionApproval.ReasonCodes = []string{"explicit_user_confirmation"}
		record.ExecutionApproval.ApprovedAt = now
		record.ExecutionApproval.AssessedAt = now
	}
	if pending.Inspection.Intent.Action == string(registry.ExternalPackageInstall) {
		record.EnableState = registry.EnableDisabled
		record.DisabledReason = "installed from an external source; explicit permission review and enable are required"
		record.EnabledAt = nil
	}
	if record.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, record); err != nil {
			return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
		}
	}
	h.externalInspections.updateRecord(pending.Inspection.InspectionID, record)
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
		Type: "plugin.external_package.committed", PluginID: record.PluginID,
		PluginInstanceID: record.PluginInstanceID, RequestID: pending.CommitID,
	})
	if err != nil {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
	}
	auditDetails := map[string]any{"status": "committing"}
	defer func() {
		retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails)
	}()
	if err := h.adapters.Assets.PutOwnedPackage(ctx, &pkg); err != nil {
		return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, err)
	}
	registryIntent := registry.ExternalPackageCommitIntent(pending.Inspection.Intent.Action)
	stored, err := h.adapters.Registry.CommitExternalPackage(ctx, registry.CommitExternalPackageRequest{
		InspectionID: pending.Inspection.InspectionID, CommitID: pending.CommitID, Intent: registryIntent,
		ConfirmationDigest:         pending.Inspection.ConfirmationDigest,
		ExpectedManagementRevision: pending.Inspection.Intent.ExpectedManagementRevision,
		IntendedFingerprint:        record.ActiveFingerprint, IntendedPackageSHA256: record.PackageHash, Record: record, Now: now,
	})
	if err != nil {
		reconciled, found, queryErr := h.queryExternalPackageCommitAfterError(ctx, pending)
		if found && reconciled.Status == registry.ExternalPackageCommitted {
			stored = reconciled
		} else if found {
			h.externalInspections.finish(pending.Inspection.InspectionID, externalPackageCommitting)
			auditDetails["status"] = "committing"
			return publicExternalPackageCommitResult(reconciled), mutation.Unknown(errors.Join(err, queryErr))
		} else {
			// Package assets are content-addressed and may already be referenced by
			// another installation. Without an asset-store claim token, deleting
			// here could corrupt that installation or a commit with unknown outcome.
			return ExternalPackageCommitResult{}, h.failExternalPackageInspection(pending, managementMutationError(record, errors.Join(err, queryErr)))
		}
	}
	h.externalInspections.finish(pending.Inspection.InspectionID, externalPackageCommitted)
	auditDetails["status"] = "committed"
	result = publicExternalPackageCommitResult(stored)
	var postCommitErr error
	if previous != nil && stored.RecordSnapshot != nil {
		revokeRecord := *stored.RecordSnapshot
		if pluginHasWorkers(previous.Manifest) {
			revokeRecord.Manifest = previous.Manifest
		}
		if err := h.revokePluginRuntimeCapabilities(ctx, revokeRecord, now); err != nil {
			postCommitErr = errors.Join(postCommitErr, err)
		} else if err := h.refreshEnabledRuntimeState(ctx, *stored.RecordSnapshot); err != nil {
			postCommitErr = errors.Join(postCommitErr, err)
		}
	}
	if err := h.removeExternalPackageInspectionArtifact(pending.Inspection.InspectionID, false); err != nil {
		postCommitErr = errors.Join(postCommitErr, err)
	}
	if postCommitErr != nil {
		return result, mutation.Committed(postCommitErr)
	}
	return result, nil
}

func (h *Host) queryExternalPackageCommitAfterError(ctx context.Context, pending externalPackagePendingInspection) (registry.ExternalPackageCommitResult, bool, error) {
	result, err := h.adapters.Registry.QueryExternalPackageCommit(ctx, registry.QueryExternalPackageCommitRequest{
		InspectionID: pending.Inspection.InspectionID,
		CommitID:     pending.CommitID,
	})
	if errors.Is(err, registry.ErrExternalPackageCommitNotFound) {
		return registry.ExternalPackageCommitResult{}, false, nil
	}
	if err != nil {
		return registry.ExternalPackageCommitResult{}, false, err
	}
	return result, true, nil
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

func (h *Host) drainExternalPackageInspectionArtifacts() error {
	if h == nil || h.externalInspections == nil || h.adapters.ExternalPackageStageStore == nil {
		return nil
	}
	var resultErr error
	for _, pending := range h.externalInspections.drain() {
		if strings.TrimSpace(pending.Artifact.ID) == "" {
			continue
		}
		resultErr = errors.Join(resultErr, h.adapters.ExternalPackageStageStore.Remove(pending.Artifact))
	}
	return resultErr
}

func (h *Host) removeExpiredExternalPackageInspectionArtifacts(now time.Time) error {
	if h == nil || h.externalInspections == nil || h.adapters.ExternalPackageStageStore == nil {
		return nil
	}
	var resultErr error
	for _, pending := range h.externalInspections.takeExpiredPending(now) {
		if strings.TrimSpace(pending.Artifact.ID) == "" {
			continue
		}
		resultErr = errors.Join(resultErr, h.adapters.ExternalPackageStageStore.Remove(pending.Artifact))
	}
	return resultErr
}

func (h *Host) QueryExternalPackageCommit(ctx context.Context, req QueryExternalPackageCommitRequest) (ExternalPackageCommitResult, error) {
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return ExternalPackageCommitResult{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionQueryExternalPackageCommit,
		scopedAuthorizationTarget(ResourcePlugin, strings.TrimSpace(req.InspectionID), sessionctx.ScopeEnvironment),
	); err != nil {
		return ExternalPackageCommitResult{}, err
	}
	result, err := h.adapters.Registry.QueryExternalPackageCommit(ctx, registry.QueryExternalPackageCommitRequest{
		InspectionID: strings.TrimSpace(req.InspectionID), CommitID: strings.TrimSpace(req.CommitID),
	})
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	return publicExternalPackageCommitResult(result), nil
}

func (h *Host) fetchExternalPackage(ctx context.Context, source ExternalPackageSource, quotaKey string, now time.Time) (externalsource.FetchResult, registry.PackageSourceProvenance, error) {
	switch strings.TrimSpace(source.Kind) {
	case string(registry.PackageSourcePackageURL):
		if strings.TrimSpace(source.Tag) != "" {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, errors.New("tag is valid only for GitHub repository sources")
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
		return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, errors.New("external package source kind is invalid")
	}
}

func (h *Host) resolveExternalPackageIntent(ctx context.Context, intent ExternalPackageIntent, pkg pluginpkg.Package) (*registry.PluginRecord, string, error) {
	if intent.Action == string(registry.ExternalPackageInstall) {
		instanceID, err := newExternalPackageID("plugin")
		return nil, instanceID, err
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, intent.PluginInstanceID)
	if err != nil {
		return nil, "", err
	}
	if err := requireManagementRevision(current, intent.ExpectedManagementRevision); err != nil {
		return nil, "", err
	}
	if current.PublisherID != pkg.Manifest.Publisher.PublisherID || current.PluginID != pkg.Manifest.PluginID() {
		return nil, "", errors.New("external package update identity does not match installed plugin")
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
		registry.PackageSourceOfficialCatalog, registry.PackageSourceApprovedCatalog:
		return true
	default:
		return false
	}
}

func normalizeExternalPackageIntent(intent ExternalPackageIntent) (ExternalPackageIntent, error) {
	intent.Action = strings.TrimSpace(intent.Action)
	intent.PluginInstanceID = strings.TrimSpace(intent.PluginInstanceID)
	switch registry.ExternalPackageCommitIntent(intent.Action) {
	case registry.ExternalPackageInstall:
		if intent.PluginInstanceID != "" || intent.ExpectedManagementRevision != 0 {
			return ExternalPackageIntent{}, errors.New("external package install intent cannot select an instance or revision")
		}
	case registry.ExternalPackageUpdate:
		if intent.PluginInstanceID == "" || intent.ExpectedManagementRevision == 0 {
			return ExternalPackageIntent{}, errors.New("external package update intent requires plugin_instance_id and expected_management_revision")
		}
	default:
		return ExternalPackageIntent{}, errors.New("external package intent is invalid")
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

func externalPackageConfirmationDigest(inspection ExternalPackageInspection) (string, error) {
	inspection.ConfirmationDigest = ""
	raw, err := json.Marshal(inspection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
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
		Kind: string(value.Kind), SourceOrigin: value.SourceOrigin, SourcePath: value.SourcePath, RedirectChain: redirects,
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

func publicExternalPackageCommitResult(value registry.ExternalPackageCommitResult) ExternalPackageCommitResult {
	result := ExternalPackageCommitResult{
		Status: "in_progress", InspectionID: value.InspectionID,
		Intent: ExternalPackageIntent{Action: string(value.Intent)}, RetryAfterMS: 250,
	}
	if value.Status != registry.ExternalPackageCommitted || value.RecordSnapshot == nil {
		return result
	}
	result.Status = "committed"
	record := value.RecordSnapshot
	result.Receipt = &ExternalPackageCommitReceipt{
		CommitID: value.CommitID, InspectionID: value.InspectionID, PackageSHA256: record.PackageHash,
		ManagementRevision: record.ManagementRevision, CommittedAt: value.UpdatedAt,
	}
	result.Plugin = record
	signature := publicExternalSignatureAssessment(record.SignatureAssessment)
	provenance := publicExternalSourceProvenance(record.PackageSourceProvenance)
	approval := publicExternalExecutionApproval(record.ExecutionApproval)
	update := publicExternalUpdateEligibility(record.UpdateEligibility, record.SignatureAssessment, value.UpdatedAt)
	result.SignatureAssessment = &signature
	result.SourceProvenance = &provenance
	result.ExecutionApproval = &approval
	result.UpdateEligibility = &update
	if record.SecurityCapabilitySummary.CanonicalJSON != "" {
		var summary ExternalPackageSecuritySummary
		if json.Unmarshal([]byte(record.SecurityCapabilitySummary.CanonicalJSON), &summary) == nil {
			result.SecuritySummary = &summary
		}
	}
	result.RetryAfterMS = 0
	return result
}

var _ = mutation.OutcomeCommitted
