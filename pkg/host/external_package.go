package host

import (
	"context"
	"crypto/rand"
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

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releaseprojection"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

const externalPackageInspectionTTL = 15 * time.Minute

var (
	ErrExternalPackageInspectionNotFound = errors.New("external package inspection not found")
	ErrExternalPackageInspectionExpired  = errors.New("external package inspection expired")
	ErrExternalPackageConfirmation       = errors.New("external package hash does not match inspection")
	ErrExternalPackageInstallInProgress  = errors.New("external package install is in progress")
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
	ListPlugins(context.Context, string, string) ([]repositoryindex.Plugin, error)
	ResolvePackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.ResolvedGitHubAsset, error)
}

type ExternalPackageSource struct {
	Host         string `json:"host,omitempty"`
	PluginID     string `json:"plugin_id,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	ReleaseID    string `json:"release_id,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	Kind         string `json:"kind"`
	URL          string `json:"url"`
	Tag          string `json:"tag,omitempty"`
}

type InspectExternalPackageRequest struct {
	ExpectedSecuritySummarySHA256 string                `json:"expected_security_summary_sha256,omitempty"`
	ExpectedContractSetSHA256     string                `json:"expected_contract_set_sha256,omitempty"`
	ExpectedPublisherID           string                `json:"expected_publisher_id,omitempty"`
	ExpectedPluginID              string                `json:"expected_plugin_id,omitempty"`
	ExpectedVersion               string                `json:"expected_version,omitempty"`
	ExpectedPackageSHA256         string                `json:"expected_package_sha256,omitempty"`
	Intent                        ExternalPackageIntent `json:"intent"`
	Source                        ExternalPackageSource `json:"source"`
	Now                           time.Time             `json:"-"`
}

type InspectUploadedExternalPackageRequest struct {
	Intent       ExternalPackageIntent `json:"intent"`
	Package      io.Reader             `json:"-"`
	DeclaredSize int64                 `json:"-"`
	Now          time.Time             `json:"-"`
}

type installInspectedPackageRequest struct {
	claimed               bool
	automatic             bool
	operationEvidence     string
	progress              func(stage, status string) error
	InspectionID          string    `json:"inspection_id"`
	ExpectedPackageSHA256 string    `json:"expected_package_sha256"`
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
		if expiredAt != nil && expiredAt.Before(record.Inspection.ExpiresAt) {
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

	fetched, provenance, selectedPlugin, selectedVersion, err := h.fetchExternalPackage(ctx, req.Source, scope.OwnerEnvHash, now)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	inspection, err := h.inspectStagedExternalPackage(ctx, scope, intent, fetched.Artifact, provenance, now)
	if err != nil {
		return inspection, err
	}
	defer func() {
		if retErr != nil {
			h.externalInspections.finish(inspection.InspectionID, externalPackageFailed)
			retErr = errors.Join(retErr, h.removeExternalPackageInspectionArtifact(inspection.InspectionID, true))
		}
	}()
	if (req.ExpectedPublisherID != "" && req.ExpectedPublisherID != inspection.PublisherID) || (req.ExpectedPluginID != "" && req.ExpectedPluginID != inspection.PluginID) || (req.ExpectedVersion != "" && req.ExpectedVersion != inspection.Version) || (req.ExpectedPackageSHA256 != "" && req.ExpectedPackageSHA256 != inspection.InspectedHashes.PackageSHA256) || (req.Source.PluginID != "" && req.Source.PluginID != inspection.PluginID) {
		return ExternalPackageInspection{}, ErrExternalPackageConfirmation
	}
	contractHash, contractErr := releaseprojection.CapabilityContractSetSHA256(inspection.SecuritySummary)
	if contractErr != nil || (req.ExpectedSecuritySummarySHA256 != "" && req.ExpectedSecuritySummarySHA256 != inspection.SecuritySummary.SummarySHA256) || (req.ExpectedContractSetSHA256 != "" && req.ExpectedContractSetSHA256 != contractHash) {
		return ExternalPackageInspection{}, errors.Join(ErrExternalPackageConfirmation, contractErr)
	}
	if provenance.Kind == registry.PackageSourceGitHubRepository {
		pending, e := h.externalInspections.get(inspection.InspectionID, scope)
		if e != nil {
			return ExternalPackageInspection{}, e
		}
		if pending.Record.PluginID != selectedPlugin || pending.Record.Version != selectedVersion {
			return ExternalPackageInspection{}, ErrExternalPackageConfirmation
		}
	}
	return inspection, nil
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
	if provenance.Kind == registry.PackageSourceGitHubRepository {
		repositoryID, parseErr := strconv.ParseInt(provenance.GitHubRepositoryID, 10, 64)
		if parseErr != nil || strconv.FormatInt(repositoryID, 10) != provenance.GitHubRepositoryID {
			return ExternalPackageInspection{}, fmt.Errorf("%w: invalid observed repository identity", ErrExternalPackageConfirmation)
		}
		if err := pluginidentity.ValidateGitHub(repositoryID, pkg.Manifest.Publisher.PublisherID, pkg.Manifest.PluginID()); err != nil {
			return ExternalPackageInspection{}, fmt.Errorf("%w: %v", ErrExternalPackageConfirmation, err)
		}
	}
	current, instanceID, err := h.resolveExternalPackageIntent(ctx, intent, pkg)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	intent.PluginInstanceID = instanceID
	if err := h.preflightPackageFeatures(pkg.Manifest, packageInput{}); err != nil {
		return ExternalPackageInspection{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, registry.PluginRecord{Manifest: pkg.Manifest}); err != nil {
		return ExternalPackageInspection{}, err
	}
	pins, err := h.resolvePackageCapabilityPins(pkg.Manifest)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	provenance.PackageSHA256 = pkg.PackageHash
	record := packageRecord(pkg, instanceID, map[string]string{"source.type": "external"}, provenance, pins)
	if current != nil {
		if err := validatePackageUpdate(*current, record, intent.AllowSourceChange); err != nil {
			return ExternalPackageInspection{}, err
		}
		if _, err := pluginDataUpgradeRequired(current.Manifest, record.Manifest); err != nil {
			return ExternalPackageInspection{}, err
		}
		record.VersionHistory = versionSwitchHistory(current.VersionHistory, record.PackageHash, versionSnapshot(*current, now))
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
	record.ExecutionApproval = registry.ExecutionApproval{
		Status: registry.ExecutionApprovalPending, OwnerEnvHash: scope.OwnerEnvHash,
		PackageSHA256: pkg.PackageHash, ReasonCodes: []string{"explicit_confirmation_required"}, AssessedAt: now,
	}
	record.UpdateEligibility = registry.UpdateManualOnly
	if current != nil && samePackageUpdateSource(current.PackageSourceProvenance, record.PackageSourceProvenance) {
		record.AutomaticUpdates = current.AutomaticUpdates
		if record.AutomaticUpdates && retrievableUpdateSource(record.PackageSourceProvenance) {
			record.UpdateEligibility = registry.UpdateAutomaticEligible
		}
	}
	record.SecurityCapabilitySummary = registry.SecurityCapabilitySummary{
		SchemaVersion: "redevplugin.external_security_summary.v1",
		Summary:       securitySummary.SummarySHA256, SHA256: securitySummary.SummarySHA256,
	}
	if raw, marshalErr := json.Marshal(securitySummary); marshalErr == nil {
		record.SecurityCapabilitySummary.CanonicalJSON = string(raw)
	} else {
		return ExternalPackageInspection{}, marshalErr
	}

	updateReasons := []string{"manual_confirmation_required"}
	if current != nil && record.AutomaticUpdates {
		if err := validateAutomaticUpdate(*current, record); err != nil {
			record.UpdateEligibility = registry.UpdateManualOnly
			if errors.Is(err, ErrUpdateReviewRequired) {
				updateReasons = []string{"capabilities_changed"}
			} else {
				updateReasons = []string{"no_newer_version"}
			}
		} else {
			updateReasons = []string{"user_enabled_original_source_updates"}
		}
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
		InspectedHashes:   packageHashSetForPackage(pkg),
		SourceProvenance:  publicExternalSourceProvenance(provenance),
		ExecutionApproval: publicExternalExecutionApproval(record.ExecutionApproval),
		UpdateEligibility: publicExternalUpdateEligibility(record.UpdateEligibility, now),
		SecuritySummary:   securitySummary,
	}
	inspection.UpdateEligibility.ReasonCodes = updateReasons
	h.externalInspections.put(externalPackagePendingInspection{
		Scope: scope, Artifact: artifact, Inspection: inspection, Record: record, State: externalPackagePending,
	})
	keepArtifact = true
	return inspection, nil
}

func (h *Host) installInspectedPackage(ctx context.Context, req installInspectedPackageRequest) (result installedExternalPackageResult, retErr error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return installedExternalPackageResult{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	inspectionID := strings.TrimSpace(req.InspectionID)
	preview, err := h.externalInspections.get(inspectionID, scope)
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	authorization, err := h.authorizeManagementSession(ctx, session, ManagementActionInstallInspectedPackage,
		scopedAuthorizationTarget(ResourcePlugin, preview.Record.PluginInstanceID, sessionctx.ScopeEnvironment))
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	ctx, releaseReservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return installedExternalPackageResult{}, err
	}
	defer releaseReservation()
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pending := preview
	if req.claimed {
		if preview.State != externalPackageCommitting || preview.Inspection.InspectedHashes.PackageSHA256 != req.ExpectedPackageSHA256 {
			return installedExternalPackageResult{}, ErrExternalPackageConfirmation
		}
	} else {
		pending, err = h.externalInspections.begin(inspectionID, scope, strings.TrimSpace(req.ExpectedPackageSHA256), now)
	}
	if err != nil {
		if errors.Is(err, ErrExternalPackageInspectionExpired) {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
		return installedExternalPackageResult{}, err
	}
	unlockLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pending.Record.PluginInstanceID)
	if err != nil {
		h.externalInspections.finish(pending.Inspection.InspectionID, externalPackagePending)
		return installedExternalPackageResult{}, err
	}
	defer unlockLifecycle()
	var previous *registry.PluginRecord
	if pending.Inspection.Intent.Action == string(registry.ExternalPackageUpdate) {
		current, err := h.controlStore.Registry().GetPlugin(ctx, scope.OwnerEnvHash, pending.Record.PluginInstanceID)
		if err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
		if err := requireManagementRevision(current, pending.Inspection.Intent.ExpectedManagementRevision); err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
		if req.automatic {
			if err := validateAutomaticUpdate(current, pending.Record); err != nil {
				return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
			}
		}
		previous = &current
	} else if req.automatic {
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, ErrExternalPackageRequestInvalid)
	}
	if req.progress != nil {
		if err := req.progress("verify", "running"); err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
	}
	// Reopen and parse the staged artifact immediately before install.
	pkg, err := h.adapters.ExternalPackageStageStore.VerifyPackage(ctx, pending.Artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
	}
	if pkg.PackageHash != pending.Record.PackageHash || pkg.ManifestHash != pending.Record.ManifestHash || pkg.EntriesHash != pending.Record.EntriesHash {
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, errors.New("external package changed after inspection"))
	}
	if req.progress != nil {
		if err := req.progress("verify", "completed"); err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
		if err := req.progress("install", "running"); err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
	}
	record := pending.Record
	// Preferences may change after inspection without revoking live Surfaces.
	// Preserve the current choice at commit; a source switch always resets it.
	if previous != nil {
		record.AutomaticUpdates = previous.AutomaticUpdates && samePackageUpdateSource(previous.PackageSourceProvenance, record.PackageSourceProvenance)
		record.UpdateEligibility = registry.UpdateManualOnly
		if record.AutomaticUpdates && retrievableUpdateSource(record.PackageSourceProvenance) {
			record.UpdateEligibility = registry.UpdateAutomaticEligible
		}
	}
	record.ExecutionApproval.Status = registry.ExecutionApprovalUserApproved
	record.ExecutionApproval.EvidenceReference = req.operationEvidence
	record.ExecutionApproval.ReasonCodes = []string{"explicit_user_confirmation"}
	if req.automatic {
		record.ExecutionApproval.Status = registry.ExecutionApprovalPolicyApproved
		record.ExecutionApproval.ReasonCodes = []string{"user_enabled_original_source_update"}
	}
	record.ExecutionApproval.ApprovedAt = now
	record.ExecutionApproval.AssessedAt = now
	if record.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, record); err != nil {
			return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
		Type: "plugin.external_package.installed", PluginID: record.PluginID,
		PluginInstanceID: record.PluginInstanceID, RequestID: pending.Inspection.InspectionID,
	})
	if err != nil {
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
	}
	auditDetails := map[string]any{
		"status":              "installing",
		"installation_action": pending.Inspection.Intent.Action,
		"package_source_kind": record.PackageSourceProvenance.Kind,
	}
	defer func() { retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails) }()
	finishAssets, err := h.preparePackageAssets(ctx, &pkg)
	if err != nil {
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, err)
	}
	var stored registry.PluginRecord
	if previous == nil {
		stored, err = h.commitInstall(ctx, record, now)
	} else {
		stored, err = h.updateExternalPackageRecord(ctx, session, registry.InstallExternalPackageRequest{
			Intent:                     registry.ExternalPackageUpdate,
			ExpectedManagementRevision: pending.Inspection.Intent.ExpectedManagementRevision,
			Record:                     record, Now: now,
		})
	}
	err = errors.Join(err, finishAssets(err == nil || mutation.ForError(err) != mutation.OutcomeNotCommitted))
	if err != nil {
		auditDetails["status"] = "failed"
		// A digest identifies shared cached bytes, not an installation. Failed
		// commit cleanup must never remove another instance's active assets.
		return installedExternalPackageResult{}, h.failExternalPackageInspection(pending, managementMutationError(record, err))
	}
	auditDetails["status"] = "committed"
	result = installedExternalPackage(stored, now)
	var postCommitErr error
	if req.progress != nil {
		postCommitErr = errors.Join(postCommitErr, req.progress("install", "completed"))
		postCommitErr = errors.Join(postCommitErr, req.progress("enable", "running"))
	}
	if previous == nil {
		postCommitErr = errors.Join(
			postCommitErr,
			h.activateEnabledRuntimeState(ctx, stored),
			h.publishEnabledSurfaces(ctx, stored),
		)
	} else {
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

func (h *Host) updateExternalPackageRecord(ctx context.Context, session sessionctx.Context, req registry.InstallExternalPackageRequest) (registry.PluginRecord, error) {
	if h.controlStore == nil {
		return registry.PluginRecord{}, ErrControlStoreRequired
	}
	current, err := h.getPluginRecord(ctx, req.Record.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	next, err := registry.PrepareExternalPackageInstall(session.OwnerEnvHash, req, &current)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	upgrade, err := pluginDataUpgradeRequired(current.Manifest, next.Manifest)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if upgrade {
		stored, err := h.commitPluginDataUpgrade(ctx, current, next, req.Now, true)
		if err != nil && mutation.ForError(err) == mutation.OutcomeNotCommitted {
			if refreshErr := h.refreshEnabledRuntimeState(context.WithoutCancel(ctx), current); refreshErr != nil {
				err = &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: errors.Join(err, fmt.Errorf("restore predecessor runtime: %w", refreshErr))}
			}
		}
		return stored, err
	}
	return h.controlStore.Registry().UpdateExternalPackage(ctx, session.OwnerEnvHash, req)
}

func installedExternalPackage(record registry.PluginRecord, now time.Time) installedExternalPackageResult {
	result := installedExternalPackageResult{Plugin: &record}
	provenance := publicExternalSourceProvenance(record.PackageSourceProvenance)
	approval := publicExternalExecutionApproval(record.ExecutionApproval)
	update := publicExternalUpdateEligibility(record.UpdateEligibility, now)
	result.SourceProvenance = &provenance
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

func (h *Host) fetchExternalPackage(ctx context.Context, source ExternalPackageSource, quotaKey string, now time.Time) (externalsource.FetchResult, registry.PackageSourceProvenance, string, string, error) {
	switch strings.TrimSpace(source.Kind) {
	case string(registry.PackageSourcePackageURL):
		if strings.TrimSpace(source.Tag) != "" || source.RepositoryID != "" || source.ReleaseID != "" || source.AssetID != "" || source.Host != "" || source.PluginID != "" {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, "", "", fmt.Errorf("%w: tag is valid only for GitHub repository sources", ErrExternalPackageRequestInvalid)
		}
		fetched, err := h.adapters.ExternalPackageFetcher.FetchPackage(ctx, externalsource.FetchRequest{URL: source.URL, QuotaKey: quotaKey})
		if err != nil {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, "", "", err
		}
		provenance, err := directExternalPackageProvenance(fetched, now)
		return fetched, provenance, "", "", err
	case string(registry.PackageSourceGitHubRepository):
		resolved, err := h.adapters.ExternalPackageGitHubResolver.ResolvePackage(ctx, externalsource.GitHubRepositorySource{RepositoryURL: source.URL, Tag: source.Tag, QuotaKey: quotaKey, Host: source.Host, PluginID: source.PluginID})
		if err != nil {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, "", "", err
		}
		if (source.RepositoryID != "" && source.RepositoryID != strconv.FormatInt(resolved.RepositoryID, 10)) || (source.ReleaseID != "" && source.ReleaseID != strconv.FormatInt(resolved.ReleaseID, 10)) || (source.AssetID != "" && source.AssetID != strconv.FormatInt(resolved.AssetID, 10)) {
			return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, "", "", errors.Join(ErrExternalPackageConfirmation, h.adapters.ExternalPackageStageStore.Remove(resolved.Fetch.Artifact))
		}
		owner, repository := githubDisplayIdentity(resolved.RepositoryURL)
		return resolved.Fetch, registry.PackageSourceProvenance{
			Kind: registry.PackageSourceGitHubRepository, RepositoryURL: resolved.RepositoryURL,
			GitHubRepositoryID: strconv.FormatInt(resolved.RepositoryID, 10), GitHubReleaseID: strconv.FormatInt(resolved.ReleaseID, 10),
			GitHubAssetID: strconv.FormatInt(resolved.AssetID, 10), GitHubOwner: owner, GitHubRepository: repository,
			ReleaseTag: resolved.Tag, AssetName: resolved.AssetName, ResolvedRevision: resolved.ResolvedCommitSHA, RetrievedAt: now,
		}, resolved.PluginID, resolved.Version, nil
	default:
		return externalsource.FetchResult{}, registry.PackageSourceProvenance{}, "", "", fmt.Errorf("%w: external package source kind is invalid", ErrExternalPackageRequestInvalid)
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
	contracts := make([]capabilitycontract.KnownContract, 0, len(record.CapabilityContracts))
	for _, pin := range record.CapabilityContracts {
		contract, err := h.adapters.Capabilities.RequireContract(pin)
		if err != nil {
			return manifest.Manifest{}, nil, err
		}
		contracts = append(contracts, contract)
	}
	return releaseprojection.ProjectManifestWithCapabilityContracts(record.Manifest, contracts)
}

func normalizeExternalPackageIntent(intent ExternalPackageIntent) (ExternalPackageIntent, error) {
	intent.Action = strings.TrimSpace(intent.Action)
	intent.PluginInstanceID = strings.TrimSpace(intent.PluginInstanceID)
	switch registry.ExternalPackageInstallIntent(intent.Action) {
	case registry.ExternalPackageInstall:
		if intent.PluginInstanceID != "" || intent.ExpectedManagementRevision != 0 || intent.AllowSourceChange {
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

func publicExternalUpdateEligibility(value registry.UpdateEligibility, now time.Time) ExternalPackageUpdateEligibility {
	reasons := []string{"manual_confirmation_required"}
	if value == registry.UpdateAutomaticEligible {
		reasons = []string{"user_enabled_original_source_updates"}
	}
	return ExternalPackageUpdateEligibility{State: string(value), ReasonCodes: reasons, AssessedAt: now}
}
