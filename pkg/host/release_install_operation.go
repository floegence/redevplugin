package host

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

const releaseInstallOperationTimeout = 5 * time.Minute

const (
	releaseInstallFailureInterrupted = string(security.ErrInstallInterrupted)
	releaseInstallFailureConflict    = string(security.ErrInstallStateConflict)
	releaseInstallFailureInternal    = string(security.ErrInternalFailure)
)

type StartReleaseInstallExecutionRequest struct {
	RequestID        string           `json:"request_id"`
	PluginInstanceID string           `json:"plugin_instance_id"`
	ReleaseRef       PluginReleaseRef `json:"release_ref"`
	InspectionID     string           `json:"inspection_id"`
	Now              time.Time        `json:"-"`
}

type InspectReleasePackageRequest struct {
	PluginInstanceID string           `json:"plugin_instance_id"`
	ReleaseRef       PluginReleaseRef `json:"release_ref"`
	Now              time.Time        `json:"-"`
}

type ReleasePackageInspection struct {
	InspectionID       string                         `json:"inspection_id"`
	ExpiresAt          time.Time                      `json:"expires_at"`
	PluginInstanceID   string                         `json:"plugin_instance_id"`
	ReleaseRef         PluginReleaseRef               `json:"release_ref"`
	InspectedHashes    PackageHashSet                 `json:"inspected_hashes"`
	Presentation       manifest.PresentationCatalog   `json:"presentation"`
	PresentationSHA256 string                         `json:"presentation_sha256"`
	SecuritySummary    ExternalPackageSecuritySummary `json:"security_summary"`
}

func (h *Host) InspectReleasePackage(ctx context.Context, req InspectReleasePackageRequest) (ReleasePackageInspection, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	if req.PluginInstanceID == "" {
		return ReleasePackageInspection{}, fmt.Errorf("%w: plugin_instance_id is required", ErrMethodRequestContract)
	}
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionInstallReleaseRef,
		scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return ReleasePackageInspection{}, err
	}
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pkg, release, sourcePolicy, verifiedRelease, metadata, err := h.resolveReleasePackage(
		ctx, PackageTrustActionInstall, req.ReleaseRef, nil, req.PluginInstanceID, now,
	)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	trustInput := packageTrustInput{
		ReleaseRef: &req.ReleaseRef, Release: &release, SourcePolicy: &sourcePolicy, VerifiedRelease: &verifiedRelease,
	}
	trustAssessment, err := h.resolvePackageTrust(ctx, PackageTrustActionInstall, pkg, trustInput, nil, req.PluginInstanceID, now)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	pins, err := h.resolvePackageCapabilityPins(pkg.Manifest)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	provenance, err := packageSourceProvenanceForTrust(pkg, trustInput)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	record := packageRecord(pkg, trustAssessment, req.PluginInstanceID, nil, provenance, pins)
	effectiveManifest, required, err := h.externalPackageEffectiveManifest(record)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	securitySummary, err := buildExternalPackageSecuritySummary(effectiveManifest, pins, required)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	presentation := pkg.Manifest.PresentationCatalog()
	presentationSHA256, err := manifest.PresentationCatalogSHA256(presentation)
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	inspectionID, err := newExternalPackageID("release_inspection")
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	inspection := ReleasePackageInspection{
		InspectionID: inspectionID, ExpiresAt: now.Add(releasePackageInspectionTTL), PluginInstanceID: req.PluginInstanceID, ReleaseRef: req.ReleaseRef,
		InspectedHashes: packageHashSetForPackage(pkg), Presentation: presentation,
		PresentationSHA256: presentationSHA256, SecuritySummary: securitySummary,
	}
	scope, err := session.SessionScope()
	if err != nil {
		return ReleasePackageInspection{}, err
	}
	h.releaseInspections.put(pendingReleasePackageInspection{
		Scope: scope, Inspection: inspection, ReleaseRef: req.ReleaseRef,
		Package: pkg, Release: release,
		SourcePolicy: sourcePolicy, Verified: verifiedRelease,
		Metadata: cloneReleasePackageInspectionMetadata(metadata),
	})
	return inspection, nil
}

func (h *Host) StartReleaseInstallExecution(ctx context.Context, req StartReleaseInstallExecutionRequest) (execution.Execution, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return execution.Execution{}, err
	}
	operation, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest(req))
	if err != nil {
		return execution.Execution{}, err
	}
	return h.controlStore.Executions().GetOwned(ctx, operation.Execution.ID, executionOwner(session))
}

type startReleaseInstallOperationRequest StartReleaseInstallExecutionRequest

func (h *Host) startReleaseInstallOperation(ctx context.Context, req startReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	if req.PluginInstanceID == "" {
		return registry.ReleaseInstallOperation{}, fmt.Errorf("%w: plugin_instance_id is required", ErrMethodRequestContract)
	}
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionInstallReleaseRef,
		scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if err := validateReleaseRef(req.ReleaseRef); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if strings.TrimSpace(req.InspectionID) == "" {
		return registry.ReleaseInstallOperation{}, ErrReleasePackageInspectionNotFound
	}
	operationID, err := newExternalPackageID("release_install")
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	operation, created, err := h.controlStore.Executions().StartReleaseInstall(ctx, releaseInstallOwner(session), registry.StartReleaseInstallOperationRequest{
		RequestID: req.RequestID, ExecutionID: operationID, PluginInstanceID: req.PluginInstanceID,
		Release: releaseInstallIdentity(req.ReleaseRef), InspectionID: req.InspectionID, Now: req.Now,
	})
	if err != nil || !created {
		return operation, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return h.failReleaseInstallOperationAtPhase(context.WithoutCancel(ctx), operation, "validate_inspection", releaseInstallFailureInternal, false, mutation.ForError(err))
	}
	pending, err := h.releaseInspections.claim(req.InspectionID, scope, req.PluginInstanceID, req.ReleaseRef, time.Now().UTC())
	if err != nil {
		return h.failReleaseInstallOperationAtPhase(context.WithoutCancel(ctx), operation, "validate_inspection", releasePackageInspectionFailureCode(err), false, mutation.OutcomeNotCommitted)
	}
	if !h.startLifecycleJob(func(lifecycleCtx context.Context) {
		jobCtx := sessionctx.WithContext(lifecycleCtx, session)
		jobCtx, cancel := context.WithTimeout(jobCtx, releaseInstallOperationTimeout)
		defer cancel()
		h.runReleaseInstallOperation(jobCtx, operation, req.ReleaseRef, pending)
	}) {
		return h.failReleaseInstallOperation(context.WithoutCancel(ctx), operation, releaseInstallFailureInterrupted, true, mutation.OutcomeNotCommitted)
	}
	return operation, nil
}

func (h *Host) runReleaseInstallOperation(ctx context.Context, operation registry.ReleaseInstallOperation, ref PluginReleaseRef, pending pendingReleasePackageInspection) {
	running, err := h.updateReleaseInstallOperation(ctx, operation, execution.StatusRunning, "refresh_trust",
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, mutation.OutcomeNotCommitted, nil, nil)
	if err != nil {
		_, _ = h.failReleaseInstallOperation(context.WithoutCancel(ctx), operation, releaseInstallFailureCode(err), false, mutation.ForError(err))
		return
	}
	tracker := &releaseInstallProgressTracker{host: h, ctx: ctx, current: running}
	pkg, release := pending.Package, pending.Release
	sourcePolicy, verifiedRelease, metadata := pending.SourcePolicy, pending.Verified, pending.Metadata
	if err = h.refreshReleaseInspectionTrust(ctx, ref, pending); err == nil {
		tracker.observe(ReleaseArtifactProgress{Phase: "verify_signatures", Attempt: 1, CacheHit: true})
	}
	running, progressErr := tracker.snapshot()
	if progressErr != nil {
		h.finishFailedReleaseInstall(ctx, running, progressErr)
		return
	}
	if err != nil {
		h.finishFailedReleaseInstall(ctx, running, err)
		return
	}
	tracker.observe(ReleaseArtifactProgress{Phase: "validate_install", Attempt: 1, CacheHit: true})
	unlock, err := h.lifecycleLocks.acquireWrite(ctx, operation.PluginInstanceID)
	if err == nil {
		defer unlock()
		refCopy := ref
		var record registry.PluginRecord
		record, err = h.installResolvedPackage(ctx, pkg, operation.PluginInstanceID, packageTrustInput{
			ReleaseRef: &refCopy, Release: &release, SourcePolicy: &sourcePolicy, VerifiedRelease: &verifiedRelease,
			Observe: tracker.observe,
		}, time.Now().UTC(), metadata)
		if err == nil {
			running, err = tracker.snapshot()
			if err != nil {
				h.finishFailedReleaseInstall(ctx, running, err)
				return
			}
			_, _ = h.updateReleaseInstallOperation(context.WithoutCancel(ctx), running, execution.StatusCompleted, "complete",
				registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
				mutation.OutcomeCommitted, nil, &record)
			return
		}
	}
	latest, progressErr := tracker.snapshot()
	running = latest
	err = errors.Join(err, progressErr)
	h.finishFailedReleaseInstall(ctx, running, err)
}

// reconcileCommittedReleaseInstalls closes the only crash window in the
// install transaction: a package record may be durable before its terminal
// execution event. InstallCommit already writes enable_state=enabled, so
// recovery only publishes that record and never performs a second lifecycle
// transition or grants permissions.
func (h *Host) reconcileCommittedReleaseInstalls(ctx context.Context) error {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return nil
	}
	operations, err := h.controlStore.Executions().ListReleaseInstalls(ctx, session.OwnerEnvHash)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if operation.Execution.Status != execution.StatusRunning {
			continue
		}
		record, err := h.getPluginRecord(ctx, operation.PluginInstanceID)
		if err != nil || !releaseInstallRecordMatches(operation, record) {
			continue
		}
		unlock, err := h.lifecycleLocks.acquireWrite(ctx, operation.PluginInstanceID)
		if err != nil {
			return err
		}
		_, updateErr := h.updateReleaseInstallOperation(context.WithoutCancel(ctx), operation, execution.StatusCompleted, "complete",
			registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
			mutation.OutcomeCommitted, nil, &record)
		unlock()
		if updateErr != nil {
			return updateErr
		}
	}
	return nil
}

type releaseInstallProgressTracker struct {
	mu             sync.Mutex
	host           *Host
	ctx            context.Context
	current        registry.ReleaseInstallOperation
	lastPhase      string
	lastCompleted  int64
	lastPersisted  time.Time
	persistenceErr error
}

func (tracker *releaseInstallProgressTracker) observe(progress ReleaseArtifactProgress) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.persistenceErr != nil {
		return
	}
	now := time.Now().UTC()
	phase := progress.Phase
	phaseChanged := phase != tracker.lastPhase
	byteThreshold := progress.Total > 0 && (progress.Completed-tracker.lastCompleted >= 256<<10 || progress.Completed == progress.Total)
	timeThreshold := tracker.lastPersisted.IsZero() || now.Sub(tracker.lastPersisted) >= 250*time.Millisecond
	if !phaseChanged && !byteThreshold && !timeThreshold {
		return
	}
	kind := registry.ReleaseInstallProgressIndeterminate
	if (progress.Phase == "download_package" || progress.Phase == "fetch_release_evidence") && progress.Total > 0 {
		kind = registry.ReleaseInstallProgressBytes
	}
	retryAfterMS := progress.RetryAfter.Milliseconds()
	updated, err := tracker.host.updateReleaseInstallRecord(tracker.ctx, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: tracker.current.Execution.ID, ExpectedCursor: tracker.current.Execution.Cursor,
		Status: execution.StatusRunning, Phase: phase,
		Progress:     registry.ReleaseInstallProgress{Kind: kind, Completed: progress.Completed, Total: progress.Total},
		ArtifactRole: progress.ArtifactRole, CacheHit: progress.CacheHit,
		Attempt: max(progress.Attempt, 1), RetryAfterMS: retryAfterMS,
		MutationOutcome: mutation.OutcomeNotCommitted, Now: now,
	})
	if err != nil {
		tracker.persistenceErr = err
		return
	}
	tracker.current = updated
	tracker.lastPhase = phase
	tracker.lastCompleted = progress.Completed
	tracker.lastPersisted = now
}

func (tracker *releaseInstallProgressTracker) snapshot() (registry.ReleaseInstallOperation, error) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.current, tracker.persistenceErr
}

func (h *Host) finishFailedReleaseInstall(ctx context.Context, running registry.ReleaseInstallOperation, installErr error) {
	durableCtx := context.WithoutCancel(ctx)
	if record, err := h.getPluginRecord(durableCtx, running.PluginInstanceID); err == nil && releaseInstallRecordMatches(running, record) {
		_, _ = h.updateReleaseInstallOperation(durableCtx, running, execution.StatusCompleted, "complete",
			registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
			mutation.OutcomeCommitted, nil, &record)
		return
	}
	_, _ = h.failReleaseInstallOperation(durableCtx, running, releaseInstallFailureCode(installErr), releaseInstallFailureRetryable(installErr), mutation.ForError(installErr))
}

func (h *Host) updateReleaseInstallOperation(ctx context.Context, current registry.ReleaseInstallOperation, status string, phase string, progress registry.ReleaseInstallProgress, outcome mutation.Outcome, failure *registry.ReleaseInstallFailure, record *registry.PluginRecord) (registry.ReleaseInstallOperation, error) {
	now := time.Now().UTC()
	if now.Before(current.Execution.UpdatedAt) {
		now = current.Execution.UpdatedAt
	}
	return h.updateReleaseInstallRecord(ctx, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: current.Execution.ID, ExpectedCursor: current.Execution.Cursor, Status: status, Phase: phase,
		Progress: progress, Attempt: current.Attempt, MutationOutcome: outcome, Failure: failure, PluginRecord: record, Now: now,
	})
}

func (h *Host) updateReleaseInstallRecord(ctx context.Context, req registry.UpdateReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	return h.controlStore.Executions().UpdateReleaseInstall(ctx, session.OwnerEnvHash, req)
}

func releaseInstallOwner(session sessionctx.Context) controlstore.ExecutionOwner {
	return controlstore.ExecutionOwner{
		OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
		OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
	}
}

func (h *Host) failReleaseInstallOperation(ctx context.Context, current registry.ReleaseInstallOperation, code string, retryable bool, outcome mutation.Outcome) (registry.ReleaseInstallOperation, error) {
	return h.failReleaseInstallOperationAtPhase(ctx, current, current.Phase, code, retryable, outcome)
}

func (h *Host) failReleaseInstallOperationAtPhase(ctx context.Context, current registry.ReleaseInstallOperation, phase string, code string, retryable bool, outcome mutation.Outcome) (registry.ReleaseInstallOperation, error) {
	return h.updateReleaseInstallOperation(ctx, current, execution.StatusFailed, phase,
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, outcome,
		&registry.ReleaseInstallFailure{Code: code, Retryable: retryable}, nil)
}

func releaseInstallIdentity(ref PluginReleaseRef) registry.ReleaseInstallIdentity {
	return registry.ReleaseInstallIdentity{
		SourceID: ref.SourceID, Channel: ref.Channel, ReleaseMetadataRef: ref.ReleaseMetadataRef,
		ReleaseMetadataSHA256: ref.ReleaseMetadataSHA256, PublisherID: ref.PublisherID, PluginID: ref.PluginID, Version: ref.Version,
		PackageSHA256: ref.ExpectedHashes.PackageSHA256, ManifestSHA256: ref.ExpectedHashes.ManifestSHA256, EntriesSHA256: ref.ExpectedHashes.EntriesSHA256,
	}
}

func releaseInstallRecordMatches(op registry.ReleaseInstallOperation, record registry.PluginRecord) bool {
	binding := record.ReleaseTrustBinding
	identity := op.Release
	return binding != nil && record.PluginInstanceID == op.PluginInstanceID &&
		binding.SourceID == identity.SourceID && binding.Channel == identity.Channel &&
		binding.ReleaseMetadataRef == identity.ReleaseMetadataRef && binding.ReleaseMetadataSHA256 == identity.ReleaseMetadataSHA256 &&
		binding.PublisherID == identity.PublisherID && binding.PluginID == identity.PluginID && binding.Version == identity.Version &&
		record.PackageHash == identity.PackageSHA256 && record.ManifestHash == identity.ManifestSHA256 && record.EntriesHash == identity.EntriesSHA256
}

func releaseInstallFailureCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return string(security.ErrReleaseTimeout)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return releaseInstallFailureInterrupted
	}
	switch externalsource.CodeOf(err) {
	case externalsource.ErrorDNS, externalsource.ErrorTransport:
		return string(security.ErrReleaseNetwork)
	case externalsource.ErrorHTTPStatus:
		if externalsource.HTTPStatusOf(err) == 404 {
			return string(security.ErrReleaseAssetMissing)
		}
		return string(security.ErrReleaseNetwork)
	case externalsource.ErrorStageIntegrity:
		return string(security.ErrReleaseAssetIntegrity)
	}
	if errors.Is(err, registry.ErrReleaseInstallOperationConflict) || errors.Is(err, ErrPluginAlreadyInstalled) {
		return releaseInstallFailureConflict
	}
	if errors.Is(err, plugindata.ErrShapeMismatch) {
		return string(security.ErrRetainedDataIncompatible)
	}
	if errors.Is(err, ErrReleaseRefVerificationFailed) {
		return string(security.ErrReleaseRefVerificationFailed)
	}
	if errors.Is(err, ErrReleaseRefPolicyDenied) {
		return string(security.ErrReleaseRefPolicyDenied)
	}
	if errors.Is(err, ErrReleasePackageInspectionExpired) {
		return string(security.ErrReleaseInspectionExpired)
	}
	if errors.Is(err, ErrReleasePackageInspectionStale) {
		return string(security.ErrReleaseInspectionStale)
	}
	if errors.Is(err, ErrPluginRuntimeNotConfigured) {
		return string(security.ErrRuntimeUnavailable)
	}
	if errors.Is(err, ErrPluginRuntimeIncompatible) {
		return string(security.ErrRuntimeVersionMismatch)
	}
	var missingFeatures FeatureNotConfiguredError
	if errors.As(err, &missingFeatures) {
		if slices.Contains(missingFeatures.MissingFeatures(), FeatureRuntime) {
			return string(security.ErrRuntimeUnavailable)
		}
		return string(security.ErrFeatureNotConfigured)
	}
	if errors.Is(err, ErrPackageTrustVerificationInvalid) {
		return string(security.ErrTrustVerificationInvalid)
	}
	if errors.Is(err, ErrPackageTrustVerifierRequired) {
		return string(security.ErrTrustVerificationRequired)
	}
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		switch packageValidationErr.Code {
		case pluginpkg.ValidationCodeManifestInvalid:
			return string(security.ErrManifestInvalid)
		case pluginpkg.ValidationCodePackageInvalid:
			return string(security.ErrPackageInvalid)
		case pluginpkg.ValidationCodePackageTooLarge:
			return string(security.ErrPackageTooLarge)
		case pluginpkg.ValidationCodePackagePathForbidden:
			return string(security.ErrPackagePathForbidden)
		}
	}
	return releaseInstallFailureInternal
}

func releaseInstallFailureRetryable(err error) bool {
	var provider ReleaseArtifactFailureProvider
	if errors.As(err, &provider) {
		return provider.ReleaseArtifactFailure().Retryable
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		externalsource.CodeOf(err) == externalsource.ErrorDNS || externalsource.CodeOf(err) == externalsource.ErrorTransport
}
