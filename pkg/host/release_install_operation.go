package host

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const releaseInstallOperationTimeout = 5 * time.Minute

const (
	releaseInstallFailureInterrupted = string(security.ErrInstallInterrupted)
	releaseInstallFailureConflict    = string(security.ErrInstallStateConflict)
	releaseInstallFailureInternal    = string(security.ErrInternalFailure)
)

type StartReleaseInstallOperationRequest struct {
	RequestID        string           `json:"request_id"`
	PluginInstanceID string           `json:"plugin_instance_id"`
	ReleaseRef       PluginReleaseRef `json:"release_ref"`
	Now              time.Time        `json:"-"`
}

func (h *Host) StartReleaseInstallOperation(ctx context.Context, req StartReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionStartReleaseInstall,
		scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if err := validateReleaseRef(req.ReleaseRef); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	operationID, err := newExternalPackageID("release_install")
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	operation, created, err := h.adapters.Registry.StartReleaseInstallOperation(ctx, registry.StartReleaseInstallOperationRequest{
		RequestID: req.RequestID, OperationID: operationID, PluginInstanceID: req.PluginInstanceID,
		Release: releaseInstallIdentity(req.ReleaseRef), Now: req.Now,
	})
	if err != nil || !created {
		return operation, err
	}
	if !h.startLifecycleJob(func(lifecycleCtx context.Context) {
		jobCtx := sessionctx.WithContext(lifecycleCtx, session)
		jobCtx, cancel := context.WithTimeout(jobCtx, releaseInstallOperationTimeout)
		defer cancel()
		h.runReleaseInstallOperation(jobCtx, operation, req.ReleaseRef)
	}) {
		return h.failReleaseInstallOperation(context.WithoutCancel(ctx), operation, releaseInstallFailureInterrupted, true, mutation.OutcomeNotCommitted)
	}
	return operation, nil
}

func (h *Host) GetReleaseInstallOperation(ctx context.Context, operationID string) (registry.ReleaseInstallOperation, error) {
	op, err := h.adapters.Registry.GetReleaseInstallOperation(ctx, strings.TrimSpace(operationID))
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if _, err := h.authorizeManagement(ctx, ManagementActionGetReleaseInstall,
		scopedAuthorizationTarget(ResourcePlugin, op.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	return h.reconcileReleaseInstallOperation(ctx, op)
}

func (h *Host) GetReleaseInstallOperationByRequest(ctx context.Context, requestID string) (registry.ReleaseInstallOperation, error) {
	op, err := h.adapters.Registry.GetReleaseInstallOperationByRequest(ctx, strings.TrimSpace(requestID))
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if _, err := h.authorizeManagement(ctx, ManagementActionGetReleaseInstall,
		scopedAuthorizationTarget(ResourcePlugin, op.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	return h.reconcileReleaseInstallOperation(ctx, op)
}

func (h *Host) ListReleaseInstallOperations(ctx context.Context) ([]registry.ReleaseInstallOperation, error) {
	if _, err := h.authorizeManagement(ctx, ManagementActionListReleaseInstalls,
		scopedAuthorizationCollectionTarget(ResourcePlugin, sessionctx.ScopeEnvironment)); err != nil {
		return nil, err
	}
	operations, err := h.adapters.Registry.ListReleaseInstallOperations(ctx)
	if err != nil {
		return nil, err
	}
	for index := range operations {
		operations[index], err = h.reconcileReleaseInstallOperation(ctx, operations[index])
		if err != nil {
			return nil, err
		}
	}
	return operations, nil
}

func (h *Host) runReleaseInstallOperation(ctx context.Context, operation registry.ReleaseInstallOperation, ref PluginReleaseRef) {
	running, err := h.updateReleaseInstallOperation(ctx, operation, registry.ReleaseInstallRunning, "verify_release",
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, mutation.OutcomeNotCommitted, nil, nil)
	if err != nil {
		return
	}
	tracker := &releaseInstallProgressTracker{host: h, ctx: ctx, current: running}
	pkg, release, sourcePolicy, verifiedRelease, metadata, err := h.resolveReleasePackage(
		ctx, PackageTrustActionInstall, ref, nil, operation.PluginInstanceID, time.Now().UTC(), tracker.observe,
	)
	running, progressErr := tracker.snapshot()
	if progressErr != nil {
		h.finishFailedReleaseInstall(ctx, running, progressErr)
		return
	}
	if err != nil {
		h.finishFailedReleaseInstall(ctx, running, err)
		return
	}
	running, err = h.updateReleaseInstallOperation(ctx, running, registry.ReleaseInstallRunning, "commit",
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, mutation.OutcomeNotCommitted, nil, nil)
	if err != nil {
		return
	}
	unlock, err := h.lifecycleLocks.acquireWrite(ctx, operation.PluginInstanceID)
	if err == nil {
		defer unlock()
		refCopy := ref
		var record registry.PluginRecord
		record, err = h.installResolvedPackage(ctx, pkg, operation.PluginInstanceID, packageTrustInput{
			ReleaseRef: &refCopy, Release: &release, SourcePolicy: &sourcePolicy, VerifiedRelease: &verifiedRelease,
		}, time.Now().UTC(), metadata)
		if err == nil {
			_, _ = h.updateReleaseInstallOperation(context.WithoutCancel(ctx), running, registry.ReleaseInstallSucceeded, "complete",
				registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
				mutation.OutcomeCommitted, nil, &record)
			return
		}
	}
	h.finishFailedReleaseInstall(ctx, running, err)
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
	if progress.ArtifactRole != "" {
		phase += "_" + progress.ArtifactRole
	}
	phaseChanged := phase != tracker.lastPhase
	byteThreshold := progress.Completed-tracker.lastCompleted >= 256<<10 || progress.Completed == progress.Total
	timeThreshold := tracker.lastPersisted.IsZero() || now.Sub(tracker.lastPersisted) >= 250*time.Millisecond
	if !phaseChanged && !byteThreshold && !timeThreshold {
		return
	}
	kind := registry.ReleaseInstallProgressIndeterminate
	if progress.Phase == "download" && progress.Total > 0 {
		kind = registry.ReleaseInstallProgressBytes
	}
	retryAfterMS := progress.RetryAfter.Milliseconds()
	updated, err := tracker.host.adapters.Registry.UpdateReleaseInstallOperation(tracker.ctx, registry.UpdateReleaseInstallOperationRequest{
		OperationID: tracker.current.OperationID, ExpectedRevision: tracker.current.Revision,
		Status: registry.ReleaseInstallRunning, Phase: phase,
		Progress: registry.ReleaseInstallProgress{Kind: kind, Completed: progress.Completed, Total: progress.Total},
		Attempt:  max(progress.Attempt, 1), RetryAfterMS: retryAfterMS,
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
	if record, err := h.adapters.Registry.GetPlugin(durableCtx, running.PluginInstanceID); err == nil && releaseInstallRecordMatches(running, record) {
		_, _ = h.updateReleaseInstallOperation(durableCtx, running, registry.ReleaseInstallSucceeded, "complete",
			registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
			mutation.OutcomeCommitted, nil, &record)
		return
	}
	_, _ = h.failReleaseInstallOperation(durableCtx, running, releaseInstallFailureCode(installErr), releaseInstallFailureRetryable(installErr), mutation.ForError(installErr))
}

func (h *Host) reconcileReleaseInstallOperation(ctx context.Context, op registry.ReleaseInstallOperation) (registry.ReleaseInstallOperation, error) {
	if op.Status != registry.ReleaseInstallReconciling {
		return op, nil
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, op.PluginInstanceID)
	if err == nil {
		if releaseInstallRecordMatches(op, record) {
			return h.updateReleaseInstallOperation(ctx, op, registry.ReleaseInstallSucceeded, "complete",
				registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
				mutation.OutcomeCommitted, nil, &record)
		}
		return h.failReleaseInstallOperation(ctx, op, releaseInstallFailureConflict, false, mutation.OutcomeUnknown)
	}
	if !errors.Is(err, registry.ErrNotFound) {
		return registry.ReleaseInstallOperation{}, err
	}
	stages, err := h.adapters.InstallStages.List(ctx, installstage.ListRequest{PluginInstanceID: op.PluginInstanceID})
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	for _, stage := range stages {
		if stage.Status == installstage.StatusCommitted {
			return h.failReleaseInstallOperation(ctx, op, releaseInstallFailureConflict, false, mutation.OutcomeUnknown)
		}
	}
	return h.failReleaseInstallOperation(ctx, op, releaseInstallFailureInterrupted, true, mutation.OutcomeNotCommitted)
}

func (h *Host) updateReleaseInstallOperation(ctx context.Context, current registry.ReleaseInstallOperation, status registry.ReleaseInstallOperationStatus, phase string, progress registry.ReleaseInstallProgress, outcome mutation.Outcome, failure *registry.ReleaseInstallFailure, record *registry.PluginRecord) (registry.ReleaseInstallOperation, error) {
	now := time.Now().UTC()
	if now.Before(current.UpdatedAt) {
		now = current.UpdatedAt
	}
	return h.adapters.Registry.UpdateReleaseInstallOperation(ctx, registry.UpdateReleaseInstallOperationRequest{
		OperationID: current.OperationID, ExpectedRevision: current.Revision, Status: status, Phase: phase,
		Progress: progress, Attempt: current.Attempt, MutationOutcome: outcome, Failure: failure, PluginRecord: record, Now: now,
	})
}

func (h *Host) failReleaseInstallOperation(ctx context.Context, current registry.ReleaseInstallOperation, code string, retryable bool, outcome mutation.Outcome) (registry.ReleaseInstallOperation, error) {
	return h.updateReleaseInstallOperation(ctx, current, registry.ReleaseInstallFailed, "failed",
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
	if errors.Is(err, ErrReleaseRefVerificationFailed) {
		return string(security.ErrReleaseRefVerificationFailed)
	}
	if errors.Is(err, ErrReleaseRefPolicyDenied) {
		return string(security.ErrReleaseRefPolicyDenied)
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
