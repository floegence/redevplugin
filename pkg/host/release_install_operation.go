package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/controlstore"
	"github.com/floegence/redevplugin/pkg/execution"
	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const releaseInstallOperationTimeout = 5 * time.Minute

const (
	releaseInstallFailureInterrupted = string(security.ErrInstallInterrupted)
	releaseInstallFailureConflict    = string(security.ErrInstallStateConflict)
	releaseInstallFailureInternal    = string(security.ErrInternalFailure)
)

type StartReleaseInstallExecutionRequest struct {
	RequestID             string           `json:"request_id"`
	PluginInstanceID      string           `json:"plugin_instance_id"`
	ReleaseRef            PluginReleaseRef `json:"release_ref"`
	ActivateAfterInstall  *bool            `json:"activate_after_install,omitempty"`
	ApprovedPermissionIDs []string         `json:"approved_permission_ids,omitempty"`
	Now                   time.Time        `json:"-"`
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
	req.ApprovedPermissionIDs = normalizeStringSet(req.ApprovedPermissionIDs)
	activation := releaseInstallActivationRequest(req)
	if _, err := h.authorizeManagementSession(ctx, session, ManagementActionInstallReleaseRef,
		scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	if activation.Mode != registry.ReleaseInstallActivationDisabled {
		if _, err := h.authorizeManagementSession(ctx, session, ManagementActionEnablePlugin,
			scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
			return registry.ReleaseInstallOperation{}, err
		}
		for _, permissionID := range activation.ApprovedPermissionIDs {
			if _, err := h.authorizeManagementSession(ctx, session, ManagementActionGrantPermission,
				scopedAuthorizationTarget(ResourcePermission, permissionID, sessionctx.ScopeEnvironment),
				scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
				return registry.ReleaseInstallOperation{}, err
			}
		}
	}
	if err := validateReleaseRef(req.ReleaseRef); err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	operationID, err := newExternalPackageID("release_install")
	if err != nil {
		return registry.ReleaseInstallOperation{}, err
	}
	operation, created, err := h.controlStore.Executions().StartReleaseInstall(ctx, releaseInstallOwner(session), registry.StartReleaseInstallOperationRequest{
		RequestID: req.RequestID, ExecutionID: operationID, PluginInstanceID: req.PluginInstanceID,
		Release: releaseInstallIdentity(req.ReleaseRef), Activation: activation, Now: req.Now,
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

func releaseInstallActivationRequest(req startReleaseInstallOperationRequest) registry.ReleaseInstallActivationRequest {
	mode := registry.ReleaseInstallActivationAutomatic
	if req.ActivateAfterInstall != nil {
		if *req.ActivateAfterInstall {
			mode = registry.ReleaseInstallActivationRequested
		} else {
			mode = registry.ReleaseInstallActivationDisabled
		}
	}
	return registry.ReleaseInstallActivationRequest{Mode: mode, ApprovedPermissionIDs: append([]string(nil), req.ApprovedPermissionIDs...)}
}

func (h *Host) runReleaseInstallOperation(ctx context.Context, operation registry.ReleaseInstallOperation, ref PluginReleaseRef) {
	running, err := h.updateReleaseInstallOperation(ctx, operation, execution.StatusRunning, "fetch_trust_evidence",
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, mutation.OutcomeNotCommitted, nil, nil)
	if err != nil {
		_, _ = h.failReleaseInstallOperation(context.WithoutCancel(ctx), operation, releaseInstallFailureCode(err), false, mutation.ForError(err))
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
			running, err = h.activateInstalledRelease(ctx, running, record, sourcePolicy, time.Now().UTC())
			if err != nil {
				h.finishFailedReleaseInstall(ctx, running, err)
				return
			}
			record = *running.PluginRecord
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

func (h *Host) activateInstalledRelease(ctx context.Context, operation registry.ReleaseInstallOperation, record registry.PluginRecord, sourcePolicy releasecontract.SourcePolicyV2, now time.Time) (registry.ReleaseInstallOperation, error) {
	request := operation.ActivationRequest
	shouldActivate := request.Mode == registry.ReleaseInstallActivationRequested ||
		(request.Mode == registry.ReleaseInstallActivationAutomatic && sourcePolicy.SourceClass == "official")
	if !shouldActivate {
		operation.Activation = registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationNotRequested}
		operation.PluginRecord = &record
		return operation, nil
	}

	running, err := h.updateReleaseInstallOperation(ctx, operation, execution.StatusRunning, "enable",
		registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate}, mutation.OutcomeCommitted, nil, nil)
	if err != nil {
		return operation, err
	}
	required, err := h.releaseInstallRequiredPermissions(record)
	if err != nil {
		return running, err
	}
	approved := make(map[string]struct{}, len(request.ApprovedPermissionIDs))
	for _, permissionID := range request.ApprovedPermissionIDs {
		approved[permissionID] = struct{}{}
	}
	missing := make([]string, 0)
	for _, permissionID := range required {
		if _, ok := approved[permissionID]; !ok {
			missing = append(missing, permissionID)
			continue
		}
		revisions := registry.AuthorizationRevisionsFromRecord(record)
		if _, err := h.GrantPermission(ctx, GrantPermissionRequest{
			PluginInstanceID: record.PluginInstanceID, PermissionID: permissionID,
			ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision,
			ExpectedRevokeEpoch: revisions.RevokeEpoch, Now: now,
		}); err != nil {
			return running, err
		}
		record, err = h.getPluginRecord(ctx, record.PluginInstanceID)
		if err != nil {
			return running, err
		}
	}
	if len(missing) > 0 {
		running.Activation = registry.ReleaseInstallActivation{
			Status:               registry.ReleaseInstallActivationNeedsAttention,
			MissingPermissionIDs: missing,
			NextAction:           registry.ReleaseInstallNextActionApprovePermissions,
		}
		running.PluginRecord = &record
		return running, nil
	}

	enabled, err := h.enablePluginLocked(ctx, record, now)
	if err != nil {
		return running, err
	}
	running.Activation = registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationEnabled}
	running.PluginRecord = &enabled
	return running, nil
}

func (h *Host) releaseInstallRequiredPermissions(record registry.PluginRecord) ([]string, error) {
	permissions := make([]string, 0)
	for _, method := range record.Manifest.Methods {
		if method.Route.Kind != manifest.MethodRouteCapability {
			continue
		}
		binding, ok := manifestBinding(record.Manifest, method.Route.BindingID)
		if !ok {
			return nil, fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
		}
		verified, err := h.adapters.Capabilities.RequireContract(binding.Contract)
		if err != nil {
			return nil, err
		}
		target, ok := contractMethod(verified.Contract, method.Route.TargetMethod)
		if !ok {
			return nil, fmt.Errorf("capability target method %q is not published", method.Route.TargetMethod)
		}
		permissions = append(permissions, target.RequiredPermissions...)
	}
	return normalizeStringSet(permissions), nil
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
		Activation: tracker.current.Activation,
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
		running.Activation = reconciledReleaseInstallActivation(running, record)
		_, _ = h.updateReleaseInstallOperation(durableCtx, running, execution.StatusCompleted, "complete",
			registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
			mutation.OutcomeCommitted, nil, &record)
		return
	}
	_, _ = h.failReleaseInstallOperation(durableCtx, running, releaseInstallFailureCode(installErr), releaseInstallFailureRetryable(installErr), mutation.ForError(installErr))
}

func reconciledReleaseInstallActivation(operation registry.ReleaseInstallOperation, record registry.PluginRecord) registry.ReleaseInstallActivation {
	if record.EnableState == registry.EnableEnabled {
		return registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationEnabled}
	}
	if operation.ActivationRequest.Mode == registry.ReleaseInstallActivationDisabled ||
		operation.Activation.Status == registry.ReleaseInstallActivationNotRequested {
		return registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationNotRequested}
	}
	if operation.Activation.Status == registry.ReleaseInstallActivationNeedsAttention {
		return operation.Activation
	}
	return registry.ReleaseInstallActivation{Status: registry.ReleaseInstallActivationNeedsAttention, NextAction: registry.ReleaseInstallNextActionRetryActivation}
}

func (h *Host) updateReleaseInstallOperation(ctx context.Context, current registry.ReleaseInstallOperation, status string, phase string, progress registry.ReleaseInstallProgress, outcome mutation.Outcome, failure *registry.ReleaseInstallFailure, record *registry.PluginRecord) (registry.ReleaseInstallOperation, error) {
	now := time.Now().UTC()
	if now.Before(current.Execution.UpdatedAt) {
		now = current.Execution.UpdatedAt
	}
	return h.updateReleaseInstallRecord(ctx, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: current.Execution.ID, ExpectedCursor: current.Execution.Cursor, Status: status, Phase: phase,
		Progress: progress, Attempt: current.Attempt, MutationOutcome: outcome, Failure: failure, PluginRecord: record, Now: now,
		Activation: current.Activation,
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
	return h.updateReleaseInstallOperation(ctx, current, execution.StatusFailed, "failed",
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
