package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// BackgroundPolicyRequest identifies the installed, declared method. Policy
// grants no capabilities: the Host independently checks current package trust,
// permission grants, revisions, quotas and revocation before dispatch.
type BackgroundPolicyRequest struct {
	Plugin             PluginRef
	OwnerEnvHash       string
	Method             string
	Effect             manifest.MethodEffect
	ManagementRevision uint64
	PolicyRevision     uint64
	RevokeEpoch        uint64
}

type BackgroundPolicyAdapter interface {
	EvaluateBackgroundPolicy(context.Context, BackgroundPolicyRequest) (PolicyDecision, error)
}

type backgroundIntervalScheduler struct {
	host    *Host
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

type intervalExecutionKey struct{}

func (s *backgroundIntervalScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := s.tick(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
			s.reportFailure(ctx, "background_interval_maintenance", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func intervalKey(owner, instance string) string { return owner + "\x00" + instance }

func (s *backgroundIntervalScheduler) cancel(owner, instance string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel := s.running[intervalKey(owner, instance)]; cancel != nil {
		cancel()
	}
}

func (s *backgroundIntervalScheduler) tick(ctx context.Context, now time.Time) error {
	if err := s.host.controlStore.ReconcileIntervals(ctx, now); err != nil {
		return err
	}
	plans, err := s.host.controlStore.IntervalPlans(ctx)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if plan.NextRun.After(now) || plan.ClaimID != "" {
			continue
		}
		key := intervalKey(plan.OwnerEnvHash, plan.PluginInstanceID)
		s.mu.Lock()
		if s.running[key] != nil {
			s.mu.Unlock()
			continue
		}
		claim, ok, err := s.host.controlStore.ClaimInterval(ctx, plan, now)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if !ok {
			s.mu.Unlock()
			continue
		}
		runCtx, cancel := context.WithTimeout(ctx, time.Duration(claim.MaxRuntimeMS)*time.Millisecond)
		s.running[key] = cancel
		started := s.host.startLifecycleJob(func(context.Context) {
			defer func() { cancel(); s.mu.Lock(); delete(s.running, key); s.mu.Unlock() }()
			outcome, runErr := s.host.runBackgroundInterval(runCtx, claim)
			if runErr != nil {
				record := registry.PluginRecord{PluginInstanceID: claim.PluginInstanceID, OwnerEnvHash: claim.OwnerEnvHash, ActiveFingerprint: claim.ActiveFingerprint}
				diagnosticCtx := sessionctx.WithContext(context.WithoutCancel(runCtx), backgroundSessionContext(backgroundOwner(record)))
				s.host.reportLifecycleDiagnostic(diagnosticCtx, record, "plugin.background.failed", "background interval execution failed", runErr, observability.DiagnosticDetails{Operation: "background_interval_execution"})
			}
			// Completion persists even after cancellation. CAS cannot overwrite a
			// replacement plan; an unavailable store leaves the claim unknown on restart.
			finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(runCtx), 5*time.Second)
			defer finishCancel()
			if _, err := s.host.controlStore.FinishInterval(finishCtx, claim, time.Now().UTC(), outcome); err != nil {
				s.reportFailure(finishCtx, "background_interval_completion", err)
			}
		})
		s.mu.Unlock()
		if !started {
			cancel()
			s.mu.Lock()
			delete(s.running, key)
			s.mu.Unlock()
			return ErrHostClosed
		}
	}
	return nil
}

func intervalRecordMatches(plan controlstore.IntervalPlan, record registry.PluginRecord) bool {
	return record.OwnerEnvHash == plan.OwnerEnvHash && record.PluginInstanceID == plan.PluginInstanceID && record.ActiveFingerprint == plan.ActiveFingerprint && record.ManagementRevision == plan.ManagementRevision && record.PolicyRevision == plan.PolicyRevision && record.RevokeEpoch == plan.RevokeEpoch && record.EnableState == registry.EnableEnabled && record.DeletedAt == nil && record.Manifest.Background != nil && record.Manifest.Background.Strategy == manifest.BackgroundInterval
}

func (h *Host) authorizeBackgroundInterval(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec) error {
	if h.backgroundPolicy == nil {
		return security.ErrPolicyDenied
	}
	decision, err := h.backgroundPolicy.EvaluateBackgroundPolicy(ctx, BackgroundPolicyRequest{Plugin: pluginRefFromRecord(record), OwnerEnvHash: record.OwnerEnvHash, Method: method.Method, Effect: method.Effect, ManagementRevision: record.ManagementRevision, PolicyRevision: record.PolicyRevision, RevokeEpoch: record.RevokeEpoch})
	if err != nil {
		return err
	}
	if decision != PolicyAllow {
		return security.ErrPolicyDenied
	}
	return h.authorizeDeclaredMethod(ctx, record, method, time.Now().UTC())
}

func (h *Host) runBackgroundInterval(ctx context.Context, plan controlstore.IntervalPlan) (outcome string, runErr error) {
	outcome = "unknown"
	if ctx.Err() != nil {
		return "canceled", ctx.Err()
	}
	defer func() {
		if recover() != nil {
			outcome = "unknown"
			runErr = ErrMethodAdapterPanic
		}
	}()
	session := backgroundSessionContext(backgroundOwner(registry.PluginRecord{PluginInstanceID: plan.PluginInstanceID, OwnerEnvHash: plan.OwnerEnvHash}))
	ctx = sessionctx.WithContext(ctx, session)
	ctx = context.WithValue(ctx, intervalExecutionKey{}, plan)
	if err := h.controlStore.ValidateIntervalClaim(ctx, plan); err != nil {
		return "blocked", err
	}
	record, err := h.getPluginRecord(ctx, plan.PluginInstanceID)
	if err != nil || !intervalRecordMatches(plan, record) {
		return "blocked", security.ErrPolicyDenied
	}
	if _, err := h.checkRunnable(ctx, record); err != nil {
		return "blocked", err
	}
	entry := record.Manifest.Background
	method, ok := backgroundWorkerMethod(record.Manifest, entry.WorkerID)
	if !ok || method.Execution != manifest.MethodExecutionSync || methodRequiresConfirmation(method) || method.PreflightOnly {
		return "blocked", security.ErrPolicyDenied
	}
	if err := h.authorizeBackgroundInterval(ctx, record, method); err != nil {
		return "blocked", err
	}
	params, err := deepCloneParams(entry.Params)
	if err != nil {
		return "failed", err
	}
	if err := h.validateMethodRequest(method, params); err != nil {
		return "failed", err
	}
	if _, err := h.bindPreparedWorkerRuntime(ctx, record); err != nil {
		return "failed", err
	}
	if ctx.Err() != nil {
		return "canceled", ctx.Err()
	}
	_, err = h.dispatchMethod(ctx, record, method, CallMethodRequest{PluginInstanceID: record.PluginInstanceID, Method: method.Method, Params: params, session: session, Now: time.Now().UTC()})
	if err == nil && ctx.Err() == nil {
		return "success", nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || mutation.ForError(err) == mutation.OutcomeUnknown || errors.Is(err, ErrMethodAdapterPanic) {
		return "unknown", errors.Join(err, ctx.Err())
	}
	return "failed", err
}

func (s *backgroundIntervalScheduler) reportFailure(ctx context.Context, operation string, err error) {
	s.host.diagnostic(ctx, observability.DiagnosticEvent{Type: "plugin.background.failed", Severity: observability.DiagnosticSeverityWarning, Message: "background interval maintenance failed", Details: observability.DiagnosticDetails{Operation: operation}, Failure: observability.FailureFromError(observability.FailureAction, observability.FailureComponentLifecycle, observability.FailureOperationLifecycle, err)})
}
