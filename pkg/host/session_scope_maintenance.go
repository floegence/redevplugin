package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

// SessionScopeTeardownMaintenanceStatus reports whether teardown is pending,
// complete, or has no remaining durable evidence.
type SessionScopeTeardownMaintenanceStatus string

const (
	SessionScopeTeardownIncomplete SessionScopeTeardownMaintenanceStatus = "incomplete"
	SessionScopeTeardownComplete   SessionScopeTeardownMaintenanceStatus = "complete"
	SessionScopeTeardownAbsent     SessionScopeTeardownMaintenanceStatus = "absent"
)

// SessionScopeFinalizationStatus reports whether this call finalized an exact
// scope or found no Host-owned platform fence.
type SessionScopeFinalizationStatus string

const (
	SessionScopeFinalized          SessionScopeFinalizationStatus = "finalized"
	SessionScopeFinalizationAbsent SessionScopeFinalizationStatus = "absent"
)

// CloseAuthenticatedSessionScopeRequest starts Host-owned teardown for one
// exact authenticated session.
type CloseAuthenticatedSessionScopeRequest struct {
	Session sessionctx.Context `json:"-"`
	Now     time.Time          `json:"-"`
}

// ResumeClosedSessionScopeTeardownRequest continues an existing exact teardown
// without requiring an active browser authorization context.
type ResumeClosedSessionScopeTeardownRequest struct {
	Session  sessionctx.Context            `json:"-"`
	Identity sessionscope.TeardownIdentity `json:"-"`
	Now      time.Time                     `json:"-"`
}

// FinalizeClosedSessionScopeRequest finalizes a complete exact teardown after
// the adapter independently validates durable terminal evidence.
type FinalizeClosedSessionScopeRequest struct {
	Session  sessionctx.Context            `json:"-"`
	Identity sessionscope.TeardownIdentity `json:"-"`
}

// SessionScopeTeardownMaintenanceResult contains the opaque identity required
// for host-side continuation. Identity is never part of a JSON projection.
type SessionScopeTeardownMaintenanceResult struct {
	Status   SessionScopeTeardownMaintenanceStatus `json:"status"`
	Identity sessionscope.TeardownIdentity         `json:"-"`
	Teardown RevokeSessionScopeResult              `json:"teardown"`
}

// SessionScopeFinalizationResult distinguishes a newly finalized scope from a
// scope for which both durable evidence stores were already absent.
type SessionScopeFinalizationResult struct {
	Status SessionScopeFinalizationStatus `json:"status"`
}

type sessionScopeMaintenanceLockRegistry struct {
	mu    sync.Mutex
	locks map[sessionctx.SessionScope]*sessionScopeMaintenanceLock
}

type sessionScopeMaintenanceLock struct {
	gate chan struct{}
	refs uint64
}

func newSessionScopeMaintenanceLockRegistry() *sessionScopeMaintenanceLockRegistry {
	return &sessionScopeMaintenanceLockRegistry{locks: make(map[sessionctx.SessionScope]*sessionScopeMaintenanceLock)}
}

func (registry *sessionScopeMaintenanceLockRegistry) acquire(ctx context.Context, scope sessionctx.SessionScope) (func(), error) {
	if registry == nil {
		return nil, ErrSessionMaintenanceState
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	registry.mu.Lock()
	lock := registry.locks[scope]
	if lock == nil {
		lock = &sessionScopeMaintenanceLock{gate: make(chan struct{}, 1)}
		lock.gate <- struct{}{}
		registry.locks[scope] = lock
	}
	lock.refs++
	registry.mu.Unlock()
	select {
	case <-ctx.Done():
		registry.releaseReference(scope, lock)
		return nil, ctx.Err()
	case <-lock.gate:
	}
	return func() {
		lock.gate <- struct{}{}
		registry.releaseReference(scope, lock)
	}, nil
}

func (registry *sessionScopeMaintenanceLockRegistry) releaseReference(scope sessionctx.SessionScope, lock *sessionScopeMaintenanceLock) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if lock.refs > 0 {
		lock.refs--
	}
	if lock.refs == 0 && registry.locks[scope] == lock {
		delete(registry.locks, scope)
	}
}

// CloseAuthenticatedSessionScope starts Host-owned teardown for one exact
// authenticated session scope. It is a Go maintenance API and never consults
// browser authorization state.
func (h *Host) CloseAuthenticatedSessionScope(
	ctx context.Context,
	req CloseAuthenticatedSessionScopeRequest,
) (SessionScopeTeardownMaintenanceResult, error) {
	scope, err := req.Session.SessionScope()
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	release, err := h.sessionMaintenance.acquire(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	defer release()
	identity, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	teardown, revokeErr := h.revokeAuthenticatedSessionScope(ctx, req.Session, RevokeSessionScopeRequest{Identity: identity, Now: req.Now})
	return teardownMaintenanceResult(identity, teardown), revokeErr
}

// ResumeClosedSessionScopeTeardown continues an exact prepared, draining, or
// incomplete teardown without consulting browser authorization state.
func (h *Host) ResumeClosedSessionScopeTeardown(
	ctx context.Context,
	req ResumeClosedSessionScopeTeardownRequest,
) (SessionScopeTeardownMaintenanceResult, error) {
	if !req.Identity.Valid() {
		return SessionScopeTeardownMaintenanceResult{}, sessionscope.ErrTeardownIdentityInvalid
	}
	scope, err := req.Session.SessionScope()
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	release, err := h.sessionMaintenance.acquire(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	defer release()
	return h.resumeClosedSessionScopeTeardownLocked(ctx, req, scope)
}

func (h *Host) resumeClosedSessionScopeTeardownLocked(
	ctx context.Context,
	req ResumeClosedSessionScopeTeardownRequest,
	scope sessionctx.SessionScope,
) (SessionScopeTeardownMaintenanceResult, error) {
	expected, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	if !expected.Matches(req.Identity) {
		return SessionScopeTeardownMaintenanceResult{}, sessionscope.ErrTeardownIdentityMismatch
	}
	fence, fencePresent, err := h.inspectSessionScopeFence(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	if !fencePresent {
		return SessionScopeTeardownMaintenanceResult{Status: SessionScopeTeardownAbsent}, nil
	}
	if !fence.MatchesIdentity(req.Identity) {
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}

	switch fence.Snapshot.State {
	case sessionscope.StateDraining, sessionscope.StateIncomplete:
		return h.continueSessionScopeTeardown(ctx, req)
	case sessionscope.StateComplete:
		return SessionScopeTeardownMaintenanceResult{
			Status: SessionScopeTeardownComplete, Identity: req.Identity, Teardown: revokeSessionScopeResult(fence.Snapshot),
		}, nil
	default:
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}
}

func (h *Host) continueSessionScopeTeardown(
	ctx context.Context,
	req ResumeClosedSessionScopeTeardownRequest,
) (SessionScopeTeardownMaintenanceResult, error) {
	teardown, err := h.revokeAuthenticatedSessionScope(ctx, req.Session, RevokeSessionScopeRequest{Identity: req.Identity, Now: req.Now})
	return teardownMaintenanceResult(req.Identity, teardown), err
}

// FinalizeClosedSessionScope validates the Host-owned identity and deletes the
// complete platform fence as the finalization commit point.
func (h *Host) FinalizeClosedSessionScope(
	ctx context.Context,
	req FinalizeClosedSessionScopeRequest,
) (SessionScopeFinalizationResult, error) {
	if !req.Identity.Valid() {
		return SessionScopeFinalizationResult{}, sessionscope.ErrTeardownIdentityInvalid
	}
	scope, err := req.Session.SessionScope()
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	release, err := h.sessionMaintenance.acquire(ctx, scope)
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	defer release()
	return h.finalizeClosedSessionScopeLocked(ctx, req, scope)
}

func (h *Host) finalizeClosedSessionScopeLocked(
	ctx context.Context,
	req FinalizeClosedSessionScopeRequest,
	scope sessionctx.SessionScope,
) (result SessionScopeFinalizationResult, retErr error) {
	expected, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	if !expected.Matches(req.Identity) {
		return SessionScopeFinalizationResult{}, sessionscope.ErrTeardownIdentityMismatch
	}
	fence, fencePresent, err := h.inspectSessionScopeFence(ctx, scope)
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	if !fencePresent {
		return SessionScopeFinalizationResult{Status: SessionScopeFinalizationAbsent}, nil
	}
	if !fence.MatchesIdentity(req.Identity) {
		return SessionScopeFinalizationResult{}, ErrSessionMaintenanceState
	}
	if fence.Snapshot.State != sessionscope.StateComplete {
		return SessionScopeFinalizationResult{}, ErrSessionMaintenanceState
	}

	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.session_scope.finalized"})
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	auditResult := revokeSessionScopeResult(fence.Snapshot)
	platformFinalized := false
	defer func() {
		completedErr := auditMutation.completeWithDetails(
			context.WithoutCancel(ctx), retErr, sessionRevokeAuditDetails(auditResult),
		)
		if platformFinalized {
			retErr = mutation.ForceCommitted(completedErr)
		} else {
			retErr = completedErr
		}
	}()

	if err := h.cleanupExternalPackageInspectionArtifactsForScope(scope); err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	if err := h.adapters.ConfirmationIntents.FinalizeSessionConfirmationRevocation(ctx, security.FinalizeSessionConfirmationRevocationRequest{
		SessionScope: scope, TeardownOperationID: req.Identity.OperationID,
	}); err != nil {
		return SessionScopeFinalizationResult{}, ErrAdapterFailure
	}
	if err := h.sessionScopes.Finalize(ctx, scope, req.Identity); err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	platformFinalized = true
	result.Status = SessionScopeFinalized
	return result, nil
}

func (h *Host) inspectSessionScopeFence(
	ctx context.Context,
	scope sessionctx.SessionScope,
) (sessionscope.RetainedScope, bool, error) {
	retained, err := h.sessionScopes.InspectRetained(ctx, scope)
	if errors.Is(err, sessionscope.ErrScopeNotFound) {
		return sessionscope.RetainedScope{}, false, nil
	}
	return retained, err == nil, err
}

func teardownMaintenanceResult(
	identity sessionscope.TeardownIdentity,
	teardown RevokeSessionScopeResult,
) SessionScopeTeardownMaintenanceResult {
	status := SessionScopeTeardownIncomplete
	if teardown.Complete && teardown.State == sessionscope.StateComplete {
		status = SessionScopeTeardownComplete
	}
	return SessionScopeTeardownMaintenanceResult{Status: status, Identity: identity, Teardown: teardown}
}

func (h *Host) reconcileSessionScopeMaintenance(ctx context.Context) error {
	retained, err := h.sessionScopes.ListRetained(ctx)
	if err != nil {
		return err
	}
	for _, fence := range retained {
		session := sessionctx.Context{
			OwnerSessionHash:     fence.SessionScope.OwnerSessionHash,
			OwnerUserHash:        fence.SessionScope.OwnerUserHash,
			OwnerEnvHash:         fence.SessionScope.OwnerEnvHash,
			SessionChannelIDHash: fence.SessionScope.SessionChannelIDHash,
		}
		if err := h.reconcileOneSessionScopeMaintenance(ctx, session); err != nil {
			return err
		}
	}
	remainingFences, err := h.sessionScopes.ListRetained(ctx)
	if err != nil {
		return err
	}
	if len(remainingFences) != 0 {
		return ErrSessionMaintenanceState
	}
	return nil
}

func (h *Host) reconcileOneSessionScopeMaintenance(ctx context.Context, session sessionctx.Context) error {
	scope, err := session.SessionScope()
	if err != nil {
		return err
	}
	identity, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		return err
	}
	result, err := h.ResumeClosedSessionScopeTeardown(ctx, ResumeClosedSessionScopeTeardownRequest{Session: session, Identity: identity})
	if err != nil {
		return err
	}
	if result.Status != SessionScopeTeardownComplete {
		return ErrSessionMaintenanceState
	}
	finalized, err := h.FinalizeClosedSessionScope(ctx, FinalizeClosedSessionScopeRequest{Session: session, Identity: identity})
	if err != nil {
		return err
	}
	if finalized.Status != SessionScopeFinalized {
		return ErrSessionMaintenanceState
	}
	return nil
}
