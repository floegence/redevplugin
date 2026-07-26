package host

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
// scope or found no adapter record and no platform fence.
type SessionScopeFinalizationStatus string

const (
	SessionScopeFinalized          SessionScopeFinalizationStatus = "finalized"
	SessionScopeFinalizationAbsent SessionScopeFinalizationStatus = "absent"
)

// CloseAuthenticatedSessionScopeRequest starts the first teardown for terminal
// adapter evidence that has no prepared identity or platform fence.
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

// CloseAuthenticatedSessionScope starts teardown only after the host adapter
// has durably proved that the exact authenticated channel is terminal. It is a
// Go maintenance API and never consults browser authorization state.
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
	adapter, err := h.sessionMaintenanceAdapter()
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	record, err := adapter.ValidateTerminalSessionScopeClose(ctx, ValidateTerminalSessionScopeCloseRequest{Session: req.Session})
	if errors.Is(err, ErrSessionMaintenanceAbsent) {
		return SessionScopeTeardownMaintenanceResult{Status: SessionScopeTeardownAbsent}, nil
	}
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, ErrAdapterFailure
	}
	if !record.Valid() || record.Session != req.Session || record.Phase != "" || !record.TerminalEvidence {
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}
	if _, err := h.sessionScopes.InspectRetained(ctx, scope); err == nil {
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	} else if !errors.Is(err, sessionscope.ErrScopeNotFound) {
		return SessionScopeTeardownMaintenanceResult{}, err
	}

	teardown, revokeErr := h.revokeAuthenticatedSessionScope(ctx, req.Session, RevokeSessionScopeRequest{Now: req.Now})
	prepared, inspectErr := adapter.InspectSessionScopeMaintenance(ctx, InspectSessionScopeMaintenanceRequest{Session: req.Session})
	if inspectErr != nil || !prepared.Valid() || prepared.Session != req.Session || !prepared.Identity.Valid() ||
		(prepared.Phase != SessionScopeLifecyclePrepared && prepared.Phase != SessionScopeLifecycleClosed) {
		if revokeErr != nil {
			return SessionScopeTeardownMaintenanceResult{}, errors.Join(revokeErr, ErrAdapterFailure)
		}
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}
	result := teardownMaintenanceResult(prepared.Identity, teardown)
	return result, revokeErr
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
	adapter, err := h.sessionMaintenanceAdapter()
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	record, recordPresent, err := inspectSessionScopeMaintenanceRecord(ctx, adapter, req.Session)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	fence, fencePresent, err := h.inspectSessionScopeFence(ctx, scope)
	if err != nil {
		return SessionScopeTeardownMaintenanceResult{}, err
	}
	if !recordPresent && !fencePresent {
		return SessionScopeTeardownMaintenanceResult{Status: SessionScopeTeardownAbsent}, nil
	}
	if !recordPresent || !record.Identity.Matches(req.Identity) || record.Session != req.Session {
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}
	if fencePresent && !fence.MatchesIdentity(req.Identity) {
		return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
	}

	if !fencePresent {
		switch record.Phase {
		case SessionScopeLifecyclePrepared:
			if err := validateExactTerminalRecord(ctx, adapter, record); err != nil {
				return SessionScopeTeardownMaintenanceResult{}, err
			}
			return h.continueSessionScopeTeardown(ctx, req)
		case SessionScopeLifecycleFinalizing:
			if err := validateExactTerminalRecord(ctx, adapter, record); err != nil {
				return SessionScopeTeardownMaintenanceResult{}, err
			}
			return SessionScopeTeardownMaintenanceResult{
				Status: SessionScopeTeardownComplete, Identity: req.Identity,
				Teardown: RevokeSessionScopeResult{State: sessionscope.StateComplete, Fenced: false, Complete: true},
			}, nil
		default:
			return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
		}
	}

	switch fence.Snapshot.State {
	case sessionscope.StateDraining, sessionscope.StateIncomplete:
		if record.Phase != SessionScopeLifecyclePrepared && record.Phase != SessionScopeLifecycleClosed {
			return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
		}
		return h.continueSessionScopeTeardown(ctx, req)
	case sessionscope.StateComplete:
		if record.Phase != SessionScopeLifecycleClosed && record.Phase != SessionScopeLifecycleFinalizing {
			return SessionScopeTeardownMaintenanceResult{}, ErrSessionMaintenanceState
		}
		if err := validateExactTerminalRecord(ctx, adapter, record); err != nil {
			return SessionScopeTeardownMaintenanceResult{}, err
		}
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

// FinalizeClosedSessionScope validates terminal evidence, persists finalizing,
// deletes the complete platform fence as the commit point, and then performs
// idempotent adapter cleanup.
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
	adapter, err := h.sessionMaintenanceAdapter()
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	record, recordPresent, err := inspectSessionScopeMaintenanceRecord(ctx, adapter, req.Session)
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	fence, fencePresent, err := h.inspectSessionScopeFence(ctx, scope)
	if err != nil {
		return SessionScopeFinalizationResult{}, err
	}
	if !recordPresent && !fencePresent {
		return SessionScopeFinalizationResult{Status: SessionScopeFinalizationAbsent}, nil
	}
	if !recordPresent || !record.Identity.Matches(req.Identity) || record.Session != req.Session ||
		(fencePresent && !fence.MatchesIdentity(req.Identity)) {
		return SessionScopeFinalizationResult{}, ErrSessionMaintenanceState
	}
	platformFinalized := !fencePresent && record.Phase == SessionScopeLifecycleFinalizing
	if err := validateExactTerminalRecord(ctx, adapter, record); err != nil {
		if platformFinalized {
			return SessionScopeFinalizationResult{}, mutation.ForceCommitted(err)
		}
		return SessionScopeFinalizationResult{}, err
	}
	if fencePresent {
		if fence.Snapshot.State != sessionscope.StateComplete ||
			(record.Phase != SessionScopeLifecycleClosed && record.Phase != SessionScopeLifecycleFinalizing) {
			return SessionScopeFinalizationResult{}, ErrSessionMaintenanceState
		}
	} else if record.Phase != SessionScopeLifecycleFinalizing {
		return SessionScopeFinalizationResult{}, ErrSessionMaintenanceState
	}

	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.session_scope.finalized"})
	if err != nil {
		if platformFinalized {
			return SessionScopeFinalizationResult{}, mutation.ForceCommitted(err)
		}
		return SessionScopeFinalizationResult{}, err
	}
	auditResult := RevokeSessionScopeResult{State: sessionscope.StateComplete, Complete: true}
	if fencePresent {
		auditResult = revokeSessionScopeResult(fence.Snapshot)
	}
	defer func() {
		if platformFinalized {
			retErr = mutation.ForceCommitted(retErr)
		}
		completedErr := auditMutation.completeWithDetails(
			context.WithoutCancel(ctx), retErr, sessionRevokeAuditDetails(auditResult),
		)
		if platformFinalized {
			retErr = mutation.ForceCommitted(completedErr)
		} else {
			retErr = completedErr
		}
	}()

	if record.Phase == SessionScopeLifecycleClosed {
		if err := adapter.PrepareSessionScopeFinalization(ctx, PrepareSessionScopeFinalizationRequest{
			Session: req.Session, Identity: req.Identity,
		}); err != nil {
			return SessionScopeFinalizationResult{}, ErrAdapterFailure
		}
		record.Phase = SessionScopeLifecycleFinalizing
	}
	if fencePresent {
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
	}
	if err := adapter.CommitSessionScopeFinalization(ctx, CommitSessionScopeFinalizationRequest{
		Session: req.Session, Identity: req.Identity,
	}); err != nil {
		return SessionScopeFinalizationResult{}, ErrAdapterFailure
	}
	result.Status = SessionScopeFinalized
	return result, nil
}

func (h *Host) sessionMaintenanceAdapter() (SessionLifecycleMaintenanceAdapter, error) {
	if h == nil || isNilInterfaceValue(h.adapters.SessionMaintenance) {
		return nil, ErrSessionMaintenanceUnavailable
	}
	return h.adapters.SessionMaintenance, nil
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

func inspectSessionScopeMaintenanceRecord(
	ctx context.Context,
	adapter SessionLifecycleMaintenanceAdapter,
	session sessionctx.Context,
) (SessionScopeMaintenanceRecord, bool, error) {
	record, err := adapter.InspectSessionScopeMaintenance(ctx, InspectSessionScopeMaintenanceRequest{Session: session})
	if errors.Is(err, ErrSessionMaintenanceAbsent) {
		return SessionScopeMaintenanceRecord{}, false, nil
	}
	if err != nil {
		return SessionScopeMaintenanceRecord{}, false, ErrAdapterFailure
	}
	if !record.Valid() || record.Session != session {
		return SessionScopeMaintenanceRecord{}, false, ErrSessionMaintenanceState
	}
	return record, true, nil
}

func validateExactTerminalRecord(
	ctx context.Context,
	adapter SessionLifecycleMaintenanceAdapter,
	expected SessionScopeMaintenanceRecord,
) error {
	if !expected.TerminalEvidence {
		return ErrSessionMaintenanceState
	}
	actual, err := adapter.ValidateTerminalSessionScopeClose(ctx, ValidateTerminalSessionScopeCloseRequest{
		Session: expected.Session, Identity: expected.Identity,
	})
	if err != nil {
		if errors.Is(err, ErrSessionMaintenanceAbsent) {
			return ErrSessionMaintenanceState
		}
		return ErrAdapterFailure
	}
	if !actual.Valid() || !actual.TerminalEvidence || actual.Session != expected.Session || actual.Phase != expected.Phase ||
		!actual.Identity.Matches(expected.Identity) {
		return ErrSessionMaintenanceState
	}
	return nil
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

func sessionScopeMaintenanceRecordKey(record SessionScopeMaintenanceRecord) (sessionctx.SessionScope, error) {
	if !record.Valid() {
		return sessionctx.SessionScope{}, ErrSessionMaintenanceState
	}
	scope, err := record.Session.SessionScope()
	if err != nil {
		return sessionctx.SessionScope{}, fmt.Errorf("%w: %v", ErrSessionMaintenanceState, err)
	}
	return scope, nil
}

func (h *Host) reconcileSessionScopeMaintenance(ctx context.Context) error {
	adapter, err := h.sessionMaintenanceAdapter()
	if errors.Is(err, ErrSessionMaintenanceUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	records, err := adapter.ListSessionScopeMaintenanceRecords(ctx)
	if err != nil {
		return ErrAdapterFailure
	}
	recordByScope := make(map[sessionctx.SessionScope]SessionScopeMaintenanceRecord, len(records))
	scopes := make([]sessionctx.SessionScope, 0, len(records))
	for _, record := range records {
		scope, keyErr := sessionScopeMaintenanceRecordKey(record)
		if keyErr != nil {
			return keyErr
		}
		if _, duplicate := recordByScope[scope]; duplicate {
			return ErrSessionMaintenanceState
		}
		recordByScope[scope] = record
		scopes = append(scopes, scope)
	}
	retained, err := h.sessionScopes.ListRetained(ctx)
	if err != nil {
		return err
	}
	for _, fence := range retained {
		record, ok := recordByScope[fence.SessionScope]
		if !ok || !record.Identity.Valid() || !fence.MatchesIdentity(record.Identity) {
			return ErrSessionMaintenanceState
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return sessionScopeLess(scopes[i], scopes[j]) })
	for _, scope := range scopes {
		if err := h.reconcileOneSessionScopeMaintenance(ctx, recordByScope[scope].Session); err != nil {
			return err
		}
	}
	remainingRecords, err := adapter.ListSessionScopeMaintenanceRecords(ctx)
	if err != nil {
		return ErrAdapterFailure
	}
	remainingFences, err := h.sessionScopes.ListRetained(ctx)
	if err != nil {
		return err
	}
	if len(remainingRecords) != 0 || len(remainingFences) != 0 {
		return ErrSessionMaintenanceState
	}
	return nil
}

func (h *Host) reconcileOneSessionScopeMaintenance(ctx context.Context, session sessionctx.Context) error {
	for attempt := 0; attempt < 4; attempt++ {
		adapter, err := h.sessionMaintenanceAdapter()
		if err != nil {
			return err
		}
		record, present, err := inspectSessionScopeMaintenanceRecord(ctx, adapter, session)
		if err != nil {
			return err
		}
		scope, err := session.SessionScope()
		if err != nil {
			return err
		}
		fence, fenced, err := h.inspectSessionScopeFence(ctx, scope)
		if err != nil {
			return err
		}
		if !present && !fenced {
			return nil
		}
		if !present || (fenced && (!record.Identity.Valid() || !fence.MatchesIdentity(record.Identity))) {
			return ErrSessionMaintenanceState
		}
		if !fenced && record.Phase == "" && record.TerminalEvidence {
			result, closeErr := h.CloseAuthenticatedSessionScope(ctx, CloseAuthenticatedSessionScopeRequest{Session: session})
			if closeErr != nil {
				return closeErr
			}
			if result.Status == SessionScopeTeardownAbsent {
				return ErrSessionMaintenanceState
			}
			continue
		}
		if (!fenced && (record.Phase == SessionScopeLifecyclePrepared || record.Phase == SessionScopeLifecycleFinalizing)) ||
			(fenced && (fence.Snapshot.State == sessionscope.StateDraining || fence.Snapshot.State == sessionscope.StateIncomplete || fence.Snapshot.State == sessionscope.StateComplete)) {
			resume, resumeErr := h.ResumeClosedSessionScopeTeardown(ctx, ResumeClosedSessionScopeTeardownRequest{
				Session: session, Identity: record.Identity,
			})
			if resumeErr != nil {
				return resumeErr
			}
			if resume.Status == SessionScopeTeardownAbsent {
				return ErrSessionMaintenanceState
			}
			if resume.Status == SessionScopeTeardownComplete {
				finalized, finalizeErr := h.FinalizeClosedSessionScope(ctx, FinalizeClosedSessionScopeRequest{
					Session: session, Identity: record.Identity,
				})
				if finalizeErr != nil {
					return finalizeErr
				}
				if finalized.Status == SessionScopeFinalizationAbsent {
					return ErrSessionMaintenanceState
				}
			}
			continue
		}
		return ErrSessionMaintenanceState
	}
	return ErrSessionMaintenanceState
}

func sessionScopeLess(left, right sessionctx.SessionScope) bool {
	if left.OwnerSessionHash != right.OwnerSessionHash {
		return left.OwnerSessionHash < right.OwnerSessionHash
	}
	if left.OwnerUserHash != right.OwnerUserHash {
		return left.OwnerUserHash < right.OwnerUserHash
	}
	if left.OwnerEnvHash != right.OwnerEnvHash {
		return left.OwnerEnvHash < right.OwnerEnvHash
	}
	return left.SessionChannelIDHash < right.SessionChannelIDHash
}
