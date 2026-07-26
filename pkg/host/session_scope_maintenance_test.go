package host

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

type maintenanceSessionLifecycleAdapter struct {
	mu                     sync.Mutex
	records                map[sessionctx.SessionScope]SessionScopeMaintenanceRecord
	listedRecords          []SessionScopeMaintenanceRecord
	allowMissingRetained   bool
	prepareCloseStarted    chan<- struct{}
	prepareCloseContinue   <-chan struct{}
	commitCloseErr         error
	validateTerminalErr    error
	prepareFinalizationErr error
	commitFinalizationErr  error
	prepareCalls           int
	commitCloseCalls       int
	prepareFinalizeCalls   int
	commitFinalizeCalls    int
}

func newMaintenanceSessionLifecycleAdapter() *maintenanceSessionLifecycleAdapter {
	return &maintenanceSessionLifecycleAdapter{records: make(map[sessionctx.SessionScope]SessionScopeMaintenanceRecord)}
}

func (adapter *maintenanceSessionLifecycleAdapter) addTerminalIntent(t *testing.T, session sessionctx.Context) {
	t.Helper()
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.records[scope] = SessionScopeMaintenanceRecord{Session: session, TerminalEvidence: true}
}

func (adapter *maintenanceSessionLifecycleAdapter) markTerminal(t *testing.T, session sessionctx.Context) {
	t.Helper()
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	record := adapter.records[scope]
	record.TerminalEvidence = true
	adapter.records[scope] = record
}

func (adapter *maintenanceSessionLifecycleAdapter) putRecord(t *testing.T, record SessionScopeMaintenanceRecord) {
	t.Helper()
	scope, err := record.Session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.records[scope] = record
}

func (adapter *maintenanceSessionLifecycleAdapter) ReconcileRetainedSessionScopes(_ context.Context, req ReconcileRetainedSessionScopesRequest) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	for _, retained := range req.Scopes {
		record, ok := adapter.records[retained.SessionScope]
		if !ok && adapter.allowMissingRetained {
			continue
		}
		if !ok || !record.Identity.Valid() || !retained.MatchesIdentity(record.Identity) {
			return errors.New("retained session identity is unavailable")
		}
	}
	return nil
}

func (adapter *maintenanceSessionLifecycleAdapter) PrepareSessionScopeClose(_ context.Context, req PrepareSessionScopeCloseRequest) (sessionscope.TeardownIdentity, error) {
	scope, err := req.Session.SessionScope()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	if adapter.prepareCloseStarted != nil {
		adapter.prepareCloseStarted <- struct{}{}
	}
	if adapter.prepareCloseContinue != nil {
		<-adapter.prepareCloseContinue
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.prepareCalls++
	record, ok := adapter.records[scope]
	if ok && record.Identity.Valid() {
		return record.Identity, nil
	}
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	identity, err := sessionscope.NewTeardownIdentity("maintenance_close", proof)
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	if !ok {
		record.Session = req.Session
	}
	record.Identity = identity
	record.Phase = SessionScopeLifecyclePrepared
	adapter.records[scope] = record
	return identity, nil
}

func (adapter *maintenanceSessionLifecycleAdapter) CommitSessionScopeClose(_ context.Context, req CommitSessionScopeCloseRequest) error {
	scope, err := req.Session.SessionScope()
	if err != nil {
		return err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.commitCloseCalls++
	record, ok := adapter.records[scope]
	if !ok || !record.Identity.Matches(req.Identity) ||
		(record.Phase != SessionScopeLifecyclePrepared && record.Phase != SessionScopeLifecycleClosed) {
		return errors.New("prepared session identity does not match")
	}
	if adapter.commitCloseErr != nil {
		return adapter.commitCloseErr
	}
	record.Phase = SessionScopeLifecycleClosed
	adapter.records[scope] = record
	return nil
}

func (adapter *maintenanceSessionLifecycleAdapter) ValidateClosedSessionScope(_ context.Context, req ValidateClosedSessionScopeRequest) error {
	record, err := adapter.inspect(req.Session)
	if err != nil || !record.Identity.Matches(req.Identity) ||
		(record.Phase != SessionScopeLifecycleClosed && record.Phase != SessionScopeLifecycleFinalizing) {
		return errors.New("closed session identity does not match")
	}
	return nil
}

func (adapter *maintenanceSessionLifecycleAdapter) ListSessionScopeMaintenanceRecords(context.Context) ([]SessionScopeMaintenanceRecord, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.listedRecords != nil {
		return append([]SessionScopeMaintenanceRecord(nil), adapter.listedRecords...), nil
	}
	records := make([]SessionScopeMaintenanceRecord, 0, len(adapter.records))
	for _, record := range adapter.records {
		records = append(records, record)
	}
	return records, nil
}

func (adapter *maintenanceSessionLifecycleAdapter) InspectSessionScopeMaintenance(_ context.Context, req InspectSessionScopeMaintenanceRequest) (SessionScopeMaintenanceRecord, error) {
	return adapter.inspect(req.Session)
}

func (adapter *maintenanceSessionLifecycleAdapter) ValidateTerminalSessionScopeClose(_ context.Context, req ValidateTerminalSessionScopeCloseRequest) (SessionScopeMaintenanceRecord, error) {
	if adapter.validateTerminalErr != nil {
		return SessionScopeMaintenanceRecord{}, adapter.validateTerminalErr
	}
	record, err := adapter.inspect(req.Session)
	if err != nil {
		return SessionScopeMaintenanceRecord{}, err
	}
	if !record.TerminalEvidence || (req.Identity.Valid() && !record.Identity.Matches(req.Identity)) {
		return SessionScopeMaintenanceRecord{}, errors.New("terminal session evidence does not match")
	}
	return record, nil
}

func (adapter *maintenanceSessionLifecycleAdapter) PrepareSessionScopeFinalization(_ context.Context, req PrepareSessionScopeFinalizationRequest) error {
	scope, err := req.Session.SessionScope()
	if err != nil {
		return err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.prepareFinalizeCalls++
	if adapter.prepareFinalizationErr != nil {
		return adapter.prepareFinalizationErr
	}
	record, ok := adapter.records[scope]
	if !ok || !record.TerminalEvidence || !record.Identity.Matches(req.Identity) ||
		(record.Phase != SessionScopeLifecycleClosed && record.Phase != SessionScopeLifecycleFinalizing) {
		return errors.New("closed session cannot enter finalization")
	}
	record.Phase = SessionScopeLifecycleFinalizing
	adapter.records[scope] = record
	return nil
}

func (adapter *maintenanceSessionLifecycleAdapter) CommitSessionScopeFinalization(_ context.Context, req CommitSessionScopeFinalizationRequest) error {
	scope, err := req.Session.SessionScope()
	if err != nil {
		return err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.commitFinalizeCalls++
	record, ok := adapter.records[scope]
	if !ok || !record.TerminalEvidence || record.Phase != SessionScopeLifecycleFinalizing || !record.Identity.Matches(req.Identity) {
		return errors.New("finalizing session identity does not match")
	}
	if adapter.commitFinalizationErr != nil {
		return adapter.commitFinalizationErr
	}
	delete(adapter.records, scope)
	return nil
}

func (adapter *maintenanceSessionLifecycleAdapter) inspect(session sessionctx.Context) (SessionScopeMaintenanceRecord, error) {
	scope, err := session.SessionScope()
	if err != nil {
		return SessionScopeMaintenanceRecord{}, err
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	record, ok := adapter.records[scope]
	if !ok {
		return SessionScopeMaintenanceRecord{}, ErrSessionMaintenanceAbsent
	}
	return record, nil
}

func TestCloseAuthenticatedSessionScopeFinalizesFreshTerminalIntentWithoutRequestAuthorization(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("fresh")
	adapter.addTerminalIntent(t, session)

	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{
		Session: session, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CloseAuthenticatedSessionScope() error = %v", err)
	}
	if closed.Status != SessionScopeTeardownComplete || !closed.Identity.Valid() || !closed.Teardown.Complete {
		t.Fatalf("CloseAuthenticatedSessionScope() = %#v", closed)
	}
	finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	})
	if err != nil || finalized.Status != SessionScopeFinalized {
		t.Fatalf("FinalizeClosedSessionScope() = %#v, %v", finalized, err)
	}

	replayed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil || replayed.Status != SessionScopeTeardownAbsent {
		t.Fatalf("CloseAuthenticatedSessionScope(stale) = %#v, %v", replayed, err)
	}
	scope, _ := session.SessionScope()
	if _, err := h.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("stale close recreated fence: %v", err)
	}
	if adapter.prepareCalls != 1 {
		t.Fatalf("PrepareSessionScopeClose calls = %d, want 1", adapter.prepareCalls)
	}
}

func TestResumeClosedSessionScopeTeardownDoesNotRequireAuthenticatedContext(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("resume")
	adapter.commitCloseErr = errors.New("injected close persistence failure")
	ctx := sessionctx.WithContext(context.Background(), session)
	incomplete, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) || incomplete.Complete {
		t.Fatalf("RevokeSessionScope() = %#v, %v", incomplete, err)
	}
	adapter.markTerminal(t, session)
	adapter.commitCloseErr = nil
	record, err := adapter.inspect(session)
	if err != nil {
		t.Fatal(err)
	}

	resumed, err := h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{
		Session: session, Identity: record.Identity, Now: time.Now().UTC(),
	})
	if err != nil || resumed.Status != SessionScopeTeardownComplete || !resumed.Teardown.Complete {
		t.Fatalf("ResumeClosedSessionScopeTeardown() = %#v, %v", resumed, err)
	}
}

func TestFinalizeClosedSessionScopeRecoversPostFenceAdapterFailure(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("post_commit")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	journal := observability.NewMemorySecurityAuditJournal()
	h.securityJournal = journal
	h.securityExporter = nil
	adapter.commitFinalizationErr = errors.New("injected post-commit cleanup failure")
	_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: closed.Identity})
	if !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("FinalizeClosedSessionScope() error = %v, want ErrAdapterFailure", err)
	}
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("FinalizeClosedSessionScope() outcome = %q, %v", outcome, explicit)
	}
	audits, auditErr := journal.ListUnexportedSecurityAudits(context.Background())
	if auditErr != nil || len(audits) != 1 || audits[0].Outcome != mutation.OutcomeCommitted {
		t.Fatalf("finalization audit = %#v, %v, want one committed record", audits, auditErr)
	}
	scope, _ := session.SessionScope()
	if _, err := h.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("platform fence remains after commit point: %v", err)
	}
	record, err := adapter.inspect(session)
	if err != nil || record.Phase != SessionScopeLifecycleFinalizing {
		t.Fatalf("adapter recovery record = %#v, %v", record, err)
	}

	adapter.commitFinalizationErr = nil
	finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: closed.Identity})
	if err != nil || finalized.Status != SessionScopeFinalized {
		t.Fatalf("FinalizeClosedSessionScope(retry) = %#v, %v", finalized, err)
	}
}

func TestFinalizeClosedSessionScopePrepareFailurePreservesFence(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("prepare_failure")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	adapter.prepareFinalizationErr = errors.New("injected finalization prepare failure")

	_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	})
	if !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("FinalizeClosedSessionScope() error = %v, want ErrAdapterFailure", err)
	}
	if _, explicit := mutation.Explicit(err); explicit {
		t.Fatalf("pre-commit failure reported a mutation outcome: %v", err)
	}
	scope, _ := session.SessionScope()
	retained, err := h.sessionScopes.InspectRetained(context.Background(), scope)
	if err != nil || retained.Snapshot.State != sessionscope.StateComplete || !retained.MatchesIdentity(closed.Identity) {
		t.Fatalf("complete fence was not preserved = %#v, %v", retained, err)
	}
	record, err := adapter.inspect(session)
	if err != nil || record.Phase != SessionScopeLifecycleClosed {
		t.Fatalf("adapter phase changed after prepare failure = %#v, %v", record, err)
	}
}

func TestFinalizeClosedSessionScopeAuditCompletionFailureIsCommitted(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("audit_completion")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	h.securityJournal = &hostFailingSecurityJournal{completeErr: errors.New("injected audit completion failure")}

	_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	})
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("FinalizeClosedSessionScope() outcome = %q, %v, error = %v", outcome, explicit, err)
	}
	scope, _ := session.SessionScope()
	if _, err := h.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("platform fence remains after committed audit failure: %v", err)
	}
	if _, err := adapter.inspect(session); !errors.Is(err, ErrSessionMaintenanceAbsent) {
		t.Fatalf("adapter record remains after committed audit failure: %v", err)
	}
}

func TestFinalizeClosedSessionScopePostCommitAuditBeginFailureIsCommitted(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("audit_begin_post_commit")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	adapter.commitFinalizationErr = errors.New("injected post-commit cleanup failure")
	if _, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	}); !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("FinalizeClosedSessionScope(first) error = %v, want ErrAdapterFailure", err)
	}
	scope, _ := session.SessionScope()
	if _, err := h.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("platform fence remains after commit point: %v", err)
	}

	h.securityJournal = &hostFailingSecurityJournal{beginErr: errors.New("injected audit begin failure")}
	_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	})
	if !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("FinalizeClosedSessionScope(recovery) error = %v, want ErrSecurityEventPersistence", err)
	}
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("FinalizeClosedSessionScope(recovery) outcome = %q, %v, error = %v", outcome, explicit, err)
	}
	record, inspectErr := adapter.inspect(session)
	if inspectErr != nil || record.Phase != SessionScopeLifecycleFinalizing {
		t.Fatalf("adapter recovery record = %#v, %v", record, inspectErr)
	}
}

func TestFinalizeClosedSessionScopePostCommitTerminalValidationFailureIsCommitted(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("terminal_validation_post_commit")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	adapter.commitFinalizationErr = errors.New("injected post-commit cleanup failure")
	if _, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	}); !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("FinalizeClosedSessionScope(first) error = %v, want ErrAdapterFailure", err)
	}
	adapter.validateTerminalErr = errors.New("injected terminal validation failure")

	_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: closed.Identity,
	})
	if !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("FinalizeClosedSessionScope(recovery) error = %v, want ErrAdapterFailure", err)
	}
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("FinalizeClosedSessionScope(recovery) outcome = %q, %v, error = %v", outcome, explicit, err)
	}
}

func TestFinalizeClosedSessionScopeSerializesConcurrentRetries(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("concurrent_finalize")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 32
	results := make(chan SessionScopeFinalizationStatus, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
				Session: session, Identity: closed.Identity,
			})
			results <- result.Status
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent FinalizeClosedSessionScope() error = %v", err)
		}
	}
	finalized := 0
	absent := 0
	for status := range results {
		switch status {
		case SessionScopeFinalized:
			finalized++
		case SessionScopeFinalizationAbsent:
			absent++
		default:
			t.Fatalf("unexpected concurrent finalization status %q", status)
		}
	}
	if finalized != 1 || absent != callers-1 {
		t.Fatalf("concurrent finalization statuses: finalized=%d absent=%d", finalized, absent)
	}
	adapter.mu.Lock()
	commitCalls := adapter.commitFinalizeCalls
	adapter.mu.Unlock()
	if commitCalls != 1 {
		t.Fatalf("CommitSessionScopeFinalization calls = %d, want 1", commitCalls)
	}
}

func TestLegacyRevokeAndMaintenanceFinalizationShareExactScopeLock(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("legacy_revoke_finalize")
	adapter.addTerminalIntent(t, session)
	closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}

	prepareStarted := make(chan struct{}, 1)
	continuePrepare := make(chan struct{})
	adapter.prepareCloseStarted = prepareStarted
	adapter.prepareCloseContinue = continuePrepare
	revokeDone := make(chan error, 1)
	go func() {
		ctx := sessionctx.WithContext(context.Background(), session)
		_, revokeErr := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Identity: closed.Identity})
		revokeDone <- revokeErr
	}()
	<-prepareStarted

	finalizeDone := make(chan error, 1)
	go func() {
		_, finalizeErr := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
			Session: session, Identity: closed.Identity,
		})
		finalizeDone <- finalizeErr
	}()
	scope, _ := session.SessionScope()
	deadline := time.Now().Add(time.Second)
	for {
		h.sessionMaintenance.mu.Lock()
		lock := h.sessionMaintenance.locks[scope]
		var refs uint64
		if lock != nil {
			refs = lock.refs
		}
		h.sessionMaintenance.mu.Unlock()
		if refs == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("finalization did not wait on the exact-scope lock; refs=%d", refs)
		}
		time.Sleep(time.Millisecond)
	}
	close(continuePrepare)
	if err := <-revokeDone; err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if err := <-finalizeDone; err != nil {
		t.Fatalf("FinalizeClosedSessionScope() error = %v", err)
	}
	if _, err := h.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("platform fence remains after serialized finalization: %v", err)
	}
	if _, err := adapter.inspect(session); !errors.Is(err, ErrSessionMaintenanceAbsent) {
		t.Fatalf("adapter record remains after serialized finalization: %v", err)
	}
}

func TestSessionScopeMaintenanceMatrixRejectsImpossibleCombinations(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		phase     SessionScopeLifecyclePhase
		terminal  bool
		withFence bool
		complete  bool
		finalize  bool
	}{
		{name: "closed without fence", id: "closed_no_fence", phase: SessionScopeLifecycleClosed, terminal: true},
		{name: "complete with prepared", id: "complete_prepared", phase: SessionScopeLifecyclePrepared, terminal: true, withFence: true, complete: true},
		{name: "draining with finalizing", id: "draining_finalizing", phase: SessionScopeLifecycleFinalizing, terminal: true, withFence: true},
		{name: "complete closed without terminal", id: "complete_no_terminal", phase: SessionScopeLifecycleClosed, withFence: true, complete: true, finalize: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _ := newTestHost(t, true, true)
			adapter := newMaintenanceSessionLifecycleAdapter()
			h.adapters.SessionLifecycle = adapter
			h.adapters.SessionMaintenance = adapter
			session := maintenanceTestSession(tt.id)
			identity := maintenanceTestIdentity(t, tt.id)
			adapter.putRecord(t, SessionScopeMaintenanceRecord{
				Session: session, Identity: identity, Phase: tt.phase, TerminalEvidence: tt.terminal,
			})
			scope, _ := session.SessionScope()
			if tt.withFence {
				teardown, _, err := h.sessionScopes.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if tt.complete {
					if _, err := teardown.MarkComplete(context.Background(), time.Now().UTC()); err != nil {
						t.Fatal(err)
					}
				}
				teardown.Release()
			}
			var err error
			if tt.finalize {
				_, err = h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{Session: session, Identity: identity})
			} else {
				_, err = h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{Session: session, Identity: identity})
			}
			if !errors.Is(err, ErrSessionMaintenanceState) {
				t.Fatalf("maintenance error = %v, want ErrSessionMaintenanceState", err)
			}
		})
	}
}

func TestOpenRecoversPendingTerminalSessionScopeToAbsent(t *testing.T) {
	config := modularTestConfig(t)
	adapter := newMaintenanceSessionLifecycleAdapter()
	session := maintenanceTestSession("startup")
	adapter.addTerminalIntent(t, session)
	config.Core.SessionLifecycle = adapter
	config.Core.SessionMaintenance = adapter

	h, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if records, err := adapter.ListSessionScopeMaintenanceRecords(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("remaining adapter records = %#v, %v", records, err)
	}
	if retained, err := h.sessionScopes.ListRetained(context.Background()); err != nil || len(retained) != 0 {
		t.Fatalf("remaining platform fences = %#v, %v", retained, err)
	}
}

func TestOpenRecoversSessionScopeFinalizationCrashStages(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		phase     SessionScopeLifecyclePhase
		withFence bool
	}{
		{name: "complete closed", id: "complete_closed", phase: SessionScopeLifecycleClosed, withFence: true},
		{name: "complete finalizing", id: "complete_finalizing", phase: SessionScopeLifecycleFinalizing, withFence: true},
		{name: "post commit finalizing", id: "post_commit_finalizing", phase: SessionScopeLifecycleFinalizing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := modularTestConfig(t)
			adapter := newMaintenanceSessionLifecycleAdapter()
			session := maintenanceTestSession("startup_" + tt.id)
			identity := maintenanceTestIdentity(t, "startup_"+tt.id)
			adapter.putRecord(t, SessionScopeMaintenanceRecord{
				Session: session, Identity: identity, Phase: tt.phase, TerminalEvidence: true,
			})
			config.Core.SessionLifecycle = adapter
			config.Core.SessionMaintenance = adapter
			if tt.withFence {
				scope, err := session.SessionScope()
				if err != nil {
					t.Fatal(err)
				}
				teardown, _, err := config.Core.SessionScopes.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := teardown.MarkComplete(context.Background(), time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
				teardown.Release()
			}

			h, err := Open(context.Background(), config)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() { _ = h.Close() })
			if records, err := adapter.ListSessionScopeMaintenanceRecords(context.Background()); err != nil || len(records) != 0 {
				t.Fatalf("remaining adapter records = %#v, %v", records, err)
			}
			if retained, err := h.sessionScopes.ListRetained(context.Background()); err != nil || len(retained) != 0 {
				t.Fatalf("remaining platform fences = %#v, %v", retained, err)
			}
		})
	}
}

func TestSessionScopeFinalizationReusesCapacityBeyondDefaultLimit(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter

	for index := 0; index <= sessionscope.DefaultMaxScopes; index++ {
		session := maintenanceTestSession(fmt.Sprintf("capacity_%d", index))
		adapter.addTerminalIntent(t, session)
		closed, err := h.CloseAuthenticatedSessionScope(context.Background(), CloseAuthenticatedSessionScopeRequest{Session: session})
		if err != nil {
			t.Fatalf("CloseAuthenticatedSessionScope(%d) error = %v", index, err)
		}
		finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
			Session: session, Identity: closed.Identity,
		})
		if err != nil || finalized.Status != SessionScopeFinalized {
			t.Fatalf("FinalizeClosedSessionScope(%d) = %#v, %v", index, finalized, err)
		}
	}
	if retained, err := h.sessionScopes.ListRetained(context.Background()); err != nil || len(retained) != 0 {
		t.Fatalf("remaining platform fences = %#v, %v", retained, err)
	}
	if records, err := adapter.ListSessionScopeMaintenanceRecords(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("remaining adapter records = %#v, %v", records, err)
	}
	h.sessionMaintenance.mu.Lock()
	remainingLocks := len(h.sessionMaintenance.locks)
	h.sessionMaintenance.mu.Unlock()
	if remainingLocks != 0 {
		t.Fatalf("remaining session maintenance locks = %d", remainingLocks)
	}
}

func TestSessionScopeMaintenanceAbsentIsNotHistoricalSuccess(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := newMaintenanceSessionLifecycleAdapter()
	h.adapters.SessionLifecycle = adapter
	h.adapters.SessionMaintenance = adapter
	session := maintenanceTestSession("absent")
	identity := maintenanceTestIdentity(t, "absent")

	resumed, err := h.ResumeClosedSessionScopeTeardown(context.Background(), ResumeClosedSessionScopeTeardownRequest{
		Session: session, Identity: identity,
	})
	if err != nil || resumed.Status != SessionScopeTeardownAbsent {
		t.Fatalf("ResumeClosedSessionScopeTeardown() = %#v, %v", resumed, err)
	}
	finalized, err := h.FinalizeClosedSessionScope(context.Background(), FinalizeClosedSessionScopeRequest{
		Session: session, Identity: identity,
	})
	if err != nil || finalized.Status != SessionScopeFinalizationAbsent {
		t.Fatalf("FinalizeClosedSessionScope() = %#v, %v", finalized, err)
	}
}

func TestOpenRejectsMaintenanceFenceWithoutAdapterRecord(t *testing.T) {
	config := modularTestConfig(t)
	adapter := newMaintenanceSessionLifecycleAdapter()
	adapter.allowMissingRetained = true
	config.Core.SessionLifecycle = adapter
	config.Core.SessionMaintenance = adapter
	session := maintenanceTestSession("missing_record")
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity := maintenanceTestIdentity(t, "missing_record")
	teardown, _, err := config.Core.SessionScopes.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.MarkComplete(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	teardown.Release()

	if _, err := Open(context.Background(), config); !errors.Is(err, ErrSessionMaintenanceState) {
		t.Fatalf("Open() error = %v, want ErrSessionMaintenanceState", err)
	}
	retained, err := config.Core.SessionScopes.InspectRetained(context.Background(), scope)
	if err != nil || !retained.MatchesIdentity(identity) {
		t.Fatalf("retained fence was modified = %#v, %v", retained, err)
	}
}

func TestOpenRejectsDuplicateMaintenanceScopeRecords(t *testing.T) {
	config := modularTestConfig(t)
	adapter := newMaintenanceSessionLifecycleAdapter()
	session := maintenanceTestSession("duplicate")
	record := SessionScopeMaintenanceRecord{Session: session, TerminalEvidence: true}
	adapter.listedRecords = []SessionScopeMaintenanceRecord{record, record}
	config.Core.SessionLifecycle = adapter
	config.Core.SessionMaintenance = adapter

	if _, err := Open(context.Background(), config); !errors.Is(err, ErrSessionMaintenanceState) {
		t.Fatalf("Open() error = %v, want ErrSessionMaintenanceState", err)
	}
}

func TestOpenRejectsTypedNilSessionMaintenanceAdapter(t *testing.T) {
	config := modularTestConfig(t)
	var adapter *maintenanceSessionLifecycleAdapter
	config.Core.SessionMaintenance = adapter

	_, err := Open(context.Background(), config)
	var configErr *HostConfigError
	if !errors.As(err, &configErr) || configErr.Adapter != "session lifecycle maintenance adapter" {
		t.Fatalf("Open() error = %#v, want session maintenance HostConfigError", err)
	}
}

func maintenanceTestSession(suffix string) sessionctx.Context {
	return sessionctx.Context{
		OwnerSessionHash:     "maintenance_session_" + suffix,
		OwnerUserHash:        "maintenance_user_" + suffix,
		OwnerEnvHash:         "maintenance_env_" + suffix,
		SessionChannelIDHash: "maintenance_channel_" + suffix,
	}
}

func maintenanceTestIdentity(t *testing.T, suffix string) sessionscope.TeardownIdentity {
	t.Helper()
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessionscope.NewTeardownIdentity("maintenance_"+suffix, proof)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

var _ SessionLifecycleAdapter = (*maintenanceSessionLifecycleAdapter)(nil)
var _ SessionLifecycleMaintenanceAdapter = (*maintenanceSessionLifecycleAdapter)(nil)
