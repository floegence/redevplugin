package host

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
	"github.com/floegence/redevplugin/pkg/stream"
)

type recordingSessionLifecycleAdapter struct {
	identity       sessionscope.TeardownIdentity
	closeErrBefore error
	closeErrAfter  error
	closeCalls     int
	commitCalls    int
	validateCalls  int
	reconcileCalls int
	reconciled     []sessionscope.RetainedScope
	reconcileErr   error
}

func (a *recordingSessionLifecycleAdapter) ReconcileRetainedSessionScopes(_ context.Context, req ReconcileRetainedSessionScopesRequest) error {
	a.reconcileCalls++
	a.reconciled = append([]sessionscope.RetainedScope(nil), req.Scopes...)
	return a.reconcileErr
}

func (a *recordingSessionLifecycleAdapter) PrepareSessionScopeClose(_ context.Context, req PrepareSessionScopeCloseRequest) (sessionscope.TeardownIdentity, error) {
	a.closeCalls++
	if a.closeErrBefore != nil {
		return sessionscope.TeardownIdentity{}, a.closeErrBefore
	}
	if !a.identity.Valid() {
		proof, err := sessionscope.GenerateClosedSessionProof()
		if err != nil {
			return sessionscope.TeardownIdentity{}, err
		}
		identity, err := sessionscope.NewTeardownIdentity("teardown_host_test", proof)
		if err != nil {
			return sessionscope.TeardownIdentity{}, err
		}
		a.identity = identity
	}
	if !req.Session.Valid() {
		return sessionscope.TeardownIdentity{}, errors.New("session is required")
	}
	return a.identity, nil
}

func (a *recordingSessionLifecycleAdapter) CommitSessionScopeClose(_ context.Context, req CommitSessionScopeCloseRequest) error {
	a.commitCalls++
	if !req.Session.Valid() || !a.identity.Matches(req.Identity) {
		return errors.New("prepared close identity does not match")
	}
	if a.closeErrAfter != nil {
		return a.closeErrAfter
	}
	return nil
}

func (a *recordingSessionLifecycleAdapter) ValidateClosedSessionScope(_ context.Context, req ValidateClosedSessionScopeRequest) error {
	a.validateCalls++
	if !req.Session.Valid() || !a.identity.Matches(req.Identity) {
		return errors.New("closed session proof does not match")
	}
	return nil
}

func TestRevokeSessionScopeFencesDrainsAndResumesIdempotently(t *testing.T) {
	h, _, audits := newTestHost(t, true, true)
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter
	ctx := hostTestContext()
	session, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	liveExecution := seedHostSessionScopeResources(t, h, session, now)

	result, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Now: now})
	if err != nil {
		t.Fatalf("RevokeSessionScope() result = %#v, error = %v", result, err)
	}
	if result.State != sessionscope.StateComplete || !result.Fenced || !result.Complete {
		t.Fatalf("RevokeSessionScope() = %#v", result)
	}
	if result.Counts.Surfaces != 1 || result.Counts.AssetTickets != 1 ||
		result.Counts.Confirmations != 1 || result.Counts.Operations != 1 || result.Counts.Streams != 1 ||
		result.Counts.RuntimeExecutions != 1 {
		t.Fatalf("RevokeSessionScope() counts = %#v", result.Counts)
	}
	if err := liveExecution.validate(context.Background()); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("live execution validation error = %v", err)
	}
	if _, err := h.Features(ctx); !errors.Is(err, sessionscope.ErrSessionRevoked) {
		t.Fatalf("Features(after fence) error = %v, want ErrSessionRevoked", err)
	}

	resumed, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Identity: adapter.identity, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("RevokeSessionScope(resume) error = %v", err)
	}
	if resumed != result || adapter.closeCalls != 2 || adapter.commitCalls != 2 || adapter.validateCalls != 0 {
		t.Fatalf(
			"resume = %#v, first = %#v, prepare calls = %d, commit calls = %d, validate calls = %d",
			resumed, result, adapter.closeCalls, adapter.commitCalls, adapter.validateCalls,
		)
	}
	if err := h.FinalizeSessionScope(ctx, FinalizeSessionScopeRequest{Identity: adapter.identity}); err != nil {
		t.Fatalf("FinalizeSessionScope() error = %v", err)
	}
	if event, ok := audits.lastEvent("plugin.session_scope.finalized"); !ok || event.Details["session_scope_state"] != "complete" {
		t.Fatalf("finalize audit = %#v, found = %v", event, ok)
	}
	if err := h.FinalizeSessionScope(ctx, FinalizeSessionScopeRequest{Identity: adapter.identity}); !errors.Is(err, sessionscope.ErrClosedSessionProofInvalid) {
		t.Fatalf("FinalizeSessionScope(replay) error = %v", err)
	}
}

func TestRevokeSessionScopeFailureAfterFenceIsCommittedIncomplete(t *testing.T) {
	h, _, audits := newTestHost(t, true, true)
	adapter := &recordingSessionLifecycleAdapter{closeErrAfter: errors.New("closed session persistence failed")}
	h.adapters.SessionLifecycle = adapter
	result, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) {
		t.Fatalf("RevokeSessionScope() error = %v, want ErrSessionTeardownIncomplete", err)
	}
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("mutation outcome = %q, %v", outcome, explicit)
	}
	if result.State != sessionscope.StateIncomplete || !result.Fenced || result.Complete {
		t.Fatalf("RevokeSessionScope() result = %#v", result)
	}
	if event, ok := audits.lastEvent("plugin.session_scope.revoked"); !ok || event.Details["session_scope_state"] != "incomplete" {
		t.Fatalf("incomplete revoke audit = %#v, found = %v", event, ok)
	}

	adapter.closeErrAfter = nil
	continued := make(chan error, 1)
	go func() {
		_, resumeErr := h.RevokeSessionScope(
			hostTestContext(),
			RevokeSessionScopeRequest{Identity: adapter.identity, Now: time.Now().UTC()},
		)
		continued <- resumeErr
	}()
	select {
	case resumeErr := <-continued:
		if resumeErr != nil {
			t.Fatalf("RevokeSessionScope(resume) error = %v", resumeErr)
		}
		if adapter.closeCalls != 2 || adapter.commitCalls != 2 {
			t.Fatalf("resume calls = prepare %d commit %d, want 2 each", adapter.closeCalls, adapter.commitCalls)
		}
	case <-time.After(time.Second):
		t.Fatal("RevokeSessionScope(resume) did not acquire the teardown lock")
	}
}

func TestRevokeSessionScopeWaitsForRuntimeTerminalAckAndPersistsCounts(t *testing.T) {
	runtimeManager := newRecordingRuntimeManager()
	runtimeManager.sessionRevokeResult = runtimeclient.SessionRevokeResult{Counts: runtimeclient.SessionRevokeCounts{
		QueuedInvocations: 2, RunningInvocations: 1, StorageHostcalls: 3,
		ActiveNetworkRequests: 5, Sockets: 7, NetworkStreams: 11,
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtimeManager})
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter

	result, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if runtimeManager.sessionRevokeCalls != 1 || runtimeManager.lastSessionRevoke.SessionRevokeSequence == 0 {
		t.Fatalf("runtime revoke = calls %d request %#v", runtimeManager.sessionRevokeCalls, runtimeManager.lastSessionRevoke)
	}
	if result.Counts.StorageHostcalls != 3 || result.Counts.ActiveNetworkRequests != 5 || result.Counts.Sockets != 7 || result.Counts.NetworkStreams != 11 {
		t.Fatalf("RevokeSessionScope() runtime counts = %#v", result.Counts)
	}
}

func TestRevokeSessionScopeCompletesWithStoppedRuntimeWithoutRestart(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter
	h.adapters.RuntimeManager = newNeverStartedProcessManagerForHost(t, h)

	result, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if result.State != sessionscope.StateComplete || !result.Fenced || !result.Complete || result.Counts != (sessionscope.Counts{}) {
		t.Fatalf("RevokeSessionScope() result = %#v, want complete zero-count teardown", result)
	}
}

func TestRevokeSessionScopeResumesDurableIncompleteTeardownAfterReopenWithoutRuntimeArtifact(t *testing.T) {
	sessionScopePath := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	lifecycle := &recordingSessionLifecycleAdapter{}
	failingRuntime := newRecordingRuntimeManager()
	failingRuntime.sessionRevokeErr = errors.New("terminal runtime acknowledgement lost")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: failingRuntime,
		sessionLifecycle: lifecycle, sessionScopePath: sessionScopePath,
	})
	session, err := requireUserSession(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	seedHostSessionScopeResources(t, h, session, time.Now().UTC())

	incomplete, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) || incomplete.State != sessionscope.StateIncomplete {
		t.Fatalf("first RevokeSessionScope() = %#v, %v", incomplete, err)
	}
	if incomplete.Counts.Surfaces != 1 || incomplete.Counts.AssetTickets != 1 || incomplete.Counts.Confirmations != 1 || incomplete.Counts.RuntimeExecutions != 1 {
		t.Fatalf("durable incomplete counts = %#v", incomplete.Counts)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: newNeverStartedProcessManager(t),
		sessionLifecycle: lifecycle, sessionScopePath: sessionScopePath,
	})
	if len(lifecycle.reconciled) != 1 || lifecycle.reconciled[0].Snapshot.State != sessionscope.StateIncomplete {
		t.Fatalf("retained scopes after reopen = %#v", lifecycle.reconciled)
	}
	complete, err := reopened.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{
		Identity: lifecycle.identity, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("resumed RevokeSessionScope() error = %v", err)
	}
	if complete.State != sessionscope.StateComplete || !complete.Fenced || !complete.Complete {
		t.Fatalf("resumed RevokeSessionScope() = %#v", complete)
	}
	if complete.Counts.Surfaces != 1 || complete.Counts.AssetTickets != 1 || complete.Counts.Confirmations != 1 || complete.Counts.RuntimeExecutions != 1 {
		t.Fatalf("resumed durable counts = %#v", complete.Counts)
	}
}

func TestRevokeSessionScopeRuntimeAckFailureIsCommittedIncomplete(t *testing.T) {
	runtimeManager := newRecordingRuntimeManager()
	runtimeManager.sessionRevokeErr = errors.New("terminal runtime acknowledgement lost")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtimeManager})
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter

	result, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: time.Now().UTC()})
	if !errors.Is(err, ErrSessionTeardownIncomplete) {
		t.Fatalf("RevokeSessionScope() error = %v, want committed incomplete", err)
	}
	if outcome, explicit := mutation.Explicit(err); !explicit || outcome != mutation.OutcomeCommitted {
		t.Fatalf("mutation outcome = %q explicit=%v", outcome, explicit)
	}
	if result.State != sessionscope.StateIncomplete || result.Complete {
		t.Fatalf("RevokeSessionScope() result = %#v", result)
	}
}

func TestRevokeSessionScopeCancelsAndAwaitsDetachedCancelJob(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	adapter := &recordingSessionLifecycleAdapter{}
	h.adapters.SessionLifecycle = adapter
	session, err := requireUserSession(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seedHostSessionScopeResources(t, h, session, now)
	record, err := h.adapters.Operations.Get(context.Background(), "operation_scope")
	if err != nil {
		t.Fatal(err)
	}
	record.CancelAckTimeoutMS = 60_000
	if err := h.armDetachedOperationCancelAckTimeout(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.detachedCancelJobs.Load(record.OperationID); !ok {
		t.Fatal("detached cancellation job was not registered")
	}

	if _, err := h.RevokeSessionScope(hostTestContext(), RevokeSessionScopeRequest{Now: now}); err != nil {
		t.Fatalf("RevokeSessionScope() error = %v", err)
	}
	if _, ok := h.detachedCancelJobs.Load(record.OperationID); ok {
		t.Fatal("detached cancellation job remained after session teardown")
	}
}

func seedHostSessionScopeResources(t *testing.T, h *Host, session sessionctx.Context, now time.Time) *executionLease {
	t.Helper()
	_, err := h.surfaceTokens.OpenSurface(bridge.OpenSurfaceRequest{
		PluginID: "com.example.scope", PluginInstanceID: "plugini_scope", PluginVersion: "1.0.0",
		SurfaceID: "scope.view", SurfaceInstanceID: "surface_scope", ActiveFingerprint: "sha256:scope",
		EntryPath: "ui/index.html", EntrySHA256: "sha256:entry", RouteRole: bridge.RouteRoleTrustedParent,
		RuntimeGenerationID: "runtime_generation_scope",
		OwnerSessionHash:    session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
		OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
		Revision: bridge.RevisionBinding{PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.adapters.ConfirmationIntents.PutConfirmationIntent(context.Background(), security.PutConfirmationIntentRequest{
		ConfirmationID: "confirmation_scope", ConfirmationTokenID: "confirmation_token_scope",
		PluginID: "com.example.scope", PluginInstanceID: "plugini_scope", SurfaceInstanceID: "surface_scope",
		BridgeChannelID: "bridge_scope", Method: "scope.run", RequestHash: "sha256:request", PlanHash: "sha256:plan",
		Scope: security.ConfirmationScope{
			ActiveFingerprint: "sha256:scope", OwnerSessionHash: session.OwnerSessionHash,
			OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
			SessionChannelIDHash: session.SessionChannelIDHash, PolicyRevision: 1, ManagementRevision: 1,
			RevokeEpoch: 1, TargetDescriptorSHA256: "sha256:target",
		},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := capability.ExecutionBinding{
		InvocationID: "invocation_scope", AuditCorrelationID: "audit_scope", PublisherID: "example.publisher",
		PluginID: "com.example.scope", PluginInstanceID: "plugini_scope", PluginVersion: "1.0.0",
		ActiveFingerprint: "sha256:scope", CapabilityID: "example.scope", CapabilityVersion: "1.0.0",
		BindingID: "scope", Method: "scope.run", TargetMethod: "scope.run", Effect: capability.EffectExecute,
		Execution: "operation", Target: capability.TargetDescriptor{Kind: "scope", Fields: map[string]any{"id": "one"}},
		TargetDescriptorSHA256: "sha256:target", OwnerSessionHash: session.OwnerSessionHash,
		OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
	}
	if _, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{OperationID: "operation_scope", ExecutionBinding: binding, Now: now}); err != nil {
		t.Fatal(err)
	}
	binding.Execution = "subscription"
	if _, err := h.adapters.Streams.Register(context.Background(), stream.RegisterRequest{StreamID: "stream_scope", ExecutionBinding: binding, Now: now}); err != nil {
		t.Fatal(err)
	}
	binding.Execution = "sync"
	binding.InvocationID = "invocation_scope_live"
	binding.OperationID = ""
	binding.StreamID = ""
	lease, err := h.executions.start(context.Background(), binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
