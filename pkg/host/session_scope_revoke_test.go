package host

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

func TestRevokeSessionScopeFencesDrainsAndResumesIdempotently(t *testing.T) {
	h, _, audits := newTestHost(t, true, true)
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
		result.Counts.Confirmations != 1 ||
		result.Counts.Executions != 1 {
		t.Fatalf("RevokeSessionScope() counts = %#v", result.Counts)
	}
	if err := liveExecution.validate(context.Background()); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("live execution validation error = %v", err)
	}
	if _, err := h.Features(ctx); !errors.Is(err, sessionscope.ErrSessionRevoked) {
		t.Fatalf("Features(after fence) error = %v, want ErrSessionRevoked", err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}

	resumed, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{Identity: identity, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("RevokeSessionScope(resume) error = %v", err)
	}
	if resumed != result {
		t.Fatalf("resume = %#v, first = %#v", resumed, result)
	}
	if err := h.FinalizeSessionScope(ctx, FinalizeSessionScopeRequest{Identity: identity}); err != nil {
		t.Fatalf("FinalizeSessionScope() error = %v", err)
	}
	if event, ok := audits.lastEvent("plugin.session_scope.finalized"); !ok || event.Details["session_scope_state"] != "complete" {
		t.Fatalf("finalize audit = %#v, found = %v", event, ok)
	}
	if err := h.FinalizeSessionScope(ctx, FinalizeSessionScopeRequest{Identity: identity}); !errors.Is(err, sessionscope.ErrClosedSessionProofInvalid) {
		t.Fatalf("FinalizeSessionScope(replay) error = %v", err)
	}
}

func TestRevokeSessionScopeWaitsForRuntimeTerminalAckAndPersistsCounts(t *testing.T) {
	runtimeManager := newRecordingRuntimeManager()
	runtimeManager.sessionRevokeResult = runtimeclient.SessionRevokeResult{Counts: runtimeclient.SessionRevokeCounts{
		QueuedInvocations: 2, RunningInvocations: 1, StorageHostcalls: 3,
		ActiveNetworkRequests: 5, Sockets: 7, NetworkStreams: 11,
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtimeManager})

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
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	sessionScopePath := filepath.Join(root, "session-scopes.sqlite")
	failingRuntime := newRecordingRuntimeManager()
	failingRuntime.sessionRevokeErr = errors.New("terminal runtime acknowledgement lost")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: failingRuntime,
		stateRoot: stateRoot, sessionScopePath: sessionScopePath,
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
	if incomplete.Counts.Surfaces != 1 || incomplete.Counts.AssetTickets != 1 || incomplete.Counts.Confirmations != 1 || incomplete.Counts.Executions != 1 {
		t.Fatalf("durable incomplete counts = %#v", incomplete.Counts)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: newNeverStartedProcessManager(t),
		stateRoot: stateRoot, sessionScopePath: sessionScopePath,
	})
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.sessionScopes.InspectRetained(context.Background(), scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("retained fence after startup recovery error = %v", err)
	}
}

func TestRevokeSessionScopeRuntimeAckFailureIsCommittedIncomplete(t *testing.T) {
	runtimeManager := newRecordingRuntimeManager()
	runtimeManager.sessionRevokeErr = errors.New("terminal runtime acknowledgement lost")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtimeManager})

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

func seedHostSessionScopeResources(t *testing.T, h *Host, session sessionctx.Context, now time.Time) *executionLease {
	t.Helper()
	_, err := h.surfaceTokens.OpenSurface(bridge.OpenSurfaceRequest{
		PluginID: "com.example.scope", PluginInstanceID: "plugini_scope", PluginVersion: "1.0.0", UIProtocolVersion: "plugin-ui-v7",
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
	binding.Execution = "sync"
	binding.InvocationID = "invocation_scope_live"
	binding.ExecutionID = ""
	lease, err := h.executions.start(context.Background(), binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
