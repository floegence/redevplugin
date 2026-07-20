package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
	"github.com/floegence/redevplugin/pkg/stream"
)

type blockingSessionScopeRegistry struct {
	registry.Store
	entered chan struct{}
	release chan struct{}
}

func TestDetachedCancellationRegistrationReservationPreventsPostFenceJob(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	ctx := hostTestContext()
	session, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	record := operation.Record{
		OperationID: "operation_detached_registration_race", CancelAckTimeoutMS: 60_000,
		ExecutionBinding: testSessionExecutionBinding(session),
	}

	registrationEntered := make(chan struct{})
	registrationRelease := make(chan struct{})
	registrationDone := make(chan error, 1)
	go func() {
		registrationDone <- h.withSessionScopeReservation(ctx, scope, func() error {
			close(registrationEntered)
			<-registrationRelease
			return h.armDetachedOperationCancelAckTimeoutReserved(record, scope)
		})
	}()
	<-registrationEntered
	identity, err := h.adapters.SessionLifecycle.PrepareSessionScopeClose(ctx, PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	type teardownResult struct {
		teardown *sessionscope.Teardown
		err      error
	}
	teardownDone := make(chan teardownResult, 1)
	go func() {
		teardown, _, beginErr := h.sessionScopes.BeginTeardown(ctx, scope, identity, time.Now().UTC())
		teardownDone <- teardownResult{teardown: teardown, err: beginErr}
	}()
	select {
	case result := <-teardownDone:
		if result.teardown != nil {
			result.teardown.Release()
		}
		t.Fatalf("session fence passed detached-job registration: %v", result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(registrationRelease)
	if err := <-registrationDone; err != nil {
		t.Fatal(err)
	}
	result := <-teardownDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.teardown.Release()
	if err := h.detachedCancelJobs.cancelSession(context.Background(), scope, errors.New("session revoked")); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.detachedCancelJobs.Load(record.OperationID); ok {
		t.Fatal("detached cancellation job survived the exact session fence")
	}
	if err := h.armDetachedOperationCancelAckTimeout(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.detachedCancelJobs.Load(record.OperationID); ok {
		t.Fatal("fenced session registered a new detached cancellation job")
	}
}

func TestCriticalResourceMutationReservationsPreventPostFenceCommit(t *testing.T) {
	for _, resource := range []string{"confirmation", "operation", "stream", "network_handle_grant", "storage_handle_grant"} {
		t.Run(resource, func(t *testing.T) {
			h, _, _ := newTestHost(t, true, true)
			ctx := hostTestContext()
			session, err := requireUserSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			scope, err := session.SessionScope()
			if err != nil {
				t.Fatal(err)
			}
			mutation := criticalSessionResourceMutation(t, h, session, resource)
			entered := make(chan struct{})
			release := make(chan struct{})
			mutationDone := make(chan error, 1)
			calls := 0
			go func() {
				mutationDone <- h.withSessionScopeReservation(ctx, scope, func() error {
					close(entered)
					<-release
					calls++
					return mutation()
				})
			}()
			<-entered
			identity, err := h.adapters.SessionLifecycle.PrepareSessionScopeClose(ctx, PrepareSessionScopeCloseRequest{Session: session})
			if err != nil {
				t.Fatal(err)
			}
			type teardownResult struct {
				teardown *sessionscope.Teardown
				err      error
			}
			teardownDone := make(chan teardownResult, 1)
			go func() {
				teardown, _, beginErr := h.sessionScopes.BeginTeardown(ctx, scope, identity, time.Now().UTC())
				teardownDone <- teardownResult{teardown: teardown, err: beginErr}
			}()
			select {
			case result := <-teardownDone:
				if result.teardown != nil {
					result.teardown.Release()
				}
				t.Fatalf("session fence passed %s mutation: %v", resource, result.err)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if err := <-mutationDone; err != nil {
				t.Fatalf("%s mutation error = %v", resource, err)
			}
			result := <-teardownDone
			if result.err != nil {
				t.Fatal(result.err)
			}
			result.teardown.Release()
			if err := h.withSessionScopeReservation(ctx, scope, func() error {
				calls++
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("%s mutation calls = %d, want exactly the pre-fence commit", resource, calls)
			}
		})
	}
}

func criticalSessionResourceMutation(
	t *testing.T,
	h *Host,
	session sessionctx.Context,
	resource string,
) func() error {
	t.Helper()
	now := time.Now().UTC()
	switch resource {
	case "confirmation":
		return func() error {
			_, err := h.adapters.ConfirmationIntents.PutConfirmationIntent(context.Background(), security.PutConfirmationIntentRequest{
				ConfirmationID: "confirmation_reservation", ConfirmationTokenID: "confirmation_token_reservation",
				PluginID: "com.example.reservation", PluginInstanceID: "plugini_reservation",
				SurfaceInstanceID: "surface_reservation", BridgeChannelID: "bridge_reservation",
				Method: "reservation.run", RequestHash: "sha256:request", PlanHash: "sha256:plan",
				Scope: security.ConfirmationScope{
					ActiveFingerprint: "sha256:reservation", OwnerSessionHash: session.OwnerSessionHash,
					OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
					SessionChannelIDHash: session.SessionChannelIDHash, PolicyRevision: 1,
					ManagementRevision: 1, RevokeEpoch: 1, TargetDescriptorSHA256: "sha256:target",
				},
				IssuedAt: now, ExpiresAt: now.Add(time.Minute), Now: now,
			})
			return err
		}
	case "operation":
		return func() error {
			binding := testSessionExecutionBinding(session)
			_, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
				OperationID: "operation_reservation", ExecutionBinding: binding, Now: now,
			})
			return err
		}
	case "stream":
		return func() error {
			binding := testSessionExecutionBinding(session)
			binding.Execution = "subscription"
			_, err := h.adapters.Streams.Register(context.Background(), stream.RegisterRequest{
				StreamID: "stream_reservation", ExecutionBinding: binding, Now: now,
			})
			return err
		}
	case "network_handle_grant", "storage_handle_grant":
		return func() error {
			resourceScope, err := session.ResourceScope(sessionctx.ScopeUser)
			if err != nil {
				return err
			}
			_, err = h.surfaceTokens.MintHandleGrant(bridge.MintHandleGrantRequest{
				PluginInstanceID: "plugini_reservation", ActiveFingerprint: "sha256:reservation",
				RuntimeGenerationID: "runtime_generation_reservation", OwnerSessionHash: session.OwnerSessionHash,
				OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
				SessionChannelIDHash: session.SessionChannelIDHash, HandleID: "handle_" + resource,
				Method: resource + ".open", ResourceScope: resourceScope,
				Revision: bridge.RevisionBinding{PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1}, Now: now,
			})
			return err
		}
	default:
		t.Fatalf("unknown critical session resource %q", resource)
		return nil
	}
}

func testSessionExecutionBinding(session sessionctx.Context) capability.ExecutionBinding {
	return capability.ExecutionBinding{
		InvocationID: "invocation_detached_registration_race", AuditCorrelationID: "audit_detached_registration_race",
		PublisherID: "example.publisher", PluginID: "com.example.detached", PluginInstanceID: "plugini_detached",
		PluginVersion: "1.0.0", ActiveFingerprint: "sha256:detached", CapabilityID: "example.detached",
		CapabilityVersion: "1.0.0", BindingID: "detached", Method: "detached.run", TargetMethod: "detached.run",
		Effect: capability.EffectExecute, Execution: "operation",
		Target:                 capability.TargetDescriptor{Kind: "detached", Fields: map[string]any{"id": "one"}},
		TargetDescriptorSHA256: "sha256:detached_target", OwnerSessionHash: session.OwnerSessionHash,
		OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
	}
}

func (s *blockingSessionScopeRegistry) GetPlugin(ctx context.Context, pluginInstanceID string) (registry.PluginRecord, error) {
	select {
	case <-s.entered:
	default:
		close(s.entered)
	}
	select {
	case <-ctx.Done():
		return registry.PluginRecord{}, ctx.Err()
	case <-s.release:
		return s.Store.GetPlugin(ctx, pluginInstanceID)
	}
}

func TestOpenSurfaceReservationPreventsPostFenceCommit(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	ctx := hostTestContext()
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingSessionScopeRegistry{
		Store:   h.adapters.Registry,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	h.adapters.Registry = blocking
	openDone := make(chan error, 1)
	go func() {
		_, err := h.OpenSurface(ctx, OpenSurfaceRequest{
			PluginInstanceID:           enabled.PluginInstanceID,
			SurfaceID:                  enabled.Manifest.Surfaces[0].SurfaceID,
			SurfaceInstanceID:          "surface_session_reservation",
			ExpectedManagementRevision: enabled.ManagementRevision,
		})
		openDone <- err
	}()
	<-blocking.entered
	session, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.adapters.SessionLifecycle.PrepareSessionScopeClose(ctx, PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	type teardownResult struct {
		teardown *sessionscope.Teardown
		err      error
	}
	teardownDone := make(chan teardownResult, 1)
	go func() {
		teardown, _, err := h.sessionScopes.BeginTeardown(ctx, scope, identity, time.Now().UTC())
		teardownDone <- teardownResult{teardown: teardown, err: err}
	}()
	select {
	case result := <-teardownDone:
		if result.teardown != nil {
			result.teardown.Release()
		}
		t.Fatalf("session fence committed before resource reservation released: %v", result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocking.release)
	if err := <-openDone; err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	result := <-teardownDone
	if result.err != nil {
		t.Fatalf("BeginTeardown() error = %v", result.err)
	}
	defer result.teardown.Release()
	if _, err := h.surfaceTokens.ExchangeAssetTicket(bridge.ExchangeAssetTicketRequest{
		SurfaceInstanceID:    "surface_session_reservation",
		AssetTicket:          "unreachable",
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
	}); err == nil {
		t.Fatal("surface remained usable after exact session fence")
	}
}
