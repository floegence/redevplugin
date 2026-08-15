package host

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/internal/controlstore"
	"github.com/floegence/redevplugin/v2/pkg/bridge"
	"github.com/floegence/redevplugin/v2/pkg/execution"
	"github.com/floegence/redevplugin/v2/pkg/security"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
	"github.com/floegence/redevplugin/v2/pkg/sessionscope"
)

func TestCriticalResourceMutationReservationsPreventPostFenceCommit(t *testing.T) {
	for _, resource := range []string{"confirmation", "execution", "network_handle_grant", "storage_handle_grant"} {
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
			identity, err := h.sessionTeardownIdentity(ctx, scope)
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
	case "execution":
		return func() error {
			return h.controlStore.Executions().CreateOwned(context.Background(), execution.Execution{
				ID: "execution_reservation", PluginInstanceID: "plugini_reservation", Kind: execution.KindOperation,
			}, controlstore.ExecutionOwner{
				OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
				OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
			})
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
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
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
	waitForQueuedLifecycleOperation(t, h.lifecycleLocks, []string{enabled.PluginInstanceID}, "surface open")
	session, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.sessionTeardownIdentity(ctx, scope)
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
	releaseLifecycle()
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
