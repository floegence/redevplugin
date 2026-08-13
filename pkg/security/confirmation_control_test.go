package security_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/controlstore"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestControlConfirmationStorePreservesCapacityRevocationAndExpiry(t *testing.T) {
	ctx := context.Background()
	control, err := controlstore.Open(ctx, controlstore.Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	store, err := security.NewControlConfirmationIntentStore(control.Confirmations(), security.ConfirmationIntentStoreOptions{MaxTotal: 2, MaxPerOwnerPlugin: 2, MaxPerSession: 2, MaxSessionRevocations: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	scope := sessionctx.SessionScope{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	for _, id := range []string{"confirmation-1", "confirmation-2"} {
		if _, err := store.PutConfirmationIntent(ctx, controlConfirmationRequest(id, scope, now, now.Add(time.Hour))); err != nil {
			t.Fatalf("PutConfirmationIntent(%s) error = %v", id, err)
		}
	}
	if _, err := store.PutConfirmationIntent(ctx, controlConfirmationRequest("confirmation-overflow", scope, now, now.Add(time.Hour))); !errors.Is(err, security.ErrConfirmationIntentCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	revoke := security.RevokeSessionConfirmationIntentsRequest{SessionScope: scope, TeardownOperationID: "teardown-1", Now: now}
	if count, err := store.RevokeSessionConfirmationIntents(ctx, revoke); err != nil || count != 2 {
		t.Fatalf("RevokeSessionConfirmationIntents() = %d, %v", count, err)
	}
	if count, err := store.RevokeSessionConfirmationIntents(ctx, revoke); err != nil || count != 2 {
		t.Fatalf("RevokeSessionConfirmationIntents(replay) = %d, %v", count, err)
	}
	if err := store.FinalizeSessionConfirmationRevocation(ctx, security.FinalizeSessionConfirmationRevocationRequest{SessionScope: scope, TeardownOperationID: revoke.TeardownOperationID}); err != nil {
		t.Fatal(err)
	}
	if count, err := store.RevokeSessionConfirmationIntents(ctx, security.RevokeSessionConfirmationIntentsRequest{SessionScope: scope, TeardownOperationID: "teardown-2", Now: now}); err != nil || count != 0 {
		t.Fatalf("RevokeSessionConfirmationIntents(after finalize) = %d, %v", count, err)
	}
	if err := store.FinalizeSessionConfirmationRevocation(ctx, security.FinalizeSessionConfirmationRevocationRequest{SessionScope: scope, TeardownOperationID: "teardown-2"}); err != nil {
		t.Fatal(err)
	}

	expired := controlConfirmationRequest("confirmation-expired", scope, now, now.Add(time.Second))
	if _, err := store.PutConfirmationIntent(ctx, expired); err != nil {
		t.Fatal(err)
	}
	consume := security.ConsumeConfirmationIntentRequest{ConfirmationID: expired.ConfirmationID, SessionScope: scope, Now: now.Add(2 * time.Second)}
	if _, err := store.ConsumeConfirmationIntent(ctx, consume); !errors.Is(err, security.ErrConfirmationIntentExpired) {
		t.Fatalf("expired consume error = %v", err)
	}
	if _, err := store.ConsumeConfirmationIntent(ctx, consume); !errors.Is(err, security.ErrConfirmationIntentNotFound) {
		t.Fatalf("expired replay error = %v", err)
	}
}

func controlConfirmationRequest(id string, scope sessionctx.SessionScope, issuedAt, expiresAt time.Time) security.PutConfirmationIntentRequest {
	return security.PutConfirmationIntentRequest{
		ConfirmationID: id, ConfirmationTokenID: "token-" + id,
		PluginID: "com.example.control", PluginInstanceID: "instance-control",
		SurfaceInstanceID: "surface-control", BridgeChannelID: "bridge-control",
		Method: "documents.write", RequestHash: "sha256:request", PlanHash: "sha256:plan",
		Scope: security.ConfirmationScope{
			ActiveFingerprint: "sha256:fingerprint", OwnerSessionHash: scope.OwnerSessionHash,
			OwnerUserHash: scope.OwnerUserHash, OwnerEnvHash: scope.OwnerEnvHash,
			SessionChannelIDHash: scope.SessionChannelIDHash, PolicyRevision: 1,
			ManagementRevision: 1, TargetDescriptorSHA256: "sha256:target",
		},
		IssuedAt: issuedAt, ExpiresAt: expiresAt, Now: issuedAt,
	}
}
