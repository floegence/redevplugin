package operation

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestOperationStoresRevokeExactSessionScope(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctx := context.Background()
			now := time.Unix(1, 0).UTC()
			targetBinding := operationTestBinding("com.example.plugin", "plugini_scope", "scope.run", nil)
			siblingBinding := operationTestBinding("com.example.plugin", "plugini_scope", "scope.run", func(binding *capability.ExecutionBinding) {
				binding.SessionChannelIDHash = "channel_sibling"
			})
			if _, err := store.Register(ctx, RegisterRequest{OperationID: "operation_target", ExecutionBinding: targetBinding, Now: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Register(ctx, RegisterRequest{OperationID: "operation_sibling", ExecutionBinding: siblingBinding, Now: now}); err != nil {
				t.Fatal(err)
			}
			scope := sessionctx.SessionScope{
				OwnerSessionHash:     targetBinding.OwnerSessionHash,
				OwnerUserHash:        targetBinding.OwnerUserHash,
				OwnerEnvHash:         targetBinding.OwnerEnvHash,
				SessionChannelIDHash: targetBinding.SessionChannelIDHash,
			}
			result, err := store.RevokeSessionScope(ctx, RevokeSessionScopeRequest{SessionScope: scope, Now: now.Add(time.Second)})
			if err != nil {
				t.Fatalf("RevokeSessionScope() error = %v", err)
			}
			if result.Revoked != 1 {
				t.Fatalf("RevokeSessionScope() = %#v", result)
			}
			target, err := store.Get(ctx, "operation_target")
			if err != nil {
				t.Fatal(err)
			}
			if target.Status != StatusCanceled || target.TerminalAt == nil || target.Reason != SessionRevokedReason {
				t.Fatalf("target operation = %#v", target)
			}
			sibling, err := store.Get(ctx, "operation_sibling")
			if err != nil {
				t.Fatal(err)
			}
			if sibling.Status != StatusRunning {
				t.Fatalf("sibling operation = %#v", sibling)
			}
			replay, err := store.RevokeSessionScope(ctx, RevokeSessionScopeRequest{SessionScope: scope, Now: now.Add(2 * time.Second)})
			if err != nil || replay.Revoked != 1 {
				t.Fatalf("RevokeSessionScope(replay) = %#v, %v", replay, err)
			}
		})
	}
}
