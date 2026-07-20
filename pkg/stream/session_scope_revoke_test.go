package stream

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestStreamStoresRevokeExactSessionScopeAndDiscardBufferedData(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		now := time.Unix(1, 0).UTC()
		targetBinding := streamTestBinding("plugini_scope")
		siblingBinding := streamTestBinding("plugini_scope")
		siblingBinding.SessionChannelIDHash = "channel_sibling"
		if _, err := store.Register(ctx, RegisterRequest{StreamID: "stream_target", ExecutionBinding: targetBinding, Now: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Register(ctx, RegisterRequest{StreamID: "stream_sibling", ExecutionBinding: siblingBinding, Now: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_target", Data: []byte("private target data"), Now: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_sibling", Data: []byte("sibling data"), Now: now}); err != nil {
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
		target, err := store.Get(ctx, "stream_target")
		if err != nil {
			t.Fatal(err)
		}
		if target.Status != StatusCanceled || target.ClosedAt == nil || target.BufferedBytes != 0 || target.Reason != SessionRevokedReason {
			t.Fatalf("target stream = %#v", target)
		}
		_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: "stream_target", ReadID: "read_after_revoke"})
		if err != nil {
			t.Fatalf("Deliver(target) error = %v", err)
		}
		if len(delivery.Events) != 0 {
			t.Fatalf("target delivery after revoke = %#v", delivery)
		}
		sibling, err := store.Get(ctx, "stream_sibling")
		if err != nil {
			t.Fatal(err)
		}
		if sibling.Status != StatusOpen || sibling.BufferedBytes == 0 {
			t.Fatalf("sibling stream = %#v", sibling)
		}
		replay, err := store.RevokeSessionScope(ctx, RevokeSessionScopeRequest{SessionScope: scope, Now: now.Add(2 * time.Second)})
		if err != nil || replay.Revoked != 1 {
			t.Fatalf("RevokeSessionScope(replay) = %#v, %v", replay, err)
		}
	})
}
