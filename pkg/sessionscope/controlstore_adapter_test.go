package sessionscope_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/controlstore"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

func TestControlStorePreservesFencePhaseIdentityAndFinalization(t *testing.T) {
	ctx := context.Background()
	control, err := controlstore.Open(ctx, controlstore.Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	backend, err := sessionscope.NewControlStore(control.Sessions(), sessionscope.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := sessionscope.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	scope := sessionctx.SessionScope{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	identity := controlTeardownIdentity(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	teardown, snapshot, err := coordinator.BeginTeardown(ctx, scope, identity, now)
	if err != nil || !snapshot.Fenced {
		t.Fatalf("BeginTeardown() = %#v, %v", snapshot, err)
	}
	if snapshot, err = teardown.AccumulatePhase(ctx, sessionscope.PhaseExecution, sessionscope.Counts{Executions: 3}); err != nil || snapshot.Counts.Executions != 3 {
		t.Fatalf("AccumulatePhase() = %#v, %v", snapshot, err)
	}
	if snapshot, err = teardown.AccumulatePhase(ctx, sessionscope.PhaseExecution, sessionscope.Counts{Executions: 99}); err != nil || snapshot.Counts.Executions != 3 {
		t.Fatalf("AccumulatePhase(replay) = %#v, %v", snapshot, err)
	}
	if snapshot, err = teardown.MarkComplete(ctx, now.Add(time.Minute)); err != nil || !snapshot.Complete {
		t.Fatalf("MarkComplete() = %#v, %v", snapshot, err)
	}
	teardown.Release()
	retained, err := coordinator.InspectRetained(ctx, scope)
	if err != nil || !retained.MatchesIdentity(identity) || retained.Snapshot.Counts.Executions != 3 {
		t.Fatalf("InspectRetained() = %#v, %v", retained, err)
	}
	wrong := controlTeardownIdentity(t)
	if err := coordinator.Finalize(ctx, scope, wrong); !errors.Is(err, sessionscope.ErrClosedSessionProofInvalid) {
		t.Fatalf("wrong-proof Finalize() error = %v", err)
	}
	if err := coordinator.Finalize(ctx, scope, identity); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Snapshot(ctx, scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("finalized Snapshot() error = %v", err)
	}
}

func controlTeardownIdentity(t *testing.T) sessionscope.TeardownIdentity {
	t.Helper()
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessionscope.NewTeardownIdentity("teardown-control", proof)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
