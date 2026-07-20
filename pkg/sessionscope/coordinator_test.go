package sessionscope

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestCoordinatorFenceIsIrreversibleAndCountsAreCumulative(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{MaxScopes: 2})
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	scope := testSessionScope("one")
	identity := testTeardownIdentity(t, "one")
	reservation, err := coordinator.Reserve(context.Background(), scope)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	reservation.Release()

	teardown, snapshot, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown() error = %v", err)
	}
	if snapshot.State != StateDraining || !snapshot.Fenced || snapshot.Complete {
		t.Fatalf("BeginTeardown() snapshot = %#v", snapshot)
	}
	if _, err := coordinator.Reserve(context.Background(), scope); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Reserve(fenced) error = %v, want ErrSessionRevoked", err)
	}
	if _, err := teardown.Accumulate(context.Background(), Counts{Surfaces: 2, AssetTickets: 1}); err != nil {
		t.Fatalf("Accumulate(first) error = %v", err)
	}
	if _, err := teardown.Accumulate(context.Background(), Counts{Operations: 3, StorageHostcalls: 4}); err != nil {
		t.Fatalf("Accumulate(second) error = %v", err)
	}
	if _, err := teardown.MarkIncomplete(context.Background(), time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("MarkIncomplete() error = %v", err)
	}
	teardown.Release()

	continued, resumed, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(3, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown(resume) error = %v", err)
	}
	if resumed.Counts.Surfaces != 2 || resumed.Counts.AssetTickets != 1 || resumed.Counts.Operations != 3 || resumed.Counts.StorageHostcalls != 4 {
		t.Fatalf("resumed counts = %#v", resumed.Counts)
	}
	complete, err := continued.MarkComplete(context.Background(), time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	continued.Release()
	if complete.State != StateComplete || !complete.Fenced || !complete.Complete {
		t.Fatalf("complete snapshot = %#v", complete)
	}
}

func TestCoordinatorResumeRequiresExactTeardownIdentity(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	scope := testSessionScope("identity")
	identity := testTeardownIdentity(t, "identity")
	teardown, _, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown() error = %v", err)
	}
	if _, err := teardown.MarkIncomplete(context.Background(), time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("MarkIncomplete() error = %v", err)
	}
	teardown.Release()
	for name, wrong := range map[string]TeardownIdentity{
		"operation": testTeardownIdentity(t, "other_operation"),
		"proof":     mustTeardownIdentity(t, identity.OperationID, []byte("fedcba9876543210fedcba9876543210")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := coordinator.BeginTeardown(context.Background(), scope, wrong, time.Unix(3, 0).UTC()); !errors.Is(err, ErrTeardownIdentityMismatch) {
				t.Fatalf("BeginTeardown(wrong %s) error = %v, want ErrTeardownIdentityMismatch", name, err)
			}
		})
	}
	continued, _, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown(correct identity) error = %v", err)
	}
	continued.Release()
}

func TestRetainedScopeMatchesOperationAndProofExactly(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("retained_identity")
	identity := testTeardownIdentity(t, "retained_identity")
	teardown, _, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	retained, err := coordinator.ListRetained(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || !retained[0].MatchesIdentity(identity) {
		t.Fatalf("retained identity match = %#v", retained)
	}
	sameOperationDifferentProof := mustTeardownIdentity(
		t,
		identity.OperationID,
		[]byte("fedcba9876543210fedcba9876543210"),
	)
	if retained[0].MatchesIdentity(sameOperationDifferentProof) {
		t.Fatal("retained scope matched the same operation with a different proof")
	}
	differentOperationSameProof, err := NewTeardownIdentity("teardown_other_operation", identity.proof)
	if err != nil {
		t.Fatal(err)
	}
	if retained[0].MatchesIdentity(differentOperationSameProof) {
		t.Fatal("retained scope matched a different operation with the same proof")
	}
}

func TestCoordinatorCapacityAndProofAreFailClosed(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{MaxScopes: 1})
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	first := testSessionScope("first")
	teardown, _, err := coordinator.BeginTeardown(context.Background(), first, testTeardownIdentity(t, "first"), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown(first) error = %v", err)
	}
	defer teardown.Release()
	if _, _, err := coordinator.BeginTeardown(context.Background(), testSessionScope("second"), testTeardownIdentity(t, "second"), time.Unix(2, 0).UTC()); !errors.Is(err, ErrFenceCapacity) {
		t.Fatalf("BeginTeardown(second) error = %v, want ErrFenceCapacity", err)
	}
	if _, err := NewClosedSessionProof(make([]byte, 31)); !errors.Is(err, ErrClosedSessionProofInvalid) {
		t.Fatalf("NewClosedSessionProof(short) error = %v", err)
	}
	if _, err := NewClosedSessionProof(make([]byte, 33)); !errors.Is(err, ErrClosedSessionProofInvalid) {
		t.Fatalf("NewClosedSessionProof(long) error = %v", err)
	}
}

type failingBeginTeardownStore struct {
	Store
	err error
}

func (s *failingBeginTeardownStore) BeginTeardown(
	context.Context,
	sessionctx.SessionScope,
	string,
	[sha256.Size]byte,
	time.Time,
) (record, error) {
	return record{}, s.err
}

func TestCoordinatorBeginTeardownStoreFailureDoesNotCommitFence(t *testing.T) {
	base, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected atomic begin failure")
	coordinator, err := NewCoordinator(&failingBeginTeardownStore{Store: base, err: injected})
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("atomic_failure")
	teardown, snapshot, err := coordinator.BeginTeardown(
		context.Background(), scope, testTeardownIdentity(t, "atomic_failure"), time.Now().UTC(),
	)
	if !errors.Is(err, injected) || teardown != nil || snapshot.Fenced {
		t.Fatalf("BeginTeardown() = %#v, %#v, %v", teardown, snapshot, err)
	}
	if _, err := base.Get(context.Background(), scope); !errors.Is(err, ErrScopeNotFound) {
		t.Fatalf("store.Get(after failed atomic begin) error = %v, want ErrScopeNotFound", err)
	}
}

func TestCoordinatorActiveReservationsDoNotConsumeFenceCapacity(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{MaxScopes: 1})
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	for index := 0; index < 100; index++ {
		scope := testSessionScope(fmt.Sprintf("active_%d", index))
		reservation, err := coordinator.Reserve(context.Background(), scope)
		if err != nil {
			t.Fatalf("Reserve(%d) error = %v", index, err)
		}
		reservation.Release()
		if _, err := coordinator.Snapshot(context.Background(), scope); !errors.Is(err, ErrScopeNotFound) {
			t.Fatalf("active scope %d persisted a fence record: %v", index, err)
		}
	}
	coordinator.mu.Lock()
	gateCount := len(coordinator.gates)
	coordinator.mu.Unlock()
	if gateCount != 0 {
		t.Fatalf("released active session gates = %d, want 0", gateCount)
	}
}

func TestCoordinatorTeardownWaitIsContextCancelable(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("cancel_wait")
	reservation, err := coordinator.Reserve(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	identity := testTeardownIdentity(t, "cancel_wait")
	go func() {
		_, _, beginErr := coordinator.BeginTeardown(ctx, scope, identity, time.Now().UTC())
		done <- beginErr
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case beginErr := <-done:
		if !errors.Is(beginErr, context.Canceled) {
			t.Fatalf("BeginTeardown() error = %v, want context.Canceled", beginErr)
		}
	case <-time.After(time.Second):
		t.Fatal("BeginTeardown() did not observe context cancellation")
	}
	reservation.Release()

	next, err := coordinator.Reserve(context.Background(), scope)
	if err != nil {
		t.Fatalf("Reserve(after canceled teardown) error = %v", err)
	}
	next.Release()
}

func TestCoordinatorHundredWayReserveRaceCannotCommitAfterFence(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("hundred_way")
	blocker, err := coordinator.Reserve(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	type teardownResult struct {
		teardown *Teardown
		err      error
	}
	identity := testTeardownIdentity(t, "hundred_way")
	teardownDone := make(chan teardownResult, 1)
	go func() {
		teardown, _, err := coordinator.BeginTeardown(
			context.Background(), scope, identity, time.Now().UTC(),
		)
		teardownDone <- teardownResult{teardown: teardown, err: err}
	}()
	for {
		coordinator.mu.Lock()
		started := coordinator.gates[scope] != nil && coordinator.gates[scope].teardown
		coordinator.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}

	errs := make(chan error, 100)
	for range 100 {
		go func() {
			reservation, err := coordinator.Reserve(context.Background(), scope)
			if reservation != nil {
				reservation.Release()
			}
			errs <- err
		}()
	}
	blocker.Release()
	result := <-teardownDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.teardown.Release()
	for range 100 {
		if err := <-errs; !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("Reserve(racing fence) error = %v, want ErrSessionRevoked", err)
		}
	}
}

func TestCoordinatorFinalizeConsumesProofAndReleasesFenceCapacity(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("finalize")
	identity := testTeardownIdentity(t, "finalize")
	teardown, _, err := coordinator.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.MarkComplete(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if err := coordinator.Finalize(context.Background(), scope, identity); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Finalize(context.Background(), scope, identity); !errors.Is(err, ErrClosedSessionProofInvalid) {
		t.Fatalf("Finalize(replay) error = %v", err)
	}
	reservation, err := coordinator.Reserve(context.Background(), scope)
	if err != nil {
		t.Fatalf("Reserve(after finalize) error = %v", err)
	}
	reservation.Release()
}

func TestCoordinatorAccumulatePhaseIsReplayStable(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := coordinator.BeginTeardown(
		context.Background(), testSessionScope("phase"), testTeardownIdentity(t, "phase"), time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer teardown.Release()
	delta := Counts{Surfaces: 2, AssetTickets: 3}
	first, err := teardown.AccumulatePhase(context.Background(), PhaseBridge, delta)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := teardown.AccumulatePhase(context.Background(), PhaseBridge, delta)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Counts != first.Counts || replayed.Counts != delta {
		t.Fatalf("replayed counts = %#v, first = %#v", replayed.Counts, first.Counts)
	}
	mismatchedReplay, err := teardown.AccumulatePhase(context.Background(), PhaseBridge, Counts{Surfaces: 1})
	if err != nil || mismatchedReplay.Counts != delta {
		t.Fatalf("mismatched replay = %#v, %v", mismatchedReplay, err)
	}
}

func TestTeardownHandleRejectsMutationAfterRelease(t *testing.T) {
	store, err := NewMemoryStore(StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := coordinator.BeginTeardown(
		context.Background(), testSessionScope("released"), testTeardownIdentity(t, "released"), time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if _, err := teardown.AccumulatePhase(context.Background(), PhaseRuntime, Counts{Sockets: 1}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("AccumulatePhase(after release) error = %v, want ErrInvalidState", err)
	}
	if _, err := teardown.MarkComplete(context.Background(), time.Now().UTC()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("MarkComplete(after release) error = %v, want ErrInvalidState", err)
	}
}

func testSessionScope(suffix string) sessionctx.SessionScope {
	return sessionctx.SessionScope{
		OwnerSessionHash:     "session_" + suffix,
		OwnerUserHash:        "user_" + suffix,
		OwnerEnvHash:         "env_" + suffix,
		SessionChannelIDHash: "channel_" + suffix,
	}
}

func testTeardownIdentity(t *testing.T, suffix string) TeardownIdentity {
	t.Helper()
	return mustTeardownIdentity(t, "teardown_"+suffix, []byte("0123456789abcdef0123456789abcdef"))
}

func mustTeardownIdentity(t *testing.T, operationID string, proofBytes []byte) TeardownIdentity {
	t.Helper()
	proof, err := NewClosedSessionProof(proofBytes)
	if err != nil {
		t.Fatalf("NewClosedSessionProof() error = %v", err)
	}
	identity, err := NewTeardownIdentity(operationID, proof)
	if err != nil {
		t.Fatalf("NewTeardownIdentity() error = %v", err)
	}
	return identity
}
