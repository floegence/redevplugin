package sessionscope

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSQLiteStorePersistsIncompleteTeardownAndCumulativeCounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	store, err := NewSQLiteStore(ctx, path, StoreOptions{MaxScopes: 2})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	scope := testSessionScope("durable")
	identity := testTeardownIdentity(t, "durable")
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown() error = %v", err)
	}
	if _, err := teardown.Accumulate(ctx, Counts{Surfaces: 2, RuntimeExecutions: 3}); err != nil {
		t.Fatalf("Accumulate() error = %v", err)
	}
	if _, err := teardown.MarkIncomplete(ctx, time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("MarkIncomplete() error = %v", err)
	}
	teardown.Release()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, path, StoreOptions{MaxScopes: 2})
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	resumedCoordinator, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatalf("NewCoordinator(reopened) error = %v", err)
	}
	if !resumedCoordinator.Durable() {
		t.Fatal("SQLite coordinator is not durable")
	}
	if _, err := resumedCoordinator.Reserve(ctx, scope); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Reserve(reopened fenced scope) error = %v, want ErrSessionRevoked", err)
	}
	continued, snapshot, err := resumedCoordinator.BeginTeardown(ctx, scope, identity, time.Unix(3, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown(reopened) error = %v", err)
	}
	if snapshot.State != StateDraining || snapshot.Counts.Surfaces != 2 || snapshot.Counts.RuntimeExecutions != 3 {
		t.Fatalf("resumed snapshot = %#v", snapshot)
	}
	if _, err := continued.Accumulate(ctx, Counts{Streams: 4}); err != nil {
		t.Fatalf("Accumulate(resumed) error = %v", err)
	}
	complete, err := continued.MarkComplete(ctx, time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	continued.Release()
	if complete.Counts.Surfaces != 2 || complete.Counts.RuntimeExecutions != 3 || complete.Counts.Streams != 4 {
		t.Fatalf("complete counts = %#v", complete.Counts)
	}
}

func TestSQLiteStoreFinalizeProofIsSingleUseAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	store, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	scope := testSessionScope("proof")
	identity := testTeardownIdentity(t, "proof")
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown() error = %v", err)
	}
	wrongProof, err := NewClosedSessionProof([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewClosedSessionProof(wrong) error = %v", err)
	}
	if _, err := teardown.MarkComplete(ctx, time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	teardown.Release()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	resumedCoordinator, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatalf("NewCoordinator(reopened) error = %v", err)
	}
	wrongIdentity, err := NewTeardownIdentity(identity.OperationID, wrongProof)
	if err != nil {
		t.Fatalf("NewTeardownIdentity(wrong) error = %v", err)
	}
	if err := resumedCoordinator.Finalize(ctx, scope, wrongIdentity); !errors.Is(err, ErrClosedSessionProofInvalid) {
		t.Fatalf("Finalize(wrong proof) error = %v", err)
	}
	if err := resumedCoordinator.Finalize(ctx, scope, identity); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if err := resumedCoordinator.Finalize(ctx, scope, identity); !errors.Is(err, ErrClosedSessionProofInvalid) {
		t.Fatalf("Finalize(replay) error = %v, want ErrClosedSessionProofInvalid", err)
	}
	reservation, err := resumedCoordinator.Reserve(ctx, scope)
	if err != nil {
		t.Fatalf("Reserve(after finalize) error = %v", err)
	}
	reservation.Release()
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedAgain, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedAgain.Close() })
	coordinatorAgain, err := NewCoordinator(reopenedAgain)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err = coordinatorAgain.Reserve(ctx, scope)
	if err != nil {
		t.Fatalf("Reserve(after finalize reopen) error = %v", err)
	}
	reservation.Release()
}

func TestSQLiteStoreAccumulatePhaseIsReplayStableAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	store, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("phase_reopen")
	identity := testTeardownIdentity(t, "phase_reopen")
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	delta := Counts{Operations: 4}
	if _, err := teardown.AccumulatePhase(ctx, PhaseOperation, delta); err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	resumed, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatal(err)
	}
	continued, _, err := resumed.BeginTeardown(ctx, scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer continued.Release()
	snapshot, err := continued.AccumulatePhase(ctx, PhaseOperation, delta)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Counts.Operations != 4 {
		t.Fatalf("replayed operation count = %d, want 4", snapshot.Counts.Operations)
	}
}

func TestSQLiteCoordinatorListsRetainedScopesForStartupReconciliation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	store, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := testSessionScope("startup_reconcile")
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, testTeardownIdentity(t, "startup_reconcile"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.AccumulatePhase(ctx, PhaseRuntime, Counts{Sockets: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.MarkIncomplete(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := restarted.ListRetained(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[0].SessionScope != scope || retained[0].Snapshot.State != StateIncomplete || retained[0].Snapshot.Counts.Sockets != 2 {
		t.Fatalf("ListRetained() = %#v", retained)
	}
}

func TestSQLiteStoreRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(context.Background(), path, StoreOptions{}); !errors.Is(err, ErrSchemaVersion) {
		t.Fatalf("NewSQLiteStore() error = %v, want ErrSchemaVersion", err)
	}
}

func TestSQLiteStoreCapacityDoesNotEvictCompleteTombstones(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "session-scopes.sqlite"), StoreOptions{MaxScopes: 1})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	first := testSessionScope("complete")
	identity := testTeardownIdentity(t, "complete")
	teardown, _, err := coordinator.BeginTeardown(ctx, first, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown() error = %v", err)
	}
	if _, err := teardown.MarkComplete(ctx, time.Unix(2, 0).UTC()); err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	teardown.Release()
	if _, _, err := coordinator.BeginTeardown(ctx, testSessionScope("overflow"), testTeardownIdentity(t, "overflow"), time.Unix(3, 0).UTC()); !errors.Is(err, ErrFenceCapacity) {
		t.Fatalf("BeginTeardown(over capacity) error = %v, want ErrFenceCapacity", err)
	}
	snapshot, err := coordinator.Snapshot(ctx, first)
	if err != nil || snapshot.State != StateComplete {
		t.Fatalf("complete tombstone after capacity error = %#v, %v", snapshot, err)
	}
	if err := coordinator.Finalize(ctx, first, identity); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	next, _, err := coordinator.BeginTeardown(ctx, testSessionScope("after_finalize"), testTeardownIdentity(t, "after_finalize"), time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("BeginTeardown(after finalize) error = %v", err)
	}
	next.Release()
}

func TestSQLiteStoreConcurrentEnsureActiveRespectsCapacity(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "session-scopes.sqlite"), StoreOptions{MaxScopes: 1})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	identities := map[string]TeardownIdentity{
		"first":  testTeardownIdentity(t, "concurrent_first"),
		"second": testTeardownIdentity(t, "concurrent_second"),
	}
	for _, scope := range []string{"first", "second"} {
		wg.Add(1)
		go func(scope string) {
			defer wg.Done()
			<-start
			teardown, _, err := coordinator.BeginTeardown(ctx, testSessionScope(scope), identities[scope], time.Now().UTC())
			if err == nil {
				teardown.Release()
			}
			errs <- err
		}(scope)
	}
	close(start)
	wg.Wait()
	close(errs)
	var succeeded, capacity int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrFenceCapacity):
			capacity++
		default:
			t.Fatalf("Reserve() error = %v", err)
		}
	}
	if succeeded != 1 || capacity != 1 {
		t.Fatalf("concurrent results: succeeded=%d capacity=%d", succeeded, capacity)
	}
}
