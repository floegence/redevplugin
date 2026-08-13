package sessionscope

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
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
	if _, err := teardown.Accumulate(ctx, Counts{Surfaces: 2, Executions: 3}); err != nil {
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
	if snapshot.State != StateDraining || snapshot.Counts.Surfaces != 2 || snapshot.Counts.Executions != 3 {
		t.Fatalf("resumed snapshot = %#v", snapshot)
	}
	if _, err := continued.Accumulate(ctx, Counts{StorageHostcalls: 4}); err != nil {
		t.Fatalf("Accumulate(resumed) error = %v", err)
	}
	complete, err := continued.MarkComplete(ctx, time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("MarkComplete() error = %v", err)
	}
	continued.Release()
	if complete.Counts.Surfaces != 2 || complete.Counts.Executions != 3 || complete.Counts.StorageHostcalls != 4 {
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

func TestSQLiteCoordinatorInspectRetainedAcrossReopen(t *testing.T) {
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
	scope := testSessionScope("inspect_reopen")
	identity := testTeardownIdentity(t, "inspect_reopen")
	teardown, _, err := coordinator.BeginTeardown(ctx, scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
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
	retained, err := resumed.InspectRetained(ctx, scope)
	if err != nil || !retained.MatchesIdentity(identity) {
		t.Fatalf("InspectRetained(reopened) = %#v, %v", retained, err)
	}
	if retained.MatchesIdentity(testTeardownIdentity(t, "inspect_reopen_wrong")) {
		t.Fatal("InspectRetained(reopened) matched a different teardown identity")
	}
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
	delta := Counts{Executions: 4}
	if _, err := teardown.AccumulatePhase(ctx, PhaseExecution, delta); err != nil {
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
	snapshot, err := continued.AccumulatePhase(ctx, PhaseExecution, delta)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Counts.Executions != 4 {
		t.Fatalf("replayed execution count = %d, want 4", snapshot.Counts.Executions)
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

func TestSQLiteStoreMigratesV1ParallelExecutionCountsAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session-scopes.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE plugin_session_scope_fences (
			owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL,
			state TEXT NOT NULL, teardown_operation_id TEXT NOT NULL,
			surfaces INTEGER NOT NULL, asset_tickets INTEGER NOT NULL, asset_sessions INTEGER NOT NULL,
			plugin_gateway_tokens INTEGER NOT NULL, confirmation_tokens INTEGER NOT NULL, stream_tickets INTEGER NOT NULL,
			handle_grants INTEGER NOT NULL, confirmations INTEGER NOT NULL, operations INTEGER NOT NULL, streams INTEGER NOT NULL,
			runtime_executions INTEGER NOT NULL, active_network_requests INTEGER NOT NULL, sockets INTEGER NOT NULL,
			network_streams INTEGER NOT NULL, storage_hostcalls INTEGER NOT NULL, proof_sha256 BLOB,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
			PRIMARY KEY(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash))`,
		`CREATE TABLE plugin_session_scope_teardown_phases (
			owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL,
			phase TEXT NOT NULL, counts_json BLOB NOT NULL,
			PRIMARY KEY(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, phase))`,
		`INSERT INTO plugin_session_scope_fences VALUES ('session','user','env','channel','incomplete','close-1',1,2,3,4,5,6,7,8,3,2,4,9,10,11,12,zeroblob(32),1,2)`,
		`INSERT INTO plugin_session_scope_teardown_phases VALUES ('session','user','env','channel','execution','{"runtime_executions":4}')`,
		`INSERT INTO plugin_session_scope_teardown_phases VALUES ('session','user','env','channel','operation','{"operations":3}')`,
		`INSERT INTO plugin_session_scope_teardown_phases VALUES ('session','user','env','channel','stream','{"streams":2}')`,
		`PRAGMA user_version = 1`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(ctx, path, StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	coordinator, err := NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := coordinator.Snapshot(ctx, sessionctx.SessionScope{
		OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel",
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Counts.Executions != 4 || snapshot.Counts.AssetTickets != 2 || snapshot.Counts.StorageHostcalls != 12 {
		t.Fatalf("migrated counts = %#v", snapshot.Counts)
	}
	var version, executionPhases, retiredPhases int
	if err := store.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_session_scope_teardown_phases WHERE phase='execution'`).Scan(&executionPhases); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_session_scope_teardown_phases WHERE phase IN ('operation','stream')`).Scan(&retiredPhases); err != nil {
		t.Fatal(err)
	}
	if version != 2 || executionPhases != 1 || retiredPhases != 0 {
		t.Fatalf("migration metadata version=%d execution=%d retired=%d", version, executionPhases, retiredPhases)
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
