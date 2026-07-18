package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedNamespaceUsageLeaderCancellationDoesNotCancelFlight(t *testing.T) {
	store := newNamespaceUsageFlightTestStore(t)
	const key = "generation\x00leader-cancel"
	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int32
	loader := func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return namespaceUsage{bytes: 64, files: 4}, nil
	}

	leaderCtx, cancelLeader := context.WithCancel(internalTestContext())
	leaderDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(leaderCtx, namespaceUsageLoadRequest{cacheKey: key, root: "unused", kind: NamespaceFiles}, loader)
		leaderDone <- usageLoadResult{usage: usage, err: err}
	}()
	<-started
	followerDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{cacheKey: key, root: "unused", kind: NamespaceFiles}, loader)
		followerDone <- usageLoadResult{usage: usage, err: err}
	}()
	waitForNamespaceUsageFlightWaiters(t, store, key, 2)
	cancelLeader()
	if result := <-leaderDone; !errors.Is(result.err, context.Canceled) || result.usage != (namespaceUsage{}) {
		t.Fatalf("leader result = %#v, want context canceled", result)
	}
	if loads.Load() != 1 {
		t.Fatalf("usage loader calls after leader cancellation = %d, want 1", loads.Load())
	}
	close(release)
	if result := <-followerDone; result.err != nil || result.usage != (namespaceUsage{bytes: 64, files: 4}) {
		t.Fatalf("follower result = %#v", result)
	}
	assertNamespaceUsageFlightCompleted(t, store, key, namespaceUsage{bytes: 64, files: 4})
}

func TestCachedNamespaceUsageFollowerCancellationDoesNotCancelFlight(t *testing.T) {
	store := newNamespaceUsageFlightTestStore(t)
	const key = "generation\x00follower-cancel"
	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int32
	loader := func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return namespaceUsage{bytes: 32, files: 2}, nil
	}

	leaderDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{cacheKey: key, root: "unused", kind: NamespaceFiles}, loader)
		leaderDone <- usageLoadResult{usage: usage, err: err}
	}()
	<-started
	followerCtx, cancelFollower := context.WithCancel(internalTestContext())
	followerDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(followerCtx, namespaceUsageLoadRequest{cacheKey: key, root: "unused", kind: NamespaceFiles}, loader)
		followerDone <- usageLoadResult{usage: usage, err: err}
	}()
	waitForNamespaceUsageFlightWaiters(t, store, key, 2)
	cancelFollower()
	if result := <-followerDone; !errors.Is(result.err, context.Canceled) || result.usage != (namespaceUsage{}) {
		t.Fatalf("follower result = %#v, want context canceled", result)
	}
	if loads.Load() != 1 {
		t.Fatalf("usage loader calls after follower cancellation = %d, want 1", loads.Load())
	}
	close(release)
	if result := <-leaderDone; result.err != nil || result.usage != (namespaceUsage{bytes: 32, files: 2}) {
		t.Fatalf("leader result = %#v", result)
	}
	assertNamespaceUsageFlightCompleted(t, store, key, namespaceUsage{bytes: 32, files: 2})
}

func TestCachedNamespaceUsageSharesLoaderFailure(t *testing.T) {
	store := newNamespaceUsageFlightTestStore(t)
	const key = "generation\x00shared-failure"
	const callers = 16
	started := make(chan struct{})
	release := make(chan struct{})
	sharedErr := errors.New("stable namespace usage load failure")
	var loads atomic.Int32
	loader := func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return namespaceUsage{}, sharedErr
	}

	results := make(chan usageLoadResult, callers)
	for range callers {
		go func() {
			usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{cacheKey: key, root: "unused", kind: NamespaceFiles}, loader)
			results <- usageLoadResult{usage: usage, err: err}
		}()
	}
	<-started
	waitForNamespaceUsageFlightWaiters(t, store, key, callers)
	close(release)
	for range callers {
		result := <-results
		if result.err != sharedErr || result.usage != (namespaceUsage{}) {
			t.Fatalf("shared failure result = %#v, want exact error %p", result, sharedErr)
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("usage loader calls = %d, want 1", loads.Load())
	}
	store.usageMu.Lock()
	_, cached := store.usage[key]
	_, inFlight := store.usageFlights[key]
	store.usageMu.Unlock()
	if cached || inFlight {
		t.Fatalf("failed usage flight cached=%v in_flight=%v", cached, inFlight)
	}
}

func TestFileStoreCloseCancelsAndDrainsNamespaceUsageFlight(t *testing.T) {
	store := newNamespaceUsageFlightTestStore(t)
	db, err := sql.Open("sqlite", "file:usage-flight-close?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(internalTestContext()); err != nil {
		t.Fatal(err)
	}
	const dbKey = "generation\x00files\x00files"
	const usageKey = "generation\x00files"
	store.namespaceDB[dbKey] = &namespaceDBEntry{db: db, refs: 1, lastUse: 1}
	releaseCallerDB := store.releaseNamespaceDatabase(dbKey)
	started := make(chan struct{})
	cancelObserved := make(chan struct{})
	releaseLoader := make(chan struct{})
	loaderPing := make(chan error, 1)
	loader := func(ctx context.Context, _ string, _ NamespaceKind, db *sql.DB) (namespaceUsage, error) {
		close(started)
		<-ctx.Done()
		close(cancelObserved)
		<-releaseLoader
		loaderPing <- db.PingContext(context.Background())
		return namespaceUsage{}, ctx.Err()
	}
	loadDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{
			cacheKey:    usageKey,
			root:        "unused",
			kind:        NamespaceFiles,
			databaseKey: dbKey,
			database:    db,
		}, loader)
		loadDone <- usageLoadResult{usage: usage, err: err}
	}()
	<-started
	waitForNamespaceUsageFlightWaiters(t, store, usageKey, 1)
	store.namespaceDBMu.Lock()
	refsBeforeRelease := store.namespaceDB[dbKey].refs
	store.namespaceDBMu.Unlock()
	if refsBeforeRelease != 2 {
		t.Fatalf("namespace database refs before caller release = %d, want 2", refsBeforeRelease)
	}
	releaseCallerDB()
	store.namespaceDBMu.Lock()
	refsAfterRelease := store.namespaceDB[dbKey].refs
	store.namespaceDBMu.Unlock()
	if refsAfterRelease != 1 {
		t.Fatalf("namespace database refs after caller release = %d, want flight-owned ref", refsAfterRelease)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	<-cancelObserved
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before loader drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := db.PingContext(internalTestContext()); err != nil {
		t.Fatalf("flight-owned database closed before loader returned: %v", err)
	}
	close(releaseLoader)
	if err := <-loaderPing; err != nil {
		t.Fatalf("loader database ping after store cancellation: %v", err)
	}
	if result := <-loadDone; !errors.Is(result.err, context.Canceled) || result.usage != (namespaceUsage{}) {
		t.Fatalf("load result after Close() = %#v", result)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(internalTestContext()); err == nil {
		t.Fatal("namespace database remained open after Close() drained the usage loader")
	}
	store.namespaceDBMu.Lock()
	databaseEntries := len(store.namespaceDB)
	store.namespaceDBMu.Unlock()
	if databaseEntries != 0 {
		t.Fatalf("namespace database cache entries after Close() = %d, want 0", databaseEntries)
	}
	var postCloseLoads atomic.Int32
	if _, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{cacheKey: "post-close", root: "unused", kind: NamespaceFiles}, func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
		postCloseLoads.Add(1)
		return namespaceUsage{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-close usage load error = %v, want context canceled", err)
	}
	if postCloseLoads.Load() != 0 {
		t.Fatalf("post-close loader calls = %d, want 0", postCloseLoads.Load())
	}
}

func TestCloseNamespaceDatabasesRejectsDatabaseFreeUsageFlight(t *testing.T) {
	store := newNamespaceUsageFlightTestStore(t)
	environment := internalEnvironmentScope()
	const generationID = "gen_usage_flight"
	prefix := generationCachePrefix(environment.OwnerEnvHash, generationID)
	key := scopedNamespaceCacheKey(internalUserScope(), generationID, "sqlite")
	started := make(chan struct{})
	release := make(chan struct{})
	loadDone := make(chan usageLoadResult, 1)
	go func() {
		usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), namespaceUsageLoadRequest{
			cacheKey: key,
			root:     "unused",
			kind:     NamespaceSQLite,
		}, func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
			close(started)
			<-release
			return namespaceUsage{bytes: 4096, files: 1}, nil
		})
		loadDone <- usageLoadResult{usage: usage, err: err}
	}()
	<-started
	waitForNamespaceUsageFlightWaiters(t, store, key, 1)
	if err := store.closeNamespaceDatabases(prefix); !errors.Is(err, errNamespaceUsageInUse) {
		t.Fatalf("closeNamespaceDatabases() error = %v, want active usage flight", err)
	}
	close(release)
	if result := <-loadDone; result.err != nil || result.usage != (namespaceUsage{bytes: 4096, files: 1}) {
		t.Fatalf("database-free usage result = %#v", result)
	}
	if err := store.closeNamespaceDatabases(prefix); err != nil {
		t.Fatalf("closeNamespaceDatabases() after usage flight = %v", err)
	}
}

func TestScanNamespaceUsageHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(internalTestContext())
	cancel()
	if _, err := scanNamespaceUsage(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("scanNamespaceUsage() error = %v, want context canceled", err)
	}
}

type usageLoadResult struct {
	usage namespaceUsage
	err   error
}

func newNamespaceUsageFlightTestStore(t *testing.T) *FileStore {
	t.Helper()
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	store := &FileStore{
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		locks:           keyedLocks{locks: map[string]*keyedLock{}},
		usage:           map[string]namespaceUsage{},
		usageFlights:    map[string]*namespaceUsageFlight{},
		namespaceDB:     map[string]*namespaceDBEntry{},
		namespaceDBWake: make(chan struct{}),
		namespaceLocks:  keyedLocks{locks: map[string]*keyedLock{}},
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func waitForNamespaceUsageFlightWaiters(t *testing.T, store *FileStore, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		store.usageMu.Lock()
		flight := store.usageFlights[key]
		waiters := 0
		if flight != nil {
			waiters = flight.waiters
		}
		store.usageMu.Unlock()
		if waiters == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage flight waiters = %d, want %d", waiters, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNamespaceUsageFlightCompleted(t *testing.T, store *FileStore, key string, want namespaceUsage) {
	t.Helper()
	store.usageMu.Lock()
	cached, cachedOK := store.usage[key]
	_, inFlight := store.usageFlights[key]
	store.usageMu.Unlock()
	if !cachedOK || cached != want || inFlight {
		t.Fatalf("usage cache = %#v cached=%v in_flight=%v, want %#v", cached, cachedOK, inFlight, want)
	}
}
