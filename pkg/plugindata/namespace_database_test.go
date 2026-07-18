package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

func TestBrokerPaginatesFilesAndKVWithPersistentKeys(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"z.txt", "a.txt", "d.txt", "b.txt", "c.txt", "nested/child.txt"} {
		if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: path, Data: []byte(path)}); err != nil {
			t.Fatal(err)
		}
	}
	var filePaths []string
	cursor := ""
	for {
		page, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", MaxEntries: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Entries {
			filePaths = append(filePaths, entry.Path)
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if want := []string{"a.txt", "b.txt", "c.txt", "d.txt", "nested", "z.txt"}; !reflect.DeepEqual(filePaths, want) {
		t.Fatalf("file paths = %#v, want %#v", filePaths, want)
	}
	nested, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "nested", MaxEntries: 1})
	if err != nil || len(nested.Entries) != 1 || nested.Entries[0].Path != "nested/child.txt" || nested.NextCursor != "" {
		t.Fatalf("nested page = %#v, err = %v", nested, err)
	}
	if _, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "nested", Cursor: "a.txt"}); !errors.Is(err, storage.ErrInvalidFilePath) {
		t.Fatalf("cross-directory cursor error = %v", err)
	}

	for _, key := range []string{"beta/1", "alpha/3", "alpha/1", "alpha/2"} {
		if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: key, Value: []byte(key)}); err != nil {
			t.Fatal(err)
		}
	}
	var keys []string
	cursor = ""
	for {
		page, err := store.ListKV(ctx, storage.KVListRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Prefix: "alpha/", MaxEntries: 2, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range page.Entries {
			keys = append(keys, entry.Key)
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if want := []string{"alpha/1", "alpha/2", "alpha/3"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("kv keys = %#v, want %#v", keys, want)
	}
	if _, err := store.ListKV(ctx, storage.KVListRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Prefix: "alpha/", Cursor: "beta/1"}); !errors.Is(err, storage.ErrInvalidKVKey) {
		t.Fatalf("cross-prefix cursor error = %v", err)
	}
}

func TestNamespaceTransactionsEnforceLogicalFileQuotas(t *testing.T) {
	store, _, _ := newInternalStore(t)
	ctx := internalTestContext()
	shape := Shape{PublisherID: "example", PluginID: "com.example.quota", Settings: settingsdomain.Schema{}, Namespaces: []Namespace{
		{ID: "files", Kind: NamespaceFiles, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 2},
		{ID: "kv", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 1},
	}}
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_quota", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	write, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_quota", ResourceScope: internalUserScope(), StoreID: "files", Path: "notes/a.txt", Data: []byte("a")})
	if err != nil || write.Usage.UsageFiles != 2 {
		t.Fatalf("first file write = %#v, err = %v", write, err)
	}
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_quota", ResourceScope: internalUserScope(), StoreID: "files", Path: "b.txt", Data: []byte("b")}); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("second file write error = %v", err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_quota", ResourceScope: internalUserScope(), StoreID: "kv", Key: "one", Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_quota", ResourceScope: internalUserScope(), StoreID: "kv", Key: "two", Value: []byte("2")}); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("second kv write error = %v", err)
	}
}

func TestNamespaceDatabaseCacheReusesAndClosesGenerationConnections(t *testing.T) {
	store, _, _ := newInternalStore(t)
	ctx := internalTestContext()
	secondUserCtx := sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_second",
		OwnerUserHash:        "owner_user_second",
		OwnerEnvHash:         "owner_env_test",
		SessionChannelIDHash: "channel_second",
	})
	shape := Shape{PublisherID: "example", PluginID: "com.example.cache", Settings: settingsdomain.Schema{}, Namespaces: []Namespace{
		{ID: "user_files", Kind: NamespaceFiles, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 16},
		{ID: "environment_files", Kind: NamespaceFiles, Scope: "environment", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 16},
	}}
	dataset, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []struct {
		ctx     context.Context
		storeID string
		scope   sessionctx.ScopeKind
	}{
		{ctx: ctx, storeID: "user_files", scope: sessionctx.ScopeUser},
		{ctx: secondUserCtx, storeID: "user_files", scope: sessionctx.ScopeUser},
		{ctx: ctx, storeID: "environment_files", scope: sessionctx.ScopeEnvironment},
	} {
		requestScope, err := resourceScope(access.ctx, access.scope)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := store.ListFiles(access.ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", ResourceScope: requestScope, StoreID: access.storeID, MaxEntries: 1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	environment, user, err := requestScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondUser, err := userScope(secondUserCtx)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		namespaceDatabaseCacheKey(scopedGenerationCacheKey(user, dataset.Binding.GenerationID), "user_files", NamespaceFiles),
		namespaceDatabaseCacheKey(scopedGenerationCacheKey(secondUser, dataset.Binding.GenerationID), "user_files", NamespaceFiles),
		namespaceDatabaseCacheKey(scopedGenerationCacheKey(environment, dataset.Binding.GenerationID), "environment_files", NamespaceFiles),
	}
	dbs := make([]*sql.DB, 0, len(keys))
	store.namespaceDBMu.Lock()
	for _, key := range keys {
		entry := store.namespaceDB[key]
		if entry == nil || entry.db == nil || entry.refs != 0 {
			store.namespaceDBMu.Unlock()
			t.Fatalf("namespace cache entry %q = %#v", key, entry)
		}
		dbs = append(dbs, entry.db)
	}
	store.namespaceDBMu.Unlock()
	for _, db := range dbs {
		if err := db.PingContext(ctx); err != nil {
			t.Fatalf("cached namespace database ping: %v", err)
		}
	}
	if _, err := store.CommitUninstall(ctx, CommitUninstallRequest{
		PluginInstanceID:           "plugini_test",
		DeleteData:                 true,
		ExpectedManagementRevision: 2,
		Now:                        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	store.namespaceDBMu.Lock()
	for _, key := range keys {
		if _, cached := store.namespaceDB[key]; cached {
			store.namespaceDBMu.Unlock()
			t.Fatalf("generation namespace database %q remained cached after deletion", key)
		}
	}
	store.namespaceDBMu.Unlock()
	for _, db := range dbs {
		if err := db.PingContext(ctx); err == nil {
			t.Fatal("deleted generation namespace database remained open")
		}
	}
}

func TestDropGenerationUsageClearsEveryScopeForEnvironment(t *testing.T) {
	environment := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_a"}
	user := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_a", OwnerUserHash: "user_a"}
	secondUser := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_a", OwnerUserHash: "user_b"}
	otherUser := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_b", OwnerUserHash: "user_a"}
	targetKeys := []string{
		scopedNamespaceCacheKey(environment, "gen_a", "environment_files"),
		scopedNamespaceCacheKey(user, "gen_a", "user_files"),
		scopedNamespaceCacheKey(secondUser, "gen_a", "user_files"),
	}
	preservedKeys := []string{
		scopedNamespaceCacheKey(environment, "gen_b", "environment_files"),
		scopedNamespaceCacheKey(otherUser, "gen_a", "user_files"),
	}
	store := &FileStore{usage: map[string]namespaceUsage{}}
	for _, key := range append(append([]string{}, targetKeys...), preservedKeys...) {
		store.usage[key] = namespaceUsage{bytes: 1}
		store.sqliteQueries.Store(key, make(chan struct{}, 1))
	}

	store.dropGenerationUsage(environment, "gen_a")

	for _, key := range targetKeys {
		if _, ok := store.usage[key]; ok {
			t.Fatalf("target usage key %q remained cached", key)
		}
		if _, ok := store.sqliteQueries.Load(key); ok {
			t.Fatalf("target sqlite limiter key %q remained cached", key)
		}
	}
	for _, key := range preservedKeys {
		if _, ok := store.usage[key]; !ok {
			t.Fatalf("unrelated usage key %q was removed", key)
		}
		if _, ok := store.sqliteQueries.Load(key); !ok {
			t.Fatalf("unrelated sqlite limiter key %q was removed", key)
		}
	}
}

func TestCachedNamespaceUsageSharesConcurrentMiss(t *testing.T) {
	var loads atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	store := &FileStore{
		usage:        map[string]namespaceUsage{},
		usageFlights: map[string]*namespaceUsageFlight{},
	}
	loader := func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return namespaceUsage{bytes: 42, files: 3}, nil
	}
	const callers = 16
	results := make(chan namespaceUsage, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			usage, err := store.cachedNamespaceUsageWithLoader(internalTestContext(), "generation\x00files", "unused", NamespaceFiles, nil, loader)
			results <- usage
			errs <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(results)
	close(errs)
	if loads.Load() != 1 {
		t.Fatalf("usage loader calls = %d, want 1", loads.Load())
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for usage := range results {
		if usage != (namespaceUsage{bytes: 42, files: 3}) {
			t.Fatalf("usage = %#v", usage)
		}
	}
}

func TestNamespaceDatabaseCacheWaitsWhenEveryEntryIsActive(t *testing.T) {
	root := t.TempDir()
	if err := initializeNamespaceDatabase(internalTestContext(), root, NamespaceKV); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &FileStore{
		namespaceDB:     make(map[string]*namespaceDBEntry, maxNamespaceDatabaseCacheEntries),
		namespaceDBWake: make(chan struct{}),
	}
	for i := 0; i < maxNamespaceDatabaseCacheEntries; i++ {
		key := fmt.Sprintf("generation-%03d", i)
		store.namespaceDB[key] = &namespaceDBEntry{rootPath: key, refs: 1, lastUse: uint64(i + 1)}
	}
	ctx, cancel := context.WithTimeout(internalTestContext(), 10*time.Millisecond)
	defer cancel()
	if _, _, _, err := store.acquireNamespaceDatabase(ctx, "new", root, rootInfo); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquireNamespaceDatabase() error = %v, want context deadline", err)
	}
	if len(store.namespaceDB) != maxNamespaceDatabaseCacheEntries {
		t.Fatalf("namespace cache entries = %d, want %d", len(store.namespaceDB), maxNamespaceDatabaseCacheEntries)
	}
}

func TestNamespaceDatabaseCacheSharesConcurrentOpen(t *testing.T) {
	root := t.TempDir()
	if err := initializeNamespaceDatabase(internalTestContext(), root, NamespaceKV); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &FileStore{namespaceDB: map[string]*namespaceDBEntry{}, namespaceDBWake: make(chan struct{})}
	t.Cleanup(func() { _ = store.closeNamespaceDatabases("") })
	const callers = 16
	type lease struct {
		db      *sql.DB
		root    *os.Root
		release func()
		err     error
	}
	leases := make(chan lease, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			db, namespaceRoot, release, err := store.acquireNamespaceDatabase(internalTestContext(), "generation\x00kv", root, rootInfo)
			leases <- lease{db: db, root: namespaceRoot, release: release, err: err}
		}()
	}
	wg.Wait()
	close(leases)
	var first lease
	for current := range leases {
		if current.err != nil {
			t.Fatal(current.err)
		}
		if first.db == nil {
			first = current
		} else if current.db != first.db || current.root != first.root {
			t.Fatal("concurrent namespace opens did not share the cached resources")
		}
		current.release()
	}
	store.namespaceDBMu.Lock()
	entry := store.namespaceDB["generation\x00kv"]
	store.namespaceDBMu.Unlock()
	if entry == nil || entry.refs != 0 {
		t.Fatalf("namespace cache entry = %#v", entry)
	}
}

func TestNamespaceDatabaseCacheEvictsLeastRecentlyUsedIdleEntry(t *testing.T) {
	root := t.TempDir()
	if err := initializeNamespaceDatabase(internalTestContext(), root, NamespaceKV); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &FileStore{
		namespaceDB:     make(map[string]*namespaceDBEntry, maxNamespaceDatabaseCacheEntries),
		namespaceDBWake: make(chan struct{}),
	}
	for i := 0; i < maxNamespaceDatabaseCacheEntries; i++ {
		key := fmt.Sprintf("cached-%03d", i)
		store.namespaceDB[key] = &namespaceDBEntry{rootPath: key, lastUse: uint64(i + 1)}
	}
	_, _, release, err := store.acquireNamespaceDatabase(internalTestContext(), "new", root, rootInfo)
	if err != nil {
		t.Fatal(err)
	}
	release()
	store.namespaceDBMu.Lock()
	_, oldestPresent := store.namespaceDB["cached-000"]
	entryCount := len(store.namespaceDB)
	store.namespaceDBMu.Unlock()
	if oldestPresent || entryCount != maxNamespaceDatabaseCacheEntries {
		t.Fatalf("oldest present = %v, entries = %d", oldestPresent, entryCount)
	}
	if err := store.closeNamespaceDatabases(""); err != nil {
		t.Fatal(err)
	}
}

func TestExportClosesWarmNamespaceDatabasesBeforeSnapshot(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	for index := range shape.Namespaces {
		if shape.Namespaces[index].ID == "kv" {
			shape.Namespaces[index].QuotaBytes = 4096
		}
	}
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for index := 0; index < 16; index++ {
				_, err := store.PutKV(ctx, storage.KVPutRequest{
					PluginInstanceID: "plugini_test",
					ResourceScope:    internalUserScope(),
					StoreID:          "kv",
					Key:              fmt.Sprintf("worker/%02d/%02d", worker, index),
					Value:            make([]byte, 128),
				})
				if err != nil && !errors.Is(err, storage.ErrQuotaExceeded) {
					errs <- err
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	binding, _, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil {
		t.Fatal(err)
	}
	prefix := generationCachePrefix(internalEnvironmentScope().OwnerEnvHash, binding.GenerationID)
	store.namespaceDBMu.Lock()
	warmEntries := 0
	for key := range store.namespaceDB {
		if strings.HasPrefix(key, prefix) {
			warmEntries++
		}
	}
	store.namespaceDBMu.Unlock()
	if warmEntries == 0 {
		t.Fatal("namespace database cache was not warmed before export")
	}
	exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		workspaceRoot := store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID)
		dataRoot := filepath.Join(workspaceNamespaceRoot(workspaceRoot, internalUserScope()), namespacesDirName, "kv", namespaceDataName)
		entries, readErr := os.ReadDir(dataRoot)
		if readErr != nil {
			t.Fatalf("Export() error = %v; inspect source namespace: %v", err, readErr)
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("Export() error = %v; source namespace entries = %#v", err, names)
	}
	store.namespaceDBMu.Lock()
	for key := range store.namespaceDB {
		if strings.HasPrefix(key, prefix) {
			store.namespaceDBMu.Unlock()
			t.Fatalf("export retained namespace database cache entry %q", key)
		}
	}
	store.namespaceDBMu.Unlock()
	dataRoot := filepath.Join(
		store.scopedObjectPath(internalUserScope(), exported.ObjectID),
		exportPayloadName,
		workspaceScopeRoot("", internalUserScope()),
		namespacesDirName,
		"kv",
		namespaceDataName,
	)
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != namespaceDatabaseName {
		t.Fatalf("exported namespace entries = %#v, want only %s", entries, namespaceDatabaseName)
	}
}

func TestBrokerRejectsUnexpectedPhysicalNamespaceEntries(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "valid", Value: []byte("value")}); err != nil {
		t.Fatal(err)
	}
	binding, _, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(
		store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID),
		workspaceScopeRoot("", internalUserScope()),
		namespacesDirName,
		"kv",
		namespaceDataName,
	)
	if err := os.WriteFile(filepath.Join(dataRoot, "unexpected"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "valid"}); !errors.Is(err, ErrDatasetCorrupt) {
		t.Fatalf("GetKV() error = %v, want ErrDatasetCorrupt", err)
	}
}

func TestBrokerRequiresExactRequestResourceScope(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	shape.Namespaces = append(shape.Namespaces, Namespace{ID: "db", Kind: NamespaceSQLite, Scope: "user", SchemaVersion: 1, QuotaBytes: 1 << 20, QuotaFiles: 8})
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "scope.txt", Data: []byte("scope")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "scope", Value: []byte("scope")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "db", SQL: `CREATE TABLE scoped (id INTEGER PRIMARY KEY)`}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		invoke func(sessionctx.ResourceScope) error
	}{
		{name: "files read", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "files", Path: "scope.txt"})
			return err
		}},
		{name: "files write", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "files", Path: "scope.txt", Data: []byte("scope")})
			return err
		}},
		{name: "files list", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "files"})
			return err
		}},
		{name: "files delete", invoke: func(scope sessionctx.ResourceScope) error {
			return store.DeleteFile(ctx, storage.FileDeleteRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "files", Path: "scope.txt"})
		}},
		{name: "kv get", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "kv", Key: "scope"})
			return err
		}},
		{name: "kv put", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "kv", Key: "scope", Value: []byte("scope")})
			return err
		}},
		{name: "kv list", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.ListKV(ctx, storage.KVListRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "kv"})
			return err
		}},
		{name: "kv delete", invoke: func(scope sessionctx.ResourceScope) error {
			return store.DeleteKV(ctx, storage.KVDeleteRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "kv", Key: "scope"})
		}},
		{name: "sqlite exec", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "db", SQL: `INSERT INTO scoped DEFAULT VALUES`})
			return err
		}},
		{name: "sqlite query", invoke: func(scope sessionctx.ResourceScope) error {
			_, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: "plugini_test", ResourceScope: scope, StoreID: "db", SQL: `SELECT id FROM scoped`})
			return err
		}},
	}
	deniedScopes := []sessionctx.ResourceScope{
		{},
		internalEnvironmentScope(),
		{Kind: sessionctx.ScopeUser, OwnerEnvHash: internalUserScope().OwnerEnvHash, OwnerUserHash: "owner_user_other"},
		{Kind: sessionctx.ScopeUser, OwnerEnvHash: "owner_env_other", OwnerUserHash: internalUserScope().OwnerUserHash},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, denied := range deniedScopes {
				if err := test.invoke(denied); !errors.Is(err, ErrStorageScopeMismatch) {
					t.Fatalf("scope %#v error = %v, want ErrStorageScopeMismatch", denied, err)
				}
			}
		})
	}
}

func TestExportRejectsNonCanonicalFilesNamespaceLayout(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	binding, _, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil {
		t.Fatal(err)
	}
	workspaceRoot := store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID)
	dataRoot := filepath.Join(workspaceNamespaceRoot(workspaceRoot, internalUserScope()), "files", namespaceDataName)
	if err := os.WriteFile(filepath.Join(dataRoot, "unexpected.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"}); !errors.Is(err, ErrDatasetCorrupt) {
		t.Fatalf("Export() error = %v, want ErrDatasetCorrupt", err)
	}
}
