package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

func TestBrokerPaginatesFilesAndKVWithPersistentKeys(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := context.Background()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"z.txt", "a.txt", "d.txt", "b.txt", "c.txt", "nested/child.txt"} {
		if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", StoreID: "files", Path: path, Data: []byte(path)}); err != nil {
			t.Fatal(err)
		}
	}
	var filePaths []string
	cursor := ""
	for {
		page, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", StoreID: "files", MaxEntries: 2, Cursor: cursor})
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
	nested, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", StoreID: "files", Path: "nested", MaxEntries: 1})
	if err != nil || len(nested.Entries) != 1 || nested.Entries[0].Path != "nested/child.txt" || nested.NextCursor != "" {
		t.Fatalf("nested page = %#v, err = %v", nested, err)
	}
	if _, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", StoreID: "files", Path: "nested", Cursor: "a.txt"}); !errors.Is(err, storage.ErrInvalidFilePath) {
		t.Fatalf("cross-directory cursor error = %v", err)
	}

	for _, key := range []string{"beta/1", "alpha/3", "alpha/1", "alpha/2"} {
		if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", StoreID: "kv", Key: key, Value: []byte(key)}); err != nil {
			t.Fatal(err)
		}
	}
	var keys []string
	cursor = ""
	for {
		page, err := store.ListKV(ctx, storage.KVListRequest{PluginInstanceID: "plugini_test", StoreID: "kv", Prefix: "alpha/", MaxEntries: 2, Cursor: cursor})
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
	if _, err := store.ListKV(ctx, storage.KVListRequest{PluginInstanceID: "plugini_test", StoreID: "kv", Prefix: "alpha/", Cursor: "beta/1"}); !errors.Is(err, storage.ErrInvalidKVKey) {
		t.Fatalf("cross-prefix cursor error = %v", err)
	}
}

func TestNamespaceTransactionsEnforceLogicalFileQuotas(t *testing.T) {
	store, _, _ := newInternalStore(t)
	ctx := context.Background()
	shape := Shape{PublisherID: "example", PluginID: "com.example.quota", Settings: settingsdomain.Schema{}, Namespaces: []Namespace{
		{ID: "files", Kind: NamespaceFiles, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 2},
		{ID: "kv", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 1},
	}}
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_quota", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	write, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_quota", StoreID: "files", Path: "notes/a.txt", Data: []byte("a")})
	if err != nil || write.Usage.UsageFiles != 2 {
		t.Fatalf("first file write = %#v, err = %v", write, err)
	}
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_quota", StoreID: "files", Path: "b.txt", Data: []byte("b")}); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("second file write error = %v", err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_quota", StoreID: "kv", Key: "one", Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_quota", StoreID: "kv", Key: "two", Value: []byte("2")}); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("second kv write error = %v", err)
	}
}

func TestNamespaceDatabaseCacheReusesAndClosesGenerationConnections(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := context.Background()
	dataset, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := store.ListFiles(ctx, storage.FileListRequest{PluginInstanceID: "plugini_test", StoreID: "files", MaxEntries: 1}); err != nil {
			t.Fatal(err)
		}
	}
	key := namespaceDatabaseCacheKey(dataset.Binding.GenerationID, "files", NamespaceFiles)
	store.namespaceDBMu.Lock()
	entry := store.namespaceDB[key]
	if entry == nil || entry.db == nil || entry.refs != 0 {
		store.namespaceDBMu.Unlock()
		t.Fatalf("namespace cache entry = %#v", entry)
	}
	db := entry.db
	store.namespaceDBMu.Unlock()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("cached namespace database ping: %v", err)
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
	_, cached := store.namespaceDB[key]
	store.namespaceDBMu.Unlock()
	if cached {
		t.Fatal("generation namespace database remained cached after deletion")
	}
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("deleted generation namespace database remained open")
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
			usage, err := store.cachedNamespaceUsageWithLoader(context.Background(), "generation\x00files", "unused", NamespaceFiles, nil, loader)
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
	if err := initializeNamespaceDatabase(context.Background(), root, NamespaceKV); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
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
	if err := initializeNamespaceDatabase(context.Background(), root, NamespaceKV); err != nil {
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
			db, namespaceRoot, release, err := store.acquireNamespaceDatabase(context.Background(), "generation\x00kv", root, rootInfo)
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
	if err := initializeNamespaceDatabase(context.Background(), root, NamespaceKV); err != nil {
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
	_, _, release, err := store.acquireNamespaceDatabase(context.Background(), "new", root, rootInfo)
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

func TestExportRejectsNonCanonicalFilesNamespaceLayout(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := context.Background()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	binding, _, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(store.workspacePath(binding.GenerationID), namespacesDirName, "files", namespaceDataName)
	if err := os.WriteFile(filepath.Join(dataRoot, "unexpected.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"}); !errors.Is(err, ErrDatasetCorrupt) {
		t.Fatalf("Export() error = %v, want ErrDatasetCorrupt", err)
	}
}
