package plugindata

import (
	"fmt"
	"path/filepath"
	"testing"

	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

const paginationBenchmarkPageSize = 100

func BenchmarkBrokerCursorPagination(b *testing.B) {
	for _, kind := range []NamespaceKind{NamespaceFiles, NamespaceKV} {
		for _, entries := range []int{1_000, 10_000} {
			name := fmt.Sprintf("%s/%d", kind, entries)
			b.Run(name+"/single_page", func(b *testing.B) {
				store := newPaginationBenchmarkStore(b, kind, entries)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if kind == NamespaceFiles {
						result, err := store.ListFiles(internalTestContext(), storage.FileListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: paginationBenchmarkPageSize})
						if err != nil || len(result.Entries) != paginationBenchmarkPageSize {
							b.Fatalf("ListFiles() entries = %d, err = %v", len(result.Entries), err)
						}
					} else {
						result, err := store.ListKV(internalTestContext(), storage.KVListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: paginationBenchmarkPageSize})
						if err != nil || len(result.Entries) != paginationBenchmarkPageSize {
							b.Fatalf("ListKV() entries = %d, err = %v", len(result.Entries), err)
						}
					}
				}
			})
			b.Run(name+"/all_pages", func(b *testing.B) {
				store := newPaginationBenchmarkStore(b, kind, entries)
				b.ReportMetric(float64(entries), "entries")
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					count := pageThroughBenchmarkNamespace(b, store, kind)
					if count != entries {
						b.Fatalf("paginated entries = %d, want %d", count, entries)
					}
				}
			})
		}
	}
}

func newPaginationBenchmarkStore(b *testing.B, kind NamespaceKind, entries int) *FileStore {
	b.Helper()
	root, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	catalog := &internalCatalog{objects: map[string]Object{}}
	store, err := Open(internalTestContext(), root, catalog)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	shape := Shape{
		PublisherID: "example",
		PluginID:    "com.example.bench",
		Settings:    settingsdomain.Schema{},
		Namespaces: []Namespace{{
			ID:            "data",
			Kind:          kind,
			Scope:         "user",
			SchemaVersion: 1,
			QuotaBytes:    64 * 1024 * 1024,
			QuotaFiles:    int64(entries + 100),
		}},
	}
	dataset, err := store.CommitEnable(internalTestContext(), CommitEnableRequest{
		PluginInstanceID:           "plugini_bench",
		Shape:                      shape,
		ExpectedManagementRevision: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	workspaceRoot := store.scopedWorkspacePath(internalEnvironmentScope(), dataset.Binding.GenerationID)
	namespaceRoot := filepath.Join(workspaceNamespaceRoot(workspaceRoot, internalUserScope()), "data", namespaceDataName)
	db, err := openNamespaceDatabase(internalTestContext(), namespaceRoot, false)
	if err != nil {
		b.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		b.Fatal(err)
	}
	updatedAtNS := store.now().UnixNano()
	for i := 0; i < entries; i++ {
		name := fmt.Sprintf("entry-%05d", i)
		if kind == NamespaceKV {
			_, err = tx.Exec(`INSERT INTO kv_entries(key, value, size_bytes, updated_at_ns) VALUES (?, ?, 1, ?)`, name, []byte("x"), updatedAtNS)
		} else {
			_, err = tx.Exec(`INSERT INTO file_entries(path, parent, entry_type, content, size_bytes, updated_at_ns) VALUES (?, '.', ?, ?, 1, ?)`, name, fileEntryTypeFile, []byte("x"), updatedAtNS)
		}
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				b.Fatalf("insert entry: %v; rollback: %v", err, rollbackErr)
			}
			db.Close()
			b.Fatal(err)
		}
	}
	if _, err := tx.Exec(`UPDATE namespace_usage SET usage_bytes = ?, usage_files = ? WHERE singleton = 1`, entries, entries); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			b.Fatalf("update usage: %v; rollback: %v", err, rollbackErr)
		}
		db.Close()
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		b.Fatal(err)
	}
	if err := db.Close(); err != nil {
		b.Fatal(err)
	}
	// Warm the usage cache so the benchmark isolates cursor enumeration.
	if kind == NamespaceFiles {
		_, err = store.ListFiles(internalTestContext(), storage.FileListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: 1})
	} else {
		_, err = store.ListKV(internalTestContext(), storage.KVListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: 1})
	}
	if err != nil {
		b.Fatal(err)
	}
	return store
}

func pageThroughBenchmarkNamespace(b *testing.B, store *FileStore, kind NamespaceKind) int {
	b.Helper()
	count := 0
	cursor := ""
	for {
		if kind == NamespaceFiles {
			result, err := store.ListFiles(internalTestContext(), storage.FileListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: paginationBenchmarkPageSize, Cursor: cursor})
			if err != nil {
				b.Fatal(err)
			}
			count += len(result.Entries)
			cursor = result.NextCursor
		} else {
			result, err := store.ListKV(internalTestContext(), storage.KVListRequest{PluginInstanceID: "plugini_bench", StoreID: "data", MaxEntries: paginationBenchmarkPageSize, Cursor: cursor})
			if err != nil {
				b.Fatal(err)
			}
			count += len(result.Entries)
			cursor = result.NextCursor
		}
		if cursor == "" {
			return count
		}
	}
}
