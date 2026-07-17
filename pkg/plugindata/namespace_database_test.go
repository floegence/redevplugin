package plugindata

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
