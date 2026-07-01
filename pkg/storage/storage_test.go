package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMemoryBrokerNamespaceLifecycle(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	ns := Namespace{
		PluginInstanceID: "plugini_test",
		StoreID:          "cache",
		Kind:             StoreKV,
		Scope:            "user",
		QuotaBytes:       1024,
		SchemaVersion:    2,
	}

	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatalf("EnsureNamespace() error = %v", err)
	}
	if err := broker.SetUsage(ctx, ns.PluginInstanceID, ns.StoreID, 512); err != nil {
		t.Fatalf("SetUsage() error = %v", err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatalf("Usage() error = %v", err)
	}
	if usage.UsageBytes != 512 || usage.QuotaBytes != 1024 {
		t.Fatalf("usage mismatch: %#v", usage)
	}
	if err := broker.SetUsage(ctx, ns.PluginInstanceID, ns.StoreID, 2048); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("SetUsage() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestMemoryBrokerRetainsAndDeletesNamespaces(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	ns := Namespace{
		PluginInstanceID: "plugini_test",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       4096,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}

	if err := broker.DeleteNamespace(ctx, ns.PluginInstanceID, false); err != nil {
		t.Fatalf("DeleteNamespace(retain) error = %v", err)
	}
	retained, err := broker.ListNamespaces(ctx, ns.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[0].State != NamespaceRetained || retained[0].RetainedAt == nil {
		t.Fatalf("retained namespace mismatch: %#v", retained)
	}

	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatalf("EnsureNamespace() after retain error = %v", err)
	}
	active, err := broker.ListNamespaces(ctx, ns.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].State != NamespaceActive || active[0].RetainedAt != nil {
		t.Fatalf("reactivated namespace mismatch: %#v", active)
	}

	if err := broker.DeleteNamespace(ctx, ns.PluginInstanceID, true); err != nil {
		t.Fatalf("DeleteNamespace(delete) error = %v", err)
	}
	deleted, err := broker.ListNamespaces(ctx, ns.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("namespaces were not deleted: %#v", deleted)
	}
}

func TestMemoryBrokerKVStoreReadWriteListDelete(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	ns := Namespace{
		PluginInstanceID: "plugini_kv",
		StoreID:          "prefs",
		Kind:             StoreKV,
		QuotaBytes:       16,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	written, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "ui/theme",
		Value:            []byte("dark"),
	})
	if err != nil {
		t.Fatalf("PutKV() error = %v", err)
	}
	if written.Key != "ui/theme" || written.SizeBytes != 4 || written.Usage.UsageBytes != 4 {
		t.Fatalf("PutKV() result mismatch: %#v", written)
	}
	read, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "ui/theme",
	})
	if err != nil {
		t.Fatalf("GetKV() error = %v", err)
	}
	if string(read.Value) != "dark" || read.Usage.UsageBytes != 4 {
		t.Fatalf("GetKV() result mismatch: value=%q result=%#v", string(read.Value), read)
	}
	list, err := broker.ListKV(ctx, KVListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Prefix:           "ui/",
	})
	if err != nil {
		t.Fatalf("ListKV() error = %v", err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Key != "ui/theme" || list.Usage.UsageBytes != 4 {
		t.Fatalf("ListKV() result mismatch: %#v", list)
	}
	if _, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "blob",
		Value:            []byte("0123456789abcdef0"),
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("PutKV(quota) error = %v, want ErrQuotaExceeded", err)
	}
	if _, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "ui/theme",
		MaxBytes:         3,
	}); !errors.Is(err, ErrKVValueTooLarge) {
		t.Fatalf("GetKV(max bytes) error = %v, want ErrKVValueTooLarge", err)
	}
	if err := broker.DeleteKV(ctx, KVDeleteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "ui/theme",
	}); err != nil {
		t.Fatalf("DeleteKV() error = %v", err)
	}
	if _, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "ui/theme",
	}); !errors.Is(err, ErrKVKeyNotFound) {
		t.Fatalf("GetKV(deleted) error = %v, want ErrKVKeyNotFound", err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes != 0 {
		t.Fatalf("usage after DeleteKV = %d, want 0", usage.UsageBytes)
	}
}

func TestMemoryBrokerKVStoreExportImportAndDeleteData(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	source := Namespace{
		PluginInstanceID: "plugini_source",
		StoreID:          "prefs",
		Kind:             StoreKV,
		QuotaBytes:       64,
	}
	if err := broker.EnsureNamespace(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: source.PluginInstanceID,
		StoreID:          source.StoreID,
		Key:              "city",
		Value:            []byte("Shanghai"),
	}); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportData() error = %v", err)
	}
	if err := broker.DeleteNamespace(ctx, source.PluginInstanceID, true); err != nil {
		t.Fatal(err)
	}
	target := Namespace{
		StoreID:    "prefs",
		Kind:       StoreKV,
		QuotaBytes: 64,
	}
	if err := broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		TargetNamespaces: []Namespace{target},
	}); err != nil {
		t.Fatalf("ImportData() error = %v", err)
	}
	read, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: "plugini_target",
		StoreID:          "prefs",
		Key:              "city",
	})
	if err != nil {
		t.Fatalf("GetKV(imported) error = %v", err)
	}
	if string(read.Value) != "Shanghai" || read.Usage.UsageBytes != int64(len("Shanghai")) {
		t.Fatalf("imported KV mismatch: value=%q result=%#v", string(read.Value), read)
	}
	if err := broker.DeleteNamespace(ctx, "plugini_target", true); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: "plugini_target",
		StoreID:          "prefs",
		Key:              "city",
	}); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("GetKV(after delete data) error = %v, want ErrNamespaceNotFound", err)
	}
}

func TestMemoryBrokerExportImport(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	if err := broker.EnsureNamespace(ctx, Namespace{
		PluginInstanceID: "plugini_source",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       8192,
		SchemaVersion:    4,
	}); err != nil {
		t.Fatal(err)
	}
	if err := broker.SetUsage(ctx, "plugini_source", "db", 4096); err != nil {
		t.Fatal(err)
	}

	archiveRef, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: "plugini_source"})
	if err != nil {
		t.Fatalf("ExportData() error = %v", err)
	}
	if archiveRef == "" {
		t.Fatal("ExportData() returned empty archive ref")
	}
	if err := broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
	}); err != nil {
		t.Fatalf("ImportData() error = %v", err)
	}

	target, err := broker.ListNamespaces(ctx, "plugini_target")
	if err != nil {
		t.Fatal(err)
	}
	if len(target) != 1 {
		t.Fatalf("imported namespace count = %d", len(target))
	}
	if target[0].PluginInstanceID != "plugini_target" || target[0].StoreID != "db" || target[0].UsageBytes != 4096 {
		t.Fatalf("imported namespace mismatch: %#v", target[0])
	}

	if err := broker.DeleteNamespace(ctx, "plugini_source", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := broker.Archive(archiveRef); !ok {
		t.Fatal("exported archive should outlive source namespace deletion")
	}
}

func TestMemoryBrokerImportHonorsTargetNamespaces(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	if err := broker.EnsureNamespace(ctx, Namespace{
		PluginInstanceID: "plugini_source",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       8192,
		SchemaVersion:    1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := broker.SetUsage(ctx, "plugini_source", "db", 4096); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: "plugini_source"})
	if err != nil {
		t.Fatal(err)
	}

	err = broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		TargetNamespaces: []Namespace{{
			StoreID:    "db",
			Kind:       StoreSQLite,
			QuotaBytes: 1024,
		}},
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("ImportData() error = %v, want ErrQuotaExceeded", err)
	}

	err = broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		TargetNamespaces: []Namespace{{
			StoreID:    "cache",
			Kind:       StoreKV,
			QuotaBytes: 8192,
		}},
	})
	if !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("ImportData() error = %v, want ErrInvalidNamespace", err)
	}
}

func TestFileBrokerNamespaceLifecycle(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_test/with/slashes",
		StoreID:          "workspace/../files",
		Kind:             StoreFiles,
		Scope:            "user",
		QuotaBytes:       16,
		SchemaVersion:    3,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatalf("EnsureNamespace() error = %v", err)
	}
	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatalf("NamespacePath() error = %v", err)
	}
	assertUnderRoot(t, broker.Root(), dataPath)
	if strings.Contains(filepath.ToSlash(dataPath), "../") {
		t.Fatalf("namespace path contains traversal segment: %s", dataPath)
	}
	if err := os.WriteFile(filepath.Join(dataPath, "note.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatalf("Usage() error = %v", err)
	}
	if usage.UsageBytes != 5 || usage.QuotaBytes != 16 {
		t.Fatalf("usage mismatch: %#v", usage)
	}
	if err := os.WriteFile(filepath.Join(dataPath, "too-large.txt"), []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Usage() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestFileBrokerRetainsAndDeletesNamespaceDirectories(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_test",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       128,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(dataPath, "kept.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := broker.DeleteNamespace(ctx, ns.PluginInstanceID, false); err != nil {
		t.Fatalf("DeleteNamespace(retain) error = %v", err)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("retained namespace data missing: %v", err)
	}
	retained, err := broker.ListNamespaces(ctx, ns.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[0].State != NamespaceRetained || retained[0].RetainedAt == nil {
		t.Fatalf("retained namespace mismatch: %#v", retained)
	}
	if _, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("NamespacePath(retained) error = %v, want ErrNamespaceNotFound", err)
	}

	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatalf("EnsureNamespace() after retain error = %v", err)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("reactivated namespace data missing: %v", err)
	}
	if err := broker.DeleteNamespace(ctx, ns.PluginInstanceID, true); err != nil {
		t.Fatalf("DeleteNamespace(delete) error = %v", err)
	}
	if _, err := os.Stat(filePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted namespace file stat error = %v, want not exist", err)
	}
	deleted, err := broker.ListNamespaces(ctx, ns.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted namespace still listed: %#v", deleted)
	}
}

func TestFileBrokerExportImportCopiesData(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	source := Namespace{
		PluginInstanceID: "plugini_source",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       128,
		SchemaVersion:    2,
	}
	if err := broker.EnsureNamespace(ctx, source); err != nil {
		t.Fatal(err)
	}
	sourcePath, err := broker.NamespacePath(ctx, source.PluginInstanceID, source.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "plugin.sqlite"), []byte("sqlite bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportData() error = %v", err)
	}

	target := Namespace{
		StoreID:       "db",
		Kind:          StoreSQLite,
		QuotaBytes:    128,
		SchemaVersion: 3,
	}
	if err := broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		TargetNamespaces: []Namespace{target},
	}); err != nil {
		t.Fatalf("ImportData() error = %v", err)
	}
	targetPath, err := broker.NamespacePath(ctx, "plugini_target", "db")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(targetPath, "plugin.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sqlite bytes" {
		t.Fatalf("imported data = %q", string(data))
	}
	usage, err := broker.Usage(ctx, "plugini_target", "db")
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes != int64(len("sqlite bytes")) {
		t.Fatalf("imported usage = %d", usage.UsageBytes)
	}
}

func TestFileBrokerFilesStoreReadWriteListDelete(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_files",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       64,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	written, err := broker.WriteFile(ctx, FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "notes/today.txt",
		Data:             []byte("hello"),
	})
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if written.Path != "notes/today.txt" || written.SizeBytes != 5 || written.Usage.UsageBytes != 5 {
		t.Fatalf("write result mismatch: %#v", written)
	}
	read, err := broker.ReadFile(ctx, FileReadRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "notes/today.txt",
	})
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(read.Data) != "hello" || read.Usage.UsageBytes != 5 {
		t.Fatalf("read result mismatch: data=%q result=%#v", string(read.Data), read)
	}
	list, err := broker.ListFiles(ctx, FileListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "notes",
	})
	if err != nil {
		t.Fatalf("ListFiles() error = %v", err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Path != "notes/today.txt" || list.Entries[0].Dir {
		t.Fatalf("list result mismatch: %#v", list)
	}
	if err := broker.DeleteFile(ctx, FileDeleteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "notes/today.txt",
	}); err != nil {
		t.Fatalf("DeleteFile() error = %v", err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes != 0 {
		t.Fatalf("usage after delete = %d, want 0", usage.UsageBytes)
	}
}

func TestFileBrokerKVStoreReadWriteListDelete(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_kv",
		StoreID:          "prefs",
		Kind:             StoreKV,
		QuotaBytes:       64,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	written, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "weather.location",
		Value:            []byte("London"),
	})
	if err != nil {
		t.Fatalf("PutKV() error = %v", err)
	}
	if written.Key != "weather.location" || written.SizeBytes != 6 || written.Usage.UsageBytes != 6 {
		t.Fatalf("PutKV() result mismatch: %#v", written)
	}
	read, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "weather.location",
	})
	if err != nil {
		t.Fatalf("GetKV() error = %v", err)
	}
	if string(read.Value) != "London" || read.Usage.UsageBytes != 6 {
		t.Fatalf("GetKV() result mismatch: value=%q result=%#v", string(read.Value), read)
	}
	if _, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "oversized",
		Value:            []byte(strings.Repeat("x", 65)),
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("PutKV(quota) error = %v, want ErrQuotaExceeded", err)
	}
	list, err := broker.ListKV(ctx, KVListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Prefix:           "weather.",
	})
	if err != nil {
		t.Fatalf("ListKV() error = %v", err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Key != "weather.location" || list.Usage.UsageBytes != 6 {
		t.Fatalf("ListKV() result mismatch: %#v", list)
	}
	if err := broker.DeleteKV(ctx, KVDeleteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "weather.location",
	}); err != nil {
		t.Fatalf("DeleteKV() error = %v", err)
	}
	if _, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Key:              "weather.location",
	}); !errors.Is(err, ErrKVKeyNotFound) {
		t.Fatalf("GetKV(deleted) error = %v, want ErrKVKeyNotFound", err)
	}
}

func TestFileBrokerKVStoreExportImportCopiesValues(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	source := Namespace{
		PluginInstanceID: "plugini_source",
		StoreID:          "prefs",
		Kind:             StoreKV,
		QuotaBytes:       64,
	}
	if err := broker.EnsureNamespace(ctx, source); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PutKV(ctx, KVPutRequest{
		PluginInstanceID: source.PluginInstanceID,
		StoreID:          source.StoreID,
		Key:              "theme",
		Value:            []byte("teal"),
	}); err != nil {
		t.Fatal(err)
	}
	archiveRef, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportData() error = %v", err)
	}
	if err := broker.DeleteNamespace(ctx, source.PluginInstanceID, true); err != nil {
		t.Fatal(err)
	}
	target := Namespace{
		StoreID:    "prefs",
		Kind:       StoreKV,
		QuotaBytes: 64,
	}
	if err := broker.ImportData(ctx, ImportRequest{
		PluginInstanceID: "plugini_target",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		TargetNamespaces: []Namespace{target},
	}); err != nil {
		t.Fatalf("ImportData() error = %v", err)
	}
	read, err := broker.GetKV(ctx, KVGetRequest{
		PluginInstanceID: "plugini_target",
		StoreID:          "prefs",
		Key:              "theme",
	})
	if err != nil {
		t.Fatalf("GetKV(imported) error = %v", err)
	}
	if string(read.Value) != "teal" || read.Usage.UsageBytes != int64(len("teal")) {
		t.Fatalf("imported KV mismatch: value=%q result=%#v", string(read.Value), read)
	}
}

func TestFileBrokerImplementsSQLiteBroker(t *testing.T) {
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	var _ SQLiteBroker = broker
}

func TestFileBrokerSQLiteExecQueryAndArguments(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       1 << 20,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, score INTEGER NOT NULL, ratio REAL, payload BLOB, nullable TEXT)",
	}); err != nil {
		t.Fatalf("ExecSQLite(create) error = %v", err)
	}

	title := "Launch demo"
	score := int64(42)
	ratio := 1.25
	written, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "INSERT INTO events (title, score, ratio, payload, nullable) VALUES (?, ?, ?, ?, ?)",
		Args: []SQLiteValue{
			{Text: &title},
			{Int: &score},
			{Float: &ratio},
			{Blob: []byte("blob-value")},
			{Null: true},
		},
	})
	if err != nil {
		t.Fatalf("ExecSQLite(insert) error = %v", err)
	}
	if written.Database != "plugin.sqlite" || written.RowsAffected != 1 || written.LastInsertID != 1 || written.Usage.UsageBytes == 0 {
		t.Fatalf("ExecSQLite(insert) result mismatch: %#v", written)
	}

	query, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT title, score, ratio, payload, nullable FROM events WHERE score = ?",
		Args:             []SQLiteValue{{Int: &score}},
	})
	if err != nil {
		t.Fatalf("QuerySQLite() error = %v", err)
	}
	if query.Database != "plugin.sqlite" || len(query.Columns) != 5 || len(query.Rows) != 1 {
		t.Fatalf("QuerySQLite() result shape mismatch: %#v", query)
	}
	row := query.Rows[0]
	if row[0].Text == nil || *row[0].Text != title {
		t.Fatalf("title value mismatch: %#v", row[0])
	}
	if row[1].Int == nil || *row[1].Int != score {
		t.Fatalf("score value mismatch: %#v", row[1])
	}
	if row[2].Float == nil || *row[2].Float != ratio {
		t.Fatalf("ratio value mismatch: %#v", row[2])
	}
	if string(row[3].Blob) != "blob-value" {
		t.Fatalf("blob value mismatch: %#v", row[3])
	}
	if !row[4].Null {
		t.Fatalf("null value mismatch: %#v", row[4])
	}
	if query.Usage.UsageBytes == 0 || query.Usage.QuotaBytes != ns.QuotaBytes {
		t.Fatalf("QuerySQLite() usage mismatch: %#v", query.Usage)
	}
}

func TestFileBrokerSQLiteRejectsSymlinkDatabase(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       1 << 20,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.sqlite")
	if err := os.WriteFile(outside, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataPath, "plugin.sqlite")); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE x (id INTEGER)",
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("ExecSQLite(symlink database) error = %v, want ErrInvalidFilePath", err)
	}
	if _, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT 1",
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("QuerySQLite(symlink database) error = %v, want ErrInvalidFilePath", err)
	}
}

func TestFileBrokerSQLiteRejectsInvalidBoundary(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	if err := broker.EnsureNamespace(ctx, Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       1 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Database:         "../escape.sqlite",
		SQL:              "CREATE TABLE x (id INTEGER)",
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("ExecSQLite(traversal database) error = %v, want ErrInvalidFilePath", err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Database:         "plugin.txt",
		SQL:              "CREATE TABLE x (id INTEGER)",
	}); !errors.Is(err, ErrInvalidSQLite) {
		t.Fatalf("ExecSQLite(extension) error = %v, want ErrInvalidSQLite", err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		SQL:              "ATTACH DATABASE 'other.db' AS other",
	}); !errors.Is(err, ErrInvalidSQLite) {
		t.Fatalf("ExecSQLite(attach) error = %v, want ErrInvalidSQLite", err)
	}
}

func TestFileBrokerSQLiteRejectsWrongNamespaceKindAndQueryWrites(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	if err := broker.EnsureNamespace(ctx, Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "prefs",
		Kind:             StoreKV,
		QuotaBytes:       1 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "prefs",
		SQL:              "CREATE TABLE x (id INTEGER)",
	}); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("ExecSQLite(wrong namespace) error = %v, want ErrInvalidNamespace", err)
	}

	if err := broker.EnsureNamespace(ctx, Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       1 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		SQL:              "CREATE TABLE x (id INTEGER)",
	}); err != nil {
		t.Fatalf("ExecSQLite(create) error = %v", err)
	}
	if _, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		SQL:              "INSERT INTO x (id) VALUES (1)",
	}); err == nil {
		t.Fatal("QuerySQLite(insert) succeeded, want query-only error")
	}
}

func TestFileBrokerSQLiteLimitsRowsAndResponseBytes(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       1 << 20,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE items (name TEXT)",
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		n := name
		if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
			PluginInstanceID: ns.PluginInstanceID,
			StoreID:          ns.StoreID,
			SQL:              "INSERT INTO items (name) VALUES (?)",
			Args:             []SQLiteValue{{Text: &n}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT name FROM items ORDER BY name",
		MaxRows:          1,
	}); !errors.Is(err, ErrSQLiteResultTooLarge) {
		t.Fatalf("QuerySQLite(max rows) error = %v, want ErrSQLiteResultTooLarge", err)
	}
	if _, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT name FROM items ORDER BY name LIMIT 1",
		MaxResponseBytes: 3,
	}); !errors.Is(err, ErrSQLiteResultTooLarge) {
		t.Fatalf("QuerySQLite(max response) error = %v, want ErrSQLiteResultTooLarge", err)
	}
}

func TestFileBrokerSQLiteQuotaRollback(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_sqlite",
		StoreID:          "db",
		Kind:             StoreSQLite,
		QuotaBytes:       16 * 1024,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE items (body TEXT)",
	}); err != nil {
		t.Fatal(err)
	}
	before, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 128*1024)
	if _, err := broker.ExecSQLite(ctx, SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "INSERT INTO items (body) VALUES (?)",
		Args:             []SQLiteValue{{Text: &body}},
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("ExecSQLite(quota) error = %v, want ErrQuotaExceeded", err)
	}
	after, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if after.UsageBytes != before.UsageBytes {
		t.Fatalf("usage after failed sqlite write = %d, want rollback to %d", after.UsageBytes, before.UsageBytes)
	}
	query, err := broker.QuerySQLite(ctx, SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT COUNT(*) FROM items",
	})
	if err != nil {
		t.Fatalf("QuerySQLite(count) error = %v", err)
	}
	if query.Rows[0][0].Int == nil || *query.Rows[0][0].Int != 0 {
		t.Fatalf("row count after rollback mismatch: %#v", query.Rows)
	}
}

func TestFileBrokerFilesStoreEnforcesQuotaAndSafePaths(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_files",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       8,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.WriteFile(ctx, FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "too-large.txt",
		Data:             []byte("0123456789"),
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("WriteFile(quota) error = %v, want ErrQuotaExceeded", err)
	}
	if _, err := broker.WriteFile(ctx, FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "../escape.txt",
		Data:             []byte("nope"),
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("WriteFile(traversal) error = %v, want ErrInvalidFilePath", err)
	}
	if _, err := broker.ReadFile(ctx, FileReadRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "/absolute.txt",
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("ReadFile(absolute) error = %v, want ErrInvalidFilePath", err)
	}
	if _, err := broker.ReadFile(ctx, FileReadRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "missing.txt",
	}); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("ReadFile(missing) error = %v, want ErrFileNotFound", err)
	}
	if _, err := broker.ListFiles(ctx, FileListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "missing",
	}); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("ListFiles(missing) error = %v, want ErrFileNotFound", err)
	}
	if _, err := broker.WriteFile(ctx, FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "small.txt",
		Data:             []byte("12345678"),
	}); err != nil {
		t.Fatalf("WriteFile(small) error = %v", err)
	}
	if _, err := broker.ReadFile(ctx, FileReadRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "small.txt",
		MaxBytes:         4,
	}); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("ReadFile(max bytes) error = %v, want ErrFileTooLarge", err)
	}
}

func TestFileBrokerFilesStoreRejectsSymlinkTargets(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_files",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       128,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataPath, "link.txt")); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, err := broker.ReadFile(ctx, FileReadRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "link.txt",
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("ReadFile(symlink) error = %v, want ErrInvalidFilePath", err)
	}
	if _, err := broker.ListFiles(ctx, FileListRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("ListFiles(symlink) error = %v, want ErrInvalidFilePath", err)
	}
	if err := os.MkdirAll(filepath.Join(dataPath, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataPath, "dir", "link.txt")); err != nil {
		t.Skipf("nested symlink unavailable on this platform: %v", err)
	}
	if err := broker.DeleteFile(ctx, FileDeleteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "dir",
		Recursive:        true,
	}); !errors.Is(err, ErrInvalidFilePath) {
		t.Fatalf("DeleteFile(nested symlink) error = %v, want ErrInvalidFilePath", err)
	}
}

func TestFileBrokerRejectsSymlinkNamespaces(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_test",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       128,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(dataPath, "outside")); err != nil {
		t.Skipf("symlink unavailable on this platform: %v", err)
	}
	if _, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("Usage() error = %v, want ErrInvalidNamespace", err)
	}
	if _, err := broker.ExportData(ctx, ExportRequest{PluginInstanceID: ns.PluginInstanceID}); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("ExportData() error = %v, want ErrInvalidNamespace", err)
	}
}

func TestFileBrokerRejectsMismatchedNamespaceMetadata(t *testing.T) {
	ctx := context.Background()
	broker, err := NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	ns := Namespace{
		PluginInstanceID: "plugini_test",
		StoreID:          "workspace",
		Kind:             StoreFiles,
		QuotaBytes:       128,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(broker.Root(), fileBrokerNamespacesDir, pathSegment(ns.PluginInstanceID), pathSegment(ns.StoreID), fileBrokerNamespaceFile)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var record NamespaceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record.PluginInstanceID = "plugini_other"
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("Usage() error = %v, want ErrInvalidNamespace", err)
	}
	if _, err := broker.ListNamespaces(ctx, ns.PluginInstanceID); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("ListNamespaces() error = %v, want ErrInvalidNamespace", err)
	}
}

func assertUnderRoot(t *testing.T, root string, path string) {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("filepath.Rel() error = %v", err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		t.Fatalf("path %q is not under root %q", path, root)
	}
}
