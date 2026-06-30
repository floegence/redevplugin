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
