package storage

import (
	"context"
	"errors"
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
