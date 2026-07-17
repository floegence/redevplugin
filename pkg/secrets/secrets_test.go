package secrets

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreLifecycleListAndDeletePlugin(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time {
		now = now.Add(time.Second)
		return now
	}})
	ctx := context.Background()

	req := BindRequest{PluginInstanceID: " plugin_1 ", SecretRef: " api_token ", Scope: ScopeUser}
	if err := store.BindSecretRef(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := store.TestSecretRef(ctx, TestRequest(req)); err != nil {
		t.Fatal(err)
	}
	if err := store.BindSecretRef(ctx, BindRequest{PluginInstanceID: "plugin_2", SecretRef: "env_token", Scope: ScopeEnvironment}); err != nil {
		t.Fatal(err)
	}

	records, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", BoundOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].SecretRef != "api_token" || records[0].Scope != ScopeUser || !records[0].Bound || records[0].LastTestStatus != "passed" {
		t.Fatalf("List() = %#v", records)
	}
	records[0].SecretRef = "mutated"
	again, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1"})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].SecretRef != "api_token" {
		t.Fatalf("List() returned mutable records: %#v", again)
	}

	if err := store.DeleteSecretRef(ctx, DeleteRequest(req)); err != nil {
		t.Fatal(err)
	}
	records, err = store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", BoundOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("deleted secret should not be listed as bound: %#v", records)
	}
	records, err = store.List(ctx, ListRequest{PluginInstanceID: "plugin_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Bound || records[0].DeletedAt == nil || records[0].LastTestStatus != "" {
		t.Fatalf("deleted secret record mismatch: %#v", records)
	}

	if err := store.DeletePlugin(ctx, "plugin_1"); err != nil {
		t.Fatal(err)
	}
	records, err = store.List(ctx, ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PluginInstanceID != "plugin_2" {
		t.Fatalf("DeletePlugin() records = %#v", records)
	}
}

func TestMemoryStoreRejectsInvalidSecretLifecycle(t *testing.T) {
	store := NewMemoryStore()
	if err := store.BindSecretRef(context.Background(), BindRequest{}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef() error = %v, want ErrInvalidSecretRef", err)
	}
	if err := store.BindSecretRef(context.Background(), BindRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: "workspace"}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef(scope) error = %v, want ErrInvalidSecretRef", err)
	}
	if err := store.TestSecretRef(context.Background(), TestRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: ScopeUser}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("TestSecretRef(unbound) error = %v, want ErrInvalidSecretRef", err)
	}
}

func TestSQLiteStorePersistsLifecycleAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.sqlite")
	now := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(ctx, path, MemoryStoreOptions{Now: func() time.Time {
		now = now.Add(time.Second)
		return now
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := BindRequest{PluginInstanceID: "plugin_1", SecretRef: "api_token", Scope: ScopeUser}
	if err := store.BindSecretRef(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := store.TestSecretRef(ctx, TestRequest(req)); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSecretRef(ctx, DeleteRequest{PluginInstanceID: "plugin_2", SecretRef: "deleted_token", Scope: ScopeEnvironment}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	records, err := reopened.List(ctx, ListRequest{BoundOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PluginInstanceID != "plugin_1" || records[0].SecretRef != "api_token" || records[0].LastTestStatus != "passed" || records[0].BoundAt == nil || records[0].TestedAt == nil {
		t.Fatalf("persisted bound records mismatch: %#v", records)
	}
	all, err := reopened.List(ctx, ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[1].PluginInstanceID != "plugin_2" || all[1].Bound || all[1].DeletedAt == nil {
		t.Fatalf("persisted deleted records mismatch: %#v", all)
	}
}

func TestSQLiteStoreDeletesPlugin(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "secrets.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if err := store.BindSecretRef(ctx, BindRequest{PluginInstanceID: "plugin_1", SecretRef: "a", Scope: ScopeUser}); err != nil {
		t.Fatal(err)
	}
	if err := store.BindSecretRef(ctx, BindRequest{PluginInstanceID: "plugin_2", SecretRef: "b", Scope: ScopeUser}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePlugin(ctx, "plugin_1"); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(ctx, ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PluginInstanceID != "plugin_2" {
		t.Fatalf("DeletePlugin() records = %#v", records)
	}
}

func TestSQLiteStoreRejectsInvalidRequests(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindSecretRef(ctx, BindRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: "workspace"}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef(scope) error = %v, want ErrInvalidSecretRef", err)
	}
	if err := store.TestSecretRef(ctx, TestRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: ScopeUser}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("TestSecretRef(unbound) error = %v, want ErrInvalidSecretRef", err)
	}
}
