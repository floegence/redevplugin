package secrets

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func secretTestContext() context.Context {
	return secretTestContextFor("owner_user_hash_test", "owner_env_hash_test")
}

func secretTestContextFor(ownerUserHash, ownerEnvHash string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_hash_test",
		OwnerUserHash:        ownerUserHash,
		OwnerEnvHash:         ownerEnvHash,
		SessionChannelIDHash: "session_channel_id_hash_test",
	})
}

func TestMemoryStoreLifecycleListAndDeletePlugin(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time {
		now = now.Add(time.Second)
		return now
	}})
	ctx := secretTestContext()

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
	if err := store.TestSecretRef(secretTestContext(), TestRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: ScopeUser}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("TestSecretRef(unbound) error = %v, want ErrInvalidSecretRef", err)
	}
	if err := store.BindSecretRef(context.Background(), BindRequest{PluginInstanceID: "plugin_1", SecretRef: "token", Scope: ScopeUser}); !errors.Is(err, sessionctx.ErrSessionRequired) {
		t.Fatalf("BindSecretRef(no session) error = %v, want authenticated session", err)
	}
}

func TestSQLiteStorePersistsLifecycleAcrossOpen(t *testing.T) {
	ctx := secretTestContext()
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
	ctx := secretTestContext()
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
	ctx := secretTestContext()
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

func TestStoresIsolateSecretOwners(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(*testing.T) (Store, Lister, PluginDeleter)
	}{
		{
			name: "memory",
			open: func(*testing.T) (Store, Lister, PluginDeleter) {
				store := NewMemoryStore()
				return store, store, store
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) (Store, Lister, PluginDeleter) {
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "secrets.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := store.Close(); err != nil {
						t.Error(err)
					}
				})
				return store, store, store
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, lister, deleter := tc.open(t)
			userA := secretTestContextFor("owner_user_a", "owner_env_shared")
			userB := secretTestContextFor("owner_user_b", "owner_env_shared")
			otherEnvironment := secretTestContextFor("owner_user_a", "owner_env_other")
			userRequest := BindRequest{PluginInstanceID: "plugin_shared", SecretRef: "token", Scope: ScopeUser}
			if err := store.BindSecretRef(userA, userRequest); err != nil {
				t.Fatal(err)
			}
			if err := store.BindSecretRef(userB, userRequest); err != nil {
				t.Fatal(err)
			}
			if err := store.BindSecretRef(otherEnvironment, userRequest); err != nil {
				t.Fatal(err)
			}
			environmentRequest := BindRequest{PluginInstanceID: "plugin_shared", SecretRef: "shared", Scope: ScopeEnvironment}
			if err := store.BindSecretRef(userA, environmentRequest); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				ctx context.Context
			}{
				{userA},
				{userB},
			} {
				records, err := lister.List(item.ctx, ListRequest{PluginInstanceID: "plugin_shared", BoundOnly: true})
				if err != nil {
					t.Fatal(err)
				}
				if len(records) != 2 || records[0].Scope != ScopeEnvironment || records[1].Scope != ScopeUser {
					t.Fatalf("shared environment records = %#v", records)
				}
			}
			otherRecords, err := lister.List(otherEnvironment, ListRequest{PluginInstanceID: "plugin_shared", BoundOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(otherRecords) != 1 || otherRecords[0].Scope != ScopeUser {
				t.Fatalf("other environment records = %#v", otherRecords)
			}
			if err := deleter.DeletePlugin(userA, "plugin_shared"); err != nil {
				t.Fatal(err)
			}
			for _, ctx := range []context.Context{userA, userB} {
				records, err := lister.List(ctx, ListRequest{PluginInstanceID: "plugin_shared"})
				if err != nil {
					t.Fatal(err)
				}
				if len(records) != 0 {
					t.Fatalf("deleted environment records = %#v", records)
				}
			}
			otherRecords, err = lister.List(otherEnvironment, ListRequest{PluginInstanceID: "plugin_shared", BoundOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(otherRecords) != 1 {
				t.Fatalf("other environment was deleted: %#v", otherRecords)
			}
		})
	}
}

func TestSQLiteStoreFailsClosedForOwnerlessRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE plugin_secret_bindings (
	plugin_instance_id TEXT NOT NULL,
	secret_ref TEXT NOT NULL,
	scope TEXT NOT NULL,
	bound INTEGER NOT NULL,
	last_test_status TEXT NOT NULL,
	bound_at INTEGER,
	tested_at INTEGER,
	deleted_at INTEGER,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY(plugin_instance_id, scope, secret_ref)
);
INSERT INTO plugin_secret_bindings(plugin_instance_id, secret_ref, scope, bound, last_test_status, updated_at)
VALUES('plugin_legacy', 'token', 'user', 1, '', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(context.Background(), path); !errors.Is(err, ErrOwnerScopeMigrationRequired) {
		t.Fatalf("NewSQLiteStore() error = %v, want migration required", err)
	}
}

func TestSQLiteStoreRebuildsEmptyOwnerlessTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-empty.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_secret_bindings (plugin_instance_id TEXT NOT NULL, secret_ref TEXT NOT NULL, scope TEXT NOT NULL, bound INTEGER NOT NULL, last_test_status TEXT NOT NULL, bound_at INTEGER, tested_at INTEGER, deleted_at INTEGER, updated_at INTEGER NOT NULL, PRIMARY KEY(plugin_instance_id, scope, secret_ref))`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BindSecretRef(secretTestContext(), BindRequest{PluginInstanceID: "plugin_new", SecretRef: "token", Scope: ScopeUser}); err != nil {
		t.Fatal(err)
	}
}
