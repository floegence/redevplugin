package permissions

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStoreGrantListCheckAndRevoke(t *testing.T) {
	for _, tc := range permissionStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

			record, err := store.Grant(context.Background(), GrantRequest{
				PluginInstanceID: "plugin_a",
				PermissionID:     "resources.read",
				GrantedBy:        "user_a",
				Now:              now,
			})
			if err != nil {
				t.Fatal(err)
			}
			if record.Effect != EffectGrant || record.GrantedAt != now || record.GrantedBy != "user_a" {
				t.Fatalf("grant record mismatch: %#v", record)
			}

			ok, missing, err := store.IsGranted(context.Background(), CheckRequest{
				PluginInstanceID: "plugin_a",
				PermissionIDs:    []string{"resources.read", "resources.read"},
				Now:              now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !ok || len(missing) != 0 {
				t.Fatalf("IsGranted() = %v missing=%v", ok, missing)
			}

			ok, missing, err = store.IsGranted(context.Background(), CheckRequest{
				PluginInstanceID: "plugin_a",
				PermissionIDs:    []string{"resources.read", "resources.write"},
				Now:              now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if ok || !reflect.DeepEqual(missing, []string{"resources.write"}) {
				t.Fatalf("IsGranted(missing) = %v missing=%v", ok, missing)
			}

			revoked, err := store.Revoke(context.Background(), RevokeRequest{
				PluginInstanceID: "plugin_a",
				PermissionID:     "resources.read",
				RevokedBy:        "admin",
				Reason:           "review",
				Now:              now.Add(2 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if revoked.RevokedAt == nil || revoked.RevokedBy != "admin" || revoked.RevokedReason != "review" {
				t.Fatalf("revoked record mismatch: %#v", revoked)
			}

			ok, missing, err = store.IsGranted(context.Background(), CheckRequest{
				PluginInstanceID: "plugin_a",
				PermissionIDs:    []string{"resources.read"},
				Now:              now.Add(3 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if ok || !reflect.DeepEqual(missing, []string{"resources.read"}) {
				t.Fatalf("IsGranted(revoked) = %v missing=%v", ok, missing)
			}

			records, err := store.List(context.Background(), ListRequest{PluginInstanceID: "plugin_a"})
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].RevokedAt == nil {
				t.Fatalf("List() = %#v", records)
			}
			active, err := store.List(context.Background(), ListRequest{PluginInstanceID: "plugin_a", ActiveOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(active) != 0 {
				t.Fatalf("List(active) = %#v", active)
			}
		})
	}
}

func TestStoreExpirationAndDelete(t *testing.T) {
	for _, tc := range permissionStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
			if _, err := store.Grant(context.Background(), GrantRequest{
				PluginInstanceID: "plugin_a",
				PermissionID:     "net.tcp",
				Now:              now,
				ExpiresAt:        now.Add(time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			ok, missing, err := store.IsGranted(context.Background(), CheckRequest{
				PluginInstanceID: "plugin_a",
				PermissionIDs:    []string{"net.tcp"},
				Now:              now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !ok || len(missing) != 0 {
				t.Fatalf("IsGranted(before expiry) = %v missing=%v", ok, missing)
			}
			ok, missing, err = store.IsGranted(context.Background(), CheckRequest{
				PluginInstanceID: "plugin_a",
				PermissionIDs:    []string{"net.tcp"},
				Now:              now.Add(time.Minute),
			})
			if err != nil {
				t.Fatal(err)
			}
			if ok || !reflect.DeepEqual(missing, []string{"net.tcp"}) {
				t.Fatalf("IsGranted(after expiry) = %v missing=%v", ok, missing)
			}
			if err := store.DeletePluginGrants(context.Background(), "plugin_a"); err != nil {
				t.Fatal(err)
			}
			records, err := store.List(context.Background(), ListRequest{PluginInstanceID: "plugin_a"})
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 0 {
				t.Fatalf("DeletePluginGrants left records: %#v", records)
			}
		})
	}
}

func TestMemoryStoreStateRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	if _, err := store.Grant(context.Background(), GrantRequest{
		PluginInstanceID: "plugin_b",
		PermissionID:     "storage.write",
		GrantedBy:        "dev",
		Now:              now,
		ExpiresAt:        expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant(context.Background(), GrantRequest{
		PluginInstanceID: "plugin_a",
		PermissionID:     "network.http",
		GrantedBy:        "dev",
		Now:              now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(context.Background(), RevokeRequest{
		PluginInstanceID: "plugin_b",
		PermissionID:     "storage.write",
		RevokedBy:        "reviewer",
		Reason:           "scope changed",
		Now:              now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	state := store.State()
	if len(state.Records) != 2 ||
		state.Records[0].PluginInstanceID != "plugin_a" ||
		state.Records[1].PluginInstanceID != "plugin_b" ||
		state.Records[1].ExpiresAt == nil ||
		state.Records[1].RevokedAt == nil {
		t.Fatalf("State() mismatch: %#v", state)
	}

	restored := NewMemoryStoreFromState(state)
	records, err := restored.List(context.Background(), ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(records, state.Records) {
		t.Fatalf("restored records mismatch: %#v want %#v", records, state.Records)
	}
	ok, missing, err := restored.IsGranted(context.Background(), CheckRequest{
		PluginInstanceID: "plugin_a",
		PermissionIDs:    []string{"network.http"},
		Now:              now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(missing) != 0 {
		t.Fatalf("restored IsGranted() = %v missing=%v", ok, missing)
	}
}

func TestStoreRejectsInvalidRequests(t *testing.T) {
	for _, tc := range permissionStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.Grant(context.Background(), GrantRequest{PluginInstanceID: "plugin_a"}); !errors.Is(err, ErrInvalidPermission) {
				t.Fatalf("Grant() error = %v, want ErrInvalidPermission", err)
			}
			if _, err := store.Revoke(context.Background(), RevokeRequest{PluginInstanceID: "plugin_a", PermissionID: "missing"}); !errors.Is(err, ErrGrantNotFound) {
				t.Fatalf("Revoke() error = %v, want ErrGrantNotFound", err)
			}
			if _, _, err := store.IsGranted(context.Background(), CheckRequest{PermissionIDs: []string{"read"}}); !errors.Is(err, ErrInvalidPermission) {
				t.Fatalf("IsGranted() error = %v, want ErrInvalidPermission", err)
			}
			if err := store.DeletePluginGrants(context.Background(), " "); !errors.Is(err, ErrInvalidPermission) {
				t.Fatalf("DeletePluginGrants() error = %v, want ErrInvalidPermission", err)
			}
		})
	}
}

func TestSQLiteStorePersistsRecordsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "permissions.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	if _, err := store.Grant(ctx, GrantRequest{
		PluginInstanceID: "plugin_b",
		PermissionID:     "storage.write",
		GrantedBy:        "dev",
		Now:              now,
		ExpiresAt:        now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant(ctx, GrantRequest{
		PluginInstanceID: "plugin_a",
		PermissionID:     "network.http",
		GrantedBy:        "dev",
		Now:              now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(ctx, RevokeRequest{
		PluginInstanceID: "plugin_b",
		PermissionID:     "storage.write",
		RevokedBy:        "reviewer",
		Reason:           "scope changed",
		Now:              now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})

	records, err := reopened.List(ctx, ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 ||
		records[0].PluginInstanceID != "plugin_a" ||
		records[1].PluginInstanceID != "plugin_b" ||
		records[1].ExpiresAt == nil ||
		records[1].RevokedAt == nil ||
		records[1].RevokedBy != "reviewer" ||
		records[1].RevokedReason != "scope changed" {
		t.Fatalf("persisted records mismatch: %#v", records)
	}
	ok, missing, err := reopened.IsGranted(ctx, CheckRequest{
		PluginInstanceID: "plugin_a",
		PermissionIDs:    []string{"network.http"},
		Now:              now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(missing) != 0 {
		t.Fatalf("persisted IsGranted() = %v missing=%v", ok, missing)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "permissions.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_permission_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteStore() accepted newer schema version")
	}
}

type permissionStoreCase struct {
	name string
	open func(t *testing.T) Store
}

func permissionStoreCases() []permissionStoreCase {
	return []permissionStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemoryStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "permissions.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = store.Close()
				})
				return store
			},
		},
	}
}
