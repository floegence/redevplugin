package permissions

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMemoryStoreGrantListCheckAndRevoke(t *testing.T) {
	store := NewMemoryStore()
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
}

func TestMemoryStoreExpirationAndDelete(t *testing.T) {
	store := NewMemoryStore()
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
}

func TestMemoryStoreRejectsInvalidRequests(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.Grant(context.Background(), GrantRequest{PluginInstanceID: "plugin_a"}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("Grant() error = %v, want ErrInvalidPermission", err)
	}
	if _, err := store.Revoke(context.Background(), RevokeRequest{PluginInstanceID: "plugin_a", PermissionID: "missing"}); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("Revoke() error = %v, want ErrGrantNotFound", err)
	}
	if _, _, err := store.IsGranted(context.Background(), CheckRequest{PermissionIDs: []string{"read"}}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("IsGranted() error = %v, want ErrInvalidPermission", err)
	}
}
