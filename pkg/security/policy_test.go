package security

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPolicyStorePutListEvaluateAndDelete(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
			record, err := store.PutPolicy(ctx, PutPolicyRequest{
				PluginInstanceID:   "plugini_policy",
				AllowedPermissions: []string{"write", "read", "read", ""},
				DeniedMethods:      []string{"cache.delete", "cache.delete", ""},
				Now:                now,
			})
			if err != nil {
				t.Fatalf("PutPolicy() error = %v", err)
			}
			if !reflect.DeepEqual(record.AllowedPermissions, []string{"read", "write"}) ||
				!reflect.DeepEqual(record.DeniedMethods, []string{"cache.delete"}) ||
				!record.UpdatedAt.Equal(now) {
				t.Fatalf("policy record mismatch: %#v", record)
			}

			allowed, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.list",
				RequiredPermissions: []string{"read"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(allowed) error = %v", err)
			}
			if !allowed.Allowed {
				t.Fatalf("EvaluatePolicy(allowed) denied: %#v", allowed)
			}

			deniedMethod, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.delete",
				RequiredPermissions: []string{"write"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(denied method) error = %v", err)
			}
			if deniedMethod.Allowed ||
				deniedMethod.Reason != PolicyDenyReasonMethodDenied ||
				deniedMethod.DeniedMethod != "cache.delete" {
				t.Fatalf("denied method result mismatch: %#v", deniedMethod)
			}

			deniedPermission, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.remove",
				RequiredPermissions: []string{"delete", "write"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(denied permission) error = %v", err)
			}
			if deniedPermission.Allowed ||
				deniedPermission.Reason != PolicyDenyReasonPermissionNotAllowed ||
				!reflect.DeepEqual(deniedPermission.MissingPermissions, []string{"delete"}) {
				t.Fatalf("denied permission result mismatch: %#v", deniedPermission)
			}

			listed, err := store.ListPolicies(ctx)
			if err != nil {
				t.Fatalf("ListPolicies() error = %v", err)
			}
			if len(listed) != 1 || listed[0].PluginInstanceID != "plugini_policy" {
				t.Fatalf("ListPolicies() mismatch: %#v", listed)
			}
			if err := store.DeletePolicy(ctx, "plugini_policy"); err != nil {
				t.Fatalf("DeletePolicy() error = %v", err)
			}
			afterDelete, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.delete",
				RequiredPermissions: []string{"delete"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(after delete) error = %v", err)
			}
			if !afterDelete.Allowed {
				t.Fatalf("deleted policy still denied: %#v", afterDelete)
			}
			if _, err := store.GetPolicy(ctx, "plugini_policy"); !errors.Is(err, ErrPolicyNotFound) {
				t.Fatalf("GetPolicy(after delete) error = %v, want ErrPolicyNotFound", err)
			}
		})
	}
}

func TestPolicyStoreNoPolicyAllowsByDefault(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := tc.open(t).EvaluatePolicy(context.Background(), EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_missing",
				Method:              "anything.run",
				RequiredPermissions: []string{"admin"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}
			if !allowed.Allowed {
				t.Fatalf("missing policy denied: %#v", allowed)
			}
		})
	}
}

func TestPolicyStoreRejectsInvalidRequests(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.PutPolicy(context.Background(), PutPolicyRequest{}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("PutPolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if _, err := store.GetPolicy(context.Background(), " "); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("GetPolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if _, err := store.EvaluatePolicy(context.Background(), EvaluatePolicyRequest{PluginInstanceID: "plugini"}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("EvaluatePolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if err := store.DeletePolicy(context.Background(), " "); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("DeletePolicy() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestSQLitePolicyStorePersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security-policy.sqlite")
	store, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	if _, err := store.PutPolicy(ctx, PutPolicyRequest{
		PluginInstanceID:   "plugini_persist",
		AllowedPermissions: []string{"read"},
		DeniedMethods:      []string{"cache.delete"},
		Now:                now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	record, err := reopened.GetPolicy(ctx, "plugini_persist")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.AllowedPermissions, []string{"read"}) ||
		!reflect.DeepEqual(record.DeniedMethods, []string{"cache.delete"}) ||
		!record.UpdatedAt.Equal(now) {
		t.Fatalf("persisted policy mismatch: %#v", record)
	}
}

func TestSQLitePolicyStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security-policy.sqlite")
	store, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_security_policy_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLitePolicyStore(ctx, path); err == nil {
		t.Fatal("NewSQLitePolicyStore() accepted newer schema version")
	}
}

type policyStoreCase struct {
	name string
	open func(t *testing.T) PolicyStore
}

func policyStoreCases() []policyStoreCase {
	return []policyStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) PolicyStore {
				t.Helper()
				return NewMemoryPolicyStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) PolicyStore {
				t.Helper()
				store, err := NewSQLitePolicyStore(context.Background(), filepath.Join(t.TempDir(), "security-policy.sqlite"))
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
