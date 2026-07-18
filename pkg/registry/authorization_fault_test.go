package registry

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestSQLiteAuthorizationMutationFaultRollsBack(t *testing.T) {
	type statementFault struct {
		operation string
		table     string
	}
	type mutationCase struct {
		name    string
		prepare func(context.Context, *testing.T, *SQLiteStore, AuthorizationSnapshot, time.Time) AuthorizationSnapshot
		mutate  func(context.Context, *SQLiteStore, AuthorizationSnapshot, time.Time) error
		faults  []statementFault
	}

	grantPermission := func(ctx context.Context, t *testing.T, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
		t.Helper()
		after, err := store.GrantPermission(ctx, permissions.GrantRequest{
			PluginInstanceID: before.Plugin.PluginInstanceID,
			PermissionID:     "documents.read",
			GrantedBy:        "admin",
			Now:              now,
		}, AuthorizationRevisionsFromRecord(before.Plugin))
		if err != nil {
			t.Fatal(err)
		}
		return after
	}
	putPolicy := func(ctx context.Context, t *testing.T, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
		t.Helper()
		after, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
			PluginInstanceID:   before.Plugin.PluginInstanceID,
			AllowedPermissions: []string{"documents.read"},
			DeniedMethods:      []string{"documents.delete"},
			Now:                now,
		}, AuthorizationRevisionsFromRecord(before.Plugin))
		if err != nil {
			t.Fatal(err)
		}
		return after
	}

	tests := []mutationCase{
		{
			name: "grant",
			mutate: func(ctx context.Context, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) error {
				_, err := store.GrantPermission(ctx, permissions.GrantRequest{
					PluginInstanceID: before.Plugin.PluginInstanceID,
					PermissionID:     "documents.write",
					GrantedBy:        "admin",
					Now:              now,
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			faults: []statementFault{
				{operation: "UPDATE", table: "plugin_records"},
				{operation: "INSERT", table: "plugin_permission_grants"},
			},
		},
		{
			name: "revoke",
			prepare: func(ctx context.Context, t *testing.T, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
				return grantPermission(ctx, t, store, before, now)
			},
			mutate: func(ctx context.Context, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) error {
				_, err := store.RevokePermission(ctx, permissions.RevokeRequest{
					PluginInstanceID: before.Plugin.PluginInstanceID,
					PermissionID:     "documents.read",
					RevokedBy:        "admin",
					Reason:           "fault test",
					Now:              now,
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			faults: []statementFault{
				{operation: "UPDATE", table: "plugin_records"},
				{operation: "UPDATE", table: "plugin_permission_grants"},
			},
		},
		{
			name: "policy_put_insert",
			mutate: func(ctx context.Context, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) error {
				_, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
					PluginInstanceID:   before.Plugin.PluginInstanceID,
					AllowedPermissions: []string{"documents.write"},
					DeniedMethods:      []string{"documents.delete"},
					Now:                now,
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			faults: []statementFault{
				{operation: "UPDATE", table: "plugin_records"},
				{operation: "INSERT", table: "plugin_security_policies"},
			},
		},
		{
			name: "policy_put_update",
			prepare: func(ctx context.Context, t *testing.T, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
				return putPolicy(ctx, t, store, before, now)
			},
			mutate: func(ctx context.Context, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) error {
				_, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
					PluginInstanceID:   before.Plugin.PluginInstanceID,
					AllowedPermissions: []string{"documents.read", "documents.write"},
					DeniedMethods:      []string{"documents.purge"},
					Now:                now,
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			faults: []statementFault{
				{operation: "UPDATE", table: "plugin_records"},
				{operation: "UPDATE", table: "plugin_security_policies"},
			},
		},
		{
			name: "policy_delete",
			prepare: func(ctx context.Context, t *testing.T, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
				return putPolicy(ctx, t, store, before, now)
			},
			mutate: func(ctx context.Context, store *SQLiteStore, before AuthorizationSnapshot, now time.Time) error {
				_, err := store.DeleteSecurityPolicy(
					ctx,
					before.Plugin.PluginInstanceID,
					now,
					AuthorizationRevisionsFromRecord(before.Plugin),
				)
				return err
			},
			faults: []statementFault{
				{operation: "UPDATE", table: "plugin_records"},
				{operation: "DELETE", table: "plugin_security_policies"},
			},
		},
	}

	for _, test := range tests {
		for _, fault := range test.faults {
			t.Run(test.name+"/"+fault.operation+"_"+fault.table, func(t *testing.T) {
				ctx := registryTestContext()
				path := filepath.Join(t.TempDir(), "registry.sqlite")
				store, err := NewSQLiteStore(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				closed := false
				t.Cleanup(func() {
					if !closed {
						_ = store.Close()
					}
				})

				now := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
				plugin := putAuthorizationTestPlugin(t, store, "plugini_authorization_fault", "com.example.authorization-fault", now)
				before, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				if test.prepare != nil {
					before = test.prepare(ctx, t, store, before, now.Add(time.Second))
				}

				installAuthorizationStatementFault(t, store, fault)
				if err := test.mutate(ctx, store, before, now.Add(2*time.Second)); err == nil {
					t.Fatal("authorization mutation succeeded with an injected statement fault")
				}
				assertAuthorizationSnapshotEqual(t, store, before)

				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				closed = true

				reopened, err := NewSQLiteStore(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				assertAuthorizationSnapshotEqual(t, reopened, before)
			})
		}
	}
}

func installAuthorizationStatementFault(t *testing.T, store *SQLiteStore, fault struct {
	operation string
	table     string
}) {
	t.Helper()
	statement := fmt.Sprintf(`
CREATE TEMP TRIGGER authorization_statement_fault
BEFORE %s ON %s
BEGIN
	SELECT RAISE(ABORT, 'injected authorization statement fault');
END`, fault.operation, fault.table)
	if _, err := store.db.ExecContext(registryTestContext(), statement); err != nil {
		t.Fatal(err)
	}
}

func assertAuthorizationSnapshotEqual(t *testing.T, store *SQLiteStore, want AuthorizationSnapshot) {
	t.Helper()
	got, err := store.GetAuthorization(registryTestContext(), want.Plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("authorization snapshot after statement fault = %#v, want %#v", got, want)
	}
}
