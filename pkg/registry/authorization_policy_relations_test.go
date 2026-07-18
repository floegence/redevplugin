package registry

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestSQLiteSecurityPolicyRelationMigrationSurvivesReopen(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	now := time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := store.PutPlugin(ctx, authorizationTestPlugin("plugini_policy_migration", "com.example.policy-migration"), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.read",
		GrantedBy:        "migration-test",
		Now:              now.Add(time.Second),
	}, AuthorizationRevisionsFromRecord(plugin))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.write",
		GrantedBy:        "migration-test",
		Now:              now.Add(2 * time.Second),
	}, AuthorizationRevisionsFromRecord(snapshot.Plugin))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   plugin.PluginInstanceID,
		AllowedPermissions: []string{"documents.read"},
		DeniedMethods:      []string{"documents.delete"},
		Now:                now.Add(3 * time.Second),
	}, AuthorizationRevisionsFromRecord(snapshot.Plugin))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE plugin_security_policy_allowed_permissions`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE plugin_security_policy_denied_methods`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := NewSQLiteStore(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		assertSQLiteSecurityPolicyRelations(t, ctx, reopened, plugin.OwnerEnvHash, plugin.PluginInstanceID, []string{"documents.read"}, []string{"documents.delete"})
		assertSQLiteIndexColumns(t, ctx, reopened.db, "idx_registry_security_policy_allowed_permission", []string{"owner_env_hash", "plugin_instance_id", "permission_id"})
		assertSQLiteIndexColumns(t, ctx, reopened.db, "idx_registry_security_policy_denied_method", []string{"owner_env_hash", "plugin_instance_id", "method"})
		assertSQLiteForeignKeysValid(t, ctx, reopened.db)

		allowed, err := reopened.Authorize(ctx, AuthorizeRequest{
			PluginInstanceID: plugin.PluginInstanceID,
			Method:           "documents.get",
			PermissionIDs:    []string{"documents.read"},
			Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
			Now:              now.Add(4 * time.Second),
		})
		if err != nil || !allowed.Allowed {
			_ = reopened.Close()
			t.Fatalf("allowed authorization = %#v, err = %v", allowed, err)
		}
		permissionDenied, err := reopened.Authorize(ctx, AuthorizeRequest{
			PluginInstanceID: plugin.PluginInstanceID,
			Method:           "documents.put",
			PermissionIDs:    []string{"documents.write"},
			Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
			Now:              now.Add(4 * time.Second),
		})
		if err != nil || permissionDenied.Allowed || permissionDenied.PolicyEvaluation.Reason != security.PolicyDenyReasonPermissionNotAllowed || !slices.Equal(permissionDenied.PolicyEvaluation.MissingPermissions, []string{"documents.write"}) {
			_ = reopened.Close()
			t.Fatalf("permission policy decision = %#v, err = %v", permissionDenied, err)
		}
		methodDenied, err := reopened.Authorize(ctx, AuthorizeRequest{
			PluginInstanceID: plugin.PluginInstanceID,
			Method:           "documents.delete",
			PermissionIDs:    []string{"documents.read"},
			Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
			Now:              now.Add(4 * time.Second),
		})
		if err != nil || methodDenied.Allowed || methodDenied.PolicyEvaluation.Reason != security.PolicyDenyReasonMethodDenied {
			_ = reopened.Close()
			t.Fatalf("method policy decision = %#v, err = %v", methodDenied, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteSecurityPolicyRelationsTrackMutation(t *testing.T) {
	ctx := registryTestContext()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 18, 13, 30, 0, 0, time.UTC)
	plugin, err := store.PutPlugin(ctx, authorizationTestPlugin("plugini_policy_relations", "com.example.policy-relations"), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   plugin.PluginInstanceID,
		AllowedPermissions: []string{"documents.read"},
		DeniedMethods:      []string{"documents.delete"},
		Now:                now.Add(time.Second),
	}, AuthorizationRevisionsFromRecord(plugin))
	if err != nil {
		t.Fatal(err)
	}
	assertSQLiteSecurityPolicyRelations(t, ctx, store, plugin.OwnerEnvHash, plugin.PluginInstanceID, []string{"documents.read"}, []string{"documents.delete"})

	snapshot, err = store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   plugin.PluginInstanceID,
		AllowedPermissions: []string{"documents.write"},
		DeniedMethods:      []string{"documents.archive"},
		Now:                now.Add(2 * time.Second),
	}, AuthorizationRevisionsFromRecord(snapshot.Plugin))
	if err != nil {
		t.Fatal(err)
	}
	assertSQLiteSecurityPolicyRelations(t, ctx, store, plugin.OwnerEnvHash, plugin.PluginInstanceID, []string{"documents.write"}, []string{"documents.archive"})

	if _, err := store.DeleteSecurityPolicy(ctx, plugin.PluginInstanceID, now.Add(3*time.Second), AuthorizationRevisionsFromRecord(snapshot.Plugin)); err != nil {
		t.Fatal(err)
	}
	assertSQLiteSecurityPolicyRelations(t, ctx, store, plugin.OwnerEnvHash, plugin.PluginInstanceID, nil, nil)
	assertSQLiteForeignKeysValid(t, ctx, store.db)
}

func TestSQLiteSecurityPolicyRelationMismatchFailsClosedOnReopen(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 13, 45, 0, 0, time.UTC)
	plugin, err := store.PutPlugin(ctx, authorizationTestPlugin("plugini_policy_mismatch", "com.example.policy-mismatch"), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   plugin.PluginInstanceID,
		AllowedPermissions: []string{"documents.read"},
		DeniedMethods:      []string{"documents.delete"},
		Now:                now.Add(time.Second),
	}, AuthorizationRevisionsFromRecord(plugin)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
DELETE FROM plugin_security_policy_allowed_permissions
WHERE owner_env_hash = ? AND plugin_instance_id = ? AND permission_id = ?`, plugin.OwnerEnvHash, plugin.PluginInstanceID, "documents.read"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "relations do not match snapshot") {
		t.Fatalf("NewSQLiteStore() error = %v, want security policy relation mismatch", err)
	}
}

func assertSQLiteSecurityPolicyRelations(t *testing.T, ctx context.Context, store *SQLiteStore, ownerEnvHash, pluginInstanceID string, wantPermissions, wantMethods []string) {
	t.Helper()
	permissionRows, err := store.db.QueryContext(ctx, `
SELECT permission_id
FROM plugin_security_policy_allowed_permissions
WHERE owner_env_hash = ? AND plugin_instance_id = ?
ORDER BY permission_id`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	permissions := make([]string, 0)
	for permissionRows.Next() {
		var permissionID string
		if err := permissionRows.Scan(&permissionID); err != nil {
			_ = permissionRows.Close()
			t.Fatal(err)
		}
		permissions = append(permissions, permissionID)
	}
	if err := permissionRows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := permissionRows.Err(); err != nil {
		t.Fatal(err)
	}
	methodRows, err := store.db.QueryContext(ctx, `
SELECT method
FROM plugin_security_policy_denied_methods
WHERE owner_env_hash = ? AND plugin_instance_id = ?
ORDER BY method`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	methods := make([]string, 0)
	for methodRows.Next() {
		var method string
		if err := methodRows.Scan(&method); err != nil {
			_ = methodRows.Close()
			t.Fatal(err)
		}
		methods = append(methods, method)
	}
	if err := methodRows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := methodRows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(permissions, wantPermissions) || !slices.Equal(methods, wantMethods) {
		t.Fatalf("security policy relations permissions=%v methods=%v, want permissions=%v methods=%v", permissions, methods, wantPermissions, wantMethods)
	}
}

func assertSQLiteIndexColumns(t *testing.T, ctx context.Context, db *sql.DB, index string, want []string) {
	t.Helper()
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA index_info(%q)`, index))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := make([]string, 0, len(want))
	for rows.Next() {
		var sequence int
		var columnID int
		var column string
		if err := rows.Scan(&sequence, &columnID, &column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(columns, want) {
		t.Fatalf("index %s columns = %v, want %v", index, columns, want)
	}
}

func assertSQLiteForeignKeysValid(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowID sql.NullInt64
		var parent string
		var foreignKeyID int
		if err := rows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("foreign key violation table=%s row_id=%v parent=%s foreign_key_id=%d", table, rowID, parent, foreignKeyID)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
