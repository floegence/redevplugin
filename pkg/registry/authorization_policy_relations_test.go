package registry

import (
	"context"
	"database/sql"
	"errors"
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
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
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
		assertSQLiteAuthorizationPrimaryKeyIndexes(t, ctx, reopened.db)
		assertSQLiteAuthorizationQueryPlans(t, ctx, reopened.db)
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

func TestSQLiteSecurityPolicyPartialRelationSchemaFailsClosed(t *testing.T) {
	ctx := registryTestContext()
	tables := []string{
		"plugin_security_policy_allowed_permissions",
		"plugin_security_policy_denied_methods",
	}
	for _, missingTable := range tables {
		t.Run(missingTable, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.sqlite")
			store, err := NewSQLiteStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 7, 18, 13, 15, 0, 0, time.UTC)
			plugin, err := store.PutPlugin(ctx, authorizationTestPlugin("plugini_partial_schema", "com.example.partial-schema"), PutOptions{Now: now})
			if err != nil {
				_ = store.Close()
				t.Fatal(err)
			}
			if _, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID:   plugin.PluginInstanceID,
				AllowedPermissions: []string{"documents.read"},
				DeniedMethods:      []string{"documents.delete"},
				Now:                now.Add(time.Second),
			}, AuthorizationRevisionsFromRecord(plugin)); err != nil {
				_ = store.Close()
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
			if _, err := db.ExecContext(ctx, `DROP TABLE `+missingTable); err != nil {
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
			if !errors.Is(err, ErrAuthorizationSchemaIncomplete) {
				t.Fatalf("NewSQLiteStore() error = %v, want %v", err, ErrAuthorizationSchemaIncomplete)
			}

			db, err = sql.Open("sqlite", dsn)
			if err != nil {
				t.Fatal(err)
			}
			assertSQLiteTablePresence(t, ctx, db, missingTable, false)
			for _, table := range tables {
				if table != missingTable {
					assertSQLiteTablePresence(t, ctx, db, table, true)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteAuthorizationRemovesRedundantLegacyIndexes(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
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
	for _, statement := range []string{
		`CREATE INDEX idx_registry_permission_grants_plugin ON plugin_permission_grants(owner_env_hash, plugin_instance_id, permission_id)`,
		`CREATE INDEX idx_registry_security_policy_allowed_permission ON plugin_security_policy_allowed_permissions(owner_env_hash, plugin_instance_id, permission_id)`,
		`CREATE INDEX idx_registry_security_policy_denied_method ON plugin_security_policy_denied_methods(owner_env_hash, plugin_instance_id, method)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	for _, index := range []string{
		"idx_registry_permission_grants_plugin",
		"idx_registry_security_policy_allowed_permission",
		"idx_registry_security_policy_denied_method",
	} {
		assertSQLiteIndexAbsent(t, ctx, reopened.db, index)
	}
	assertSQLiteAuthorizationPrimaryKeyIndexes(t, ctx, reopened.db)
	assertSQLiteAuthorizationQueryPlans(t, ctx, reopened.db)
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

type sqliteIndexMetadata struct {
	name    string
	origin  string
	columns []string
}

func assertSQLiteAuthorizationPrimaryKeyIndexes(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for table, columns := range map[string][]string{
		"plugin_permission_grants":                   {"owner_env_hash", "plugin_instance_id", "permission_id"},
		"plugin_security_policy_allowed_permissions": {"owner_env_hash", "plugin_instance_id", "permission_id"},
		"plugin_security_policy_denied_methods":      {"owner_env_hash", "plugin_instance_id", "method"},
	} {
		indexes := sqliteTableIndexes(t, ctx, db, table)
		matching := 0
		for _, index := range indexes {
			if !slices.Equal(index.columns, columns) {
				continue
			}
			matching++
			if index.origin != "pk" {
				t.Fatalf("table %s duplicate key index %s has origin %q, want pk", table, index.name, index.origin)
			}
		}
		if matching != 1 {
			t.Fatalf("table %s indexes = %#v, want exactly one primary-key index on %v", table, indexes, columns)
		}
	}
}

func sqliteTableIndexes(t *testing.T, ctx context.Context, db *sql.DB, table string) []sqliteIndexMetadata {
	t.Helper()
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA index_list(%q)`, table))
	if err != nil {
		t.Fatal(err)
	}
	indexes := make([]sqliteIndexMetadata, 0)
	for rows.Next() {
		var sequence, unique, partial int
		var index sqliteIndexMetadata
		if err := rows.Scan(&sequence, &index.name, &unique, &index.origin, &partial); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		indexes = append(indexes, index)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for index := range indexes {
		columns, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA index_info(%q)`, indexes[index].name))
		if err != nil {
			t.Fatal(err)
		}
		for columns.Next() {
			var sequence, columnID int
			var column string
			if err := columns.Scan(&sequence, &columnID, &column); err != nil {
				_ = columns.Close()
				t.Fatal(err)
			}
			indexes[index].columns = append(indexes[index].columns, column)
		}
		if err := columns.Err(); err != nil {
			_ = columns.Close()
			t.Fatal(err)
		}
		if err := columns.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return indexes
}

func assertSQLiteIndexAbsent(t *testing.T, ctx context.Context, db *sql.DB, want string) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, want).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("index %s still exists", want)
	}
}

func assertSQLiteAuthorizationQueryPlans(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	assertSQLiteQueryUsesPrimaryKey(t, ctx, db, "plugin_security_policy_denied_methods", `
SELECT EXISTS(
	SELECT 1 FROM plugin_security_policy_denied_methods
	WHERE owner_env_hash = ? AND plugin_instance_id = ? AND method = ?
)`, "env", "plugin", "documents.delete")
	assertSQLiteQueryUsesPrimaryKey(t, ctx, db, "plugin_security_policy_allowed_permissions", `
SELECT EXISTS(
	SELECT 1 FROM plugin_security_policy_allowed_permissions
	WHERE owner_env_hash = ? AND plugin_instance_id = ?
	LIMIT 1
)`, "env", "plugin")
	assertSQLiteQueryUsesPrimaryKey(t, ctx, db, "plugin_security_policy_allowed_permissions", `
WITH required(permission_id) AS (
	SELECT value FROM json_each(?)
)
SELECT policy.permission_id
FROM required
JOIN plugin_security_policy_allowed_permissions AS policy
	ON policy.owner_env_hash = ? AND policy.plugin_instance_id = ? AND policy.permission_id = required.permission_id
ORDER BY policy.permission_id`, `["documents.read","documents.write"]`, "env", "plugin")
	assertSQLiteQueryUsesPrimaryKey(t, ctx, db, "plugin_permission_grants", `
WITH required(permission_id) AS (
	SELECT value FROM json_each(?)
)
SELECT grants.permission_id
FROM required
JOIN plugin_permission_grants AS grants
	ON grants.owner_env_hash = ? AND grants.plugin_instance_id = ? AND grants.permission_id = required.permission_id
ORDER BY grants.permission_id`, `["documents.read","documents.write"]`, "env", "plugin")
}

func assertSQLiteQueryUsesPrimaryKey(t *testing.T, ctx context.Context, db *sql.DB, table, query string, args ...any) {
	t.Helper()
	rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := "USING COVERING INDEX sqlite_autoindex_" + table + "_1"
	details := make([]string, 0)
	found := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
		if strings.Contains(detail, want) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("query plan for %s = %v, want %q", table, details, want)
	}
}

func assertSQLiteTablePresence(t *testing.T, ctx context.Context, db *sql.DB, table string, want bool) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if got := count == 1; got != want {
		t.Fatalf("table %s present = %v, want %v", table, got, want)
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
