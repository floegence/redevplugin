package registry

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestAuthorizationStoreContract(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_authorization", "com.example.authorization", now)

			initial, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if len(initial.Grants) != 0 || initial.Policy != nil {
				t.Fatalf("initial authorization state = %#v", initial)
			}

			granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				GrantedBy:        "admin",
				Now:              now.Add(time.Second),
			}, AuthorizationRevisionsFromRecord(initial.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if granted.Plugin.PolicyRevision != 2 || granted.Plugin.RevokeEpoch != 0 || len(granted.Grants) != 1 {
				t.Fatalf("grant snapshot = %#v", granted)
			}
			_, err = store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(initial.Plugin),
				Now:              now.Add(2 * time.Second),
			})
			if !errors.Is(err, ErrAuthorizationRevisionConflict) {
				t.Fatalf("Authorize() with stale gateway revisions error = %v, want %v", err, ErrAuthorizationRevisionConflict)
			}

			allowed, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(granted.Plugin),
				Now:              now.Add(2 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !allowed.Allowed || !allowed.PolicyEvaluation.Allowed || len(allowed.MissingPermissions) != 0 {
				t.Fatalf("authorization decision after grant = %#v", allowed)
			}

			withPolicy, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID:   plugin.PluginInstanceID,
				AllowedPermissions: []string{"documents.read", "documents.read"},
				DeniedMethods:      []string{"documents.delete", "documents.delete"},
				Now:                now.Add(3 * time.Second),
			}, AuthorizationRevisionsFromRecord(granted.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if withPolicy.Plugin.PolicyRevision != 3 || withPolicy.Plugin.RevokeEpoch != 1 || withPolicy.Policy == nil ||
				len(withPolicy.Policy.AllowedPermissions) != 1 || len(withPolicy.Policy.DeniedMethods) != 1 {
				t.Fatalf("policy snapshot = %#v", withPolicy)
			}

			denied, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.delete",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(withPolicy.Plugin),
				Now:              now.Add(4 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if denied.Allowed || denied.PolicyEvaluation.Reason != security.PolicyDenyReasonMethodDenied {
				t.Fatalf("denied method decision = %#v", denied)
			}

			revoked, err := store.RevokePermission(ctx, permissions.RevokeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				RevokedBy:        "admin",
				Reason:           "access removed",
				Now:              now.Add(5 * time.Second),
			}, AuthorizationRevisionsFromRecord(withPolicy.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if revoked.Plugin.PolicyRevision != 4 || revoked.Plugin.RevokeEpoch != 2 || revoked.Grants[0].RevokedAt == nil {
				t.Fatalf("revoke snapshot = %#v", revoked)
			}

			missing, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(revoked.Plugin),
				Now:              now.Add(6 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if missing.Allowed || len(missing.MissingPermissions) != 1 || missing.MissingPermissions[0] != "documents.read" {
				t.Fatalf("revoked permission decision = %#v", missing)
			}

			withoutPolicy, err := store.DeleteSecurityPolicy(ctx, plugin.PluginInstanceID, now.Add(7*time.Second), AuthorizationRevisionsFromRecord(revoked.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if withoutPolicy.Plugin.PolicyRevision != 5 || withoutPolicy.Plugin.RevokeEpoch != 3 || withoutPolicy.Policy != nil {
				t.Fatalf("deleted policy snapshot = %#v", withoutPolicy)
			}

			withoutPolicy.Grants[0].RevokedBy = "mutated"
			withoutPolicy.Plugin.Metadata = map[string]string{"mutated": "true"}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Grants[0].RevokedBy != "admin" || got.Plugin.Metadata["mutated"] != "" {
				t.Fatalf("authorization snapshot retained caller mutation: %#v", got)
			}
		})
	}
}

func TestSQLiteStoreRejectsCorruptPersistedAuthorizationDataOnOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	plugin, err := store.PutPlugin(ctx, authorizationTestPlugin("plugini_corrupt_auth", "com.example.corrupt-auth"), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.read",
		GrantedBy:        "test",
		Now:              now,
	}, AuthorizationRevisionsFromRecord(plugin))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.write",
		GrantedBy:        "test",
		Now:              now,
	}, AuthorizationRevisionsFromRecord(snapshot.Plugin)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE plugin_permission_grants SET effect = 'invalid' WHERE plugin_instance_id = ? AND permission_id = ?`, plugin.PluginInstanceID, "documents.write"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); !errors.Is(err, permissions.ErrInvalidPermission) {
		t.Fatalf("NewSQLiteStore() error = %v, want invalid permission", err)
	}
}

func TestAuthorizationMutationsRejectEveryStaleRevision(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_stale", "com.example.stale", now)
			base := AuthorizationRevisionsFromRecord(plugin)
			for _, test := range []struct {
				name     string
				expected AuthorizationRevisions
			}{
				{name: "policy", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision + 1, ManagementRevision: base.ManagementRevision, RevokeEpoch: base.RevokeEpoch}},
				{name: "management", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision, ManagementRevision: base.ManagementRevision + 1, RevokeEpoch: base.RevokeEpoch}},
				{name: "revoke", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision, ManagementRevision: base.ManagementRevision, RevokeEpoch: base.RevokeEpoch + 1}},
			} {
				t.Run(test.name, func(t *testing.T) {
					_, err := store.GrantPermission(ctx, permissions.GrantRequest{
						PluginInstanceID: plugin.PluginInstanceID,
						PermissionID:     "documents." + test.name,
						Now:              now.Add(time.Second),
					}, test.expected)
					if !errors.Is(err, ErrAuthorizationRevisionConflict) {
						t.Fatalf("GrantPermission() error = %v, want %v", err, ErrAuthorizationRevisionConflict)
					}
					var conflict *AuthorizationRevisionConflictError
					if !errors.As(err, &conflict) || conflict.Expected != test.expected || conflict.Actual != base {
						t.Fatalf("revision conflict details = %#v", conflict)
					}
				})
			}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if AuthorizationRevisionsFromRecord(got.Plugin) != base || len(got.Grants) != 0 {
				t.Fatalf("stale mutations changed authorization state: %#v", got)
			}
		})
	}
}

func TestAuthorizationMutationConcurrencyCommitsOneSnapshot(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_concurrent", "com.example.concurrent", now)
			expected := AuthorizationRevisionsFromRecord(plugin)
			const writers = 16
			start := make(chan struct{})
			errs := make(chan error, writers)
			var wg sync.WaitGroup
			for i := 0; i < writers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					_, err := store.GrantPermission(ctx, permissions.GrantRequest{
						PluginInstanceID: plugin.PluginInstanceID,
						PermissionID:     "concurrent." + string(rune('a'+i)),
						Now:              now.Add(time.Duration(i+1) * time.Second),
					}, expected)
					errs <- err
				}(i)
			}
			close(start)
			wg.Wait()
			close(errs)
			succeeded := 0
			conflicted := 0
			for err := range errs {
				switch {
				case err == nil:
					succeeded++
				case errors.Is(err, ErrAuthorizationRevisionConflict):
					conflicted++
				default:
					t.Fatalf("unexpected concurrent mutation error: %v", err)
				}
			}
			if succeeded != 1 || conflicted != writers-1 {
				t.Fatalf("concurrent mutations: succeeded=%d conflicted=%d", succeeded, conflicted)
			}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Plugin.PolicyRevision != plugin.PolicyRevision+1 || len(got.Grants) != 1 {
				t.Fatalf("concurrent mutation state = %#v", got)
			}
		})
	}
}

func TestMarkUninstalledDeletesAuthorizationState(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_uninstall_auth", "com.example.uninstall-auth", now)
			granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				Now:              now.Add(time.Second),
			}, AuthorizationRevisionsFromRecord(plugin))
			if err != nil {
				t.Fatal(err)
			}
			withPolicy, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				DeniedMethods:    []string{"documents.delete"},
				Now:              now.Add(2 * time.Second),
			}, AuthorizationRevisionsFromRecord(granted.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
				PluginInstanceID:           plugin.PluginInstanceID,
				DeleteData:                 true,
				ExpectedManagementRevision: withPolicy.Plugin.ManagementRevision,
				Now:                        now.Add(3 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}

			reinstalled := authorizationTestPlugin(plugin.PluginInstanceID, plugin.PluginID)
			reinstalled, err = store.PutPlugin(ctx, reinstalled, PutOptions{Now: now.Add(4 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.GetAuthorization(ctx, reinstalled.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Grants) != 0 || snapshot.Policy != nil {
				t.Fatalf("authorization survived uninstall: %#v", snapshot)
			}
		})
	}
}

func TestSQLiteAuthorizationPersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	plugin := putAuthorizationTestPlugin(t, store, "plugini_auth_reopen", "com.example.auth-reopen", now)
	granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.read",
		GrantedBy:        "admin",
		Now:              now.Add(time.Second),
	}, AuthorizationRevisionsFromRecord(plugin))
	if err != nil {
		t.Fatal(err)
	}
	withPolicy, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   plugin.PluginInstanceID,
		AllowedPermissions: []string{"documents.read"},
		DeniedMethods:      []string{"documents.delete"},
		Now:                now.Add(2 * time.Second),
	}, AuthorizationRevisionsFromRecord(granted.Plugin))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	snapshot, err := reopened.GetAuthorization(ctx, plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Plugin.PolicyRevision != withPolicy.Plugin.PolicyRevision ||
		snapshot.Plugin.RevokeEpoch != withPolicy.Plugin.RevokeEpoch ||
		len(snapshot.Grants) != 1 || snapshot.Grants[0].GrantedBy != "admin" ||
		snapshot.Policy == nil || len(snapshot.Policy.DeniedMethods) != 1 {
		t.Fatalf("reopened authorization snapshot = %#v", snapshot)
	}
}

func TestSQLiteAuthorizationCASAcrossStoreInstances(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	first, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	now := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
	plugin := putAuthorizationTestPlugin(t, first, "plugini_multi_store", "com.example.multi-store", now)
	expected := AuthorizationRevisionsFromRecord(plugin)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, store := range []*SQLiteStore{first, second} {
		go func(i int, store *SQLiteStore) {
			<-start
			_, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "multi-store." + string(rune('a'+i)),
				Now:              now.Add(time.Duration(i+1) * time.Second),
			}, expected)
			errs <- err
		}(i, store)
	}
	close(start)
	firstErr := <-errs
	secondErr := <-errs
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("multi-store mutation errors = (%v, %v), want one success", firstErr, secondErr)
	}
	conflict := firstErr
	if conflict == nil {
		conflict = secondErr
	}
	if !errors.Is(conflict, ErrAuthorizationRevisionConflict) {
		t.Fatalf("losing multi-store mutation error = %v, want %v", conflict, ErrAuthorizationRevisionConflict)
	}
	snapshot, err := first.GetAuthorization(ctx, plugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Plugin.PolicyRevision != plugin.PolicyRevision+1 || len(snapshot.Grants) != 1 {
		t.Fatalf("multi-store mutation state = %#v", snapshot)
	}
}

func TestSQLiteAuthorizationCrossPluginReadsBypassWriteCoordinator(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)
	snapshots := make([]AuthorizationSnapshot, 2)
	for i, pluginInstanceID := range []string{"plugini_parallel_read_a", "plugini_parallel_read_b"} {
		plugin := putAuthorizationTestPlugin(t, store, pluginInstanceID, "com.example."+pluginInstanceID, now)
		snapshots[i], err = store.GrantPermission(ctx, permissions.GrantRequest{
			PluginInstanceID: pluginInstanceID,
			PermissionID:     "documents.read",
			GrantedBy:        "admin",
			Now:              now.Add(time.Second),
		}, AuthorizationRevisionsFromRecord(plugin))
		if err != nil {
			t.Fatal(err)
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	results := make(chan error, len(snapshots))
	for _, snapshot := range snapshots {
		go func(snapshot AuthorizationSnapshot) {
			decision, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: snapshot.Plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
				Now:              now.Add(2 * time.Second),
			})
			if err == nil && !decision.Allowed {
				err = errors.New("authorization unexpectedly denied")
			}
			results <- err
		}(snapshot)
	}
	for range snapshots {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cross-plugin authorization read waited for the write coordinator")
		}
	}
}

func TestSQLiteAuthorizationReadSeesCommittedSnapshotsDuringWrite(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	plugin := putAuthorizationTestPlugin(t, store, "plugini_snapshot_read", "com.example.snapshot-read", now)
	before, err := store.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		PermissionID:     "documents.read",
		GrantedBy:        "admin",
		Now:              now.Add(time.Second),
	}, AuthorizationRevisionsFromRecord(plugin))
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	locked := true
	defer func() {
		if locked {
			store.mu.Unlock()
		}
	}()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	updatedAt := now.Add(2 * time.Second)
	updatedPlugin, err := advanceSQLiteAuthorizationRevisions(ctx, tx, plugin.PluginInstanceID, AuthorizationRevisionsFromRecord(before.Plugin), true, updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := security.NewPolicy(security.PutPolicyRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		DeniedMethods:    []string{"documents.delete"},
		Now:              updatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertSQLiteSecurityPolicy(ctx, tx, policy); err != nil {
		t.Fatal(err)
	}

	readResult := make(chan struct {
		decision AuthorizationDecision
		err      error
	}, 1)
	go func() {
		decision, err := store.Authorize(ctx, AuthorizeRequest{
			PluginInstanceID: plugin.PluginInstanceID,
			Method:           "documents.delete",
			PermissionIDs:    []string{"documents.read"},
			Expected:         AuthorizationRevisionsFromRecord(before.Plugin),
			Now:              updatedAt,
		})
		readResult <- struct {
			decision AuthorizationDecision
			err      error
		}{decision: decision, err: err}
	}()
	select {
	case result := <-readResult:
		if result.err != nil || !result.decision.Allowed {
			t.Fatalf("authorization during uncommitted write = %#v, err = %v", result.decision, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorization read blocked behind an uncommitted WAL writer")
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	store.mu.Unlock()
	locked = false
	if _, err := store.Authorize(ctx, AuthorizeRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		Method:           "documents.delete",
		PermissionIDs:    []string{"documents.read"},
		Expected:         AuthorizationRevisionsFromRecord(before.Plugin),
		Now:              updatedAt,
	}); !errors.Is(err, ErrAuthorizationRevisionConflict) {
		t.Fatalf("Authorize() with pre-commit revisions error = %v, want %v", err, ErrAuthorizationRevisionConflict)
	}
	decision, err := store.Authorize(ctx, AuthorizeRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		Method:           "documents.delete",
		PermissionIDs:    []string{"documents.read"},
		Expected:         AuthorizationRevisionsFromRecord(updatedPlugin),
		Now:              updatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.PolicyEvaluation.Reason != security.PolicyDenyReasonMethodDenied {
		t.Fatalf("authorization after committed write = %#v", decision)
	}
}

func TestSQLiteAuthorizationReadPoolConfigurationSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry pool #1.sqlite")
	for attempt := 0; attempt < 2; attempt++ {
		store, err := NewSQLiteStore(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		assertSQLiteAuthorizationReadPoolConfiguration(t, ctx, store)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func assertSQLiteAuthorizationReadPoolConfiguration(t *testing.T, ctx context.Context, store *SQLiteStore) {
	t.Helper()
	if got := store.db.Stats().MaxOpenConnections; got != maxRegistrySQLiteConnections {
		t.Fatalf("MaxOpenConnections = %d, want %d", got, maxRegistrySQLiteConnections)
	}
	connections := make([]*sql.Conn, 0, maxRegistrySQLiteConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for i := 0; i < maxRegistrySQLiteConnections; i++ {
		connection, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		var foreignKeys int
		var busyTimeout int
		var journalMode string
		if err := connection.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || busyTimeout != 5000 || journalMode != "wal" {
			t.Fatalf("connection %d pragmas = foreign_keys:%d busy_timeout:%d journal_mode:%q", i, foreignKeys, busyTimeout, journalMode)
		}
	}
}

func putAuthorizationTestPlugin(t *testing.T, store Store, pluginInstanceID string, pluginID string, now time.Time) PluginRecord {
	t.Helper()
	record, err := store.PutPlugin(context.Background(), authorizationTestPlugin(pluginInstanceID, pluginID), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func authorizationTestPlugin(pluginInstanceID string, pluginID string) PluginRecord {
	return PluginRecord{
		PluginInstanceID:  pluginInstanceID,
		PublisherID:       "example",
		PluginID:          pluginID,
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:" + pluginInstanceID,
		TrustState:        TrustVerified,
		EnableState:       EnableEnabled,
		Manifest: manifest.Manifest{
			Plugin: manifest.Plugin{PluginID: pluginID, Version: "1.0.0"},
		},
	}
}
