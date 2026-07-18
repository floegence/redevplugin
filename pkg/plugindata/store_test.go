package plugindata_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

func pluginDataTestContext() context.Context {
	return pluginDataTestContextFor("owner_user_hash_test", "owner_env_hash_test")
}

func pluginDataTestContextFor(ownerUserHash, ownerEnvHash string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_hash_test",
		OwnerUserHash:        ownerUserHash,
		OwnerEnvHash:         ownerEnvHash,
		SessionChannelIDHash: "session_channel_id_hash_test",
	})
}

func pluginDataResourceScope(t testing.TB, ctx context.Context, kind sessionctx.ScopeKind) sessionctx.ResourceScope {
	t.Helper()
	session, err := sessionctx.Require(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.ResourceScope(kind)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func pluginDataWorkspacePath(root, ownerEnvHash, generationID string) string {
	return filepath.Join(root, "workspaces", "environment", ownerEnvHash, generationID)
}

func pluginDataObjectPath(root, ownerEnvHash, ownerUserHash, objectID string) string {
	return filepath.Join(root, "objects", "user", ownerEnvHash, ownerUserHash, objectID)
}

func pluginDataScopeRoot(workspaceRoot, ownerUserHash string, scope sessionctx.ScopeKind) string {
	if scope == sessionctx.ScopeEnvironment {
		return filepath.Join(workspaceRoot, "scopes", "environment")
	}
	return filepath.Join(workspaceRoot, "scopes", "users", ownerUserHash)
}

type catalogCase struct {
	name string
	open func(*testing.T) registry.Store
}

func catalogCases() []catalogCase {
	return []catalogCase{
		{name: "memory", open: func(t *testing.T) registry.Store { return registry.NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) registry.Store {
			store, err := registry.NewSQLiteStore(pluginDataTestContext(), filepath.Join(t.TempDir(), "registry.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	}
}

func TestFileStoreLifecycleAndBrokers(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := pluginDataTestContext()
			catalog := tc.open(t)
			root := resolvedTempDir(t)
			store, err := plugindata.Open(ctx, root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
			record := putPlugin(t, catalog, "plugini_source", now)
			shape := testShape()
			dataset, err := store.CommitEnable(ctx, plugindata.CommitEnableRequest{
				PluginInstanceID:           record.PluginInstanceID,
				Shape:                      shape,
				InitialSettings:            map[string]json.RawMessage{"theme": json.RawMessage(`"dark"`)},
				ExpectedManagementRevision: record.ManagementRevision,
				Now:                        now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if dataset.Binding.Revision != 1 || dataset.Binding.ShapeHash == "" {
				t.Fatalf("dataset = %#v", dataset)
			}
			enabled, err := catalog.GetPlugin(ctx, record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if enabled.EnableState != registry.EnableEnabled || enabled.ManagementRevision != record.ManagementRevision+1 {
				t.Fatalf("enabled = %#v", enabled)
			}

			if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "notes/a.txt", Data: []byte("hello")}); err != nil {
				t.Fatal(err)
			}
			file, err := store.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "notes/a.txt"})
			if err != nil || string(file.Data) != "hello" {
				t.Fatalf("file = %#v, err = %v", file, err)
			}
			if _, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "kv", Key: "theme", Value: []byte("dark")}); err != nil {
				t.Fatal(err)
			}
			kv, err := store.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "kv", Key: "theme"})
			if err != nil || string(kv.Value) != "dark" {
				t.Fatalf("kv = %#v, err = %v", kv, err)
			}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `CREATE TABLE drafts (id TEXT PRIMARY KEY)`}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `INSERT INTO drafts(id) VALUES ('composer')`}); err != nil {
				t.Fatal(err)
			}
			triggerSQL := `CREATE TRIGGER clear_draft AFTER INSERT ON notes BEGIN DELETE FROM drafts WHERE id = 'composer'; END`
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: triggerSQL}); err != nil {
				t.Fatalf("ExecSQLite(trigger) error = %v", err)
			}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: triggerSQL + `; SELECT 1`}); !errors.Is(err, storage.ErrInvalidSQLite) {
				t.Fatalf("ExecSQLite(trigger with trailing statement) error = %v, want ErrInvalidSQLite", err)
			}
			body := "saved"
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `INSERT INTO notes(body) VALUES (?)`, Args: []storage.SQLiteValue{{Text: &body}}}); err != nil {
				t.Fatal(err)
			}
			rows, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `SELECT body FROM notes`})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0].Text == nil || *rows.Rows[0][0].Text != body {
				t.Fatalf("rows = %#v, err = %v", rows, err)
			}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `CREATE TABLE blobs (body BLOB)`}); err != nil {
				t.Fatal(err)
			}
			emptyBlob := []byte{}
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `INSERT INTO blobs(body) VALUES (?)`, Args: []storage.SQLiteValue{{Blob: emptyBlob}}}); err != nil {
				t.Fatal(err)
			}
			blobRows, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `SELECT body FROM blobs`})
			if err != nil || len(blobRows.Rows) != 1 || blobRows.Rows[0][0].Blob == nil || len(blobRows.Rows[0][0].Blob) != 0 {
				t.Fatalf("empty blob rows = %#v, err = %v", blobRows, err)
			}
			drafts, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `SELECT id FROM drafts`})
			if err != nil || len(drafts.Rows) != 0 {
				t.Fatalf("trigger did not clear draft rows: rows=%#v err=%v", drafts, err)
			}
			for _, query := range []string{
				`SELECT randomblob(16)`,
				`WITH selected AS (SELECT 1) DELETE FROM notes`,
				`BEGIN`,
			} {
				if _, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: query}); !errors.Is(err, storage.ErrInvalidSQLite) {
					t.Fatalf("QuerySQLite(%q) error = %v, want ErrInvalidSQLite", query, err)
				}
			}
			columns := make([]string, 129)
			for i := range columns {
				columns[i] = "1"
			}
			if _, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: "SELECT " + strings.Join(columns, ",")}); !errors.Is(err, storage.ErrSQLiteResultTooLarge) {
				t.Fatalf("QuerySQLite(column limit) error = %v, want ErrSQLiteResultTooLarge", err)
			}
			oversized := strings.Repeat("x", 1024*1024+1)
			if _, err := store.ExecSQLite(ctx, storage.SQLiteExecRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "db", SQL: `INSERT INTO notes(body) VALUES (?)`, Args: []storage.SQLiteValue{{Text: &oversized}}}); !errors.Is(err, storage.ErrInvalidSQLite) {
				t.Fatalf("ExecSQLite(argument limit) error = %v, want ErrInvalidSQLite", err)
			}

			initial, err := store.GetSettings(ctx, record.PluginInstanceID, sessionctx.ScopeUser)
			if err != nil || initial.Revision != 1 {
				t.Fatalf("initial settings = %#v, err = %v", initial, err)
			}
			patched, err := store.PatchSettings(ctx, plugindata.PatchSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: sessionctx.ScopeUser, ExpectedValuesRevision: 1, Set: map[string]json.RawMessage{"theme": json.RawMessage(`"light"`)}})
			if err != nil || patched.Revision != 2 {
				t.Fatalf("patched settings = %#v, err = %v", patched, err)
			}
			if _, err := store.PatchSettings(ctx, plugindata.PatchSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: sessionctx.ScopeUser, ExpectedValuesRevision: 1}); !errors.Is(err, plugindata.ErrRevisionConflict) {
				t.Fatalf("stale patch error = %v", err)
			}
		})
	}
}

func TestFileStoreExportImportAndRetainedBinding(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := pluginDataTestContext()
			catalog := tc.open(t)
			store, err := plugindata.Open(ctx, resolvedTempDir(t), catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
			shape := testShape()
			source := putPlugin(t, catalog, "plugini_source", now)
			if _, err := store.CommitEnable(ctx, enableRequest(source, shape, now)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: source.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "data.txt", Data: []byte("portable")}); err != nil {
				t.Fatal(err)
			}
			exported, err := store.Export(ctx, plugindata.ExportRequest{PluginInstanceID: source.PluginInstanceID})
			if err != nil || exported.ObjectID == "" || exported.ContentHash == "" {
				t.Fatalf("exported = %#v, err = %v", exported, err)
			}

			target := putPlugin(t, catalog, "plugini_target", now.Add(2*time.Second))
			if _, err := store.Import(ctx, plugindata.ImportRequest{PluginInstanceID: target.PluginInstanceID, ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: target.ManagementRevision, Now: now.Add(3 * time.Second)}); err != nil {
				t.Fatal(err)
			}
			imported, err := store.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: target.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "data.txt"})
			if err != nil || string(imported.Data) != "portable" {
				t.Fatalf("imported = %#v, err = %v", imported, err)
			}
			targetAfter, _ := catalog.GetPlugin(ctx, target.PluginInstanceID)
			if targetAfter.ManagementRevision != target.ManagementRevision+1 {
				t.Fatalf("target revision = %d", targetAfter.ManagementRevision)
			}

			sourceEnabled, _ := catalog.GetPlugin(ctx, source.PluginInstanceID)
			if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: sourceEnabled.ManagementRevision, Now: now.Add(4 * time.Second)}); err != nil {
				t.Fatal(err)
			}
			retained, err := store.ListRetained(ctx, plugindata.RetainedFilter{PluginInstanceID: source.PluginInstanceID})
			if err != nil || len(retained) != 1 {
				t.Fatalf("retained = %#v, err = %v", retained, err)
			}
			bindTarget := putPlugin(t, catalog, "plugini_bound", now.Add(5*time.Second))
			if _, err := store.BindRetained(ctx, plugindata.BindRetainedRequest{SourcePluginInstanceID: source.PluginInstanceID, ExpectedSourceBindingRevision: retained[0].Revision, TargetPluginInstanceID: bindTarget.PluginInstanceID, TargetExpectedManagementRevision: bindTarget.ManagementRevision, ExpectedShape: shape, Now: now.Add(6 * time.Second)}); err != nil {
				t.Fatal(err)
			}
			bound, err := store.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: bindTarget.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "data.txt"})
			if err != nil || string(bound.Data) != "portable" {
				t.Fatalf("bound = %#v, err = %v", bound, err)
			}
		})
	}
}

func TestCleanupExpiredRemovesEveryReturnedGeneration(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := pluginDataTestContext()
			catalog := tc.open(t)
			root := resolvedTempDir(t)
			store, err := plugindata.Open(ctx, root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
			expiresAt := now.Add(time.Minute)
			shape := testShape()
			generationIDs := make([]string, 0, 2)
			for _, instanceID := range []string{"plugini_cleanup_a", "plugini_cleanup_b"} {
				record := putPlugin(t, catalog, instanceID, now)
				dataset, err := store.CommitEnable(ctx, enableRequest(record, shape, now))
				if err != nil {
					t.Fatal(err)
				}
				generationIDs = append(generationIDs, dataset.Binding.GenerationID)
				enabled, err := catalog.GetPlugin(ctx, instanceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
					PluginInstanceID:           instanceID,
					ExpectedManagementRevision: enabled.ManagementRevision,
					RetainUntil:                &expiresAt,
					Now:                        now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			result, err := store.CleanupExpired(ctx, expiresAt.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Deleted) != len(generationIDs) {
				t.Fatalf("CleanupExpired() deleted = %#v", result.Deleted)
			}
			for _, generationID := range generationIDs {
				if _, err := os.Stat(pluginDataWorkspacePath(root, "owner_env_hash_test", generationID)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expired generation %s remains: %v", generationID, err)
				}
			}
		})
	}
}

func TestFileStoreQuotaRootLockAndClose(t *testing.T) {
	ctx := pluginDataTestContext()
	catalog := registry.NewMemoryStore()
	root := resolvedTempDir(t)
	store, err := plugindata.Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	quotaManifest := testManifest()
	for i := range quotaManifest.Storage.Stores {
		if quotaManifest.Storage.Stores[i].StoreID == "files" {
			quotaManifest.Storage.Stores[i].QuotaBytes = 4
		}
	}
	shape, err := plugindata.ShapeFromManifest(quotaManifest)
	if err != nil {
		t.Fatal(err)
	}
	plugin := putPluginWithManifest(t, catalog, "plugini_quota", time.Now(), quotaManifest)
	if _, err := store.CommitEnable(ctx, enableRequest(plugin, shape, time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: plugin.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, sessionctx.ScopeUser), StoreID: "files", Path: "too-large", Data: []byte("12345")}); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("quota error = %v", err)
	}
	if _, err := plugindata.Open(ctx, root, catalog); err == nil {
		t.Fatal("second Open() unexpectedly acquired the same root")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSettings(ctx, plugin.PluginInstanceID, sessionctx.ScopeUser); err == nil {
		t.Fatal("closed store accepted an operation")
	}
	reopened, err := plugindata.Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestFileStoreImportRejectsTamperedObject(t *testing.T) {
	ctx := pluginDataTestContext()
	catalog := registry.NewMemoryStore()
	root := resolvedTempDir(t)
	store, err := plugindata.Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	shape := testShape()
	source := putPlugin(t, catalog, "plugini_source", now)
	if _, err := store.CommitEnable(ctx, enableRequest(source, shape, now)); err != nil {
		t.Fatal(err)
	}
	exported, err := store.Export(ctx, plugindata.ExportRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	objectRoot := pluginDataObjectPath(root, "owner_env_hash_test", "owner_user_hash_test", exported.ObjectID)
	settingsPath := filepath.Join(pluginDataScopeRoot(filepath.Join(objectRoot, "payload"), "owner_user_hash_test", sessionctx.ScopeUser), "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"scope":{"kind":"user","owner_env_hash":"owner_env_hash_test","owner_user_hash":"owner_user_hash_test"},"revision":1,"values":{"theme":"tampered"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target := putPlugin(t, catalog, "plugini_target", now)
	if _, err := store.Import(ctx, plugindata.ImportRequest{PluginInstanceID: target.PluginInstanceID, ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: target.ManagementRevision}); !errors.Is(err, plugindata.ErrDatasetCorrupt) {
		t.Fatalf("tampered import error = %v", err)
	}
}

func TestCommitEnableRejectsCallerDefinedShape(t *testing.T) {
	ctx := pluginDataTestContext()
	catalog := registry.NewMemoryStore()
	store, err := plugindata.Open(ctx, resolvedTempDir(t), catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := putPlugin(t, catalog, "plugini_shape", time.Now())
	shape := testShape()
	shape.Settings.Fields[0].Options = []string{"dark", "invented"}
	_, err = store.CommitEnable(ctx, enableRequest(record, shape, time.Now()))
	if !errors.Is(err, plugindata.ErrShapeMismatch) {
		t.Fatalf("CommitEnable() error = %v, want ErrShapeMismatch", err)
	}
	if _, found, err := catalog.GetBinding(ctx, record.PluginInstanceID); err != nil || found {
		t.Fatalf("binding found = %v, err = %v", found, err)
	}
	stored, err := catalog.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil || stored.EnableState != registry.EnableDisabled || stored.ManagementRevision != record.ManagementRevision {
		t.Fatalf("stored = %#v, err = %v", stored, err)
	}
}

func TestOpenCanonicalizesSymlinkAncestor(t *testing.T) {
	base := resolvedTempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	catalog := registry.NewMemoryStore()
	store, err := plugindata.Open(pluginDataTestContext(), filepath.Join(link, "data"), catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attacker, link); err != nil {
		t.Fatal(err)
	}
	record := putPlugin(t, catalog, "plugini_canonical_root", time.Now())
	if _, err := store.CommitEnable(pluginDataTestContext(), enableRequest(record, testShape(), time.Now())); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(filepath.Join(real, "data", "workspaces", "environment", "owner_env_hash_test")); err != nil || len(entries) != 1 {
		t.Fatalf("canonical workspace entries = %d, err = %v", len(entries), err)
	}
	if _, err := os.Stat(filepath.Join(attacker, "data")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repointed symlink received plugin data: %v", err)
	}
}

func TestOpenRejectsSymlinkRootLock(t *testing.T) {
	root := resolvedTempDir(t)
	target := filepath.Join(root, "lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".redevplugin.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := plugindata.Open(pluginDataTestContext(), root, registry.NewMemoryStore()); !errors.Is(err, plugindata.ErrUnsafeFilesystem) {
		t.Fatalf("Open() error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestFileStoreMaintenancePreservesOtherOwners(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctxA := pluginDataTestContextFor("owner_user_a", "owner_env_a")
			ctxB := pluginDataTestContextFor("owner_user_b", "owner_env_b")
			catalog := tc.open(t)
			root := resolvedTempDir(t)
			store, err := plugindata.Open(ctxA, root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			shape := testShape()
			recordA := putPluginWithContext(t, ctxA, catalog, "plugini_shared", time.Now(), testManifest())
			recordB := putPluginWithContext(t, ctxB, catalog, "plugini_shared", time.Now(), testManifest())
			datasetA, err := store.CommitEnable(ctxA, enableRequest(recordA, shape, time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			datasetB, err := store.CommitEnable(ctxB, enableRequest(recordB, shape, time.Now()))
			if err != nil {
				t.Fatal(err)
			}
			exportA, err := store.Export(ctxA, plugindata.ExportRequest{PluginInstanceID: recordA.PluginInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			exportB, err := store.Export(ctxB, plugindata.ExportRequest{PluginInstanceID: recordB.PluginInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := plugindata.Open(ctxA, root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			for _, path := range []string{
				pluginDataWorkspacePath(root, "owner_env_a", datasetA.Binding.GenerationID),
				pluginDataWorkspacePath(root, "owner_env_b", datasetB.Binding.GenerationID),
				pluginDataObjectPath(root, "owner_env_a", "owner_user_a", exportA.ObjectID),
				pluginDataObjectPath(root, "owner_env_b", "owner_user_b", exportB.ObjectID),
			} {
				if info, err := os.Stat(path); err != nil || !info.IsDir() {
					t.Fatalf("maintained directory %s: info=%v err=%v", path, info, err)
				}
			}
		})
	}
}

func TestFileStoreScopesSettingsAndStorageByAuthenticatedOwner(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctxA := pluginDataTestContextFor("owner_user_a", "owner_env_shared")
			ctxB := pluginDataTestContextFor("owner_user_b", "owner_env_shared")
			ctxOtherEnv := pluginDataTestContextFor("owner_user_a", "owner_env_other")
			catalog := tc.open(t)
			store, err := plugindata.Open(ctxA, resolvedTempDir(t), catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			manifest := scopedTestManifest()
			shape, err := plugindata.ShapeFromManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			record := putPluginWithContext(t, ctxA, catalog, "plugini_scoped", time.Now(), manifest)
			if _, err := store.CommitEnable(ctxA, plugindata.CommitEnableRequest{
				PluginInstanceID: record.PluginInstanceID,
				Shape:            shape,
				InitialSettings: map[string]json.RawMessage{
					"user_theme": json.RawMessage(`"default"`),
					"env_mode":   json.RawMessage(`"shared"`),
				},
				ExpectedManagementRevision: record.ManagementRevision,
			}); err != nil {
				t.Fatal(err)
			}

			patchSetting := func(ctx context.Context, scope sessionctx.ScopeKind, revision uint64, key, value string) {
				t.Helper()
				if _, err := store.PatchSettings(ctx, plugindata.PatchSettingsRequest{
					PluginInstanceID:       record.PluginInstanceID,
					Scope:                  scope,
					ExpectedValuesRevision: revision,
					Set:                    map[string]json.RawMessage{key: json.RawMessage(strconv.Quote(value))},
				}); err != nil {
					t.Fatal(err)
				}
			}
			patchSetting(ctxA, sessionctx.ScopeUser, 1, "user_theme", "a")
			patchSetting(ctxA, sessionctx.ScopeEnvironment, 1, "env_mode", "updated")
			patchSetting(ctxB, sessionctx.ScopeUser, 1, "user_theme", "b")

			for _, check := range []struct {
				ctx      context.Context
				scope    sessionctx.ScopeKind
				key      string
				want     string
				revision uint64
			}{
				{ctx: ctxA, scope: sessionctx.ScopeUser, key: "user_theme", want: `"a"`, revision: 2},
				{ctx: ctxB, scope: sessionctx.ScopeUser, key: "user_theme", want: `"b"`, revision: 2},
				{ctx: ctxA, scope: sessionctx.ScopeEnvironment, key: "env_mode", want: `"updated"`, revision: 2},
				{ctx: ctxB, scope: sessionctx.ScopeEnvironment, key: "env_mode", want: `"updated"`, revision: 2},
			} {
				snapshot, err := store.GetSettings(check.ctx, record.PluginInstanceID, check.scope)
				if err != nil || snapshot.Scope != check.scope || snapshot.Revision != check.revision || string(snapshot.Values[check.key]) != check.want {
					t.Fatalf("settings scope %s = %#v, err = %v", check.scope, snapshot, err)
				}
			}
			if _, err := store.PatchSettings(ctxA, plugindata.PatchSettingsRequest{
				PluginInstanceID:       record.PluginInstanceID,
				Scope:                  sessionctx.ScopeUser,
				ExpectedValuesRevision: 2,
				Set:                    map[string]json.RawMessage{"env_mode": json.RawMessage(`"private"`)},
			}); !errors.Is(err, plugindata.ErrSettingScopeMismatch) {
				t.Fatalf("mixed-scope settings patch error = %v", err)
			}

			for _, write := range []struct {
				ctx     context.Context
				storeID string
				scope   sessionctx.ScopeKind
				value   string
			}{
				{ctx: ctxA, storeID: "user_files", scope: sessionctx.ScopeUser, value: "a"},
				{ctx: ctxB, storeID: "user_files", scope: sessionctx.ScopeUser, value: "b"},
				{ctx: ctxA, storeID: "env_files", scope: sessionctx.ScopeEnvironment, value: "shared"},
			} {
				if _, err := store.WriteFile(write.ctx, storage.FileWriteRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, write.ctx, write.scope), StoreID: write.storeID, Path: "value.txt", Data: []byte(write.value)}); err != nil {
					t.Fatal(err)
				}
			}
			for _, read := range []struct {
				ctx     context.Context
				storeID string
				scope   sessionctx.ScopeKind
				want    string
			}{
				{ctx: ctxA, storeID: "user_files", scope: sessionctx.ScopeUser, want: "a"},
				{ctx: ctxB, storeID: "user_files", scope: sessionctx.ScopeUser, want: "b"},
				{ctx: ctxB, storeID: "env_files", scope: sessionctx.ScopeEnvironment, want: "shared"},
			} {
				result, err := store.ReadFile(read.ctx, storage.FileReadRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, read.ctx, read.scope), StoreID: read.storeID, Path: "value.txt"})
				if err != nil || string(result.Data) != read.want {
					t.Fatalf("read %s = %q, err = %v", read.storeID, result.Data, err)
				}
			}

			otherRecord := putPluginWithContext(t, ctxOtherEnv, catalog, record.PluginInstanceID, time.Now(), manifest)
			if _, err := store.CommitEnable(ctxOtherEnv, plugindata.CommitEnableRequest{PluginInstanceID: otherRecord.PluginInstanceID, Shape: shape, ExpectedManagementRevision: otherRecord.ManagementRevision}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ReadFile(ctxOtherEnv, storage.FileReadRequest{PluginInstanceID: otherRecord.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctxOtherEnv, sessionctx.ScopeEnvironment), StoreID: "env_files", Path: "value.txt"}); !errors.Is(err, storage.ErrFileNotFound) {
				t.Fatalf("other environment read error = %v, want ErrFileNotFound", err)
			}
		})
	}
}

func TestFileStoreExportImportPreservesOtherUsersAndScopesObjects(t *testing.T) {
	for _, tc := range catalogCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctxA := pluginDataTestContextFor("owner_user_a", "owner_env_shared")
			ctxB := pluginDataTestContextFor("owner_user_b", "owner_env_shared")
			catalog := tc.open(t)
			root := resolvedTempDir(t)
			store, err := plugindata.Open(ctxA, root, catalog)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			manifest := scopedTestManifest()
			shape, err := plugindata.ShapeFromManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			record := putPluginWithContext(t, ctxA, catalog, "plugini_export_scoped", time.Now(), manifest)
			if _, err := store.CommitEnable(ctxA, plugindata.CommitEnableRequest{PluginInstanceID: record.PluginInstanceID, Shape: shape, ExpectedManagementRevision: record.ManagementRevision}); err != nil {
				t.Fatal(err)
			}
			write := func(ctx context.Context, scope sessionctx.ScopeKind, storeID, value string) {
				t.Helper()
				if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, ctx, scope), StoreID: storeID, Path: "value.txt", Data: []byte(value)}); err != nil {
					t.Fatal(err)
				}
			}
			patch := func(ctx context.Context, scope sessionctx.ScopeKind, revision uint64, key, value string) {
				t.Helper()
				if _, err := store.PatchSettings(ctx, plugindata.PatchSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: scope, ExpectedValuesRevision: revision, Set: map[string]json.RawMessage{key: json.RawMessage(strconv.Quote(value))}}); err != nil {
					t.Fatal(err)
				}
			}
			write(ctxA, sessionctx.ScopeUser, "user_files", "exported-a")
			write(ctxB, sessionctx.ScopeUser, "user_files", "before-b")
			write(ctxA, sessionctx.ScopeEnvironment, "env_files", "exported-env")
			patch(ctxA, sessionctx.ScopeUser, 1, "user_theme", "exported-a")
			patch(ctxB, sessionctx.ScopeUser, 1, "user_theme", "before-b")
			patch(ctxA, sessionctx.ScopeEnvironment, 1, "env_mode", "exported-env")

			exported, err := store.Export(ctxA, plugindata.ExportRequest{PluginInstanceID: record.PluginInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			currentRecord, err := catalog.GetPlugin(ctxA, record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(ctxB, plugindata.ImportRequest{PluginInstanceID: record.PluginInstanceID, ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: currentRecord.ManagementRevision}); !errors.Is(err, plugindata.ErrExportNotFound) {
				t.Fatalf("other user import error = %v, want ErrExportNotFound", err)
			}
			if err := store.DeleteExport(ctxB, exported.ObjectID); !errors.Is(err, plugindata.ErrExportNotFound) {
				t.Fatalf("other user delete error = %v, want ErrExportNotFound", err)
			}

			write(ctxA, sessionctx.ScopeUser, "user_files", "changed-a")
			write(ctxB, sessionctx.ScopeUser, "user_files", "preserved-b")
			write(ctxA, sessionctx.ScopeEnvironment, "env_files", "changed-env")
			patch(ctxA, sessionctx.ScopeUser, 2, "user_theme", "changed-a")
			patch(ctxB, sessionctx.ScopeUser, 2, "user_theme", "preserved-b")
			patch(ctxA, sessionctx.ScopeEnvironment, 2, "env_mode", "changed-env")
			disabled, err := catalog.SetEnableState(ctxA, record.PluginInstanceID, registry.EnableDisabled, "import", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Import(ctxA, plugindata.ImportRequest{PluginInstanceID: record.PluginInstanceID, ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: disabled.ManagementRevision}); err != nil {
				t.Fatal(err)
			}

			for _, read := range []struct {
				ctx     context.Context
				storeID string
				scope   sessionctx.ScopeKind
				want    string
			}{
				{ctx: ctxA, storeID: "user_files", scope: sessionctx.ScopeUser, want: "exported-a"},
				{ctx: ctxB, storeID: "user_files", scope: sessionctx.ScopeUser, want: "preserved-b"},
				{ctx: ctxB, storeID: "env_files", scope: sessionctx.ScopeEnvironment, want: "exported-env"},
			} {
				result, err := store.ReadFile(read.ctx, storage.FileReadRequest{PluginInstanceID: record.PluginInstanceID, ResourceScope: pluginDataResourceScope(t, read.ctx, read.scope), StoreID: read.storeID, Path: "value.txt"})
				if err != nil || string(result.Data) != read.want {
					t.Fatalf("imported %s = %q, err = %v", read.storeID, result.Data, err)
				}
			}
			for _, check := range []struct {
				ctx   context.Context
				scope sessionctx.ScopeKind
				key   string
				want  string
			}{
				{ctx: ctxA, scope: sessionctx.ScopeUser, key: "user_theme", want: `"exported-a"`},
				{ctx: ctxB, scope: sessionctx.ScopeUser, key: "user_theme", want: `"preserved-b"`},
				{ctx: ctxB, scope: sessionctx.ScopeEnvironment, key: "env_mode", want: `"exported-env"`},
			} {
				snapshot, err := store.GetSettings(check.ctx, record.PluginInstanceID, check.scope)
				if err != nil || string(snapshot.Values[check.key]) != check.want {
					t.Fatalf("imported settings %s = %#v, err = %v", check.scope, snapshot, err)
				}
			}

			object, found, err := catalog.GetObject(ctxA, exported.ObjectID)
			if err != nil || !found {
				t.Fatalf("export object found = %v, err = %v", found, err)
			}
			aPath := pluginDataObjectPath(root, "owner_env_shared", "owner_user_a", exported.ObjectID)
			bPath := pluginDataObjectPath(root, "owner_env_shared", "owner_user_b", exported.ObjectID)
			if err := os.CopyFS(bPath, os.DirFS(aPath)); err != nil {
				t.Fatal(err)
			}
			if err := catalog.CreateObject(ctxB, object); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteExport(ctxB, exported.ObjectID); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(aPath); err != nil {
				t.Fatalf("deleting colliding user object removed owner A object: %v", err)
			}
		})
	}
}

func TestFileStoreRejectsNonemptyLegacyOwnerlessData(t *testing.T) {
	t.Run("nonempty", func(t *testing.T) {
		root := resolvedTempDir(t)
		legacy := filepath.Join(root, "workspaces", "gen_legacy")
		if err := os.MkdirAll(legacy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, "dataset.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := plugindata.Open(pluginDataTestContext(), root, registry.NewMemoryStore()); !errors.Is(err, plugindata.ErrOwnerScopeMigrationRequired) {
			t.Fatalf("Open() error = %v, want ErrOwnerScopeMigrationRequired", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		root := resolvedTempDir(t)
		for _, legacy := range []string{
			filepath.Join(root, "workspaces", "gen_empty"),
			filepath.Join(root, "objects", "obj_empty"),
		} {
			if err := os.MkdirAll(legacy, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		store, err := plugindata.Open(pluginDataTestContext(), root, registry.NewMemoryStore())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		for _, legacy := range []string{
			filepath.Join(root, "workspaces", "gen_empty"),
			filepath.Join(root, "objects", "obj_empty"),
		} {
			if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("empty legacy path remains: %s: %v", legacy, err)
			}
		}
	})
}

func putPlugin(t *testing.T, store registry.Store, instanceID string, now time.Time) registry.PluginRecord {
	return putPluginWithManifest(t, store, instanceID, now, testManifest())
}

func putPluginWithManifest(t *testing.T, store registry.Store, instanceID string, now time.Time, pluginManifest manifest.Manifest) registry.PluginRecord {
	return putPluginWithContext(t, pluginDataTestContext(), store, instanceID, now, pluginManifest)
}

func putPluginWithContext(t *testing.T, ctx context.Context, store registry.Store, instanceID string, now time.Time, pluginManifest manifest.Manifest) registry.PluginRecord {
	t.Helper()
	record, err := store.PutPlugin(ctx, registry.PluginRecord{
		PluginInstanceID:  instanceID,
		PublisherID:       pluginManifest.Publisher.PublisherID,
		PluginID:          pluginManifest.PluginID(),
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:" + instanceID,
		TrustState:        registry.TrustVerified,
		EnableState:       registry.EnableDisabled,
		Manifest:          pluginManifest,
	}, registry.PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testShape() plugindata.Shape {
	shape, err := plugindata.ShapeFromManifest(testManifest())
	if err != nil {
		panic(err)
	}
	return shape
}

func testManifest() manifest.Manifest {
	files := int64(64)
	dbFiles := int64(8)
	return manifest.Manifest{
		Publisher: manifest.Publisher{PublisherID: "example"},
		Plugin:    manifest.Plugin{PluginID: "com.example.notes", Version: "1.0.0"},
		Settings: &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{{
			Key: "theme", Type: settings.FieldEnum, Scope: "user", Options: []string{"dark", "light"}, Default: "dark", Label: "Theme",
		}}},
		Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{
			{StoreID: "db", Kind: string(plugindata.NamespaceSQLite), Scope: "user", SchemaVersion: 1, QuotaBytes: 1024 * 1024, QuotaFiles: &dbFiles},
			{StoreID: "files", Kind: string(plugindata.NamespaceFiles), Scope: "user", SchemaVersion: 1, QuotaBytes: 1024 * 1024, QuotaFiles: &files},
			{StoreID: "kv", Kind: string(plugindata.NamespaceKV), Scope: "user", SchemaVersion: 1, QuotaBytes: 1024 * 1024, QuotaFiles: &files},
		}},
	}
}

func scopedTestManifest() manifest.Manifest {
	files := int64(64)
	return manifest.Manifest{
		Publisher: manifest.Publisher{PublisherID: "example"},
		Plugin:    manifest.Plugin{PluginID: "com.example.scoped", Version: "1.0.0"},
		Settings: &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{
			{Key: "user_theme", Type: settings.FieldString, Scope: "user", Default: "default", Label: "User theme"},
			{Key: "env_mode", Type: settings.FieldString, Scope: "environment", Default: "shared", Label: "Environment mode"},
		}},
		Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{
			{StoreID: "user_files", Kind: string(plugindata.NamespaceFiles), Scope: "user", SchemaVersion: 1, QuotaBytes: 1024 * 1024, QuotaFiles: &files},
			{StoreID: "env_files", Kind: string(plugindata.NamespaceFiles), Scope: "environment", SchemaVersion: 1, QuotaBytes: 1024 * 1024, QuotaFiles: &files},
		}},
	}
}

func enableRequest(record registry.PluginRecord, shape plugindata.Shape, now time.Time) plugindata.CommitEnableRequest {
	return plugindata.CommitEnableRequest{PluginInstanceID: record.PluginInstanceID, Shape: shape, InitialSettings: map[string]json.RawMessage{"theme": json.RawMessage(`"dark"`)}, ExpectedManagementRevision: record.ManagementRevision, Now: now.Add(time.Second)}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
