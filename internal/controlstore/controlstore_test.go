package controlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/capability"
	"github.com/floegence/redevplugin/v2/pkg/manifest"
	"github.com/floegence/redevplugin/v2/pkg/permissions"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/security"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

func TestOpenFreshControlStoreAndReopenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Generation(); got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before := info.Size()
	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Generation() != 1 {
		t.Fatalf("reopened generation = %d, want 1", reopened.Generation())
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != before {
		t.Fatalf("idempotent reopen rewrote database: %d -> %d", before, info.Size())
	}
	var namespaceTables int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'plugin_namespace%'`).Scan(&namespaceTables); err != nil {
		t.Fatal(err)
	}
	if namespaceTables != 0 {
		t.Fatalf("plugin namespace leaked into control DB: %d tables", namespaceTables)
	}
}

func TestMigratedStoreAllowsPostMigrationMutationAndColdReopen(t *testing.T) {
	dir := t.TempDir()
	operationPath := filepath.Join(dir, "operations.sqlite")
	target := filepath.Join(dir, "control.sqlite")
	binding := testBinding("operation-1", "")
	binding.Execution = "operation"
	if err := createLegacyOperationFixture(operationPath, 1, "operation-1", binding); err != nil {
		t.Fatal(err)
	}
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "operation", Path: operationPath, Kind: "operation", Version: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateExecution(context.Background(), Execution{ID: "post-migration", PluginInstanceID: "plugin-1", Kind: "operation", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), Config{Path: target})
	if err != nil {
		t.Fatalf("cold reopen after mutation: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.GetExecution(context.Background(), "post-migration"); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationRejectsOperationStreamLifecycleMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, mutation string
	}{
		{name: "terminal operation with open stream", mutation: `UPDATE plugin_operations SET status='completed', terminal_at=10`},
		{name: "running operation with closed stream", mutation: `UPDATE plugin_streams SET status='closed', closed_at=10`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			operationPath := filepath.Join(dir, "operations.sqlite")
			streamPath := filepath.Join(dir, "streams.sqlite")
			if err := createExecutionFixtures(operationPath, streamPath, false); err != nil {
				t.Fatal(err)
			}
			path := operationPath
			if strings.Contains(tc.mutation, "plugin_streams") {
				path = streamPath
			}
			db := openTestDB(t, path)
			if _, err := db.Exec(tc.mutation); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "control.sqlite")
			if _, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "operation", Path: operationPath, Kind: "operation", Version: 1}, {Name: "stream", Path: streamPath, Kind: "stream", Version: 0}}}); !errors.Is(err, ErrMigration) {
				t.Fatalf("Migrate() error = %v, want ErrMigration", err)
			}
		})
	}
}

func TestExecutionEventUsesOnePersistentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateExecution(context.Background(), Execution{ID: "exec-1", PluginInstanceID: "plugin-1", Kind: "subscription", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent(context.Background(), Event{ExecutionID: "exec-1", Sequence: 1, Kind: "data", Payload: map[string]any{"ok": true}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetExecution(context.Background(), "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cursor != 1 || got.ID != "exec-1" {
		t.Fatalf("execution = %#v", got)
	}
	if err := store.AppendEvent(context.Background(), Event{ExecutionID: "exec-1", Sequence: 1, Kind: "data"}); err == nil {
		t.Fatal("duplicate event sequence accepted")
	}
}

func TestOpenRejectsFutureSchemaAndDriftWithoutMutation(t *testing.T) {
	for _, tc := range []struct{ name, setup string }{
		{"future", "PRAGMA user_version = 999"},
		{"drift", "DROP TABLE control_generation"},
		{"extra table", "CREATE TABLE shadow_authority(id TEXT)"},
		{"extra index", "CREATE INDEX shadow_execution_status ON execution(status)"},
		{"extra trigger", "CREATE TRIGGER shadow_execution_insert AFTER INSERT ON execution BEGIN SELECT 1; END"},
		{"constraint drift", "ALTER TABLE control_metadata RENAME TO old_control_metadata; CREATE TABLE control_metadata(key TEXT, value_json TEXT); DROP TABLE old_control_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sqlite")
			store, err := Open(context.Background(), Config{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.setup); err != nil {
				t.Fatal(err)
			}
			db.Close()
			mutated, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrIncompatible) {
				t.Fatalf("Open() error = %v, want ErrIncompatible", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(mutated) {
				t.Fatal("rejected database was mutated")
			}
			_ = before
		})
	}
}

func TestMigratePreservesCommittedRegistryRowStillInWAL(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, source)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	reader, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	var count int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM plugin_records`).Scan(&count); err != nil {
		reader.Rollback()
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE plugin_records SET version='9.9.9', updated_at=updated_at+1 WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1'`); err != nil {
		reader.Rollback()
		db.Close()
		t.Fatal(err)
	}
	walBefore, err := os.ReadFile(source + "-wal")
	if err != nil || len(walBefore) == 0 {
		reader.Rollback()
		db.Close()
		t.Fatalf("committed WAL is unavailable: bytes=%d err=%v", len(walBefore), err)
	}
	mainBefore, err := os.ReadFile(source)
	if err != nil {
		reader.Rollback()
		db.Close()
		t.Fatal(err)
	}

	store, err := Migrate(context.Background(), Config{Path: filepath.Join(dir, "control.sqlite"), Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source)}}})
	if err != nil {
		reader.Rollback()
		db.Close()
		t.Fatal(err)
	}
	defer store.Close()
	var version string
	if err := store.db.QueryRow(`SELECT version FROM plugin_records WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "9.9.9" {
		t.Fatalf("migrated version = %q, want committed WAL value", version)
	}
	mainAfter, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	walAfter, err := os.ReadFile(source + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mainAfter, mainBefore) || !bytes.Equal(walAfter, walBefore) {
		t.Fatal("migration modified the source database or its WAL")
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateHistoricalV5RegistryInitializerShape(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, source)
	createHistoricalV5RegistryTables(t, db)
	if _, err := db.Exec(`PRAGMA user_version=5`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := mustSourceDigest(t, source)
	store, err := Migrate(context.Background(), Config{Path: filepath.Join(dir, "control.sqlite"), Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var records int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM plugin_records WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1'`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 1 {
		t.Fatalf("migrated plugin records = %d", records)
	}
	if after := mustSourceDigest(t, source); after != before {
		t.Fatalf("source digest changed: %s -> %s", before, after)
	}
}

func TestMigrateRejectsDriftedHistoricalV5ReceiptSchema(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, source)
	if _, err := db.Exec(`CREATE TABLE external_package_commit_receipts(legacy TEXT); PRAGMA user_version=5`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := mustSourceDigest(t, source)
	if _, err := Migrate(context.Background(), Config{Path: filepath.Join(dir, "control.sqlite"), Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: 5}}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
	if after := mustSourceDigest(t, source); after != before {
		t.Fatalf("source digest changed: %s -> %s", before, after)
	}
}

func TestOpenRejectsUnknownVersionZeroDatabaseWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db := openTestDB(t, path)
	if _, err := db.Exec(`CREATE TABLE unrelated_state(id TEXT PRIMARY KEY, value TEXT); INSERT INTO unrelated_state VALUES('id','user-data')`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("Open() error = %v, want ErrIncompatible", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("unknown version-zero database was mutated")
	}
}

func TestMigrateRejectsFutureAndDriftedSourcesWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		mutate     string
		descriptor func(*testing.T, string) Source
	}{
		{
			name:   "future",
			mutate: `PRAGMA user_version=999`,
			descriptor: func(_ *testing.T, path string) Source {
				return Source{Name: "registry", Path: path, Kind: "registry", Version: 999}
			},
		},
		{
			name:   "drift",
			mutate: `DROP TABLE plugin_permission_grants`,
			descriptor: func(t *testing.T, path string) Source {
				return Source{Name: "registry", Path: path, Kind: "registry", Version: sqliteUserVersion(t, path)}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "registry.sqlite")
			target := filepath.Join(dir, "control.sqlite")
			if err := createLegacyFixture(source); err != nil {
				t.Fatal(err)
			}
			db := openTestDB(t, source)
			if _, err := db.Exec(test.mutate); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{test.descriptor(t, source)}}); !errors.Is(err, ErrMigration) {
				t.Fatalf("Migrate() error = %v, want ErrMigration", err)
			}
			after, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("rejected source was mutated")
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("target exists after rejected source: %v", err)
			}
		})
	}
}

func TestMigrateRejectsMismatchedSourceVersion(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	actual := sqliteUserVersion(t, source)
	if _, err := Migrate(context.Background(), Config{Path: filepath.Join(dir, "control.sqlite"), Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: actual - 1}}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
}

func TestMigrateRejectsConfirmationRowsThatRequireAmbiguousOwnerMigration(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "confirmation.sqlite")
	legacy, err := security.NewSQLiteConfirmationIntentStore(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, source)
	if _, err := db.Exec(`INSERT INTO plugin_confirmation_intents(confirmation_id,confirmation_token_id,plugin_id,plugin_instance_id,surface_instance_id,bridge_channel_id,method,request_hash,plan_hash,scope_json,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,migration_required,issued_at,expires_at) VALUES('ambiguous','token','plugin','instance','surface','bridge','method','request','plan','{}','','','','',1,1,2)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := mustSourceDigest(t, source)
	if _, err := Migrate(context.Background(), Config{Path: filepath.Join(dir, "control.sqlite"), Sources: []Source{{Name: "confirmation", Path: source, Kind: "confirmation", Version: 0}}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
	if after := mustSourceDigest(t, source); after != before {
		t.Fatalf("source digest changed: %s -> %s", before, after)
	}
}

func TestMigratePublishesOnlyAfterVerificationAndPreservesSourceOnFault(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	registryVersion := sqliteUserVersion(t, source)
	_, err = Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: registryVersion}}, Faults: Faults{AfterImport: errors.New("inject import")}})
	if !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
	after, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("source changed after failed migration")
	}
	sourceDB, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceDB.Close()
	var sourceManagementRevision uint64
	if err := sourceDB.QueryRow(`SELECT management_revision FROM plugin_records WHERE plugin_instance_id='instance-1'`).Scan(&sourceManagementRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("target published after failed migration: %v", err)
	}
	syncCalls := 0
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: registryVersion}}, Faults: Faults{SyncDirectory: func(path string) error { syncCalls++; return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", store.Generation())
	}
	if syncCalls != 3 {
		t.Fatalf("directory sync calls = %d, want 3", syncCalls)
	}
	marker, err := os.ReadFile(target + ".migration.json")
	if err != nil {
		t.Fatal(err)
	}
	var state descriptor
	if err := json.Unmarshal(marker, &state); err != nil {
		t.Fatal(err)
	}
	if state.Stage != "complete" || state.VerifiedCounts["plugin_records"] != 1 || state.VerifiedCounts["permission_grants"] != 1 || state.VerifiedCounts["security_policies"] != 1 {
		t.Fatalf("marker = %#v", state)
	}
	var owner, pluginID, version, packageHash, recordState string
	var managementRevision uint64
	if err := store.db.QueryRow(`SELECT owner_env_hash,plugin_id,version,package_sha256,state,management_revision FROM plugin_records WHERE plugin_instance_id='instance-1'`).Scan(&owner, &pluginID, &version, &packageHash, &recordState, &managementRevision); err != nil {
		t.Fatal(err)
	}
	if owner != "env-1" || pluginID != "com.example.plugin" || version != "1.2.3" || packageHash != "sha256:package" || recordState != "enabled" || managementRevision != sourceManagementRevision {
		t.Fatalf("migrated plugin = %q %q %q %q %q %d", owner, pluginID, version, packageHash, recordState, managementRevision)
	}
	legacyStore, err := registry.NewSQLiteStore(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyStore.Close()
	legacyContext := sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash: "migration", OwnerUserHash: "migration", OwnerEnvHash: "env-1", SessionChannelIDHash: "migration",
	})
	wantRecord, err := legacyStore.GetPlugin(legacyContext, "instance-1")
	if err != nil {
		t.Fatal(err)
	}
	wantRecordJSON, err := json.Marshal(wantRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		sourceTable, targetTable, targetColumn, condition string
	}{
		{"plugin_permission_grants", "permission_grants", "grant_json", `plugin_instance_id='instance-1'`},
		{"plugin_security_policies", "security_policies", "policy_json", `plugin_instance_id='instance-1'`},
	} {
		want, err := canonicalRowJSON(context.Background(), sourceDB, check.sourceTable, check.condition)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		if err := store.db.QueryRow(`SELECT ` + check.targetColumn + ` FROM ` + check.targetTable + ` WHERE ` + check.condition).Scan(&got); err != nil {
			t.Fatal(err)
		}
		assertJSONEqual(t, got, want)
	}
	var gotRecordJSON string
	if err := store.db.QueryRow(`SELECT record_json FROM plugin_records WHERE plugin_instance_id='instance-1'`).Scan(&gotRecordJSON); err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, gotRecordJSON, string(wantRecordJSON))
	afterSuccess, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterSuccess) != string(before) {
		t.Fatal("source changed after successful migration")
	}
}

func TestMigratePopulatedRegistryEverySupportedVersion(t *testing.T) {
	for version := 0; version <= registry.SQLiteSchemaVersion; version++ {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "registry.sqlite")
			if err := createLegacyFixture(source); err != nil {
				t.Fatal(err)
			}
			db := openTestDB(t, source)
			switch version {
			case 2:
				if _, err := db.Exec(`DROP TABLE IF EXISTS release_install_operations`); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := mustSourceDigest(t, source)

			store, err := Migrate(context.Background(), Config{
				Path: filepath.Join(dir, "control.sqlite"),
				Sources: []Source{{
					Name: "registry", Path: source, Kind: "registry", Version: version,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			if after := mustSourceDigest(t, source); after != before {
				t.Fatalf("source digest changed: %s -> %s", before, after)
			}
			var records, grants, policies int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM plugin_records WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1'`).Scan(&records); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM permission_grants WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1' AND capability_id='documents.read'`).Scan(&grants); err != nil {
				t.Fatal(err)
			}
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE owner_env_hash='env-1' AND plugin_instance_id='instance-1'`).Scan(&policies); err != nil {
				t.Fatal(err)
			}
			if records != 1 || grants != 1 || policies != 1 {
				t.Fatalf("migrated counts = records:%d grants:%d policies:%d", records, grants, policies)
			}
		})
	}
}

func TestMigrateRegistryReleaseInstallOperationFailsClosedWithoutExactSessionOwner(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	want := createRegistryReleaseInstallOperation(t, source, "env-1", "operation_install_example")
	before := mustSourceDigest(t, source)
	target := filepath.Join(dir, "control.sqlite")

	_, err := Migrate(context.Background(), Config{
		Path: target,
		Sources: []Source{{
			Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source),
		}},
	})
	if !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want %v", err, ErrMigration)
	}
	if after := mustSourceDigest(t, source); after != before {
		t.Fatalf("source digest changed: %s -> %s", before, after)
	}
	db := openTestDB(t, source)
	defer db.Close()
	var gotOperationID, gotStatus, gotDiagnostics string
	var gotRevision uint64
	if err := db.QueryRow(`SELECT operation_id,status,revision,phase_diagnostics_json FROM release_install_operations WHERE operation_id=?`, want.operationID).Scan(&gotOperationID, &gotStatus, &gotRevision, &gotDiagnostics); err != nil {
		t.Fatal(err)
	}
	if gotOperationID != want.operationID || gotRevision != want.revision || gotStatus != want.status || gotDiagnostics != want.phaseDiagnosticsJSON {
		t.Fatalf("preserved legacy row = id:%q status:%q revision:%d diagnostics:%s", gotOperationID, gotStatus, gotRevision, gotDiagnostics)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("target should not publish after ambiguous migration: %v", statErr)
	}
}

func TestMigrateRegistryReleaseInstallOperationFailsClosedForEveryJournalVersion(t *testing.T) {
	for version := 3; version <= registry.SQLiteSchemaVersion; version++ {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "registry.sqlite")
			createRegistryReleaseInstallOperation(t, source, "env-1", fmt.Sprintf("operation_v%d", version))
			db := openTestDB(t, source)
			if version == 3 {
				for _, column := range []string{"phase_diagnostics_json", "activation_json", "activation_request_json"} {
					if _, err := db.Exec(`ALTER TABLE release_install_operations DROP COLUMN ` + column); err != nil {
						db.Close()
						t.Fatal(err)
					}
				}
			}
			if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := mustSourceDigest(t, source)

			_, err := Migrate(context.Background(), Config{
				Path: filepath.Join(dir, "control.sqlite"),
				Sources: []Source{{
					Name: "registry", Path: source, Kind: "registry", Version: version,
				}},
			})
			if !errors.Is(err, ErrMigration) {
				t.Fatalf("Migrate() error = %v, want %v", err, ErrMigration)
			}
			if after := mustSourceDigest(t, source); after != before {
				t.Fatalf("source digest changed: %s -> %s", before, after)
			}
		})
	}
}

func TestMigrateRegistryReleaseInstallOperationRejectsSchemaDriftWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	createRegistryReleaseInstallOperation(t, source, "env-1", "operation_drift")
	db := openTestDB(t, source)
	if _, err := db.Exec(`ALTER TABLE release_install_operations ADD COLUMN unexpected_owner TEXT NOT NULL DEFAULT ''`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := mustSourceDigest(t, source)
	target := filepath.Join(dir, "control.sqlite")

	_, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{
		Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source),
	}}})
	if !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want %v", err, ErrMigration)
	}
	if after := mustSourceDigest(t, source); after != before {
		t.Fatalf("source digest changed: %s -> %s", before, after)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("target should not publish after schema drift: %v", statErr)
	}
}

func TestMigrateRegistryReleaseInstallOperationRejectsMultipleAmbiguousSourcesWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "registry-a.sqlite")
	second := filepath.Join(dir, "registry-b.sqlite")
	createRegistryReleaseInstallOperation(t, first, "env-a", "shared_operation_id")
	createRegistryReleaseInstallOperation(t, second, "env-b", "shared_operation_id")
	firstBefore := mustSourceDigest(t, first)
	secondBefore := mustSourceDigest(t, second)
	target := filepath.Join(dir, "control.sqlite")

	_, err := Migrate(context.Background(), Config{
		Path: target,
		Sources: []Source{
			{Name: "registry-a", Path: first, Kind: "registry", Version: sqliteUserVersion(t, first)},
			{Name: "registry-b", Path: second, Kind: "registry", Version: sqliteUserVersion(t, second)},
		},
	})
	if !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want %v", err, ErrMigration)
	}
	if after := mustSourceDigest(t, first); after != firstBefore {
		t.Fatalf("first source digest changed: %s -> %s", firstBefore, after)
	}
	if after := mustSourceDigest(t, second); after != secondBefore {
		t.Fatalf("second source digest changed: %s -> %s", secondBefore, after)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("target should not publish after conflict: %v", statErr)
	}
}

func TestMigrateConfirmationIntentsAndRevocationsLosslessly(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "confirmations.sqlite")
	target := filepath.Join(dir, "control.sqlite")
	ctx := context.Background()
	legacy, err := security.NewSQLiteConfirmationIntentStore(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(40, 0).UTC()
	scope := security.ConfirmationScope{ActiveFingerprint: "sha256:fingerprint", OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel", PolicyRevision: 2, ManagementRevision: 3, RevokeEpoch: 4, TargetDescriptorSHA256: "sha256:target"}
	if _, err := legacy.PutConfirmationIntent(ctx, security.PutConfirmationIntentRequest{ConfirmationID: "confirm-keep", ConfirmationTokenID: "token", PluginID: "com.example", PluginInstanceID: "plugin", SurfaceInstanceID: "surface", BridgeChannelID: "bridge", Method: "documents.write", RequestHash: "sha256:request", PlanHash: "sha256:plan", Scope: scope, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Now: now}); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	revokedScope := sessionctx.SessionScope{OwnerSessionHash: "revoked-session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "revoked-channel"}
	if _, err := legacy.RevokeSessionConfirmationIntents(ctx, security.RevokeSessionConfirmationIntentsRequest{SessionScope: revokedScope, TeardownOperationID: "teardown-1", Now: now}); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	beforeDigest, err := SourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceDB := openTestDB(t, source)
	defer sourceDB.Close()
	wantIntent, err := canonicalRowJSON(ctx, sourceDB, "plugin_confirmation_intents", `confirmation_id='confirm-keep'`)
	if err != nil {
		t.Fatal(err)
	}
	wantRevocation, err := canonicalRowJSON(ctx, sourceDB, "plugin_confirmation_session_revocations", `teardown_operation_id='teardown-1'`)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Migrate(ctx, Config{Path: target, Sources: []Source{{Name: "confirmation", Path: source, Kind: "confirmation", Version: 0}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var gotIntent, gotRevocation string
	if err := store.db.QueryRow(`SELECT confirmation_json FROM confirmation_intents WHERE confirmation_id='confirm-keep'`).Scan(&gotIntent); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT revocation_json FROM confirmation_session_revocations WHERE teardown_operation_id='teardown-1'`).Scan(&gotRevocation); err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, gotIntent, wantIntent)
	assertJSONEqual(t, gotRevocation, wantRevocation)
	afterDigest, err := SourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	if afterDigest != beforeDigest {
		t.Fatalf("confirmation source digest changed: %s -> %s", beforeDigest, afterDigest)
	}
}

func TestPublishFaultBlocksReopenUntilVerified(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	registryVersion := sqliteUserVersion(t, source)
	if _, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: registryVersion}}, Faults: Faults{AfterPublish: errors.New("inject reopen")}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
	if _, err := Open(context.Background(), Config{Path: target}); !errors.Is(err, ErrRequestsBlocked) {
		t.Fatalf("Open() error = %v, want ErrRequestsBlocked", err)
	}
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: registryVersion}}})
	if err != nil {
		t.Fatalf("resume Migrate() error = %v", err)
	}
	defer store.Close()
	if !store.Ready() {
		t.Fatal("resumed store is not ready")
	}
}

func TestPendingMigrationRejectsChangedSource(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	sources := []Source{{Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source)}}
	if _, err := Migrate(context.Background(), Config{Path: target, Sources: sources, Faults: Faults{AfterPublish: errors.New("inject reopen")}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("Migrate() error = %v, want ErrMigration", err)
	}
	file, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("changed")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(context.Background(), Config{Path: target, Sources: sources}); !errors.Is(err, ErrMigration) {
		t.Fatalf("resume with changed source error = %v, want ErrMigration", err)
	}
	if _, err := Open(context.Background(), Config{Path: target}); !errors.Is(err, ErrRequestsBlocked) {
		t.Fatalf("Open() error = %v, want ErrRequestsBlocked", err)
	}
}

func TestOpenIgnoresHistoricalCompleteMarkerCountsAfterMigration(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	source := filepath.Join(dir, "registry.sqlite")
	if err := createLegacyFixture(source); err != nil {
		t.Fatal(err)
	}
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	markerPath := target + ".migration.json"
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var state descriptor
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state.VerifiedCounts["plugin_records"]++
	if err := writeDescriptor(markerPath, state); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(context.Background(), Config{Path: target}); err != nil {
		t.Fatalf("Open() error = %v", err)
	} else {
		reopened.Close()
	}
}

func TestMigrateExecutionAndStreamByBinding(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	operationPath := filepath.Join(dir, "operations.sqlite")
	streamPath := filepath.Join(dir, "streams.sqlite")
	if err := createExecutionFixtures(operationPath, streamPath, false); err != nil {
		t.Fatal(err)
	}
	operationDigest := mustSourceDigest(t, operationPath)
	streamDigest := mustSourceDigest(t, streamPath)
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "operation", Path: operationPath, Kind: "operation", Version: 1}, {Name: "stream", Path: streamPath, Kind: "stream", Version: 0}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	execution, err := store.GetExecution(context.Background(), "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	if execution.Kind != "subscription" || execution.PluginInstanceID != "plugin-1" {
		t.Fatalf("execution = %#v", execution)
	}
	operationDB := openTestDB(t, operationPath)
	defer operationDB.Close()
	streamDB := openTestDB(t, streamPath)
	defer streamDB.Close()
	wantOperation, err := canonicalRowJSON(context.Background(), operationDB, "plugin_operations", `operation_id=?`, "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	wantStream, err := canonicalRowJSON(context.Background(), streamDB, "plugin_streams", `stream_id=?`, "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	var gotOperation, gotStream string
	if err := store.db.QueryRow(`SELECT operation_json,stream_json FROM execution WHERE execution_id='operation-1'`).Scan(&gotOperation, &gotStream); err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, gotOperation, wantOperation)
	assertJSONEqual(t, gotStream, wantStream)
	rows, err := store.db.Query(`SELECT sequence,kind,payload_json,error_json FROM execution_events WHERE execution_id='operation-1' ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type migratedEvent struct {
		sequence uint64
		kind     string
		payload  map[string]any
		err      any
	}
	var events []migratedEvent
	for rows.Next() {
		var event migratedEvent
		var payload, eventError string
		if err := rows.Scan(&event.sequence, &event.kind, &payload, &eventError); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(payload), &event.payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(eventError), &event.err); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].sequence != 1 || events[0].kind != "data" || events[0].payload["legacy_kind"] != "data" || events[0].payload["data"] != "YWxwaGE=" || events[0].payload["at"] != float64(21) || events[0].err != nil {
		t.Fatalf("first migrated event = %#v", events)
	}
	secondError, ok := events[1].err.(map[string]any)
	if len(events) != 2 || events[1].sequence != 2 || events[1].kind != "diagnostic" || events[1].payload["legacy_kind"] != "error" || events[1].payload["at"] != float64(22) || !ok || secondError["message"] != "worker failed" {
		t.Fatalf("second migrated event = %#v", events)
	}
	if got := mustSourceDigest(t, operationPath); got != operationDigest {
		t.Fatalf("operation source digest changed: %s -> %s", operationDigest, got)
	}
	if got := mustSourceDigest(t, streamPath); got != streamDigest {
		t.Fatalf("stream source digest changed: %s -> %s", streamDigest, got)
	}

	badTarget := filepath.Join(dir, "bad-control.sqlite")
	badOperationPath := filepath.Join(dir, "bad-operations.sqlite")
	badStreamPath := filepath.Join(dir, "bad-streams.sqlite")
	if err := createExecutionFixtures(badOperationPath, badStreamPath, true); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(context.Background(), Config{Path: badTarget, Sources: []Source{{Name: "operation", Path: badOperationPath, Kind: "operation", Version: 1}, {Name: "stream", Path: badStreamPath, Kind: "stream", Version: 0}}}); !errors.Is(err, ErrMigration) {
		t.Fatalf("conflicting binding error = %v, want ErrMigration", err)
	}
}

func TestMigrateOperationWithoutStream(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	operationPath := filepath.Join(dir, "operations.sqlite")
	binding := testBinding("operation-only", "")
	binding.Execution = "operation"
	if err := createLegacyOperationFixture(operationPath, 1, "operation-only", binding); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := Migrate(ctx, Config{Path: target, Sources: []Source{{Name: "operation", Path: operationPath, Kind: "operation", Version: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	execution, err := store.GetExecution(ctx, "operation-only")
	if err != nil {
		t.Fatal(err)
	}
	if execution.Kind != "operation" || execution.Cursor != 0 {
		t.Fatalf("execution = %#v", execution)
	}
}

func TestMigratePopulatedOperationV0AndStreamIntoOneExecution(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "control.sqlite")
	operationPath := filepath.Join(dir, "operations-v0.sqlite")
	streamPath := filepath.Join(dir, "streams.sqlite")
	if err := createExecutionFixtures(operationPath, streamPath, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(operationPath); err != nil {
		t.Fatal(err)
	}
	binding := testBinding("operation-1", "")
	binding.Execution = "subscription"
	if err := createLegacyOperationFixture(operationPath, 0, "operation-1", binding); err != nil {
		t.Fatal(err)
	}
	operationDigest := mustSourceDigest(t, operationPath)
	streamDigest := mustSourceDigest(t, streamPath)
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{
		{Name: "operation", Path: operationPath, Kind: "operation", Version: 0},
		{Name: "stream", Path: streamPath, Kind: "stream", Version: 0},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	execution, err := store.GetExecution(context.Background(), "operation-1")
	if err != nil {
		t.Fatal(err)
	}
	if execution.ID != "operation-1" || execution.PluginInstanceID != "plugin-1" || execution.Kind != "subscription" || execution.Status != "running" || execution.Cursor != 2 {
		t.Fatalf("execution = %#v", execution)
	}
	if got := mustSourceDigest(t, operationPath); got != operationDigest {
		t.Fatalf("operation source digest changed: %s -> %s", operationDigest, got)
	}
	if got := mustSourceDigest(t, streamPath); got != streamDigest {
		t.Fatalf("stream source digest changed: %s -> %s", streamDigest, got)
	}
}

func TestMigrateRejectsLegacyExecutionSchemaDriftWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   string
		mutate string
	}{
		{name: "operation missing column", kind: "operation", mutate: `ALTER TABLE plugin_operations DROP COLUMN failure_code`},
		{name: "operation extra object", kind: "operation", mutate: `CREATE TABLE unexpected_state(id TEXT)`},
		{name: "stream missing column", kind: "stream", mutate: `ALTER TABLE plugin_stream_events DROP COLUMN error`},
		{name: "stream extra object", kind: "stream", mutate: `CREATE INDEX unexpected_index ON plugin_streams(stream_id)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			operationPath := filepath.Join(dir, "operations.sqlite")
			streamPath := filepath.Join(dir, "streams.sqlite")
			if err := createExecutionFixtures(operationPath, streamPath, false); err != nil {
				t.Fatal(err)
			}
			path := operationPath
			if tc.kind == "stream" {
				path = streamPath
			}
			db := openTestDB(t, path)
			if _, err := db.Exec(tc.mutate); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := mustSourceDigest(t, path)
			version := 0
			if tc.kind == "operation" {
				version = 1
			}
			target := filepath.Join(dir, "control.sqlite")
			if _, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: tc.kind, Path: path, Kind: tc.kind, Version: version}}}); !errors.Is(err, ErrMigration) {
				t.Fatalf("Migrate() error = %v, want %v", err, ErrMigration)
			}
			if after := mustSourceDigest(t, path); after != before {
				t.Fatalf("source digest changed: %s -> %s", before, after)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("target published after rejected drift: %v", err)
			}
		})
	}
}

func TestMigrateSessionFenceV1PreservesTeardownFacts(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "session.sqlite")
	target := filepath.Join(dir, "control.sqlite")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	proof := make([]byte, 32)
	proof[0] = 7
	_, err = db.Exec(`PRAGMA user_version=1;CREATE TABLE plugin_session_scope_fences(owner_session_hash TEXT,owner_user_hash TEXT,owner_env_hash TEXT,session_channel_id_hash TEXT,state TEXT,teardown_operation_id TEXT,surfaces INTEGER,asset_tickets INTEGER,asset_sessions INTEGER,plugin_gateway_tokens INTEGER,confirmation_tokens INTEGER,stream_tickets INTEGER,handle_grants INTEGER,confirmations INTEGER,operations INTEGER,streams INTEGER,runtime_executions INTEGER,active_network_requests INTEGER,sockets INTEGER,network_streams INTEGER,storage_hostcalls INTEGER,proof_sha256 BLOB,created_at INTEGER,updated_at INTEGER);CREATE TABLE plugin_session_scope_teardown_phases(owner_session_hash TEXT,owner_user_hash TEXT,owner_env_hash TEXT,session_channel_id_hash TEXT,phase TEXT,counts_json BLOB);INSERT INTO plugin_session_scope_fences VALUES('session','user','env','channel','incomplete','teardown-1',1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,?,16,17);INSERT INTO plugin_session_scope_teardown_phases VALUES('session','user','env','channel','stream','{"streams":2}')`, proof)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	beforeDigest := mustSourceDigest(t, source)
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "session", Path: source, Kind: "session", Version: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var state, raw string
	var gotProof []byte
	if err := store.db.QueryRow(`SELECT state,fence_json,proof_sha256 FROM session_fences`).Scan(&state, &raw, &gotProof); err != nil {
		t.Fatal(err)
	}
	if state != "incomplete" || string(gotProof) != string(proof) {
		t.Fatalf("fence state/proof = %q %x", state, gotProof)
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(raw), &facts); err != nil {
		t.Fatal(err)
	}
	if facts["teardown_operation_id"] != "teardown-1" || facts["storage_hostcalls"] != float64(15) || facts["executions"] != float64(11) {
		t.Fatalf("fence facts = %#v", facts)
	}
	for _, retired := range []string{"stream_tickets", "operations", "streams", "runtime_executions"} {
		if _, ok := facts[retired]; ok {
			t.Fatalf("retired fence fact %q remains in %#v", retired, facts)
		}
	}
	var phaseRaw string
	if err := store.db.QueryRow(`SELECT phase_json FROM session_teardown_phases WHERE phase='execution'`).Scan(&phaseRaw); err != nil {
		t.Fatal(err)
	}
	var phaseFacts map[string]any
	if err := json.Unmarshal([]byte(phaseRaw), &phaseFacts); err != nil {
		t.Fatal(err)
	}
	if phaseFacts["phase"] != "execution" || phaseFacts["counts_json"] != `{"executions":2}` {
		t.Fatalf("execution phase facts = %#v", phaseFacts)
	}
	var retiredPhases int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM session_teardown_phases WHERE phase IN ('operation','stream')`).Scan(&retiredPhases); err != nil {
		t.Fatal(err)
	}
	if retiredPhases != 0 {
		t.Fatalf("retired teardown phases = %d", retiredPhases)
	}
	if got := mustSourceDigest(t, source); got != beforeDigest {
		t.Fatalf("session source digest changed: %s -> %s", beforeDigest, got)
	}
}

func createExecutionFixtures(operationPath, streamPath string, conflict bool) error {
	operationBinding := testBinding("operation-1", "")
	operationBinding.Execution = "subscription"
	if err := createLegacyOperationFixture(operationPath, 1, "operation-1", operationBinding); err != nil {
		return err
	}
	streamBinding := testBinding("operation-1", "")
	streamID := "operation-1"
	if conflict {
		streamBinding.ExecutionID = "operation-2"
		streamID = "operation-2"
	}
	return createLegacyStreamFixture(streamPath, streamID, streamBinding, !conflict)
}

func createLegacyOperationFixture(path string, version int, operationID string, binding capability.ExecutionBinding) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	schema := `CREATE TABLE plugin_operations (
operation_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, method TEXT NOT NULL,
effect TEXT NOT NULL, execution TEXT NOT NULL, surface_instance_id TEXT NOT NULL, owner_session_hash TEXT NOT NULL,
owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, bridge_channel_id TEXT NOT NULL,
execution_binding_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL, cancelable INTEGER NOT NULL DEFAULT 1,
cancel_ack_timeout_ms INTEGER NOT NULL DEFAULT 0, disable_behavior TEXT NOT NULL, uninstall_behavior TEXT NOT NULL,
failure_code TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
cancel_requested_at INTEGER, orphaned_at INTEGER, terminal_at INTEGER, progress_json TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_plugin_operations_plugin_instance ON plugin_operations(plugin_instance_id, created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_owner_plugin_instance ON plugin_operations(owner_env_hash, plugin_instance_id, created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_created ON plugin_operations(created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_owner ON plugin_operations(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_plugin_owner ON plugin_operations(plugin_instance_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_owner_plugin_session ON plugin_operations(owner_env_hash, plugin_instance_id, owner_session_hash, owner_user_hash, session_channel_id_hash, created_at DESC, operation_id DESC);
CREATE INDEX idx_plugin_operations_terminal_retention ON plugin_operations(plugin_instance_id, terminal_at DESC, operation_id DESC) WHERE terminal_at IS NOT NULL;
CREATE INDEX idx_plugin_operations_owner_terminal_retention ON plugin_operations(owner_env_hash, plugin_instance_id, terminal_at DESC, operation_id DESC) WHERE terminal_at IS NOT NULL;`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	if version == 0 {
		if _, err := db.Exec(`ALTER TABLE plugin_operations DROP COLUMN progress_json`); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	columns := `operation_id,plugin_id,plugin_instance_id,method,effect,execution,surface_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,bridge_channel_id,execution_binding_json,status,cancelable,cancel_ack_timeout_ms,disable_behavior,uninstall_behavior,failure_code,reason,created_at,updated_at,cancel_requested_at,orphaned_at,terminal_at`
	values := []any{operationID, binding.PluginID, binding.PluginInstanceID, binding.Method, binding.Effect, binding.Execution, binding.SurfaceInstanceID, binding.OwnerSessionHash, binding.OwnerUserHash, binding.OwnerEnvHash, binding.SessionChannelIDHash, binding.BridgeChannelID, string(raw), "running", 1, 0, "cancel", "cancel", "", "", int64(10), int64(10), nil, nil, nil}
	placeholders := `?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?`
	if version == 1 {
		columns += `,progress_json`
		placeholders += `,?`
		values = append(values, "")
	}
	if _, err := db.Exec(`INSERT INTO plugin_operations(`+columns+`) VALUES(`+placeholders+`)`, values...); err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, version))
	return err
}

func createLegacyStreamFixture(path, streamID string, binding capability.ExecutionBinding, events bool) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;
CREATE TABLE plugin_streams (
stream_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, method TEXT NOT NULL,
effect TEXT NOT NULL, execution TEXT NOT NULL, surface_instance_id TEXT NOT NULL, owner_session_hash TEXT NOT NULL,
owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, bridge_channel_id TEXT NOT NULL,
execution_binding_json TEXT NOT NULL DEFAULT '{}', direction TEXT NOT NULL, status TEXT NOT NULL, failure_code TEXT NOT NULL,
reason TEXT NOT NULL DEFAULT '', content_type TEXT NOT NULL, max_buffered_bytes INTEGER NOT NULL, buffered_bytes INTEGER NOT NULL,
next_sequence INTEGER NOT NULL, pending_delivery_id TEXT NOT NULL, pending_read_id TEXT NOT NULL, pending_through_sequence INTEGER NOT NULL,
pending_done INTEGER NOT NULL, pending_terminal_status TEXT NOT NULL, last_acknowledged_delivery_id TEXT NOT NULL,
terminal_acknowledged INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, closed_at INTEGER);
CREATE TABLE plugin_stream_events (stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL, data BLOB,
error TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(stream_id,sequence), FOREIGN KEY(stream_id) REFERENCES plugin_streams(stream_id) ON DELETE CASCADE);
CREATE INDEX idx_plugin_streams_plugin_instance ON plugin_streams(plugin_instance_id, created_at, stream_id);
CREATE INDEX idx_plugin_streams_owner_plugin_instance ON plugin_streams(owner_env_hash, plugin_instance_id, created_at, stream_id);
CREATE INDEX idx_plugin_streams_session_scope ON plugin_streams(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, stream_id);
CREATE INDEX idx_plugin_streams_terminal_retention ON plugin_streams(plugin_instance_id, closed_at DESC, stream_id DESC) WHERE terminal_acknowledged = 1;
CREATE INDEX idx_plugin_streams_owner_terminal_retention ON plugin_streams(owner_env_hash, plugin_instance_id, closed_at DESC, stream_id DESC) WHERE terminal_acknowledged = 1;`); err != nil {
		return err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO plugin_streams VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, streamID, binding.PluginID, binding.PluginInstanceID, binding.Method, binding.Effect, binding.Execution, binding.SurfaceInstanceID, binding.OwnerSessionHash, binding.OwnerUserHash, binding.OwnerEnvHash, binding.SessionChannelIDHash, binding.BridgeChannelID, string(raw), "out", "open", "", "", "application/json", 1048576, 0, 3, "", "", 0, 0, "", "", 0, int64(10), int64(10), nil); err != nil {
		return err
	}
	if events {
		if _, err := db.Exec(`INSERT INTO plugin_stream_events VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`, streamID, 1, "data", []byte("alpha"), "", int64(21), streamID, 2, "error", nil, "worker failed", int64(22)); err != nil {
			return err
		}
	}
	_, err = db.Exec(`PRAGMA user_version=0`)
	return err
}

func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func sqliteUserVersion(t *testing.T, path string) int {
	t.Helper()
	db := openTestDB(t, path)
	defer db.Close()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func mustSourceDigest(t *testing.T, path string) string {
	t.Helper()
	digest, err := SourceDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("decode got JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode want JSON: %v", err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}

func testBinding(executionID, _ string) capability.ExecutionBinding {
	return capability.ExecutionBinding{InvocationID: "invoke", AuditCorrelationID: "audit", ExecutionID: executionID, PublisherID: "publisher", PluginID: "com.example.plugin", PluginInstanceID: "plugin-1", PluginVersion: "1.0.0", ActiveFingerprint: "sha256:test", CapabilityID: "cap", CapabilityVersion: "1", BindingID: "binding", Method: "watch", TargetMethod: "watch", Effect: capability.EffectRead, Execution: "subscription", Target: capability.TargetDescriptor{Kind: "workspace", Fields: map[string]any{"id": "1"}}, TargetDescriptorSHA256: "sha256:target", OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
}

func createLegacyFixture(path string) error {
	ctx := sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env-1", SessionChannelIDHash: "channel"})
	store, err := registry.NewSQLiteStore(ctx, path)
	if err != nil {
		return err
	}
	now := time.Unix(0, 10).UTC()
	record, err := store.PutPlugin(ctx, registry.PluginRecord{PluginInstanceID: "instance-1", PublisherID: "publisher-1", PluginID: "com.example.plugin", Version: "1.2.3", ActiveFingerprint: "sha256:fingerprint", PackageHash: "sha256:package", ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries", TrustState: registry.TrustVerified, EnableState: registry.EnableEnabled, Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Plugin: manifest.Plugin{PluginID: "com.example.plugin", Version: "1.2.3"}}}, registry.PutOptions{Now: now})
	if err != nil {
		store.Close()
		return err
	}
	snapshot, err := store.GrantPermission(ctx, permissions.GrantRequest{PluginInstanceID: "instance-1", PermissionID: "documents.read", GrantedBy: "user", Now: now.Add(time.Second)}, registry.AuthorizationRevisionsFromRecord(record))
	if err != nil {
		store.Close()
		return err
	}
	_, err = store.PutSecurityPolicy(ctx, security.PutPolicyRequest{PluginInstanceID: "instance-1", AllowedPermissions: []string{"documents.read"}, Now: now.Add(2 * time.Second)}, registry.AuthorizationRevisionsFromRecord(snapshot.Plugin))
	if err != nil {
		store.Close()
		return err
	}
	return store.Close()
}

func createHistoricalV5RegistryTables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
CREATE TABLE external_package_commit_receipts (
owner_env_hash TEXT NOT NULL, inspection_id TEXT NOT NULL, commit_id TEXT NOT NULL, intent TEXT NOT NULL,
confirmation_digest TEXT NOT NULL, request_sha256 TEXT NOT NULL, expected_management_revision INTEGER NOT NULL,
intended_fingerprint TEXT NOT NULL, intended_package_sha256 TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
status TEXT NOT NULL, mutation_outcome TEXT NOT NULL, record_snapshot_json TEXT NOT NULL DEFAULT 'null',
failure_code TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
PRIMARY KEY(owner_env_hash, inspection_id), UNIQUE(owner_env_hash, commit_id));
CREATE TABLE release_install_operations (
owner_env_hash TEXT NOT NULL, request_id TEXT NOT NULL, operation_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
request_sha256 TEXT NOT NULL, release_identity_json TEXT NOT NULL,
activation_request_json TEXT NOT NULL DEFAULT '{"mode":"disabled"}', status TEXT NOT NULL, phase TEXT NOT NULL,
progress_kind TEXT NOT NULL, progress_completed INTEGER NOT NULL, progress_total INTEGER NOT NULL, attempt INTEGER NOT NULL,
retry_after_ms INTEGER NOT NULL, mutation_outcome TEXT NOT NULL, failure_code TEXT NOT NULL, failure_retryable INTEGER NOT NULL,
plugin_record_json TEXT NOT NULL DEFAULT 'null', activation_json TEXT NOT NULL DEFAULT '{"status":"not_requested"}',
phase_diagnostics_json TEXT NOT NULL DEFAULT '[]', revision INTEGER NOT NULL, created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL, terminal_at INTEGER, PRIMARY KEY(owner_env_hash, request_id), UNIQUE(owner_env_hash, operation_id))`); err != nil {
		t.Fatal(err)
	}
}

type legacyReleaseInstallSnapshot struct {
	operationID          string
	status               string
	revision             uint64
	phaseDiagnosticsJSON string
}

func createRegistryReleaseInstallOperation(t *testing.T, path, ownerEnvHash, operationID string) legacyReleaseInstallSnapshot {
	t.Helper()
	ctx := sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: ownerEnvHash, SessionChannelIDHash: "channel",
	})
	store, err := registry.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, path)
	defer db.Close()
	now := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
	if _, err := db.Exec(`CREATE TABLE release_install_operations (
owner_env_hash TEXT NOT NULL, request_id TEXT NOT NULL, operation_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
request_sha256 TEXT NOT NULL, release_identity_json TEXT NOT NULL,
activation_request_json TEXT NOT NULL DEFAULT '{"mode":"disabled"}', status TEXT NOT NULL, phase TEXT NOT NULL,
progress_kind TEXT NOT NULL, progress_completed INTEGER NOT NULL, progress_total INTEGER NOT NULL, attempt INTEGER NOT NULL,
retry_after_ms INTEGER NOT NULL, mutation_outcome TEXT NOT NULL, failure_code TEXT NOT NULL, failure_retryable INTEGER NOT NULL,
plugin_record_json TEXT NOT NULL DEFAULT 'null', activation_json TEXT NOT NULL DEFAULT '{"status":"not_requested"}',
phase_diagnostics_json TEXT NOT NULL DEFAULT '[]', revision INTEGER NOT NULL, created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL, terminal_at INTEGER, PRIMARY KEY(owner_env_hash, request_id), UNIQUE(owner_env_hash, operation_id))`); err != nil {
		t.Fatal(err)
	}
	diagnostics := `[{"phase":"failed","attempt":1,"progress":{"kind":"indeterminate"},"cache_hit":false,"started_at":"2026-08-13T01:02:03Z","completed_at":"2026-08-13T01:02:05Z","duration_ms":2000}]`
	if _, err := db.Exec(`INSERT INTO release_install_operations(
owner_env_hash,request_id,operation_id,plugin_instance_id,request_sha256,release_identity_json,activation_request_json,
status,phase,progress_kind,progress_completed,progress_total,attempt,retry_after_ms,mutation_outcome,failure_code,
failure_retryable,plugin_record_json,activation_json,phase_diagnostics_json,revision,created_at,updated_at,terminal_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, ownerEnvHash, "request_"+operationID, operationID, "instance_"+ownerEnvHash,
		"sha256:legacy-request", `{}`, `{"mode":"automatic"}`, "failed", "failed", "indeterminate", 0, 0, 1, 0,
		"not_committed", "PLUGIN_INSTALL_INTERRUPTED", 1, "null", `{"status":"pending"}`, diagnostics, 3,
		now.UnixNano(), now.Add(2*time.Second).UnixNano(), now.Add(2*time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	return legacyReleaseInstallSnapshot{operationID: operationID, status: "failed", revision: 3, phaseDiagnosticsJSON: diagnostics}
}
