package controlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func pluginDataHistoricalDatabase(t *testing.T, version int) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fmt.Sprintf("testdata/schema%d.sql", version))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO control_metadata VALUES('upgrade-preserved','original')"); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestPluginDataHistoryMigrationPreservesEveryPredecessor(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			db, path := pluginDataHistoricalDatabase(t, version)
			ctx := pluginDataCatalogContext("env-migrate", "user")
			prior := &Store{db: db, ready: true, generation: 1}
			record := putPluginDataCatalogRecord(t, prior, ctx, "migrated-instance")
			next := pluginDataUpgradeRecord(t, record, "2.0.0")
			next.VersionHistory[0].DataGenerationID = ""
			// Persist the pre-v4 representation, before generation binding existed.
			next, err := registry.PreparePluginPut(record.OwnerEnvHash, next, &record, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := encodeRegistryPluginRecord(next)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("UPDATE plugin_records SET record_json=? WHERE plugin_instance_id=?", string(raw), record.PluginInstanceID); err != nil {
				t.Fatal(err)
			}
			record = next
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			for round := range 2 {
				store, err := Open(ctx, Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var current int
				if err := store.db.QueryRow("SELECT version FROM control_schema").Scan(&current); err != nil || current != schemaVersion {
					t.Fatalf("schema %d: %v", current, err)
				}
				actual, err := store.Registry().GetPlugin(ctx, record.OwnerEnvHash, record.PluginInstanceID)
				if err != nil || actual.CanonicalManifest != record.CanonicalManifest || actual.ManagementRevision != record.ManagementRevision {
					t.Fatalf("record changed: %#v %v", actual, err)
				}
				if binding, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || !found {
					t.Fatalf("binding lost: %v %v", found, err)
				} else if len(actual.VersionHistory) != 1 || actual.VersionHistory[0].DataGenerationID != binding.GenerationID {
					t.Fatalf("legacy version not bound to current data: %+v", actual.VersionHistory)
				}
				var value string
				want := "original"
				if round == 1 {
					want = "after-migration"
				}
				if err := store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&value); err != nil || value != want {
					t.Fatalf("metadata changed: %q %v", value, err)
				}
				if _, err := store.db.Exec("UPDATE control_metadata SET value_json='after-migration' WHERE key='upgrade-preserved'"); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

type failingPluginDataHistoryMigration struct{ *sql.Tx }

func (f failingPluginDataHistoryMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if query == "UPDATE control_schema SET version=4 WHERE id=1 AND version=3" {
		return nil, errors.New("injected migration interruption")
	}
	return f.Tx.ExecContext(ctx, query, args...)
}

func TestPluginDataHistoryMigrationRollsBackAndResumes(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 3)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := migratePluginDataHistory(ctx, failingPluginDataHistoryMigration{tx}); err == nil {
		t.Fatal("interruption not reached")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var version, count int
	if err := db.QueryRow("SELECT version FROM control_schema").Scan(&version); err != nil || version != 3 {
		t.Fatalf("partial version: %d %v", version, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='plugin_data_history'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial table: %d %v", count, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var value string
	if err := store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&value); err != nil || value != "original" {
		t.Fatalf("metadata changed: %q %v", value, err)
	}
}

func TestPluginDataHistoryMigrationRejectsUnknownStateWithoutMutation(t *testing.T) {
	for _, statement := range []string{
		"ALTER TABLE network_connections ADD COLUMN drift TEXT",
		"UPDATE control_schema SET version=999",
		"UPDATE control_schema SET kind='unknown'",
		"CREATE TABLE plugin_data_history(unrecognized TEXT)",
	} {
		t.Run(statement, func(t *testing.T) {
			db, path := pluginDataHistoricalDatabase(t, 3)
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if store, err := Open(context.Background(), Config{Path: path}); err == nil {
				store.Close()
				t.Fatal("unknown schema accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected schema bytes changed")
			}
		})
	}
}

func TestPluginDataHistoryMigrationRejectsInconsistentHistoryWithoutMutation(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, damage := range []string{"future_generation", "manifest_hash", "binding_shape", "instance_identity"} {
			t.Run(fmt.Sprintf("schema_%d/%s", version, damage), func(t *testing.T) {
				db, path := pluginDataHistoricalDatabase(t, version)
				ctx := pluginDataCatalogContext("env-inconsistent", "user")
				prior := &Store{db: db, ready: true, generation: 1}
				current := putPluginDataCatalogRecord(t, prior, ctx, "inconsistent-instance")
				next := pluginDataUpgradeRecord(t, current, "2.0.0")
				switch damage {
				case "future_generation":
					next.VersionHistory[0].DataGenerationID = "unrecognized-generation"
				case "manifest_hash":
					next.VersionHistory[0].ManifestHash = next.ManifestHash
				case "binding_shape":
					if _, err := db.Exec("UPDATE plugin_data_bindings SET shape_hash=?", "sha256:unrecognized"); err != nil {
						t.Fatal(err)
					}
				case "instance_identity":
					next.PluginInstanceID = "another-instance"
				}
				raw, err := encodeRegistryPluginRecord(next)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE plugin_records SET record_json=? WHERE plugin_instance_id=?", string(raw), current.PluginInstanceID); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if store, err := Open(ctx, Config{Path: path}); err == nil {
					_ = store.Close()
					t.Fatal("inconsistent legacy history accepted")
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("rejected legacy history changed database bytes")
				}
			})
		}
	}
}
