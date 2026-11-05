package controlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type interruptedOpenMigration struct{ *sql.Tx }

func (q interruptedOpenMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(query, "UPDATE control_schema SET version=7") {
		return nil, errors.New("interrupted")
	}
	return q.Tx.ExecContext(ctx, query, args...)
}
func TestOpenDistributionMigrationPreservesPackageAndUserData(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 4)
	ctx := pluginDataCatalogContext("env-open", "user")
	if err := migrateBackgroundIntervals(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateInspectedInstalls(ctx, db); err != nil {
		t.Fatal(err)
	}
	prior := &Store{db: db, ready: true, generation: 1}
	record := putPluginDataCatalogRecord(t, prior, ctx, "open-plugin")
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err = json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	old["trust_state"] = json.RawMessage(`"verified"`)
	old["trust_assessment"] = json.RawMessage(`{"trust_state":"verified"}`)
	old["signature_assessment"] = json.RawMessage(`{"state":"verified"}`)
	old["release_trust_binding"] = json.RawMessage(`{"source_id":"official"}`)
	old["source_provenance"] = json.RawMessage(`{"kind":"official_catalog","package_sha256":"sha256:package","source_reference":"catalog/original"}`)
	historical, _ := json.Marshal(old)
	if _, err = db.Exec("UPDATE plugin_records SET record_json=?", string(historical)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateOpenDistribution(ctx, interruptedOpenMigration{tx}); err == nil {
		t.Fatal("expected interruption")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var rolled string
	if err = db.QueryRow("SELECT record_json FROM plugin_records").Scan(&rolled); err != nil || rolled != string(historical) {
		t.Fatal("partial migration committed", err)
	}
	db.Close()
	for range 2 {
		store, err := Open(ctx, Config{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.Registry().GetPlugin(ctx, record.OwnerEnvHash, record.PluginInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if got.PackageHash != record.PackageHash || got.CanonicalManifest != record.CanonicalManifest || got.ActiveFingerprint != record.ActiveFingerprint || got.ExecutionApproval.Status != record.ExecutionApproval.Status {
			t.Fatal("package or authority changed")
		}
		if got.PackageSourceProvenance.Kind != registry.PackageSourceLocalPackage || got.PackageSourceProvenance.SourceReference != "catalog/original" || got.AutomaticUpdates {
			t.Fatal("source transition invalid")
		}
		var preserved string
		if err = store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&preserved); err != nil || preserved != "original" {
			t.Fatal("data lost", err)
		}
		store.Close()
	}
}
func TestOpenDistributionMigrationRejectsUnknownRecordWithoutMutation(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 4)
	ctx := pluginDataCatalogContext("env-open", "user")
	if err := migrateBackgroundIntervals(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := migrateInspectedInstalls(ctx, db); err != nil {
		t.Fatal(err)
	}
	putPluginDataCatalogRecord(t, &Store{db: db, ready: true, generation: 1}, ctx, "invalid-plugin")
	if _, err := db.Exec(`UPDATE plugin_records SET record_json=json_set(record_json,'$.unknown_future_field',1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)
	if store, err := Open(ctx, Config{Path: path}); err == nil {
		store.Close()
		t.Fatal("unknown record accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("invalid state mutated")
	}
}
