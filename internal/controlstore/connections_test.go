package controlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectionsMigrateSchemaTwoAndPreserveSelectedResources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	raw, err := os.ReadFile("testdata/schema2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO control_metadata VALUES('preserved','yes')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		store, err := Open(ctx, Config{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		var value string
		if err := store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='preserved'").Scan(&value); err != nil || value != "yes" {
			t.Fatalf("data %q %v", value, err)
		}
		var version int
		if err := store.db.QueryRow("SELECT version FROM control_schema WHERE id=1").Scan(&version); err != nil || version != 3 {
			t.Fatalf("schema %d %v", version, err)
		}
		store.Close()
	}
}
func TestConnectionAuthorityCASRevocationAndReopen(t *testing.T) {
	store, file, revisions := selectedAuthorityFixture(t)
	now := time.Now()
	connection := Connection{ConnectionKey: ConnectionKey{OwnerEnvHash: file.OwnerEnvHash, OwnerUserHash: file.OwnerUserHash, PluginInstanceID: file.PluginInstanceID, ConnectorID: "service"}, ConnectionID: "first", ActiveFingerprint: file.ActiveFingerprint, RevokeEpoch: file.RevokeEpoch, Revision: 1, ExpiresAt: now.Add(time.Hour).UnixNano(), Evidence: json.RawMessage("{\"destination\":\"https://api.example.com\"}")}
	if err := store.PutConnection(context.Background(), connection, 0, revisions, now); err != nil {
		t.Fatal(err)
	}
	if err := store.PutConnection(context.Background(), connection, 0, revisions, now); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
	var seq int
	var name, path string
	if err := store.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var reopenErr error
	store, reopenErr = Open(context.Background(), Config{Path: path})
	if reopenErr != nil {
		t.Fatal(reopenErr)
	}
	defer store.Close()
	got, err := store.GetConnection(context.Background(), connection.ConnectionKey)
	if err != nil || got.ConnectionID != "first" {
		t.Fatalf("read %v %v", got, err)
	}
	other := connection.ConnectionKey
	other.OwnerUserHash = "other"
	if _, err := store.GetConnection(context.Background(), other); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("cross-owner read: %v", err)
	}
	if err := store.RevokeConnection(context.Background(), connection.ConnectionKey, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeConnection(context.Background(), connection.ConnectionKey, 1, now); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetConnection(context.Background(), connection.ConnectionKey)
	if err != nil || got.RevokedAt == nil || got.Revision != 2 {
		t.Fatalf("revoked %v %v", got, err)
	}
	connection.ConnectionID = "second"
	connection.Revision = 3
	if err := store.PutConnection(context.Background(), connection, 2, revisions, now); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetConnection(context.Background(), connection.ConnectionKey)
	if err != nil || got.ConnectionID != "second" || got.Revision != 3 || got.RevokedAt != nil {
		t.Fatalf("replacement %v %v", got, err)
	}
}

type failingConnectionMigration struct{ tx *sql.Tx }

func (f failingConnectionMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if query == "UPDATE control_schema SET version=3 WHERE id=1 AND version=2" {
		return nil, errors.New("injected metadata write failure")
	}
	return f.tx.ExecContext(ctx, query, args...)
}
func TestConnectionMigrationRollsBackAndReopensWithoutDataLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/schema2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO control_metadata VALUES('retained','value')"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateConnections(context.Background(), failingConnectionMigration{tx}); err == nil {
		t.Fatal("injected failure not observed")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var version, count int
	if err = db.QueryRow("SELECT version FROM control_schema").Scan(&version); err != nil || version != 2 {
		t.Fatalf("version %d %v", version, err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='network_connections'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial schema %d %v", count, err)
	}
	db.Close()
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var value string
	if err = store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='retained'").Scan(&value); err != nil || value != "value" {
		t.Fatalf("retained %s %v", value, err)
	}
}
func TestConnectionMigrationRejectsDriftWithoutChangingBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/schema2.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("ALTER TABLE selected_file_resources ADD COLUMN unexpected TEXT"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), Config{Path: path}); err == nil {
		store.Close()
		t.Fatal("drift accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unknown schema changed")
	}
}
