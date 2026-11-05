package controlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
)

type interruptedInspectedMigration struct{ *sql.Tx }

func (q interruptedInspectedMigration) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if query == "UPDATE control_schema SET version=6 WHERE id=1 AND version=5" {
		return nil, errors.New("interrupted")
	}
	return q.Tx.ExecContext(ctx, query, args...)
}
func TestInspectedMigrationPreservesAllReleasedSchemas(t *testing.T) {
	for _, version := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			prior := min(version, 4)
			db, path := pluginDataHistoricalDatabase(t, prior)
			if version == 5 {
				if err := migrateBackgroundIntervals(context.Background(), db); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			for range 2 {
				s, err := Open(context.Background(), Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				var value string
				if err = s.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='upgrade-preserved'").Scan(&value); err != nil || value != "original" {
					t.Fatal("metadata lost", err)
				}
				s.Close()
			}
		})
	}
}
func TestInspectedMigrationRollsBackAndRejectsUnknownSchema(t *testing.T) {
	db, path := pluginDataHistoricalDatabase(t, 4)
	ctx := context.Background()
	if err := migrateBackgroundIntervals(ctx, db); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateInspectedInstalls(ctx, interruptedInspectedMigration{tx}); err == nil {
		t.Fatal("interruption ignored")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var version, count int
	if err = db.QueryRow("SELECT version FROM control_schema").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='inspected_install_claim'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if version != 5 || count != 0 {
		t.Fatal("partial migration persisted")
	}
	if _, err = db.Exec("UPDATE control_schema SET version=999"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)
	if s, err := Open(ctx, Config{Path: path}); err == nil {
		s.Close()
		t.Fatal("future state accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("future state mutated")
	}
}
