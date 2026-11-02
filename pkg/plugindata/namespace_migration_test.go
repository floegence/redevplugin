package plugindata

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesNamespaceMigrationPreservesAndReopens(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := openNamespaceDatabase(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=1;`, namespaceDatabaseApplicationID) + legacyFilesNamespaceSchema); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO file_entries VALUES('draft','.',0,x'6162',2,1); UPDATE namespace_usage SET usage_bytes=2,usage_files=1;`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, namespaceDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = validateNamespaceDatabase(ctx, root, NamespaceFiles); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, namespaceDatabaseName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("snapshot validation mutated legacy database", err)
	}
	db, err = openNamespaceDatabase(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = migrateFilesNamespace(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	var data []byte
	if err = db.QueryRow(`SELECT content FROM file_entries WHERE path='draft'`).Scan(&data); err != nil || string(data) != "ab" {
		t.Fatalf("content: %q %v", data, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = validateNamespaceDatabase(ctx, root, NamespaceFiles); err != nil {
		t.Fatal(err)
	}
}

func TestFilesNamespaceMigrationRejectsDriftWithoutMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := openNamespaceDatabase(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=1;`, namespaceDatabaseApplicationID) + legacyFilesNamespaceSchema + `CREATE TABLE unexpected(value TEXT);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	path := filepath.Join(root, namespaceDatabaseName)
	before, _ := os.ReadFile(path)
	db, err = openNamespaceDatabase(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrateFilesNamespace(ctx, db); err == nil {
		t.Fatal("drift accepted")
	}
	_ = db.Close()
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected migration changed bytes")
	}
}
