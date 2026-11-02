package plugindata

import (
	"context"
	"database/sql"
	"strings"
)

// migrateFilesNamespace upgrades only live databases. Snapshot readers use the
// read-only opener, preserving retained package/data evidence byte for byte.
func migrateFilesNamespace(ctx context.Context, db *sql.DB) error {
	return migrateFilesNamespaceAtCheckpoint(ctx, db, nil)
}

// checkpoint is an internal fault-injection seam, never a host callback.
func migrateFilesNamespaceAtCheckpoint(ctx context.Context, db *sql.DB, checkpoint func(int)) error {
	var version, files int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='file_entries'`).Scan(&files); err != nil {
		return err
	}
	if files == 0 {
		if version != namespaceDatabaseVersion {
			return ErrDatasetCorrupt
		}
		return nil
	}
	if version == filesNamespaceDatabaseVersion {
		return nil
	}
	if version != namespaceDatabaseVersion {
		return ErrDatasetCorrupt
	}
	if err := validateNamespaceDatabaseObjects(ctx, db, NamespaceFiles); err != nil {
		return err
	}
	for _, statement := range strings.Split(legacyFilesNamespaceSchema, ";") {
		fields := strings.Fields(statement)
		if len(fields) < 3 || fields[0] != "CREATE" {
			continue
		}
		var ddl string
		if err := db.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE name=?`, fields[2]).Scan(&ddl); err != nil {
			return err
		}
		if strings.Join(strings.Fields(ddl), " ") != strings.Join(fields, " ") {
			return ErrDatasetCorrupt
		}
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check(1)`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return ErrDatasetCorrupt
	}
	if _, err := validateFilesNamespaceDatabase(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DROP INDEX file_entries_parent_path; ALTER TABLE file_entries RENAME TO legacy_file_entries;`); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(1)
	}
	if _, err := tx.ExecContext(ctx, filesNamespaceSchema[strings.Index(filesNamespaceSchema, "CREATE TABLE file_entries"):]); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(2)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_entries SELECT * FROM legacy_file_entries; DROP TABLE legacy_file_entries; PRAGMA user_version=2;`); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(3)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(4)
	}
	return nil
}
