package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	namespaceDatabaseName          = "namespace.sqlite"
	namespaceDatabaseVersion       = 1
	namespaceDatabaseApplicationID = 0x52445044
)

const filesNamespaceSchema = `
CREATE TABLE namespace_usage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    usage_bytes INTEGER NOT NULL CHECK (usage_bytes >= 0),
    usage_files INTEGER NOT NULL CHECK (usage_files >= 0)
);
INSERT INTO namespace_usage(singleton, usage_bytes, usage_files) VALUES (1, 0, 0);
CREATE TABLE file_entries (
    path TEXT PRIMARY KEY,
    parent TEXT NOT NULL,
    entry_type INTEGER NOT NULL CHECK (entry_type IN (0, 1)),
    content BLOB,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    updated_at_ns INTEGER NOT NULL,
    CHECK (
        (entry_type = 0 AND content IS NOT NULL AND size_bytes = length(content)) OR
        (entry_type = 1 AND content IS NULL AND size_bytes = 0)
    )
) WITHOUT ROWID;
CREATE INDEX file_entries_parent_path ON file_entries(parent, path);`

const kvNamespaceSchema = `
CREATE TABLE namespace_usage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    usage_bytes INTEGER NOT NULL CHECK (usage_bytes >= 0),
    usage_files INTEGER NOT NULL CHECK (usage_files >= 0)
);
INSERT INTO namespace_usage(singleton, usage_bytes, usage_files) VALUES (1, 0, 0);
CREATE TABLE kv_entries (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes = length(value)),
    updated_at_ns INTEGER NOT NULL
) WITHOUT ROWID;`

func initializeNamespaceDatabase(ctx context.Context, root string, kind NamespaceKind) error {
	if kind != NamespaceFiles && kind != NamespaceKV {
		return nil
	}
	db, err := openNamespaceDatabase(ctx, root, false)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA application_id = %d`, namespaceDatabaseApplicationID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, namespaceDatabaseVersion)); err != nil {
		return err
	}
	schema := filesNamespaceSchema
	if kind == NamespaceKV {
		schema = kvNamespaceSchema
	}
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	return tx.Commit()
}

func openNamespaceDatabase(ctx context.Context, root string, readOnly bool) (*sql.DB, error) {
	path := filepath.Join(root, namespaceDatabaseName)
	existing := false
	if info, err := os.Lstat(path); err == nil {
		if !validPathRegular(path, info) {
			return nil, storage.ErrInvalidNamespace
		}
		existing = true
	} else if readOnly || !errors.Is(err, os.ErrNotExist) {
		return nil, storage.ErrInvalidNamespace
	}
	mode := "rwc"
	if readOnly {
		mode = "ro"
	}
	dsn := "file:" + url.PathEscape(path) + "?mode=" + mode + "&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, storage.ErrInvalidNamespace
	}
	if existing {
		var applicationID, version int
		if err := db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != namespaceDatabaseApplicationID {
			db.Close()
			return nil, storage.ErrInvalidNamespace
		}
		if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != namespaceDatabaseVersion {
			db.Close()
			return nil, storage.ErrInvalidNamespace
		}
	}
	if readOnly {
		if _, err := db.ExecContext(ctx, `PRAGMA query_only = ON`); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func validateNamespaceDatabase(ctx context.Context, root string, kind NamespaceKind) (namespaceUsage, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return namespaceUsage{}, err
	}
	if len(entries) != 1 || entries[0].Name() != namespaceDatabaseName {
		return namespaceUsage{}, fmt.Errorf("%w: %s namespace has unexpected physical entries", ErrDatasetCorrupt, kind)
	}
	db, err := openNamespaceDatabase(ctx, root, true)
	if err != nil {
		return namespaceUsage{}, err
	}
	defer db.Close()
	var applicationID, version int
	if err := db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != namespaceDatabaseApplicationID {
		return namespaceUsage{}, fmt.Errorf("%w: invalid namespace database application ID", ErrDatasetCorrupt)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != namespaceDatabaseVersion {
		return namespaceUsage{}, fmt.Errorf("%w: invalid namespace database version", ErrDatasetCorrupt)
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check(1)`).Scan(&integrity); err != nil || integrity != "ok" {
		return namespaceUsage{}, fmt.Errorf("%w: namespace database integrity check failed", ErrDatasetCorrupt)
	}
	if err := validateNamespaceDatabaseObjects(ctx, db, kind); err != nil {
		return namespaceUsage{}, err
	}
	if kind == NamespaceFiles {
		return validateFilesNamespaceDatabase(ctx, db)
	}
	return validateKVNamespaceDatabase(ctx, db)
}

func validateNamespaceDatabaseObjects(ctx context.Context, db *sql.DB, kind NamespaceKind) error {
	rows, err := db.QueryContext(ctx, `SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var objects []string
	for rows.Next() {
		var objectType, name string
		if err := rows.Scan(&objectType, &name); err != nil {
			return err
		}
		objects = append(objects, objectType+":"+name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	expected := []string{"index:file_entries_parent_path", "table:file_entries", "table:namespace_usage"}
	if kind == NamespaceKV {
		expected = []string{"table:kv_entries", "table:namespace_usage"}
	}
	if strings.Join(objects, "\x00") != strings.Join(expected, "\x00") {
		return fmt.Errorf("%w: namespace database schema objects do not match %s model", ErrDatasetCorrupt, kind)
	}
	return nil
}

func validateFilesNamespaceDatabase(ctx context.Context, db *sql.DB) (namespaceUsage, error) {
	rows, err := db.QueryContext(ctx, `SELECT path, parent, entry_type, size_bytes, updated_at_ns FROM file_entries ORDER BY path`)
	if err != nil {
		return namespaceUsage{}, fmt.Errorf("%w: read files namespace database", ErrDatasetCorrupt)
	}
	defer rows.Close()
	var usage namespaceUsage
	directories := map[string]struct{}{}
	for rows.Next() {
		var path, parent string
		var entryType int
		var size, updatedAtNS int64
		if err := rows.Scan(&path, &parent, &entryType, &size, &updatedAtNS); err != nil {
			return namespaceUsage{}, err
		}
		clean, err := canonicalNamespacePath(path, false)
		if err != nil || clean != path || parent != namespaceParent(path) || updatedAtNS <= 0 || (entryType != 0 && entryType != 1) || size < 0 || (entryType == 1 && size != 0) {
			return namespaceUsage{}, fmt.Errorf("%w: invalid files namespace row", ErrDatasetCorrupt)
		}
		if parent != "." {
			if _, ok := directories[parent]; !ok {
				return namespaceUsage{}, fmt.Errorf("%w: files namespace row has no parent directory", ErrDatasetCorrupt)
			}
		}
		if entryType == 1 {
			directories[path] = struct{}{}
		}
		usage.files++
		usage.bytes += size
	}
	if err := rows.Err(); err != nil {
		return namespaceUsage{}, err
	}
	persisted, err := readNamespaceDatabaseUsage(ctx, db)
	if err != nil || persisted != usage {
		return namespaceUsage{}, fmt.Errorf("%w: files namespace usage does not match entries", ErrDatasetCorrupt)
	}
	return persisted, nil
}

func validateKVNamespaceDatabase(ctx context.Context, db *sql.DB) (namespaceUsage, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, size_bytes, updated_at_ns FROM kv_entries ORDER BY key`)
	if err != nil {
		return namespaceUsage{}, fmt.Errorf("%w: read kv namespace database", ErrDatasetCorrupt)
	}
	defer rows.Close()
	var usage namespaceUsage
	for rows.Next() {
		var key string
		var size, updatedAtNS int64
		if err := rows.Scan(&key, &size, &updatedAtNS); err != nil {
			return namespaceUsage{}, err
		}
		normalized, err := normalizeKVKey(key)
		if err != nil || normalized != key || size < 0 || updatedAtNS <= 0 {
			return namespaceUsage{}, fmt.Errorf("%w: invalid kv namespace row", ErrDatasetCorrupt)
		}
		usage.files++
		usage.bytes += size
	}
	if err := rows.Err(); err != nil {
		return namespaceUsage{}, err
	}
	persisted, err := readNamespaceDatabaseUsage(ctx, db)
	if err != nil || persisted != usage {
		return namespaceUsage{}, fmt.Errorf("%w: kv namespace usage does not match entries", ErrDatasetCorrupt)
	}
	return persisted, nil
}

func namespaceDatabaseUsage(ctx context.Context, root string) (namespaceUsage, error) {
	db, err := openNamespaceDatabase(ctx, root, true)
	if err != nil {
		return namespaceUsage{}, err
	}
	defer db.Close()
	return readNamespaceDatabaseUsage(ctx, db)
}

type namespaceUsageReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readNamespaceDatabaseUsage(ctx context.Context, reader namespaceUsageReader) (namespaceUsage, error) {
	var usage namespaceUsage
	if err := reader.QueryRowContext(ctx, `SELECT usage_bytes, usage_files FROM namespace_usage WHERE singleton = 1`).Scan(&usage.bytes, &usage.files); err != nil {
		return namespaceUsage{}, storage.ErrInvalidNamespace
	}
	return usage, nil
}

func writeNamespaceDatabaseUsage(ctx context.Context, tx *sql.Tx, usage namespaceUsage) error {
	result, err := tx.ExecContext(ctx, `UPDATE namespace_usage SET usage_bytes = ?, usage_files = ? WHERE singleton = 1`, usage.bytes, usage.files)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return storage.ErrInvalidNamespace
	}
	return nil
}

func canonicalNamespacePath(raw string, allowRoot bool) (string, error) {
	if !utf8.ValidString(raw) {
		return "", storage.ErrInvalidFilePath
	}
	path, err := cleanRelativePath(raw, allowRoot)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(path), nil
}

func namespaceParent(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return "."
	}
	return path[:index]
}
