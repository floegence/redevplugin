package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultSQLiteDatabase         = "plugin.sqlite"
	maxSQLiteSQLBytes             = 64 * 1024
	maxSQLiteArgs                 = 64
	defaultSQLiteMaxRows          = 100
	maxSQLiteMaxRows              = 1000
	defaultSQLiteMaxResponseBytes = 1024 * 1024
	maxSQLiteMaxResponseBytes     = 4 * 1024 * 1024
	defaultSQLiteTimeout          = 3 * time.Second
	maxSQLiteTimeout              = 10 * time.Second
)

func (b *FileBroker) ExecSQLite(ctx context.Context, req SQLiteExecRequest) (SQLiteExecResult, error) {
	if b == nil {
		return SQLiteExecResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return SQLiteExecResult{}, err
	}
	database, err := normalizeSQLiteDatabase(req.Database)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	sqlText, err := normalizeSQLiteSQL(req.SQL)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	args, err := sqliteArgs(req.Args)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	ctx, cancel := sqliteContext(ctx, req.Timeout)
	defer cancel()

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeSQLiteNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	target, err := b.prepareSQLiteDatabasePathLocked(dataPath, database, true)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	backupPath, err := b.backupSQLiteDataPathLocked(dataPath)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	defer os.RemoveAll(backupPath)

	db, err := openSQLiteDatabase(ctx, target, false)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	var committed bool
	defer func() {
		_ = db.Close()
		if !committed {
			_ = os.RemoveAll(dataPath)
			_ = copyDir(backupPath, dataPath)
		}
	}()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return SQLiteExecResult{}, err
	}
	result, err := tx.ExecContext(ctx, sqlText, args...)
	if err != nil {
		_ = tx.Rollback()
		return SQLiteExecResult{}, err
	}
	rowsAffected, _ := result.RowsAffected()
	lastInsertID, _ := result.LastInsertId()
	if err := tx.Commit(); err != nil {
		return SQLiteExecResult{}, err
	}
	if err := db.Close(); err != nil {
		return SQLiteExecResult{}, err
	}
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		_ = os.RemoveAll(dataPath)
		_ = copyDir(backupPath, dataPath)
		restored, restoreErr := b.refreshUsageLocked(record)
		if restoreErr != nil {
			return SQLiteExecResult{}, fmt.Errorf("%w: restore after sqlite failure: %v", err, restoreErr)
		}
		_ = restored
		return SQLiteExecResult{}, err
	}
	committed = true
	return SQLiteExecResult{
		Database:     database,
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
		Usage:        usage,
	}, nil
}

func (b *FileBroker) QuerySQLite(ctx context.Context, req SQLiteQueryRequest) (SQLiteQueryResult, error) {
	if b == nil {
		return SQLiteQueryResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return SQLiteQueryResult{}, err
	}
	database, err := normalizeSQLiteDatabase(req.Database)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	sqlText, err := normalizeSQLiteSQL(req.SQL)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	args, err := sqliteArgs(req.Args)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	maxRows := normalizeSQLiteMaxRows(req.MaxRows)
	maxResponseBytes := normalizeSQLiteMaxResponseBytes(req.MaxResponseBytes)
	ctx, cancel := sqliteContext(ctx, req.Timeout)
	defer cancel()

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeSQLiteNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	target, err := b.prepareSQLiteDatabasePathLocked(dataPath, database, false)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	db, err := openSQLiteDatabase(ctx, target, true)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	resultRows := make([][]SQLiteValue, 0)
	sizeBytes := sqliteColumnsSize(columns)
	for rows.Next() {
		if len(resultRows) >= maxRows {
			return SQLiteQueryResult{}, fmt.Errorf("%w: row count exceeds %d", ErrSQLiteResultTooLarge, maxRows)
		}
		values := make([]any, len(columns))
		scanTargets := make([]any, len(columns))
		for i := range values {
			scanTargets[i] = &values[i]
		}
		if err := rows.Scan(scanTargets...); err != nil {
			return SQLiteQueryResult{}, err
		}
		converted := make([]SQLiteValue, len(values))
		for i, value := range values {
			sqliteValue, valueSize, err := sqliteValueFromDriver(value)
			if err != nil {
				return SQLiteQueryResult{}, err
			}
			sizeBytes += valueSize
			if sizeBytes > maxResponseBytes {
				return SQLiteQueryResult{}, fmt.Errorf("%w: response exceeds %d bytes", ErrSQLiteResultTooLarge, maxResponseBytes)
			}
			converted[i] = sqliteValue
		}
		resultRows = append(resultRows, converted)
	}
	if err := rows.Err(); err != nil {
		return SQLiteQueryResult{}, err
	}
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return SQLiteQueryResult{}, err
	}
	return SQLiteQueryResult{
		Database: database,
		Columns:  columns,
		Rows:     resultRows,
		Usage:    usage,
	}, nil
}

func (b *FileBroker) activeSQLiteNamespaceLocked(pluginInstanceID string, storeID string) (NamespaceRecord, string, error) {
	record, err := b.readNamespaceRecordLocked(pluginInstanceID, storeID)
	if err != nil {
		return NamespaceRecord{}, "", err
	}
	if record.State != NamespaceActive {
		return NamespaceRecord{}, "", ErrNamespaceNotFound
	}
	if record.Kind != StoreSQLite {
		return NamespaceRecord{}, "", fmt.Errorf("%w: store %q is %s, not sqlite", ErrInvalidNamespace, record.StoreID, record.Kind)
	}
	dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return NamespaceRecord{}, "", err
	}
	return record, dataPath, nil
}

func (b *FileBroker) prepareSQLiteDatabasePathLocked(dataPath string, database string, create bool) (string, error) {
	target, err := resolveStorageFilePath(dataPath, database)
	if err != nil {
		return "", err
	}
	if err := rejectSymlinkAncestors(dataPath, filepath.Dir(target)); err != nil {
		return "", err
	}
	info, err := os.Lstat(target)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: sqlite database symlink is not allowed", ErrInvalidFilePath)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("%w: sqlite database path is not a regular file", ErrInvalidFilePath)
		}
		return target, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if !create {
		return "", ErrFileNotFound
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", err
	}
	return target, nil
}

func (b *FileBroker) backupSQLiteDataPathLocked(dataPath string) (string, error) {
	backupPath, err := os.MkdirTemp(b.root, ".sqlite-backup-*")
	if err != nil {
		return "", err
	}
	if err := copyDir(dataPath, backupPath); err != nil {
		_ = os.RemoveAll(backupPath)
		return "", err
	}
	return backupPath, nil
}

func openSQLiteDatabase(ctx context.Context, path string, queryOnly bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA trusted_schema=OFF"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=250"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if queryOnly {
		if _, err := db.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func normalizeSQLiteDatabase(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultSQLiteDatabase
	}
	database, err := cleanStorageFilePath(raw)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(database, "?#") || strings.ContainsRune(database, 0) {
		return "", fmt.Errorf("%w: sqlite database path cannot contain uri query characters", ErrInvalidSQLite)
	}
	ext := strings.ToLower(filepath.Ext(database))
	switch ext {
	case ".sqlite", ".sqlite3", ".db":
		return database, nil
	default:
		return "", fmt.Errorf("%w: sqlite database must end in .sqlite, .sqlite3, or .db", ErrInvalidSQLite)
	}
}

func normalizeSQLiteSQL(raw string) (string, error) {
	sqlText := strings.TrimSpace(raw)
	if sqlText == "" {
		return "", fmt.Errorf("%w: sql is required", ErrInvalidSQLite)
	}
	if len([]byte(sqlText)) > maxSQLiteSQLBytes {
		return "", fmt.Errorf("%w: sql exceeds %d bytes", ErrInvalidSQLite, maxSQLiteSQLBytes)
	}
	if err := rejectSQLiteBoundaryEscapes(sqlText); err != nil {
		return "", err
	}
	return sqlText, nil
}

func rejectSQLiteBoundaryEscapes(sqlText string) error {
	tokens := sqliteTokens(sqlText)
	for i, token := range tokens {
		switch token {
		case "attach", "detach", "vacuum":
			return fmt.Errorf("%w: %s is not allowed", ErrInvalidSQLite, token)
		case "load_extension":
			return fmt.Errorf("%w: load_extension is not allowed", ErrInvalidSQLite)
		}
		if token == "load" && i+1 < len(tokens) && tokens[i+1] == "extension" {
			return fmt.Errorf("%w: load extension is not allowed", ErrInvalidSQLite)
		}
	}
	return nil
}

func sqliteTokens(sqlText string) []string {
	tokens := make([]string, 0)
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, strings.ToLower(current.String()))
		current.Reset()
	}
	inQuote := rune(0)
	for _, ch := range sqlText {
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			flush()
			inQuote = ch
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			current.WriteRune(ch)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func sqliteArgs(values []SQLiteValue) ([]any, error) {
	if len(values) > maxSQLiteArgs {
		return nil, fmt.Errorf("%w: sqlite args exceed %d", ErrInvalidSQLite, maxSQLiteArgs)
	}
	args := make([]any, len(values))
	for i, value := range values {
		arg, err := sqliteArg(value)
		if err != nil {
			return nil, fmt.Errorf("%w: arg %d: %v", ErrInvalidSQLite, i, err)
		}
		args[i] = arg
	}
	return args, nil
}

func sqliteArg(value SQLiteValue) (any, error) {
	fields := 0
	if value.Null {
		fields++
	}
	if value.Int != nil {
		fields++
	}
	if value.Float != nil {
		fields++
	}
	if value.Text != nil {
		fields++
	}
	if value.Blob != nil {
		fields++
	}
	if fields > 1 {
		return nil, errors.New("sqlite value must contain only one typed field")
	}
	switch {
	case value.Null || fields == 0:
		return nil, nil
	case value.Int != nil:
		return *value.Int, nil
	case value.Float != nil:
		return *value.Float, nil
	case value.Text != nil:
		return *value.Text, nil
	case value.Blob != nil:
		return value.Blob, nil
	default:
		return nil, nil
	}
}

func sqliteValueFromDriver(value any) (SQLiteValue, int64, error) {
	switch typed := value.(type) {
	case nil:
		return SQLiteValue{Null: true}, 4, nil
	case int64:
		return SQLiteValue{Int: &typed}, 8, nil
	case float64:
		return SQLiteValue{Float: &typed}, 8, nil
	case string:
		return SQLiteValue{Text: &typed}, int64(len(typed)), nil
	case []byte:
		return SQLiteValue{Blob: append([]byte(nil), typed...)}, int64(len(typed)), nil
	case time.Time:
		text := typed.Format(time.RFC3339Nano)
		return SQLiteValue{Text: &text}, int64(len(text)), nil
	default:
		return SQLiteValue{}, 0, fmt.Errorf("%w: unsupported sqlite value type %T", ErrInvalidSQLite, value)
	}
}

func sqliteColumnsSize(columns []string) int64 {
	var size int64
	for _, column := range columns {
		size += int64(len(column))
	}
	return size
}

func normalizeSQLiteMaxRows(value int) int {
	if value <= 0 {
		return defaultSQLiteMaxRows
	}
	if value > maxSQLiteMaxRows {
		return maxSQLiteMaxRows
	}
	return value
}

func normalizeSQLiteMaxResponseBytes(value int64) int64 {
	if value <= 0 {
		return defaultSQLiteMaxResponseBytes
	}
	if value > maxSQLiteMaxResponseBytes {
		return maxSQLiteMaxResponseBytes
	}
	return value
}

func sqliteContext(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
	timeout := requested
	if timeout <= 0 {
		timeout = defaultSQLiteTimeout
	}
	if timeout > maxSQLiteTimeout {
		timeout = maxSQLiteTimeout
	}
	return context.WithTimeout(parent, timeout)
}
