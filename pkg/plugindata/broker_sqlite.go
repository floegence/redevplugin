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
	"time"
	"unicode"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/storage"
	_ "modernc.org/sqlite"
)

const (
	defaultSQLiteDatabase         = "plugin.sqlite"
	maxSQLiteSQLBytes             = 64 * 1024
	maxSQLiteArgs                 = 64
	maxSQLiteArgumentBytes        = 1024 * 1024
	maxSQLiteColumns              = 128
	maxSQLiteCellBytes            = 1024 * 1024
	maxConcurrentSQLiteQueries    = 8
	defaultSQLiteMaxRows          = 100
	maxSQLiteMaxRows              = 1000
	defaultSQLiteMaxResponseBytes = 1024 * 1024
	maxSQLiteMaxResponseBytes     = 4 * 1024 * 1024
	defaultSQLiteTimeout          = 3 * time.Second
	maxSQLiteTimeout              = 10 * time.Second
)

func (s *FileStore) ExecSQLite(ctx context.Context, req storage.SQLiteExecRequest) (result storage.SQLiteExecResult, resultErr error) {
	database, err := normalizeSQLiteDatabase(req.Database)
	if err != nil {
		return result, err
	}
	sqlText, err := normalizeSQLiteSQL(req.SQL, false)
	if err != nil {
		return result, err
	}
	args, err := sqliteArgs(req.Args)
	if err != nil {
		return result, err
	}
	ctx, cancel := sqliteContext(ctx, req.Timeout)
	defer cancel()
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceSQLite, true, func(a *namespaceAccess) error {
		if err := rejectRootSymlinkPath(a.root, filepath.Dir(database)); err != nil {
			return err
		}
		missing, err := missingRootDirectories(a.root, filepath.Dir(database))
		if err != nil {
			return err
		}
		if err := a.root.MkdirAll(filepath.Dir(database), 0o700); err != nil {
			return err
		}
		path := filepath.Join(a.absRoot, database)
		before, err := sqliteFileUsage(path)
		if err != nil {
			return err
		}
		other := namespaceUsage{bytes: a.usage.bytes - before.bytes, files: a.usage.files - before.files}
		if other.bytes < 0 || other.files < 0 {
			return storage.ErrInvalidNamespace
		}
		available := a.namespace.QuotaBytes - other.bytes
		if available <= 0 || (a.namespace.QuotaFiles > 0 && other.files+missing+1 > a.namespace.QuotaFiles) {
			return storage.ErrQuotaExceeded
		}
		db, err := openSQLiteDatabase(ctx, path, false)
		if err != nil {
			return err
		}
		defer db.Close()
		var pageSize int64
		if err := db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil || pageSize <= 0 {
			return storage.ErrInvalidSQLite
		}
		if _, err := db.ExecContext(ctx, `PRAGMA max_page_count = `+fmt.Sprint(max64(1, available/pageSize))); err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		execResult, err := tx.ExecContext(ctx, sqlText, args...)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "full") {
				return storage.ErrQuotaExceeded
			}
			return err
		}
		rowsAffected, _ := execResult.RowsAffected()
		lastInsertID, _ := execResult.LastInsertId()
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		if err := db.Close(); err != nil {
			return mutation.Unknown(err)
		}
		if err := s.ops.syncDir(filepath.Dir(path)); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		after, err := sqliteFileUsage(path)
		if err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		projected := namespaceUsage{bytes: other.bytes + after.bytes, files: other.files + missing + after.files}
		if err := enforceQuota(a.namespace, projected); err != nil {
			return mutation.Unknown(fmt.Errorf("sqlite transaction committed beyond declared quota: %w", err))
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, projected)
		result = storage.SQLiteExecResult{Database: database, RowsAffected: rowsAffected, LastInsertID: lastInsertID, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) QuerySQLite(ctx context.Context, req storage.SQLiteQueryRequest) (result storage.SQLiteQueryResult, resultErr error) {
	database, err := normalizeSQLiteDatabase(req.Database)
	if err != nil {
		return result, err
	}
	sqlText, err := normalizeSQLiteSQL(req.SQL, true)
	if err != nil {
		return result, err
	}
	args, err := sqliteArgs(req.Args)
	if err != nil {
		return result, err
	}
	maxRows := req.MaxRows
	if maxRows <= 0 {
		maxRows = defaultSQLiteMaxRows
	}
	if maxRows > maxSQLiteMaxRows {
		maxRows = maxSQLiteMaxRows
	}
	maxBytes := req.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = defaultSQLiteMaxResponseBytes
	}
	if maxBytes > maxSQLiteMaxResponseBytes {
		maxBytes = maxSQLiteMaxResponseBytes
	}
	ctx, cancel := sqliteContext(ctx, req.Timeout)
	defer cancel()
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceSQLite, false, func(a *namespaceAccess) error {
		releaseQuery, err := s.acquireSQLiteQuery(ctx, a.usageKey)
		if err != nil {
			return err
		}
		defer releaseQuery()
		path := filepath.Join(a.absRoot, database)
		if info, err := a.root.Lstat(database); errors.Is(err, os.ErrNotExist) {
			return storage.ErrNamespaceNotFound
		} else if err != nil || !validRootRegular(a.root, database, info) {
			return storage.ErrInvalidSQLite
		}
		db, err := openSQLiteDatabase(ctx, path, true)
		if err != nil {
			return err
		}
		defer db.Close()
		rows, err := db.QueryContext(ctx, sqlText, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			return err
		}
		if len(columns) == 0 || len(columns) > maxSQLiteColumns {
			return storage.ErrSQLiteResultTooLarge
		}
		size := int64(0)
		for _, column := range columns {
			size += int64(len(column))
		}
		values := make([][]storage.SQLiteValue, 0, maxRows)
		for rows.Next() {
			if len(values) >= maxRows {
				return storage.ErrSQLiteResultTooLarge
			}
			driverValues := make([]any, len(columns))
			targets := make([]any, len(columns))
			for i := range driverValues {
				targets[i] = &driverValues[i]
			}
			if err := rows.Scan(targets...); err != nil {
				return err
			}
			row := make([]storage.SQLiteValue, len(driverValues))
			for i, value := range driverValues {
				converted, bytes, err := sqliteValue(value)
				if err != nil {
					return err
				}
				size += bytes
				if size > maxBytes {
					return storage.ErrSQLiteResultTooLarge
				}
				row[i] = converted
			}
			values = append(values, row)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		result = storage.SQLiteQueryResult{Database: database, Columns: columns, Rows: values, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) acquireSQLiteQuery(ctx context.Context, key string) (func(), error) {
	value, _ := s.sqliteQueries.LoadOrStore(key, make(chan struct{}, maxConcurrentSQLiteQueries))
	slots := value.(chan struct{})
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func normalizeSQLiteDatabase(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultSQLiteDatabase
	}
	path, err := cleanRelativePath(raw, false)
	if err != nil || strings.ToLower(filepath.Ext(path)) != ".sqlite" {
		return "", storage.ErrInvalidSQLite
	}
	return path, nil
}

func normalizeSQLiteSQL(raw string, readOnly bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxSQLiteSQLBytes || strings.ContainsRune(raw, '\x00') {
		return "", storage.ErrInvalidSQLite
	}
	tokens, err := sqliteTokens(raw)
	if err != nil || len(tokens) == 0 {
		return "", storage.ErrInvalidSQLite
	}
	triggerStatement := isCreateTriggerStatement(tokens)
	for _, token := range tokens {
		switch token {
		case "BEGIN":
			if triggerStatement {
				continue
			}
			return "", storage.ErrInvalidSQLite
		case "ATTACH", "DETACH", "PRAGMA", "VACUUM", "LOAD_EXTENSION", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE":
			return "", storage.ErrInvalidSQLite
		}
	}
	if readOnly {
		for _, token := range tokens {
			switch token {
			case "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "ANALYZE", "REINDEX", "RANDOMBLOB", "ZEROBLOB", "PRINTF":
				return "", storage.ErrInvalidSQLite
			}
		}
		switch tokens[0] {
		case "SELECT", "WITH", "EXPLAIN":
		default:
			return "", storage.ErrInvalidSQLite
		}
	}
	return raw, nil
}

func sqliteTokens(sqlText string) ([]string, error) {
	var tokens []string
	triggerDeclaration := false
	triggerBody := false
	triggerCaseDepth := 0
	for i := 0; i < len(sqlText); {
		switch {
		case unicode.IsSpace(rune(sqlText[i])):
			i++
		case sqlText[i] == '-' && i+1 < len(sqlText) && sqlText[i+1] == '-':
			i += 2
			for i < len(sqlText) && sqlText[i] != '\n' {
				i++
			}
		case sqlText[i] == '/' && i+1 < len(sqlText) && sqlText[i+1] == '*':
			end := strings.Index(sqlText[i+2:], "*/")
			if end < 0 {
				return nil, storage.ErrInvalidSQLite
			}
			i += end + 4
		case sqlText[i] == '\'' || sqlText[i] == '"' || sqlText[i] == '`' || sqlText[i] == '[':
			quote := sqlText[i]
			endQuote := quote
			if quote == '[' {
				endQuote = ']'
			}
			i++
			for i < len(sqlText) {
				if sqlText[i] == endQuote {
					if quote != '[' && i+1 < len(sqlText) && sqlText[i+1] == endQuote {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case sqlText[i] == ';':
			i++
			if triggerBody {
				continue
			}
			hasTail, err := sqliteStatementTail(sqlText[i:])
			if err != nil || hasTail {
				return nil, storage.ErrInvalidSQLite
			}
		default:
			start := i
			for i < len(sqlText) && (unicode.IsLetter(rune(sqlText[i])) || sqlText[i] == '_') {
				i++
			}
			if start == i {
				i++
				continue
			}
			token := strings.ToUpper(sqlText[start:i])
			tokens = append(tokens, token)
			switch token {
			case "TRIGGER":
				triggerDeclaration = createTriggerPrefix(tokens)
			case "BEGIN":
				if triggerDeclaration && !triggerBody {
					triggerBody = true
				}
			case "CASE":
				if triggerBody {
					triggerCaseDepth++
				}
			case "END":
				if triggerBody {
					if triggerCaseDepth > 0 {
						triggerCaseDepth--
					} else {
						triggerBody = false
					}
				}
			}
		}
	}
	return tokens, nil
}

func createTriggerPrefix(tokens []string) bool {
	if len(tokens) == 2 {
		return tokens[0] == "CREATE" && tokens[1] == "TRIGGER"
	}
	return len(tokens) == 3 && tokens[0] == "CREATE" &&
		(tokens[1] == "TEMP" || tokens[1] == "TEMPORARY") && tokens[2] == "TRIGGER"
}

func isCreateTriggerStatement(tokens []string) bool {
	if len(tokens) >= 2 && tokens[0] == "CREATE" && tokens[1] == "TRIGGER" {
		return true
	}
	return len(tokens) >= 3 && tokens[0] == "CREATE" &&
		(tokens[1] == "TEMP" || tokens[1] == "TEMPORARY") && tokens[2] == "TRIGGER"
}

func sqliteStatementTail(raw string) (bool, error) {
	for i := 0; i < len(raw); {
		switch {
		case unicode.IsSpace(rune(raw[i])) || raw[i] == ';':
			i++
		case raw[i] == '-' && i+1 < len(raw) && raw[i+1] == '-':
			i += 2
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case raw[i] == '/' && i+1 < len(raw) && raw[i+1] == '*':
			end := strings.Index(raw[i+2:], "*/")
			if end < 0 {
				return false, storage.ErrInvalidSQLite
			}
			i += end + 4
		default:
			return true, nil
		}
	}
	return false, nil
}

func sqliteArgs(values []storage.SQLiteValue) ([]any, error) {
	if len(values) > maxSQLiteArgs {
		return nil, storage.ErrInvalidSQLite
	}
	args := make([]any, len(values))
	totalBytes := 0
	for i, value := range values {
		set := 0
		if value.Null {
			set++
		}
		if value.Int != nil {
			set++
		}
		if value.Float != nil {
			set++
		}
		if value.Text != nil {
			set++
		}
		if value.Blob != nil {
			set++
		}
		if set != 1 {
			return nil, storage.ErrInvalidSQLite
		}
		switch {
		case value.Null:
			args[i] = nil
		case value.Int != nil:
			args[i] = *value.Int
		case value.Float != nil:
			args[i] = *value.Float
		case value.Text != nil:
			totalBytes += len(*value.Text)
			args[i] = *value.Text
		default:
			totalBytes += len(value.Blob)
			args[i] = cloneSQLiteBlob(value.Blob)
		}
		if totalBytes > maxSQLiteArgumentBytes {
			return nil, storage.ErrInvalidSQLite
		}
	}
	return args, nil
}

func sqliteValue(value any) (storage.SQLiteValue, int64, error) {
	switch value := value.(type) {
	case nil:
		return storage.SQLiteValue{Null: true}, 1, nil
	case int64:
		return storage.SQLiteValue{Int: &value}, 8, nil
	case float64:
		return storage.SQLiteValue{Float: &value}, 8, nil
	case string:
		if len(value) > maxSQLiteCellBytes {
			return storage.SQLiteValue{}, 0, storage.ErrSQLiteResultTooLarge
		}
		return storage.SQLiteValue{Text: &value}, int64(len(value)), nil
	case []byte:
		if len(value) > maxSQLiteCellBytes {
			return storage.SQLiteValue{}, 0, storage.ErrSQLiteResultTooLarge
		}
		return storage.SQLiteValue{Blob: cloneSQLiteBlob(value)}, int64(len(value)), nil
	default:
		return storage.SQLiteValue{}, 0, storage.ErrInvalidSQLite
	}
}

func cloneSQLiteBlob(value []byte) []byte {
	clone := make([]byte, len(value))
	copy(clone, value)
	return clone
}

func openSQLiteDatabase(ctx context.Context, path string, readOnly bool) (*sql.DB, error) {
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
		return nil, err
	}
	if readOnly {
		if _, err := db.ExecContext(ctx, `PRAGMA query_only = ON`); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func sqliteFileUsage(path string) (namespaceUsage, error) {
	var usage namespaceUsage
	for _, candidate := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return namespaceUsage{}, err
		}
		if !validPathRegular(candidate, info) {
			return namespaceUsage{}, storage.ErrInvalidSQLite
		}
		usage.files++
		usage.bytes += info.Size()
	}
	return usage, nil
}

func sqliteContext(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
	if requested <= 0 {
		requested = defaultSQLiteTimeout
	}
	if requested > maxSQLiteTimeout {
		requested = maxSQLiteTimeout
	}
	return context.WithTimeout(parent, requested)
}
