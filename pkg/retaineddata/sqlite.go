package retaineddata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 2

const retainedDataSelectColumns = `
SELECT retained_id, source_plugin_instance_id, bound_plugin_instance_id,
	   publisher_id, plugin_id, version, package_hash, manifest_hash, state,
	   storage_retained, settings_retained, usage_bytes,
       delete_after, delete_error, metadata_json, retained_at, updated_at,
       bound_at, deleted_at, last_accessed_at`

type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite retained data store path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Retain(ctx context.Context, req RetainRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := recordFromRetain(req, now)
	if err != nil {
		return Record{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	existing, exists, err := getSQLiteRecord(ctx, tx, record.RetainedID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return existing, nil
	}
	if err := upsertSQLiteRecord(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) Get(ctx context.Context, retainedID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	retainedID = normalizeID(retainedID)
	if retainedID == "" {
		return Record{}, ErrInvalidRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteRecord(ctx, s.db, retainedID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("retained data store is nil")
	}
	if req.State != "" && !validState(req.State) {
		return nil, ErrInvalidRecord
	}
	publisherID := normalizeID(req.PublisherID)
	pluginID := normalizeID(req.PluginID)
	sourcePluginInstanceID := normalizeID(req.SourcePluginInstanceID)

	s.mu.Lock()
	defer s.mu.Unlock()

	query := retainedDataSelectColumns + ` FROM plugin_retained_data_records`
	args := []any{}
	conditions := []string{}
	if publisherID != "" {
		conditions = append(conditions, `publisher_id = ?`)
		args = append(args, publisherID)
	}
	if pluginID != "" {
		conditions = append(conditions, `plugin_id = ?`)
		args = append(args, pluginID)
	}
	if sourcePluginInstanceID != "" {
		conditions = append(conditions, `source_plugin_instance_id = ?`)
		args = append(args, sourcePluginInstanceID)
	}
	if req.State != "" {
		conditions = append(conditions, `state = ?`)
		args = append(args, string(req.State))
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY retained_at ASC, retained_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRecords(records)
	return records, nil
}

func (s *SQLiteStore) MarkBound(ctx context.Context, req BindRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State != StateRetained {
			return record, nil
		}
		boundPluginInstanceID := normalizeID(req.BoundPluginInstanceID)
		if boundPluginInstanceID == "" {
			return Record{}, ErrInvalidRecord
		}
		record.State = StateBound
		record.BoundPluginInstanceID = boundPluginInstanceID
		record.DeleteError = ""
		record.UpdatedAt = now
		record.BoundAt = &now
		return record, nil
	})
}

func (s *SQLiteStore) MarkDeleted(ctx context.Context, req DeleteRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateBound || record.State == StateDeleted {
			return record, nil
		}
		record.State = StateDeleted
		record.DeleteError = ""
		record.UpdatedAt = now
		record.DeletedAt = &now
		return record, nil
	})
}

func (s *SQLiteStore) MarkDeleteFailed(ctx context.Context, req DeleteFailedRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateBound || record.State == StateDeleted {
			return record, nil
		}
		record.State = StateDeleteFailedRetryable
		record.DeleteError = strings.TrimSpace(req.DeleteError)
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *SQLiteStore) Touch(ctx context.Context, req TouchRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateDeleted {
			return record, nil
		}
		record.LastAccessedAt = &now
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *SQLiteStore) ExpireBefore(ctx context.Context, now time.Time) ([]Record, error) {
	if s == nil {
		return nil, errors.New("retained data store is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)

	rows, err := tx.QueryContext(ctx, retainedDataSelectColumns+` FROM plugin_retained_data_records WHERE state = ? AND delete_after IS NOT NULL AND delete_after <= ? ORDER BY retained_at ASC, retained_id ASC`, string(StateRetained), now.UTC().UnixNano())
	if err != nil {
		return nil, err
	}
	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteRecord(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	changed := make([]Record, 0, len(records))
	for _, record := range records {
		record.State = StateExpired
		record.UpdatedAt = now.UTC()
		if err := upsertSQLiteRecord(ctx, tx, record); err != nil {
			return nil, err
		}
		changed = append(changed, cloneRecord(record))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	sortRecords(changed)
	return changed, nil
}

func (s *SQLiteStore) Delete(ctx context.Context, retainedID string) error {
	if s == nil {
		return errors.New("retained data store is nil")
	}
	retainedID = normalizeID(retainedID)
	if retainedID == "" {
		return ErrInvalidRecord
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM plugin_retained_data_records WHERE retained_id = ?`, retainedID)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) update(ctx context.Context, retainedID string, now time.Time, mutate func(Record, time.Time) (Record, error)) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	if retainedID == "" {
		return Record{}, ErrInvalidRecord
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteRecord(ctx, tx, retainedID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	updated, err := mutate(record, now.UTC())
	if err != nil {
		return Record{}, err
	}
	if err := upsertSQLiteRecord(ctx, tx, updated); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_retained_data_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_retained_data_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite retained data schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	legacyBrowserColumn, err := retainedDataTableHasColumn(ctx, tx, "browser_site_retained")
	if err != nil {
		return err
	}
	if maxVersion == 1 || legacyBrowserColumn {
		if err := migrateRetainedDataV2(ctx, tx); err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, retainedDataV2TableSQL("plugin_retained_data_records")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_retained_data_identity ON plugin_retained_data_records(publisher_id, plugin_id, state)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_retained_data_source ON plugin_retained_data_records(source_plugin_instance_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_retained_data_expiry ON plugin_retained_data_records(state, delete_after)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_retained_data_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func retainedDataV2TableSQL(tableName string) string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	retained_id TEXT PRIMARY KEY,
	source_plugin_instance_id TEXT NOT NULL,
	bound_plugin_instance_id TEXT NOT NULL,
	publisher_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	version TEXT NOT NULL,
	package_hash TEXT NOT NULL,
	manifest_hash TEXT NOT NULL,
	state TEXT NOT NULL,
	storage_retained INTEGER NOT NULL,
	settings_retained INTEGER NOT NULL,
	usage_bytes INTEGER NOT NULL,
	delete_after INTEGER,
	delete_error TEXT NOT NULL,
	metadata_json TEXT NOT NULL,
	retained_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	bound_at INTEGER,
	deleted_at INTEGER,
	last_accessed_at INTEGER
)`, tableName)
}

func retainedDataTableHasColumn(ctx context.Context, tx *sql.Tx, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_retained_data_records)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func migrateRetainedDataV2(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS plugin_retained_data_records_v2`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, retainedDataV2TableSQL("plugin_retained_data_records_v2")); err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_retained_data_records_v2(
	retained_id, source_plugin_instance_id, bound_plugin_instance_id,
	publisher_id, plugin_id, version, package_hash, manifest_hash, state,
	storage_retained, settings_retained, usage_bytes, delete_after, delete_error,
	metadata_json, retained_at, updated_at, bound_at, deleted_at, last_accessed_at
)
SELECT retained_id, source_plugin_instance_id, bound_plugin_instance_id,
	publisher_id, plugin_id, version, package_hash, manifest_hash,
	CASE WHEN storage_retained = 0 AND settings_retained = 0 THEN 'deleted' ELSE state END,
	storage_retained, settings_retained, usage_bytes, delete_after,
	CASE WHEN storage_retained = 0 AND settings_retained = 0 THEN '' ELSE delete_error END,
	metadata_json, retained_at,
	CASE WHEN storage_retained = 0 AND settings_retained = 0 THEN ? ELSE updated_at END,
	bound_at,
	CASE WHEN storage_retained = 0 AND settings_retained = 0 THEN COALESCE(deleted_at, ?) ELSE deleted_at END,
	last_accessed_at
FROM plugin_retained_data_records`, now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE plugin_retained_data_records`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_retained_data_records_v2 RENAME TO plugin_retained_data_records`); err != nil {
		return err
	}
	return nil
}

func getSQLiteRecord(ctx context.Context, q sqliteQuerier, retainedID string) (Record, bool, error) {
	row := q.QueryRowContext(ctx, retainedDataSelectColumns+` FROM plugin_retained_data_records WHERE retained_id = ?`, retainedID)
	record, err := scanSQLiteRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	return record, true, nil
}

func upsertSQLiteRecord(ctx context.Context, tx *sql.Tx, record Record) error {
	metadataJSON, err := encodeStringMap(record.Metadata)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_retained_data_records(
	retained_id, source_plugin_instance_id, bound_plugin_instance_id,
	publisher_id, plugin_id, version, package_hash, manifest_hash, state,
	storage_retained, settings_retained, usage_bytes,
	delete_after, delete_error, metadata_json, retained_at, updated_at,
	bound_at, deleted_at, last_accessed_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(retained_id) DO UPDATE SET
	source_plugin_instance_id = excluded.source_plugin_instance_id,
	bound_plugin_instance_id = excluded.bound_plugin_instance_id,
	publisher_id = excluded.publisher_id,
	plugin_id = excluded.plugin_id,
	version = excluded.version,
	package_hash = excluded.package_hash,
	manifest_hash = excluded.manifest_hash,
	state = excluded.state,
	storage_retained = excluded.storage_retained,
	settings_retained = excluded.settings_retained,
	usage_bytes = excluded.usage_bytes,
	delete_after = excluded.delete_after,
	delete_error = excluded.delete_error,
	metadata_json = excluded.metadata_json,
	retained_at = excluded.retained_at,
	updated_at = excluded.updated_at,
	bound_at = excluded.bound_at,
	deleted_at = excluded.deleted_at,
	last_accessed_at = excluded.last_accessed_at`,
		record.RetainedID,
		record.SourcePluginInstanceID,
		record.BoundPluginInstanceID,
		record.PublisherID,
		record.PluginID,
		record.Version,
		record.PackageHash,
		record.ManifestHash,
		string(record.State),
		boolToInt(record.StorageRetained),
		boolToInt(record.SettingsRetained),
		record.UsageBytes,
		nullableTimeToUnix(record.DeleteAfter),
		record.DeleteError,
		metadataJSON,
		record.RetainedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		nullableTimeToUnix(record.BoundAt),
		nullableTimeToUnix(record.DeletedAt),
		nullableTimeToUnix(record.LastAccessedAt),
	)
	return err
}

func scanSQLiteRecord(scanner sqliteScanner) (Record, error) {
	var record Record
	var state string
	var storageRetained int
	var settingsRetained int
	var metadataJSON string
	var deleteAfter sql.NullInt64
	var retainedAt int64
	var updatedAt int64
	var boundAt sql.NullInt64
	var deletedAt sql.NullInt64
	var lastAccessedAt sql.NullInt64
	if err := scanner.Scan(
		&record.RetainedID,
		&record.SourcePluginInstanceID,
		&record.BoundPluginInstanceID,
		&record.PublisherID,
		&record.PluginID,
		&record.Version,
		&record.PackageHash,
		&record.ManifestHash,
		&state,
		&storageRetained,
		&settingsRetained,
		&record.UsageBytes,
		&deleteAfter,
		&record.DeleteError,
		&metadataJSON,
		&retainedAt,
		&updatedAt,
		&boundAt,
		&deletedAt,
		&lastAccessedAt,
	); err != nil {
		return Record{}, err
	}
	record.State = State(state)
	if !validState(record.State) {
		return Record{}, ErrInvalidRecord
	}
	record.StorageRetained = storageRetained != 0
	record.SettingsRetained = settingsRetained != 0
	record.RetainedAt = time.Unix(0, retainedAt).UTC()
	record.UpdatedAt = time.Unix(0, updatedAt).UTC()
	record.DeleteAfter = unixToNullableTime(deleteAfter)
	record.BoundAt = unixToNullableTime(boundAt)
	record.DeletedAt = unixToNullableTime(deletedAt)
	record.LastAccessedAt = unixToNullableTime(lastAccessedAt)
	metadata, err := decodeStringMap(metadataJSON)
	if err != nil {
		return Record{}, err
	}
	record.Metadata = metadata
	return cloneRecord(record), nil
}

func encodeStringMap(values map[string]string) (string, error) {
	values = cloneStringMap(values)
	if values == nil {
		values = map[string]string{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeStringMap(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	values := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return cloneStringMap(values), nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableTimeToUnix(value *time.Time) sql.NullInt64 {
	if value == nil || value.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: value.UTC().UnixNano(), Valid: true}
}

func unixToNullableTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := time.Unix(0, value.Int64).UTC()
	return &result
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

type sqliteQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
