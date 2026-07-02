package browsersite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

type SQLiteStore struct {
	db      *sql.DB
	mu      sync.Mutex
	cleaner Cleaner
}

type SQLiteStoreOptions struct {
	Cleaner Cleaner
}

func NewSQLiteStore(ctx context.Context, path string, options ...SQLiteStoreOptions) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite browser site store path is required")
	}
	opts := SQLiteStoreOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db, cleaner: opts.Cleaner}
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

func (s *SQLiteStore) RegisterOrigin(ctx context.Context, req RegisterRequest) (OriginRecord, error) {
	if s == nil {
		return OriginRecord{}, errors.New("browser site store is nil")
	}
	normalized, err := normalizeRegisterRequest(req)
	if err != nil {
		return OriginRecord{}, err
	}
	now := normalized.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := originKey(normalized.PluginInstanceID, normalized.ActiveFingerprint, normalized.OwnerSessionHash, normalized.Origin)

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OriginRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteOrigin(ctx, tx, key)
	if err != nil {
		return OriginRecord{}, err
	}
	if exists {
		record.PluginID = normalized.PluginID
		record.SurfaceID = normalized.SurfaceID
		record.SurfaceInstanceID = normalized.SurfaceInstanceID
		record.OwnerUserHash = normalized.OwnerUserHash
		record.State = StateActive
		record.CleanupReason = ""
		record.CleanupError = ""
		record.UpdatedAt = now
		record.LastSeenAt = now
		record.CleanupRequestedAt = nil
		record.CleanedAt = nil
		record.RetainedAt = nil
	} else {
		record = OriginRecord{
			OriginKey:         key,
			PluginInstanceID:  normalized.PluginInstanceID,
			PluginID:          normalized.PluginID,
			ActiveFingerprint: normalized.ActiveFingerprint,
			SurfaceID:         normalized.SurfaceID,
			SurfaceInstanceID: normalized.SurfaceInstanceID,
			Origin:            normalized.Origin,
			OwnerSessionHash:  normalized.OwnerSessionHash,
			OwnerUserHash:     normalized.OwnerUserHash,
			State:             StateActive,
			CreatedAt:         now,
			UpdatedAt:         now,
			LastSeenAt:        now,
		}
	}
	if err := upsertSQLiteOrigin(ctx, tx, record); err != nil {
		return OriginRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return OriginRecord{}, err
	}
	return cloneRecord(record), nil
}

func (s *SQLiteStore) CleanupPluginOrigins(ctx context.Context, req CleanupRequest) (CleanupResult, error) {
	if s == nil {
		return CleanupResult{}, errors.New("browser site store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return CleanupResult{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidOrigin)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		if req.DeleteData {
			reason = "delete_data"
		} else {
			reason = "retain_data"
		}
	}

	if !req.DeleteData {
		return s.retainPluginOrigins(ctx, pluginInstanceID, reason, now)
	}
	pending, err := s.markCleanupPending(ctx, pluginInstanceID, reason, req.RequireRetained, now)
	if err != nil {
		return CleanupResult{}, err
	}
	sortRecords(pending)
	if s.cleaner == nil {
		records, updateErr := s.markCleanupMissingCleaner(ctx, pending, now)
		if updateErr != nil {
			return CleanupResult{}, updateErr
		}
		return CleanupResult{Records: records}, fmt.Errorf("%w: %w", ErrCleanupFailed, ErrCleanerRequired)
	}

	records := make([]OriginRecord, 0, len(pending))
	var firstErr error
	for _, record := range pending {
		if err := s.cleaner.ClearOriginData(ctx, record.Origin); err != nil {
			record.State = StateCleanupFailed
			record.CleanupError = err.Error()
			record.UpdatedAt = now
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: %s: %v", ErrCleanupFailed, record.Origin, err)
			}
		} else {
			record.State = StateCleanupComplete
			record.CleanupError = ""
			record.CleanedAt = &now
			record.UpdatedAt = now
		}
		if err := s.saveOrigin(ctx, record); err != nil {
			return CleanupResult{}, err
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	if firstErr != nil {
		return CleanupResult{Records: records}, firstErr
	}
	return CleanupResult{Records: records}, nil
}

func (s *SQLiteStore) ListOrigins(ctx context.Context, req ListRequest) ([]OriginRecord, error) {
	if s == nil {
		return nil, errors.New("browser site store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	state := OriginState(strings.TrimSpace(req.State))
	query := originSelectColumns + ` FROM plugin_browser_site_origins`
	args := []any{}
	where := []string{}
	if pluginInstanceID != "" {
		where = append(where, `plugin_instance_id = ?`)
		args = append(args, pluginInstanceID)
	}
	if state != "" {
		where = append(where, `state = ?`)
		args = append(args, string(state))
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY plugin_instance_id ASC, origin ASC, active_fingerprint ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []OriginRecord{}
	for rows.Next() {
		record, err := scanSQLiteOrigin(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, cloneRecord(record))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRecords(records)
	return records, nil
}

func (s *SQLiteStore) retainPluginOrigins(ctx context.Context, pluginInstanceID string, reason string, now time.Time) (CleanupResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CleanupResult{}, err
	}
	defer rollbackUnlessCommitted(tx)

	records, err := listSQLiteOriginsByPluginInstance(ctx, tx, pluginInstanceID)
	if err != nil {
		return CleanupResult{}, err
	}
	retained := make([]OriginRecord, 0, len(records))
	for _, record := range records {
		record.UpdatedAt = now
		record.CleanupReason = reason
		record.State = StateRetained
		record.RetainedAt = &now
		record.CleanupRequestedAt = nil
		record.CleanedAt = nil
		record.CleanupError = ""
		if err := upsertSQLiteOrigin(ctx, tx, record); err != nil {
			return CleanupResult{}, err
		}
		retained = append(retained, cloneRecord(record))
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, err
	}
	sortRecords(retained)
	return CleanupResult{Records: retained}, nil
}

func (s *SQLiteStore) markCleanupPending(ctx context.Context, pluginInstanceID string, reason string, requireRetained bool, now time.Time) ([]OriginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)

	records, err := listSQLiteOriginsByPluginInstance(ctx, tx, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	if requireRetained {
		for _, record := range records {
			switch record.State {
			case StateRetained, StateCleanupPending, StateCleanupFailed, StateCleanupComplete:
			default:
				return nil, fmt.Errorf("%w: %s is %s", ErrOriginNotRetained, record.Origin, record.State)
			}
		}
	}
	pending := make([]OriginRecord, 0, len(records))
	for _, record := range records {
		record.UpdatedAt = now
		record.CleanupReason = reason
		record.State = StateCleanupPending
		record.CleanupRequestedAt = &now
		record.CleanedAt = nil
		record.RetainedAt = nil
		record.CleanupError = ""
		if err := upsertSQLiteOrigin(ctx, tx, record); err != nil {
			return nil, err
		}
		pending = append(pending, cloneRecord(record))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}

func (s *SQLiteStore) markCleanupMissingCleaner(ctx context.Context, pending []OriginRecord, now time.Time) ([]OriginRecord, error) {
	records := make([]OriginRecord, 0, len(pending))
	for _, record := range pending {
		record.State = StateCleanupFailed
		record.CleanupError = ErrCleanerRequired.Error()
		record.UpdatedAt = now
		if err := s.saveOrigin(ctx, record); err != nil {
			return nil, err
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func (s *SQLiteStore) saveOrigin(ctx context.Context, record OriginRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if err := upsertSQLiteOrigin(ctx, tx, record); err != nil {
		return err
	}
	return tx.Commit()
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
CREATE TABLE IF NOT EXISTS plugin_browser_site_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_browser_site_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite browser site schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_browser_site_origins (
	origin_key TEXT PRIMARY KEY,
	plugin_instance_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	active_fingerprint TEXT NOT NULL,
	surface_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	origin TEXT NOT NULL,
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	state TEXT NOT NULL,
	cleanup_reason TEXT NOT NULL,
	cleanup_error TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	cleanup_requested_at INTEGER,
	cleaned_at INTEGER,
	retained_at INTEGER
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_browser_site_plugin_instance ON plugin_browser_site_origins(plugin_instance_id, state, origin)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_browser_site_state ON plugin_browser_site_origins(state, updated_at)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_browser_site_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const originSelectColumns = `
SELECT
	origin_key, plugin_instance_id, plugin_id, active_fingerprint, surface_id,
	surface_instance_id, origin, owner_session_hash, owner_user_hash, state,
	cleanup_reason, cleanup_error, created_at, updated_at, last_seen_at,
	cleanup_requested_at, cleaned_at, retained_at`

func getSQLiteOrigin(ctx context.Context, q sqliteQuerier, originKey string) (OriginRecord, bool, error) {
	row := q.QueryRowContext(ctx, originSelectColumns+` FROM plugin_browser_site_origins WHERE origin_key = ?`, originKey)
	record, err := scanSQLiteOrigin(row)
	if errors.Is(err, sql.ErrNoRows) {
		return OriginRecord{}, false, nil
	}
	if err != nil {
		return OriginRecord{}, false, err
	}
	return record, true, nil
}

func listSQLiteOriginsByPluginInstance(ctx context.Context, q sqliteQuerier, pluginInstanceID string) ([]OriginRecord, error) {
	rows, err := q.QueryContext(ctx, originSelectColumns+` FROM plugin_browser_site_origins WHERE plugin_instance_id = ? ORDER BY plugin_instance_id ASC, origin ASC, active_fingerprint ASC`, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []OriginRecord{}
	for rows.Next() {
		record, err := scanSQLiteOrigin(rows)
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

func upsertSQLiteOrigin(ctx context.Context, tx *sql.Tx, record OriginRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_browser_site_origins (
	origin_key, plugin_instance_id, plugin_id, active_fingerprint, surface_id,
	surface_instance_id, origin, owner_session_hash, owner_user_hash, state,
	cleanup_reason, cleanup_error, created_at, updated_at, last_seen_at,
	cleanup_requested_at, cleaned_at, retained_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(origin_key) DO UPDATE SET
	plugin_instance_id = excluded.plugin_instance_id,
	plugin_id = excluded.plugin_id,
	active_fingerprint = excluded.active_fingerprint,
	surface_id = excluded.surface_id,
	surface_instance_id = excluded.surface_instance_id,
	origin = excluded.origin,
	owner_session_hash = excluded.owner_session_hash,
	owner_user_hash = excluded.owner_user_hash,
	state = excluded.state,
	cleanup_reason = excluded.cleanup_reason,
	cleanup_error = excluded.cleanup_error,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at,
	last_seen_at = excluded.last_seen_at,
	cleanup_requested_at = excluded.cleanup_requested_at,
	cleaned_at = excluded.cleaned_at,
	retained_at = excluded.retained_at`,
		record.OriginKey,
		record.PluginInstanceID,
		record.PluginID,
		record.ActiveFingerprint,
		record.SurfaceID,
		record.SurfaceInstanceID,
		record.Origin,
		record.OwnerSessionHash,
		record.OwnerUserHash,
		string(record.State),
		record.CleanupReason,
		record.CleanupError,
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		record.LastSeenAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.CleanupRequestedAt),
		timePtrToNullableUnix(record.CleanedAt),
		timePtrToNullableUnix(record.RetainedAt),
	)
	return err
}

type sqliteQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteOriginScanner interface {
	Scan(...any) error
}

func scanSQLiteOrigin(scanner sqliteOriginScanner) (OriginRecord, error) {
	var record OriginRecord
	var state string
	var createdAt int64
	var updatedAt int64
	var lastSeenAt int64
	var cleanupRequestedAt sql.NullInt64
	var cleanedAt sql.NullInt64
	var retainedAt sql.NullInt64
	if err := scanner.Scan(
		&record.OriginKey,
		&record.PluginInstanceID,
		&record.PluginID,
		&record.ActiveFingerprint,
		&record.SurfaceID,
		&record.SurfaceInstanceID,
		&record.Origin,
		&record.OwnerSessionHash,
		&record.OwnerUserHash,
		&state,
		&record.CleanupReason,
		&record.CleanupError,
		&createdAt,
		&updatedAt,
		&lastSeenAt,
		&cleanupRequestedAt,
		&cleanedAt,
		&retainedAt,
	); err != nil {
		return OriginRecord{}, err
	}
	record.State = OriginState(state)
	record.CreatedAt = unixToTime(createdAt)
	record.UpdatedAt = unixToTime(updatedAt)
	record.LastSeenAt = unixToTime(lastSeenAt)
	record.CleanupRequestedAt = nullableUnixToTimePtr(cleanupRequestedAt)
	record.CleanedAt = nullableUnixToTimePtr(cleanedAt)
	record.RetainedAt = nullableUnixToTimePtr(retainedAt)
	return record, nil
}

func timePtrToNullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}

func nullableUnixToTimePtr(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := unixToTime(value.Int64)
	return &converted
}

func unixToTime(value int64) time.Time {
	return time.Unix(0, value).UTC()
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
