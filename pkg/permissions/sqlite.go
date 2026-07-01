package permissions

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
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite permission store path is required")
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

func (s *SQLiteStore) Grant(ctx context.Context, req GrantRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("permission store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	permissionID := normalizeID(req.PermissionID)
	if pluginInstanceID == "" || permissionID == "" {
		return Record{}, ErrInvalidPermission
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record := Record{
		PluginInstanceID: pluginInstanceID,
		PermissionID:     permissionID,
		Effect:           EffectGrant,
		GrantedBy:        strings.TrimSpace(req.GrantedBy),
		GrantedAt:        now,
	}
	if !req.ExpiresAt.IsZero() {
		expiresAt := req.ExpiresAt.UTC()
		record.ExpiresAt = &expiresAt
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)
	if err := upsertSQLitePermission(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) Revoke(ctx context.Context, req RevokeRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("permission store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	permissionID := normalizeID(req.PermissionID)
	if pluginInstanceID == "" || permissionID == "" {
		return Record{}, ErrInvalidPermission
	}
	now := req.Now
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
	record, exists, err := getSQLitePermission(ctx, tx, pluginInstanceID, permissionID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrGrantNotFound
	}
	revokedAt := now
	record.RevokedAt = &revokedAt
	record.RevokedBy = strings.TrimSpace(req.RevokedBy)
	record.RevokedReason = strings.TrimSpace(req.Reason)
	if err := upsertSQLitePermission(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("permission store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	query := permissionSelectColumns + ` FROM plugin_permission_grants`
	args := []any{}
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id = ?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY plugin_instance_id ASC, permission_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []Record{}
	for rows.Next() {
		record, err := scanSQLitePermission(rows)
		if err != nil {
			return nil, err
		}
		if req.ActiveOnly && !record.activeAt(now) {
			continue
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRecords(records)
	return records, nil
}

func (s *SQLiteStore) IsGranted(ctx context.Context, req CheckRequest) (bool, []string, error) {
	if s == nil {
		return false, nil, errors.New("permission store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return false, nil, ErrInvalidPermission
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	required := normalizePermissionIDs(req.PermissionIDs)
	if len(required) == 0 {
		return true, nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	missing := make([]string, 0)
	for _, permissionID := range required {
		record, exists, err := getSQLitePermission(ctx, s.db, pluginInstanceID, permissionID)
		if err != nil {
			return false, nil, err
		}
		if !exists || !record.activeAt(now) {
			missing = append(missing, permissionID)
		}
	}
	return len(missing) == 0, missing, nil
}

func (s *SQLiteStore) DeletePluginGrants(ctx context.Context, pluginInstanceID string) error {
	if s == nil {
		return errors.New("permission store is nil")
	}
	pluginInstanceID = normalizeID(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM plugin_permission_grants WHERE plugin_instance_id = ?`, pluginInstanceID)
	return err
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
CREATE TABLE IF NOT EXISTS plugin_permission_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_permission_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite permission schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_permission_grants (
	plugin_instance_id TEXT NOT NULL,
	permission_id TEXT NOT NULL,
	effect TEXT NOT NULL,
	granted_by TEXT NOT NULL,
	granted_at INTEGER NOT NULL,
	expires_at INTEGER,
	revoked_at INTEGER,
	revoked_by TEXT NOT NULL,
	revoked_reason TEXT NOT NULL,
	PRIMARY KEY(plugin_instance_id, permission_id)
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_permission_grants_plugin ON plugin_permission_grants(plugin_instance_id, permission_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_permission_grants_revoked ON plugin_permission_grants(plugin_instance_id, revoked_at, expires_at)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_permission_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const permissionSelectColumns = `
SELECT
	plugin_instance_id, permission_id, effect, granted_by, granted_at,
	expires_at, revoked_at, revoked_by, revoked_reason`

func getSQLitePermission(ctx context.Context, q sqliteQuerier, pluginInstanceID string, permissionID string) (Record, bool, error) {
	row := q.QueryRowContext(ctx, permissionSelectColumns+` FROM plugin_permission_grants WHERE plugin_instance_id = ? AND permission_id = ?`, pluginInstanceID, permissionID)
	record, err := scanSQLitePermission(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func upsertSQLitePermission(ctx context.Context, tx *sql.Tx, record Record) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_permission_grants (
	plugin_instance_id, permission_id, effect, granted_by, granted_at,
	expires_at, revoked_at, revoked_by, revoked_reason
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(plugin_instance_id, permission_id) DO UPDATE SET
	effect = excluded.effect,
	granted_by = excluded.granted_by,
	granted_at = excluded.granted_at,
	expires_at = excluded.expires_at,
	revoked_at = excluded.revoked_at,
	revoked_by = excluded.revoked_by,
	revoked_reason = excluded.revoked_reason`,
		record.PluginInstanceID,
		record.PermissionID,
		string(record.Effect),
		record.GrantedBy,
		record.GrantedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.ExpiresAt),
		timePtrToNullableUnix(record.RevokedAt),
		record.RevokedBy,
		record.RevokedReason,
	)
	return err
}

type sqliteQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqlitePermissionScanner interface {
	Scan(...any) error
}

func scanSQLitePermission(scanner sqlitePermissionScanner) (Record, error) {
	var record Record
	var effect string
	var grantedAt int64
	var expiresAt sql.NullInt64
	var revokedAt sql.NullInt64
	if err := scanner.Scan(
		&record.PluginInstanceID,
		&record.PermissionID,
		&effect,
		&record.GrantedBy,
		&grantedAt,
		&expiresAt,
		&revokedAt,
		&record.RevokedBy,
		&record.RevokedReason,
	); err != nil {
		return Record{}, err
	}
	record.Effect = Effect(effect)
	record.GrantedAt = unixToTime(grantedAt)
	record.ExpiresAt = nullableUnixToTimePtr(expiresAt)
	record.RevokedAt = nullableUnixToTimePtr(revokedAt)
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
