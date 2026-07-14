package security

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

const sqliteConfirmationIntentSchemaVersion = 2

type SQLiteConfirmationIntentStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteConfirmationIntentStore(ctx context.Context, path string) (*SQLiteConfirmationIntentStore, error) {
	if path == "" {
		return nil, errors.New("sqlite confirmation intent path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteConfirmationIntentStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteConfirmationIntentStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteConfirmationIntentStore) PutConfirmationIntent(ctx context.Context, req PutConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := confirmationIntentFromPut(req, now)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	maxPending := normalizeMaxPendingConfirmationIntents(req.MaxPendingPerPlugin)

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	if err := deleteSQLiteExpiredConfirmationIntents(ctx, tx, now); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	for {
		count, err := countSQLiteConfirmationIntents(ctx, tx, record.PluginInstanceID)
		if err != nil {
			return ConfirmationIntentRecord{}, err
		}
		if count < maxPending {
			break
		}
		oldestID, err := oldestSQLiteConfirmationIntentID(ctx, tx, record.PluginInstanceID)
		if err != nil {
			return ConfirmationIntentRecord{}, err
		}
		if oldestID == "" {
			break
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE confirmation_id = ?`, oldestID); err != nil {
			return ConfirmationIntentRecord{}, err
		}
	}
	if err := upsertSQLiteConfirmationIntent(ctx, tx, record); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	return record, nil
}

func (s *SQLiteConfirmationIntentStore) ConsumeConfirmationIntent(ctx context.Context, req ConsumeConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	confirmationID := strings.TrimSpace(req.ConfirmationID)
	if confirmationID == "" {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, exists, err := getSQLiteConfirmationIntent(ctx, tx, confirmationID)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if exists {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE confirmation_id = ?`, confirmationID); err != nil {
			return ConfirmationIntentRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if !exists {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !record.ExpiresAt.After(now) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	return record, nil
}

func (s *SQLiteConfirmationIntentStore) RejectConfirmationIntent(ctx context.Context, req RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	normalized, err := normalizeRejectConfirmationIntentRequest(req)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if normalized.Now.IsZero() {
		normalized.Now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, exists, err := getSQLiteConfirmationIntent(ctx, tx, normalized.ConfirmationID)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if !exists {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !record.ExpiresAt.After(normalized.Now) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE confirmation_id = ?`, normalized.ConfirmationID); err != nil {
			return ConfirmationIntentRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return ConfirmationIntentRecord{}, err
		}
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	if !confirmationIntentMatchesRejection(record, normalized) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentScopeMismatch
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE confirmation_id = ?`, normalized.ConfirmationID); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	return record, nil
}

func (s *SQLiteConfirmationIntentStore) ListConfirmationIntents(ctx context.Context, req ListConfirmationIntentsRequest) ([]ConfirmationIntentRecord, error) {
	if s == nil {
		return nil, errors.New("confirmation intent store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)

	s.mu.Lock()
	defer s.mu.Unlock()

	query := confirmationIntentSelectColumns + ` FROM plugin_confirmation_intents`
	args := []any{}
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id = ?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY issued_at ASC, confirmation_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []ConfirmationIntentRecord{}
	for rows.Next() {
		record, err := scanSQLiteConfirmationIntent(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortConfirmationIntentRecords(records)
	return records, nil
}

func (s *SQLiteConfirmationIntentStore) RevokePluginConfirmationIntents(ctx context.Context, req RevokePluginConfirmationIntentsRequest) (int, error) {
	if s == nil {
		return 0, errors.New("confirmation intent store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return 0, ErrInvalidConfirmationIntent
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE plugin_instance_id = ?`, pluginInstanceID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *SQLiteConfirmationIntentStore) migrate(ctx context.Context) error {
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
CREATE TABLE IF NOT EXISTS plugin_confirmation_intent_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_confirmation_intent_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteConfirmationIntentSchemaVersion {
		return fmt.Errorf("sqlite confirmation intent schema version %d is newer than supported version %d", maxVersion, sqliteConfirmationIntentSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_confirmation_intents (
	confirmation_id TEXT PRIMARY KEY,
	confirmation_token_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	bridge_channel_id TEXT NOT NULL,
	method TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	plan_hash TEXT NOT NULL,
	scope_json TEXT NOT NULL DEFAULT '{}',
	issued_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if maxVersion < 2 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_confirmation_intents ADD COLUMN scope_json TEXT NOT NULL DEFAULT '{}'`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_confirmation_intent_schema_migrations(version, applied_at) VALUES(?, ?)`, 2, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_confirmation_intents_plugin_instance ON plugin_confirmation_intents(plugin_instance_id, issued_at, confirmation_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_confirmation_intents_expires_at ON plugin_confirmation_intents(expires_at)`); err != nil {
		return err
	}
	if maxVersion < sqliteConfirmationIntentSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_confirmation_intent_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteConfirmationIntentSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const confirmationIntentSelectColumns = `
SELECT
	confirmation_id, confirmation_token_id, plugin_id, plugin_instance_id,
	surface_instance_id, bridge_channel_id, method, request_hash, plan_hash,
	scope_json, issued_at, expires_at`

func deleteSQLiteExpiredConfirmationIntents(ctx context.Context, q sqliteConfirmationIntentQuerier, now time.Time) error {
	_, err := q.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE expires_at <= ?`, now.UTC().UnixNano())
	return err
}

func countSQLiteConfirmationIntents(ctx context.Context, q sqliteConfirmationIntentQuerier, pluginInstanceID string) (int, error) {
	count := 0
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_confirmation_intents WHERE plugin_instance_id = ?`, pluginInstanceID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func oldestSQLiteConfirmationIntentID(ctx context.Context, q sqliteConfirmationIntentQuerier, pluginInstanceID string) (string, error) {
	var confirmationID string
	err := q.QueryRowContext(ctx, `
SELECT confirmation_id
FROM plugin_confirmation_intents
WHERE plugin_instance_id = ?
ORDER BY issued_at ASC, confirmation_id ASC
LIMIT 1`, pluginInstanceID).Scan(&confirmationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return confirmationID, nil
}

func getSQLiteConfirmationIntent(ctx context.Context, q sqliteConfirmationIntentQuerier, confirmationID string) (ConfirmationIntentRecord, bool, error) {
	row := q.QueryRowContext(ctx, confirmationIntentSelectColumns+` FROM plugin_confirmation_intents WHERE confirmation_id = ?`, confirmationID)
	record, err := scanSQLiteConfirmationIntent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfirmationIntentRecord{}, false, nil
	}
	if err != nil {
		return ConfirmationIntentRecord{}, false, err
	}
	return record, true, nil
}

func upsertSQLiteConfirmationIntent(ctx context.Context, tx *sql.Tx, record ConfirmationIntentRecord) error {
	scopeJSON, err := json.Marshal(record.Scope)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_confirmation_intents (
	confirmation_id, confirmation_token_id, plugin_id, plugin_instance_id,
	surface_instance_id, bridge_channel_id, method, request_hash, plan_hash, scope_json,
	issued_at, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(confirmation_id) DO UPDATE SET
	confirmation_token_id = excluded.confirmation_token_id,
	plugin_id = excluded.plugin_id,
	plugin_instance_id = excluded.plugin_instance_id,
	surface_instance_id = excluded.surface_instance_id,
	bridge_channel_id = excluded.bridge_channel_id,
	method = excluded.method,
	request_hash = excluded.request_hash,
	plan_hash = excluded.plan_hash,
	scope_json = excluded.scope_json,
	issued_at = excluded.issued_at,
	expires_at = excluded.expires_at`,
		record.ConfirmationID,
		record.ConfirmationTokenID,
		record.PluginID,
		record.PluginInstanceID,
		record.SurfaceInstanceID,
		record.BridgeChannelID,
		record.Method,
		record.RequestHash,
		record.PlanHash,
		string(scopeJSON),
		record.IssuedAt.UTC().UnixNano(),
		record.ExpiresAt.UTC().UnixNano(),
	)
	return err
}

type sqliteConfirmationIntentQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteConfirmationIntentScanner interface {
	Scan(...any) error
}

func scanSQLiteConfirmationIntent(scanner sqliteConfirmationIntentScanner) (ConfirmationIntentRecord, error) {
	var record ConfirmationIntentRecord
	var scopeJSON string
	var issuedAt int64
	var expiresAt int64
	if err := scanner.Scan(
		&record.ConfirmationID,
		&record.ConfirmationTokenID,
		&record.PluginID,
		&record.PluginInstanceID,
		&record.SurfaceInstanceID,
		&record.BridgeChannelID,
		&record.Method,
		&record.RequestHash,
		&record.PlanHash,
		&scopeJSON,
		&issuedAt,
		&expiresAt,
	); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if strings.TrimSpace(scopeJSON) != "" && strings.TrimSpace(scopeJSON) != "{}" {
		if err := json.Unmarshal([]byte(scopeJSON), &record.Scope); err != nil {
			return ConfirmationIntentRecord{}, err
		}
	}
	record.IssuedAt = time.Unix(0, issuedAt).UTC()
	record.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return record, nil
}

var _ ConfirmationIntentStore = (*SQLiteConfirmationIntentStore)(nil)
