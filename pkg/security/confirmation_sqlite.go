package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

type SQLiteConfirmationIntentStore struct {
	db      *sql.DB
	mu      sync.Mutex
	options ConfirmationIntentStoreOptions
}

func (*SQLiteConfirmationIntentStore) Durable() bool { return true }

func NewSQLiteConfirmationIntentStore(ctx context.Context, path string) (*SQLiteConfirmationIntentStore, error) {
	return NewSQLiteConfirmationIntentStoreWithOptions(ctx, path, ConfirmationIntentStoreOptions{})
}

func NewSQLiteConfirmationIntentStoreWithOptions(ctx context.Context, path string, options ConfirmationIntentStoreOptions) (*SQLiteConfirmationIntentStore, error) {
	if path == "" {
		return nil, errors.New("sqlite confirmation intent path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	normalized, err := normalizeConfirmationIntentStoreOptions(options)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &SQLiteConfirmationIntentStore{db: db, options: normalized}
	if err := store.initializeSchema(ctx); err != nil {
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
	if existing, exists, err := getSQLiteConfirmationIntent(ctx, tx, record.ConfirmationID); err != nil {
		return ConfirmationIntentRecord{}, err
	} else if exists || existing.ConfirmationID != "" {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	scope := confirmationSessionScope(record.Scope)
	total, err := countSQLiteConfirmationIntents(ctx, tx, `migration_required = 0`)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	ownerPlugin, err := countSQLiteConfirmationIntents(ctx, tx, `migration_required = 0 AND owner_env_hash = ? AND plugin_instance_id = ?`, scope.OwnerEnvHash, record.PluginInstanceID)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	sessionCount, err := countSQLiteConfirmationIntents(ctx, tx, `migration_required = 0 AND owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if total >= s.options.MaxTotal || ownerPlugin >= s.options.MaxPerOwnerPlugin || sessionCount >= s.options.MaxPerSession {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentCapacity
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
	if !exists {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !confirmationIntentMatchesSessionScope(record, req.SessionScope) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentScopeMismatch
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE confirmation_id = ?`, confirmationID); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConfirmationIntentRecord{}, err
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

	query := confirmationIntentSelectColumns + ` FROM plugin_confirmation_intents WHERE migration_required = 0`
	args := []any{}
	if pluginInstanceID != "" {
		query += ` AND plugin_instance_id = ?`
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
	ownerEnvHash := strings.TrimSpace(req.OwnerEnvHash)
	if pluginInstanceID == "" || !(sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEnvHash}).Valid() {
		return 0, ErrInvalidConfirmationIntent
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE migration_required = 0 AND owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *SQLiteConfirmationIntentStore) RevokeSessionConfirmationIntents(ctx context.Context, req RevokeSessionConfirmationIntentsRequest) (int, error) {
	if s == nil {
		return 0, errors.New("confirmation intent store is nil")
	}
	if err := req.SessionScope.Validate(); err != nil {
		return 0, ErrInvalidConfirmationIntent
	}
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if operationID == "" || len(operationID) > 256 {
		return 0, ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer rollbackUnlessCommitted(tx)
	var previous int
	err = tx.QueryRowContext(ctx, `
SELECT revoked_count FROM plugin_confirmation_session_revocations
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ? AND teardown_operation_id = ?`,
		req.SessionScope.OwnerSessionHash, req.SessionScope.OwnerUserHash, req.SessionScope.OwnerEnvHash,
		req.SessionScope.SessionChannelIDHash, operationID,
	).Scan(&previous)
	if err == nil {
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var revocationCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_confirmation_session_revocations`).Scan(&revocationCount); err != nil {
		return 0, err
	}
	if revocationCount >= s.options.MaxSessionRevocations {
		return 0, ErrConfirmationIntentCapacity
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM plugin_confirmation_intents
WHERE migration_required = 0 AND owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?`,
		req.SessionScope.OwnerSessionHash,
		req.SessionScope.OwnerUserHash,
		req.SessionScope.OwnerEnvHash,
		req.SessionScope.SessionChannelIDHash,
	)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_confirmation_session_revocations (
	owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, teardown_operation_id, revoked_count
) VALUES (?, ?, ?, ?, ?, ?)`,
		req.SessionScope.OwnerSessionHash, req.SessionScope.OwnerUserHash, req.SessionScope.OwnerEnvHash,
		req.SessionScope.SessionChannelIDHash, operationID, count,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *SQLiteConfirmationIntentStore) FinalizeSessionConfirmationRevocation(ctx context.Context, req FinalizeSessionConfirmationRevocationRequest) error {
	if s == nil || req.SessionScope.Validate() != nil {
		return ErrInvalidConfirmationIntent
	}
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if operationID == "" || len(operationID) > 256 {
		return ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
DELETE FROM plugin_confirmation_session_revocations
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ? AND teardown_operation_id = ?`,
		req.SessionScope.OwnerSessionHash, req.SessionScope.OwnerUserHash, req.SessionScope.OwnerEnvHash,
		req.SessionScope.SessionChannelIDHash, operationID,
	)
	return err
}

func (s *SQLiteConfirmationIntentStore) initializeSchema(ctx context.Context) error {
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
		owner_session_hash TEXT NOT NULL DEFAULT '',
		owner_user_hash TEXT NOT NULL DEFAULT '',
		owner_env_hash TEXT NOT NULL DEFAULT '',
		session_channel_id_hash TEXT NOT NULL DEFAULT '',
		migration_required INTEGER NOT NULL DEFAULT 0,
		issued_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_confirmation_session_revocations (
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	teardown_operation_id TEXT NOT NULL CHECK (length(teardown_operation_id) BETWEEN 1 AND 256),
	revoked_count INTEGER NOT NULL CHECK (revoked_count BETWEEN 0 AND 9007199254740991),
	PRIMARY KEY (owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, teardown_operation_id)
)`); err != nil {
		return err
	}
	if err := ensureSQLiteConfirmationOwnerColumns(ctx, tx); err != nil {
		return err
	}
	if err := migrateSQLiteConfirmationOwners(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS idx_plugin_confirmation_intents_plugin_instance`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_confirmation_intents_owner_plugin ON plugin_confirmation_intents(owner_env_hash, plugin_instance_id, issued_at, confirmation_id) WHERE migration_required = 0`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_confirmation_intents_expires_at ON plugin_confirmation_intents(expires_at)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_confirmation_intents_session_scope ON plugin_confirmation_intents(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, confirmation_id) WHERE migration_required = 0`); err != nil {
		return err
	}
	return tx.Commit()
}

const confirmationIntentSelectColumns = `
SELECT
	confirmation_id, confirmation_token_id, plugin_id, plugin_instance_id,
	surface_instance_id, bridge_channel_id, method, request_hash, plan_hash,
	scope_json, owner_session_hash, owner_user_hash, owner_env_hash,
	session_channel_id_hash, migration_required, issued_at, expires_at`

func deleteSQLiteExpiredConfirmationIntents(ctx context.Context, q sqliteConfirmationIntentQuerier, now time.Time) error {
	_, err := q.ExecContext(ctx, `DELETE FROM plugin_confirmation_intents WHERE expires_at <= ?`, now.UTC().UnixNano())
	return err
}

func countSQLiteConfirmationIntents(ctx context.Context, q sqliteConfirmationIntentQuerier, condition string, args ...any) (int, error) {
	count := 0
	query := `SELECT COUNT(*) FROM plugin_confirmation_intents`
	if strings.TrimSpace(condition) != "" {
		query += ` WHERE ` + condition
	}
	if err := q.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
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
	scopeJSON, err := json.Marshal(persistedConfirmationScopeFrom(record.Scope))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
	INSERT INTO plugin_confirmation_intents (
		confirmation_id, confirmation_token_id, plugin_id, plugin_instance_id,
		surface_instance_id, bridge_channel_id, method, request_hash, plan_hash, scope_json,
		owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash,
		migration_required, issued_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
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
		owner_session_hash = excluded.owner_session_hash,
		owner_user_hash = excluded.owner_user_hash,
		owner_env_hash = excluded.owner_env_hash,
		session_channel_id_hash = excluded.session_channel_id_hash,
		migration_required = 0,
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
		record.Scope.OwnerSessionHash,
		record.Scope.OwnerUserHash,
		record.Scope.OwnerEnvHash,
		record.Scope.SessionChannelIDHash,
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

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func scanSQLiteConfirmationIntent(scanner sqliteConfirmationIntentScanner) (ConfirmationIntentRecord, error) {
	var record ConfirmationIntentRecord
	var scopeJSON string
	var ownerSessionHash string
	var ownerUserHash string
	var ownerEnvHash string
	var sessionChannelIDHash string
	var migrationRequired int
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
		&ownerSessionHash,
		&ownerUserHash,
		&ownerEnvHash,
		&sessionChannelIDHash,
		&migrationRequired,
		&issuedAt,
		&expiresAt,
	); err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if migrationRequired != 0 {
		return ConfirmationIntentRecord{}, sessionctx.ErrOwnerScopeMigrationRequired
	}
	if err := decodeClosedConfirmationScope(scopeJSON, &record.Scope); err != nil {
		return ConfirmationIntentRecord{}, sessionctx.ErrOwnerScopeMigrationRequired
	}
	if record.Scope.OwnerSessionHash != ownerSessionHash || record.Scope.OwnerUserHash != ownerUserHash ||
		record.Scope.OwnerEnvHash != ownerEnvHash || record.Scope.SessionChannelIDHash != sessionChannelIDHash {
		return ConfirmationIntentRecord{}, sessionctx.ErrOwnerScopeMigrationRequired
	}
	record.IssuedAt = time.Unix(0, issuedAt).UTC()
	record.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return record, nil
}

func ensureSQLiteConfirmationOwnerColumns(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_confirmation_intents)`)
	if err != nil {
		return err
	}
	columns := map[string]struct{}{}
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		sql  string
	}{
		{"owner_session_hash", `ALTER TABLE plugin_confirmation_intents ADD COLUMN owner_session_hash TEXT NOT NULL DEFAULT ''`},
		{"owner_user_hash", `ALTER TABLE plugin_confirmation_intents ADD COLUMN owner_user_hash TEXT NOT NULL DEFAULT ''`},
		{"owner_env_hash", `ALTER TABLE plugin_confirmation_intents ADD COLUMN owner_env_hash TEXT NOT NULL DEFAULT ''`},
		{"session_channel_id_hash", `ALTER TABLE plugin_confirmation_intents ADD COLUMN session_channel_id_hash TEXT NOT NULL DEFAULT ''`},
		{"migration_required", `ALTER TABLE plugin_confirmation_intents ADD COLUMN migration_required INTEGER NOT NULL DEFAULT 0`},
	} {
		if _, ok := columns[column.name]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, column.sql); err != nil {
			return err
		}
	}
	return nil
}

func migrateSQLiteConfirmationOwners(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT confirmation_id, scope_json, owner_session_hash, owner_user_hash, owner_env_hash,
       session_channel_id_hash, migration_required
FROM plugin_confirmation_intents`)
	if err != nil {
		return err
	}
	type candidate struct {
		id                string
		scopeJSON         string
		ownerSessionHash  string
		ownerUserHash     string
		ownerEnvHash      string
		sessionChannelID  string
		migrationRequired int
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.scopeJSON, &item.ownerSessionHash, &item.ownerUserHash, &item.ownerEnvHash, &item.sessionChannelID, &item.migrationRequired); err != nil {
			_ = rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range candidates {
		if item.migrationRequired != 0 {
			continue
		}
		var scope ConfirmationScope
		if err := decodeClosedConfirmationScope(item.scopeJSON, &scope); err != nil || !confirmationSessionScope(scope).Valid() {
			if _, updateErr := tx.ExecContext(ctx, `UPDATE plugin_confirmation_intents SET migration_required = 1 WHERE confirmation_id = ?`, item.id); updateErr != nil {
				return updateErr
			}
			continue
		}
		if item.ownerSessionHash != "" || item.ownerUserHash != "" || item.ownerEnvHash != "" || item.sessionChannelID != "" {
			if item.ownerSessionHash != scope.OwnerSessionHash || item.ownerUserHash != scope.OwnerUserHash ||
				item.ownerEnvHash != scope.OwnerEnvHash || item.sessionChannelID != scope.SessionChannelIDHash {
				if _, updateErr := tx.ExecContext(ctx, `UPDATE plugin_confirmation_intents SET migration_required = 1 WHERE confirmation_id = ?`, item.id); updateErr != nil {
					return updateErr
				}
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE plugin_confirmation_intents
SET owner_session_hash = ?, owner_user_hash = ?, owner_env_hash = ?, session_channel_id_hash = ?
WHERE confirmation_id = ?`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, item.id); err != nil {
			return err
		}
	}
	return nil
}

func decodeClosedConfirmationScope(raw string, scope *ConfirmationScope) error {
	if scope == nil || strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "{}" {
		return ErrInvalidConfirmationIntent
	}
	var persisted persistedConfirmationScope
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidConfirmationIntent
	}
	*scope = persisted.confirmationScope()
	return nil
}

type persistedConfirmationScope struct {
	ActiveFingerprint      string `json:"active_fingerprint"`
	OwnerSessionHash       string `json:"owner_session_hash"`
	OwnerUserHash          string `json:"owner_user_hash"`
	OwnerEnvHash           string `json:"owner_env_hash"`
	SessionChannelIDHash   string `json:"session_channel_id_hash"`
	PolicyRevision         uint64 `json:"policy_revision"`
	ManagementRevision     uint64 `json:"management_revision"`
	RevokeEpoch            uint64 `json:"revoke_epoch"`
	TargetDescriptorSHA256 string `json:"target_descriptor_sha256"`
}

func persistedConfirmationScopeFrom(scope ConfirmationScope) persistedConfirmationScope {
	return persistedConfirmationScope(scope)
}

func (scope persistedConfirmationScope) confirmationScope() ConfirmationScope {
	return ConfirmationScope(scope)
}

var _ ConfirmationIntentStore = (*SQLiteConfirmationIntentStore)(nil)
