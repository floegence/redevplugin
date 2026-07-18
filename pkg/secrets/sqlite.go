package secrets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

const secretBindingSelectColumns = `
SELECT owner_env_hash, owner_user_hash, plugin_instance_id, secret_ref, scope, bound, last_test_status,
       bound_at, tested_at, deleted_at, updated_at`

type SQLiteStore struct {
	db  *sql.DB
	mu  sync.Mutex
	now func() time.Time
}

func NewSQLiteStore(ctx context.Context, path string, opts ...MemoryStoreOptions) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite secret store path is required")
	}
	options := MemoryStoreOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db, now: now}
	if err := store.initializeSchema(ctx); err != nil {
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

func (s *SQLiteStore) BindSecretRef(ctx context.Context, req BindRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(req)
	if err != nil {
		return err
	}
	owner, err := ownerForScope(ctx, normalized.Scope)
	if err != nil {
		return err
	}
	now := s.now()
	record := Record{
		OwnerEnvHash:     owner.OwnerEnvHash,
		OwnerUserHash:    owner.OwnerUserHash,
		PluginInstanceID: normalized.PluginInstanceID,
		SecretRef:        normalized.SecretRef,
		Scope:            normalized.Scope,
		Bound:            true,
		BoundAt:          &now,
		UpdatedAt:        now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsert(ctx, record)
}

func (s *SQLiteStore) TestSecretRef(ctx context.Context, req TestRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(BindRequest(req))
	if err != nil {
		return err
	}
	owner, err := ownerForScope(ctx, normalized.Scope)
	if err != nil {
		return err
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteRecord(ctx, s.db, owner, normalized)
	if err != nil {
		return err
	}
	if !exists || !record.Bound {
		return fmt.Errorf("%w: secret_ref must be bound before testing", ErrInvalidSecretRef)
	}
	record.PluginInstanceID = normalized.PluginInstanceID
	record.SecretRef = normalized.SecretRef
	record.Scope = normalized.Scope
	record.Bound = true
	if record.BoundAt == nil {
		record.BoundAt = &now
	}
	record.LastTestStatus = "passed"
	record.TestedAt = &now
	record.DeletedAt = nil
	record.UpdatedAt = now
	return s.upsert(ctx, record)
}

func (s *SQLiteStore) DeleteSecretRef(ctx context.Context, req DeleteRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(BindRequest(req))
	if err != nil {
		return err
	}
	owner, err := ownerForScope(ctx, normalized.Scope)
	if err != nil {
		return err
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteRecord(ctx, s.db, owner, normalized)
	if err != nil {
		return err
	}
	if !exists {
		record = Record{
			OwnerEnvHash:     owner.OwnerEnvHash,
			OwnerUserHash:    owner.OwnerUserHash,
			PluginInstanceID: normalized.PluginInstanceID,
			SecretRef:        normalized.SecretRef,
			Scope:            normalized.Scope,
		}
	}
	record.Bound = false
	record.LastTestStatus = ""
	record.DeletedAt = &now
	record.UpdatedAt = now
	return s.upsert(ctx, record)
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("secret store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	scope := strings.TrimSpace(req.Scope)
	if scope != "" && scope != ScopeUser && scope != ScopeEnvironment {
		return nil, ErrInvalidSecretRef
	}
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := secretBindingSelectColumns + ` FROM plugin_secret_bindings`
	args := []any{session.OwnerEnvHash, session.OwnerUserHash}
	conditions := []string{`owner_env_hash = ? AND ((scope = 'environment' AND owner_user_hash = '') OR (scope = 'user' AND owner_user_hash = ?))`}
	if pluginInstanceID != "" {
		conditions = append(conditions, `plugin_instance_id = ?`)
		args = append(args, pluginInstanceID)
	}
	if scope != "" {
		conditions = append(conditions, `scope = ?`)
		args = append(args, scope)
	}
	if req.BoundOnly {
		conditions = append(conditions, `bound = 1`)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY plugin_instance_id ASC, scope ASC, secret_ref ASC`

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

func (s *SQLiteStore) DeletePlugin(ctx context.Context, pluginInstanceID string) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidSecretRef
	}
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.db.ExecContext(ctx, `DELETE FROM plugin_secret_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, session.OwnerEnvHash, pluginInstanceID)
	return err
}

func (s *SQLiteStore) upsert(ctx context.Context, record Record) error {
	if err := validateRecordOwner(record); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO plugin_secret_bindings(owner_env_hash, owner_user_hash, plugin_instance_id, secret_ref, scope, bound, last_test_status, bound_at, tested_at, deleted_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner_env_hash, owner_user_hash, plugin_instance_id, scope, secret_ref) DO UPDATE SET
	bound = excluded.bound,
	last_test_status = excluded.last_test_status,
	bound_at = excluded.bound_at,
	tested_at = excluded.tested_at,
	deleted_at = excluded.deleted_at,
	updated_at = excluded.updated_at`,
		record.OwnerEnvHash,
		record.OwnerUserHash,
		record.PluginInstanceID,
		record.SecretRef,
		record.Scope,
		boolToInt(record.Bound),
		record.LastTestStatus,
		timePtrToNullableUnix(record.BoundAt),
		timePtrToNullableUnix(record.TestedAt),
		timePtrToNullableUnix(record.DeletedAt),
		record.UpdatedAt.UTC().UnixNano(),
	)
	return err
}

func (s *SQLiteStore) initializeSchema(ctx context.Context) error {
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
	legacy, err := secretSchemaNeedsOwnerMigration(ctx, tx)
	if err != nil {
		return err
	}
	if legacy {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_secret_bindings`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return sessionctx.ErrOwnerScopeMigrationRequired
		}
		if _, err := tx.ExecContext(ctx, `DROP TABLE plugin_secret_bindings`); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_secret_bindings (
	owner_env_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	secret_ref TEXT NOT NULL,
	scope TEXT NOT NULL,
	bound INTEGER NOT NULL,
	last_test_status TEXT NOT NULL,
	bound_at INTEGER,
	tested_at INTEGER,
	deleted_at INTEGER,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY(owner_env_hash, owner_user_hash, plugin_instance_id, scope, secret_ref),
	CHECK((scope = 'environment' AND owner_user_hash = '') OR (scope = 'user' AND owner_user_hash <> ''))
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_secret_bindings_plugin ON plugin_secret_bindings(owner_env_hash, plugin_instance_id, scope, owner_user_hash, bound, updated_at)`); err != nil {
		return err
	}
	return tx.Commit()
}

func secretSchemaNeedsOwnerMigration(ctx context.Context, tx *sql.Tx) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_secret_bindings)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	columns := map[string]struct{}{}
	for rows.Next() {
		var (
			columnID    int
			name        string
			columnType  string
			notNull     int
			defaultExpr sql.NullString
			primaryKey  int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultExpr, &primaryKey); err != nil {
			return false, err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(columns) == 0 {
		return false, nil
	}
	_, hasEnv := columns["owner_env_hash"]
	_, hasUser := columns["owner_user_hash"]
	return !hasEnv || !hasUser, nil
}

func getSQLiteRecord(ctx context.Context, db queryer, owner sessionctx.ResourceScope, req BindRequest) (Record, bool, error) {
	row := db.QueryRowContext(ctx, secretBindingSelectColumns+` FROM plugin_secret_bindings WHERE owner_env_hash = ? AND owner_user_hash = ? AND plugin_instance_id = ? AND scope = ? AND secret_ref = ?`, owner.OwnerEnvHash, owner.OwnerUserHash, req.PluginInstanceID, req.Scope, req.SecretRef)
	record, err := scanSQLiteRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func scanSQLiteRecord(rows *sql.Rows) (Record, error) {
	return scanSQLiteScanner(rows)
}

func scanSQLiteRow(row *sql.Row) (Record, error) {
	return scanSQLiteScanner(row)
}

func scanSQLiteScanner(scanner interface {
	Scan(dest ...any) error
}) (Record, error) {
	var record Record
	var bound int
	var boundAt sql.NullInt64
	var testedAt sql.NullInt64
	var deletedAt sql.NullInt64
	var updatedAt int64
	if err := scanner.Scan(
		&record.OwnerEnvHash,
		&record.OwnerUserHash,
		&record.PluginInstanceID,
		&record.SecretRef,
		&record.Scope,
		&bound,
		&record.LastTestStatus,
		&boundAt,
		&testedAt,
		&deletedAt,
		&updatedAt,
	); err != nil {
		return Record{}, err
	}
	record.Bound = bound != 0
	record.BoundAt = nullableUnixToTime(boundAt)
	record.TestedAt = nullableUnixToTime(testedAt)
	record.DeletedAt = nullableUnixToTime(deletedAt)
	record.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if err := validateRecordOwner(record); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func validateRecordOwner(record Record) error {
	owner := sessionctx.ResourceScope{
		Kind:          sessionctx.ScopeKind(record.Scope),
		OwnerEnvHash:  record.OwnerEnvHash,
		OwnerUserHash: record.OwnerUserHash,
	}
	if err := owner.Validate(); err != nil {
		return ErrSecretScopeMismatch
	}
	return nil
}

func nullableUnixToTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	t := time.Unix(0, value.Int64).UTC()
	return &t
}

func timePtrToNullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
var _ Lister = (*SQLiteStore)(nil)
var _ PluginDeleter = (*SQLiteStore)(nil)
