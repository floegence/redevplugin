package security

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqlitePolicySchemaVersion = 1

type SQLitePolicyStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLitePolicyStore(ctx context.Context, path string) (*SQLitePolicyStore, error) {
	if path == "" {
		return nil, errors.New("sqlite security policy path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLitePolicyStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLitePolicyStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLitePolicyStore) PutPolicy(ctx context.Context, req PutPolicyRequest) (PolicyRecord, error) {
	if s == nil {
		return PolicyRecord{}, errors.New("security policy store is nil")
	}
	record, err := policyRecordFromPut(req)
	if err != nil {
		return PolicyRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PolicyRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	if err := upsertSQLitePolicy(ctx, tx, record); err != nil {
		return PolicyRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return PolicyRecord{}, err
	}
	return record, nil
}

func (s *SQLitePolicyStore) GetPolicy(ctx context.Context, pluginInstanceID string) (PolicyRecord, error) {
	if s == nil {
		return PolicyRecord{}, errors.New("security policy store is nil")
	}
	pluginInstanceID = normalizePolicyID(pluginInstanceID)
	if pluginInstanceID == "" {
		return PolicyRecord{}, ErrInvalidPolicy
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLitePolicy(ctx, s.db, pluginInstanceID)
	if err != nil {
		return PolicyRecord{}, err
	}
	if !exists {
		return PolicyRecord{}, ErrPolicyNotFound
	}
	return record, nil
}

func (s *SQLitePolicyStore) ListPolicies(ctx context.Context) ([]PolicyRecord, error) {
	if s == nil {
		return nil, errors.New("security policy store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `SELECT plugin_instance_id FROM plugin_security_policies ORDER BY plugin_instance_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pluginIDs := []string{}
	for rows.Next() {
		var pluginInstanceID string
		if err := rows.Scan(&pluginInstanceID); err != nil {
			return nil, err
		}
		pluginIDs = append(pluginIDs, pluginInstanceID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	records := make([]PolicyRecord, 0, len(pluginIDs))
	for _, pluginInstanceID := range pluginIDs {
		record, exists, err := getSQLitePolicy(ctx, s.db, pluginInstanceID)
		if err != nil {
			return nil, err
		}
		if exists {
			records = append(records, record)
		}
	}
	sortPolicyRecords(records)
	return records, nil
}

func (s *SQLitePolicyStore) DeletePolicy(ctx context.Context, pluginInstanceID string) error {
	if s == nil {
		return errors.New("security policy store is nil")
	}
	pluginInstanceID = normalizePolicyID(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidPolicy
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_allowed_permissions WHERE plugin_instance_id = ?`, pluginInstanceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_denied_methods WHERE plugin_instance_id = ?`, pluginInstanceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policies WHERE plugin_instance_id = ?`, pluginInstanceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLitePolicyStore) EvaluatePolicy(ctx context.Context, req EvaluatePolicyRequest) (PolicyEvaluation, error) {
	if s == nil {
		return PolicyEvaluation{}, errors.New("security policy store is nil")
	}
	pluginInstanceID := normalizePolicyID(req.PluginInstanceID)
	method := normalizePolicyID(req.Method)
	if pluginInstanceID == "" || method == "" {
		return PolicyEvaluation{}, ErrInvalidPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists, err := getSQLitePolicy(ctx, s.db, pluginInstanceID)
	if err != nil {
		return PolicyEvaluation{}, err
	}
	if !exists {
		return PolicyEvaluation{Allowed: true}, nil
	}
	return evaluatePolicyRecord(record, method, req.RequiredPermissions), nil
}

func (s *SQLitePolicyStore) migrate(ctx context.Context) error {
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
CREATE TABLE IF NOT EXISTS plugin_security_policy_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_security_policy_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqlitePolicySchemaVersion {
		return fmt.Errorf("sqlite security policy schema version %d is newer than supported version %d", maxVersion, sqlitePolicySchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_security_policies (
	plugin_instance_id TEXT PRIMARY KEY,
	updated_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_security_policy_allowed_permissions (
	plugin_instance_id TEXT NOT NULL,
	permission_id TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY(plugin_instance_id, permission_id),
	FOREIGN KEY(plugin_instance_id) REFERENCES plugin_security_policies(plugin_instance_id) ON DELETE CASCADE
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_security_policy_denied_methods (
	plugin_instance_id TEXT NOT NULL,
	method TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY(plugin_instance_id, method),
	FOREIGN KEY(plugin_instance_id) REFERENCES plugin_security_policies(plugin_instance_id) ON DELETE CASCADE
)`); err != nil {
		return err
	}
	if maxVersion < sqlitePolicySchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_security_policy_schema_migrations(version, applied_at) VALUES(?, ?)`, sqlitePolicySchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func upsertSQLitePolicy(ctx context.Context, tx *sql.Tx, record PolicyRecord) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_security_policies(plugin_instance_id, updated_at)
VALUES(?, ?)
ON CONFLICT(plugin_instance_id) DO UPDATE SET updated_at = excluded.updated_at`,
		record.PluginInstanceID,
		record.UpdatedAt.UTC().UnixNano(),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_allowed_permissions WHERE plugin_instance_id = ?`, record.PluginInstanceID); err != nil {
		return err
	}
	for _, permissionID := range record.AllowedPermissions {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_security_policy_allowed_permissions(plugin_instance_id, permission_id, updated_at)
VALUES(?, ?, ?)`,
			record.PluginInstanceID,
			permissionID,
			record.UpdatedAt.UTC().UnixNano(),
		); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_denied_methods WHERE plugin_instance_id = ?`, record.PluginInstanceID); err != nil {
		return err
	}
	for _, method := range record.DeniedMethods {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_security_policy_denied_methods(plugin_instance_id, method, updated_at)
VALUES(?, ?, ?)`,
			record.PluginInstanceID,
			method,
			record.UpdatedAt.UTC().UnixNano(),
		); err != nil {
			return err
		}
	}
	return nil
}

func getSQLitePolicy(ctx context.Context, q sqlitePolicyQuerier, pluginInstanceID string) (PolicyRecord, bool, error) {
	var updatedAt int64
	if err := q.QueryRowContext(ctx, `SELECT updated_at FROM plugin_security_policies WHERE plugin_instance_id = ?`, pluginInstanceID).Scan(&updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PolicyRecord{}, false, nil
		}
		return PolicyRecord{}, false, err
	}
	allowedPermissions, err := listSQLitePolicyValues(ctx, q, `SELECT permission_id FROM plugin_security_policy_allowed_permissions WHERE plugin_instance_id = ? ORDER BY permission_id ASC`, pluginInstanceID)
	if err != nil {
		return PolicyRecord{}, false, err
	}
	deniedMethods, err := listSQLitePolicyValues(ctx, q, `SELECT method FROM plugin_security_policy_denied_methods WHERE plugin_instance_id = ? ORDER BY method ASC`, pluginInstanceID)
	if err != nil {
		return PolicyRecord{}, false, err
	}
	return PolicyRecord{
		PluginInstanceID:   pluginInstanceID,
		AllowedPermissions: allowedPermissions,
		DeniedMethods:      deniedMethods,
		UpdatedAt:          time.Unix(0, updatedAt).UTC(),
	}, true, nil
}

func listSQLitePolicyValues(ctx context.Context, q sqlitePolicyQuerier, query string, pluginInstanceID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return normalizePolicyStringSet(values), nil
}

type sqlitePolicyQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ PolicyStore = (*SQLitePolicyStore)(nil)
