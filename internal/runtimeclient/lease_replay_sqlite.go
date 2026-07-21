package runtimeclient

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteRuntimeLeaseReplayStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteRuntimeLeaseReplayStore(ctx context.Context, path string) (*SQLiteRuntimeLeaseReplayStore, error) {
	if path == "" {
		return nil, errors.New("sqlite runtime lease replay path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteRuntimeLeaseReplayStore{db: db}
	if err := store.initializeSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteRuntimeLeaseReplayStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteRuntimeLeaseReplayStore) ConsumeRuntimeLease(ctx context.Context, req RuntimeLeaseReplayConsumeRequest) (RuntimeLeaseReplayRecord, error) {
	if s == nil {
		return RuntimeLeaseReplayRecord{}, errors.New("runtime lease replay store is nil")
	}
	record, err := runtimeLeaseReplayRecordFromConsume(req)
	if err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	if err := deleteSQLiteExpiredRuntimeLeaseReplays(ctx, tx, record.ConsumedAt); err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	exists, err := sqliteRuntimeLeaseReplayExists(ctx, tx, record.LeaseNonceHash)
	if err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	if exists {
		return RuntimeLeaseReplayRecord{}, ErrRuntimeLeaseReplay
	}
	if err := insertSQLiteRuntimeLeaseReplay(ctx, tx, record); err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	return record, nil
}

func (s *SQLiteRuntimeLeaseReplayStore) ListRuntimeLeaseReplays(ctx context.Context, req RuntimeLeaseReplayListRequest) ([]RuntimeLeaseReplayRecord, error) {
	if s == nil {
		return nil, errors.New("runtime lease replay store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := deleteSQLiteExpiredRuntimeLeaseReplays(ctx, s.db, time.Now().UTC()); err != nil {
		return nil, err
	}

	query := `SELECT ` + runtimeLeaseReplaySelectColumns + ` FROM plugin_runtime_lease_replays`
	args := []any{}
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id = ?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY consumed_at ASC, lease_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []RuntimeLeaseReplayRecord{}
	for rows.Next() {
		record, err := scanSQLiteRuntimeLeaseReplay(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRuntimeLeaseReplayRecords(records)
	return records, nil
}

func (s *SQLiteRuntimeLeaseReplayStore) initializeSchema(ctx context.Context) error {
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
CREATE TABLE IF NOT EXISTS plugin_runtime_lease_replays (
	lease_nonce_hash TEXT PRIMARY KEY,
	lease_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	runtime_generation_id TEXT NOT NULL,
	method TEXT NOT NULL,
	policy_revision INTEGER NOT NULL,
	management_revision INTEGER NOT NULL,
	revoke_epoch INTEGER NOT NULL,
	consumed_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_runtime_lease_replays_plugin ON plugin_runtime_lease_replays(plugin_instance_id, consumed_at)`); err != nil {
		return err
	}
	return tx.Commit()
}

const runtimeLeaseReplaySelectColumns = `lease_id, lease_nonce_hash, plugin_instance_id, runtime_generation_id, method, policy_revision, management_revision, revoke_epoch, consumed_at, expires_at`

func sqliteRuntimeLeaseReplayExists(ctx context.Context, q sqlQuerier, leaseNonceHash string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(1) FROM plugin_runtime_lease_replays WHERE lease_nonce_hash = ?`, leaseNonceHash).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func insertSQLiteRuntimeLeaseReplay(ctx context.Context, q sqlExecer, record RuntimeLeaseReplayRecord) error {
	_, err := q.ExecContext(ctx, `
INSERT INTO plugin_runtime_lease_replays (
	lease_nonce_hash,
	lease_id,
	plugin_instance_id,
	runtime_generation_id,
	method,
	policy_revision,
	management_revision,
	revoke_epoch,
	consumed_at,
	expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.LeaseNonceHash,
		record.LeaseID,
		record.PluginInstanceID,
		record.RuntimeGenerationID,
		record.Method,
		record.PolicyRevision,
		record.ManagementRevision,
		record.RevokeEpoch,
		record.ConsumedAt.UnixNano(),
		record.ExpiresAt.UnixNano(),
	)
	return err
}

func deleteSQLiteExpiredRuntimeLeaseReplays(ctx context.Context, q sqlExecer, now time.Time) error {
	_, err := q.ExecContext(ctx, `DELETE FROM plugin_runtime_lease_replays WHERE expires_at <= ?`, now.UTC().UnixNano())
	return err
}

func scanSQLiteRuntimeLeaseReplay(scanner interface {
	Scan(dest ...any) error
}) (RuntimeLeaseReplayRecord, error) {
	var record RuntimeLeaseReplayRecord
	var consumedAt int64
	var expiresAt int64
	if err := scanner.Scan(
		&record.LeaseID,
		&record.LeaseNonceHash,
		&record.PluginInstanceID,
		&record.RuntimeGenerationID,
		&record.Method,
		&record.PolicyRevision,
		&record.ManagementRevision,
		&record.RevokeEpoch,
		&consumedAt,
		&expiresAt,
	); err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	record.ConsumedAt = time.Unix(0, consumedAt).UTC()
	record.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return record, nil
}

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type sqlQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}
