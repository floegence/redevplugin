package operation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
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
		return nil, errors.New("sqlite operation store path is required")
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

func (s *SQLiteStore) Register(ctx context.Context, req RegisterRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	operationID := strings.TrimSpace(req.OperationID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	method := strings.TrimSpace(req.Method)
	if operationID == "" || pluginInstanceID == "" || method == "" {
		return Record{}, ErrInvalidOperation
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

	existing, exists, err := getSQLiteOperation(ctx, tx, operationID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return existing, nil
	}
	record := Record{
		OperationID:          operationID,
		PluginID:             strings.TrimSpace(req.PluginID),
		PluginInstanceID:     pluginInstanceID,
		Method:               method,
		Effect:               strings.TrimSpace(req.Effect),
		Execution:            strings.TrimSpace(req.Execution),
		SurfaceInstanceID:    strings.TrimSpace(req.SurfaceInstanceID),
		SessionChannelIDHash: strings.TrimSpace(req.SessionChannelIDHash),
		BridgeChannelID:      strings.TrimSpace(req.BridgeChannelID),
		Status:               StatusRunning,
		DisableBehavior:      normalizeDisableBehavior(req.DisableBehavior),
		UninstallBehavior:    normalizeUninstallBehavior(req.UninstallBehavior),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := upsertSQLiteOperation(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	query := operationSelectColumns + ` FROM plugin_operations`
	args := []any{}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id = ?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY created_at ASC, operation_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteOperation(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortOperations(records)
	return records, nil
}

func (s *SQLiteStore) Get(ctx context.Context, operationID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteOperation(ctx, s.db, strings.TrimSpace(operationID))
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) RequestCancel(ctx context.Context, req CancelRequest) (Record, error) {
	return s.update(ctx, strings.TrimSpace(req.OperationID), req.Now, func(record Record, now time.Time) Record {
		return requestCancel(record, now, req.Reason)
	})
}

func (s *SQLiteStore) Finish(ctx context.Context, req FinishRequest) (Record, error) {
	if !finishStatus(req.Status) {
		return Record{}, ErrInvalidOperation
	}
	return s.update(ctx, strings.TrimSpace(req.OperationID), req.Now, func(record Record, now time.Time) Record {
		if terminal(record.Status) {
			return record
		}
		record.Status = req.Status
		record.Reason = req.Reason
		record.UpdatedAt = now
		return record
	})
}

func (s *SQLiteStore) MarkPluginDisabled(ctx context.Context, req PluginTransitionRequest) ([]Record, error) {
	return s.transitionPluginOperations(ctx, req, func(record Record, now time.Time) (Record, bool) {
		if terminal(record.Status) {
			return record, false
		}
		switch record.DisableBehavior {
		case DisableBehaviorWait:
			return record, false
		case DisableBehaviorOrphan:
			return markOrphaned(record, StatusOrphanedAfterDisable, now, req.Reason), true
		default:
			return requestCancel(record, now, req.Reason), true
		}
	})
}

func (s *SQLiteStore) MarkPluginUninstalled(ctx context.Context, req PluginTransitionRequest) ([]Record, error) {
	return s.transitionPluginOperations(ctx, req, func(record Record, now time.Time) (Record, bool) {
		if terminal(record.Status) {
			return record, false
		}
		if record.UninstallBehavior == UninstallBehaviorForceCleanupAllowed {
			return markOrphaned(record, StatusOrphanedAfterUninstall, now, req.Reason), true
		}
		return requestCancel(record, now, req.Reason), true
	})
}

func (s *SQLiteStore) update(ctx context.Context, operationID string, now time.Time, mutate func(Record, time.Time) Record) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
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

	record, exists, err := getSQLiteOperation(ctx, tx, operationID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	record = mutate(record, now)
	if err := upsertSQLiteOperation(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) transitionPluginOperations(ctx context.Context, req PluginTransitionRequest, mutate func(Record, time.Time) (Record, bool)) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return nil, ErrInvalidOperation
	}
	now := req.Now
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

	records, err := listSQLiteOperations(ctx, tx, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	changed := []Record{}
	for _, record := range records {
		next, ok := mutate(record, now)
		if !ok {
			continue
		}
		if err := upsertSQLiteOperation(ctx, tx, next); err != nil {
			return nil, err
		}
		changed = append(changed, next)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	sortOperations(changed)
	return changed, nil
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
CREATE TABLE IF NOT EXISTS plugin_operation_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_operation_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite operation schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_operations (
	operation_id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	method TEXT NOT NULL,
	effect TEXT NOT NULL,
	execution TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	bridge_channel_id TEXT NOT NULL,
	status TEXT NOT NULL,
	disable_behavior TEXT NOT NULL,
	uninstall_behavior TEXT NOT NULL,
	reason TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	cancel_requested_at INTEGER,
	orphaned_at INTEGER
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_plugin_instance ON plugin_operations(plugin_instance_id, created_at, operation_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_status ON plugin_operations(status)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_operation_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const operationSelectColumns = `
SELECT
	operation_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, session_channel_id_hash, bridge_channel_id, status,
	disable_behavior, uninstall_behavior, reason, created_at, updated_at,
	cancel_requested_at, orphaned_at`

func listSQLiteOperations(ctx context.Context, q sqliteQuerier, pluginInstanceID string) ([]Record, error) {
	rows, err := q.QueryContext(ctx, operationSelectColumns+` FROM plugin_operations WHERE plugin_instance_id = ? ORDER BY created_at ASC, operation_id ASC`, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteOperation(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortOperations(records)
	return records, nil
}

func getSQLiteOperation(ctx context.Context, q sqliteQuerier, operationID string) (Record, bool, error) {
	row := q.QueryRowContext(ctx, operationSelectColumns+` FROM plugin_operations WHERE operation_id = ?`, operationID)
	record, err := scanSQLiteOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func upsertSQLiteOperation(ctx context.Context, tx *sql.Tx, record Record) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_operations (
	operation_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, session_channel_id_hash, bridge_channel_id, status,
	disable_behavior, uninstall_behavior, reason, created_at, updated_at,
	cancel_requested_at, orphaned_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(operation_id) DO UPDATE SET
	plugin_id = excluded.plugin_id,
	plugin_instance_id = excluded.plugin_instance_id,
	method = excluded.method,
	effect = excluded.effect,
	execution = excluded.execution,
	surface_instance_id = excluded.surface_instance_id,
	session_channel_id_hash = excluded.session_channel_id_hash,
	bridge_channel_id = excluded.bridge_channel_id,
	status = excluded.status,
	disable_behavior = excluded.disable_behavior,
	uninstall_behavior = excluded.uninstall_behavior,
	reason = excluded.reason,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at,
	cancel_requested_at = excluded.cancel_requested_at,
	orphaned_at = excluded.orphaned_at`,
		record.OperationID,
		record.PluginID,
		record.PluginInstanceID,
		record.Method,
		record.Effect,
		record.Execution,
		record.SurfaceInstanceID,
		record.SessionChannelIDHash,
		record.BridgeChannelID,
		string(record.Status),
		record.DisableBehavior,
		record.UninstallBehavior,
		record.Reason,
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.CancelRequestedAt),
		timePtrToNullableUnix(record.OrphanedAt),
	)
	return err
}

type sqliteQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteOperationScanner interface {
	Scan(...any) error
}

func scanSQLiteOperation(scanner sqliteOperationScanner) (Record, error) {
	var record Record
	var status string
	var createdAt int64
	var updatedAt int64
	var cancelRequestedAt sql.NullInt64
	var orphanedAt sql.NullInt64
	if err := scanner.Scan(
		&record.OperationID,
		&record.PluginID,
		&record.PluginInstanceID,
		&record.Method,
		&record.Effect,
		&record.Execution,
		&record.SurfaceInstanceID,
		&record.SessionChannelIDHash,
		&record.BridgeChannelID,
		&status,
		&record.DisableBehavior,
		&record.UninstallBehavior,
		&record.Reason,
		&createdAt,
		&updatedAt,
		&cancelRequestedAt,
		&orphanedAt,
	); err != nil {
		return Record{}, err
	}
	record.Status = Status(status)
	record.CreatedAt = unixToTime(createdAt)
	record.UpdatedAt = unixToTime(updatedAt)
	record.CancelRequestedAt = nullableUnixToTimePtr(cancelRequestedAt)
	record.OrphanedAt = nullableUnixToTimePtr(orphanedAt)
	return record, nil
}

func sortOperations(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].OperationID < records[j].OperationID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
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
