package operation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/capability"
	_ "modernc.org/sqlite"
)

const maxOperationSQLiteConnections = 8

type SQLiteStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite operation store path is required")
	}
	dsn, err := operationSQLiteDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxOperationSQLiteConnections)
	db.SetMaxIdleConns(maxOperationSQLiteConnections)
	store := &SQLiteStore{db: db}
	if err := store.initializeSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func operationSQLiteDSN(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath), RawQuery: query.Encode()}).String(), nil
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
	pluginInstanceID := strings.TrimSpace(req.ExecutionBinding.PluginInstanceID)
	method := strings.TrimSpace(req.ExecutionBinding.Method)
	owner := ownerScopeForBinding(req.ExecutionBinding).Normalized()
	if operationID == "" || pluginInstanceID == "" || method == "" || !owner.Valid() {
		return Record{}, ErrInvalidOperation
	}
	if req.CancelAckTimeoutMS < 0 || !registerCancelable(req.Cancelable) && req.CancelAckTimeoutMS != 0 {
		return Record{}, ErrInvalidOperation
	}
	binding, err := cloneExecutionBinding(req.ExecutionBinding)
	if err != nil {
		return Record{}, ErrInvalidOperation
	}
	if embeddedID := strings.TrimSpace(binding.OperationID); embeddedID != "" && embeddedID != operationID {
		return Record{}, ErrInvalidOperation
	}
	binding.OperationID = operationID
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	_, exists, err := getSQLiteOperation(ctx, tx, operationID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return Record{}, ErrAlreadyExists
	}
	record := Record{
		OperationID:        operationID,
		ExecutionBinding:   binding,
		Status:             StatusRunning,
		Cancelable:         registerCancelable(req.Cancelable),
		CancelAckTimeoutMS: req.CancelAckTimeoutMS,
		DisableBehavior:    normalizeDisableBehavior(req.DisableBehavior),
		UninstallBehavior:  normalizeUninstallBehavior(req.UninstallBehavior),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	record.OwnerSessionHash = owner.OwnerSessionHash
	record.OwnerUserHash = owner.OwnerUserHash
	record.OwnerEnvHash = owner.OwnerEnvHash
	record.SessionChannelIDHash = owner.SessionChannelIDHash
	if err := upsertSQLiteOperation(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) (Page, error) {
	if s == nil {
		return Page{}, errors.New("operation store is nil")
	}
	limit, err := normalizeListRequest(&req)
	if err != nil {
		return Page{}, err
	}
	query := operationSelectColumns + ` FROM plugin_operations`
	args := []any{}
	conditions := []string{}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID != "" {
		conditions = append(conditions, `plugin_instance_id = ?`)
		args = append(args, pluginInstanceID)
	}
	if !req.AllOwners {
		conditions = append(conditions, `owner_session_hash = ?`, `owner_user_hash = ?`, `owner_env_hash = ?`, `session_channel_id_hash = ?`)
		args = append(args, req.Owner.OwnerSessionHash, req.Owner.OwnerUserHash, req.Owner.OwnerEnvHash, req.Owner.SessionChannelIDHash)
	}
	if req.Cursor != nil {
		conditions = append(conditions, `(created_at < ? OR (created_at = ? AND operation_id < ?))`)
		createdAt := req.Cursor.CreatedAt.UTC().UnixNano()
		args = append(args, createdAt, createdAt, req.Cursor.OperationID)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY created_at DESC, operation_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()

	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteOperation(rows)
		if err != nil {
			return Page{}, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	return pageRecords(records, limit), nil
}

func (s *SQLiteStore) Get(ctx context.Context, operationID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
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
	return s.update(ctx, strings.TrimSpace(req.OperationID), req.Now, func(record Record, now time.Time) (Record, error) {
		if !terminal(record.Status) && !record.Cancelable {
			return Record{}, ErrNotCancelable
		}
		return requestCancel(record, now, req.Reason), nil
	})
}

func (s *SQLiteStore) Finish(ctx context.Context, req FinishRequest) (Record, error) {
	if !finishStatus(req.Status) {
		return Record{}, ErrInvalidOperation
	}
	failureCode, reason, err := normalizeFinishOutcome(req.Status, req.FailureCode, req.Reason)
	if err != nil {
		return Record{}, err
	}
	return s.update(ctx, strings.TrimSpace(req.OperationID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminal(record.Status) {
			return record, nil
		}
		record.Status = req.Status
		record.FailureCode = failureCode
		record.Reason = reason
		record.UpdatedAt = now
		record.TerminalAt = &now
		return record, nil
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

func (s *SQLiteStore) Prune(ctx context.Context, req PruneRequest) (PruneResult, error) {
	if s == nil {
		return PruneResult{}, errors.New("operation store is nil")
	}
	before, limit, maxRecordsPerPlugin, err := normalizePruneRequest(req)
	if err != nil {
		return PruneResult{}, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `
WITH ranked_terminal AS (
	SELECT
		operation_id,
		terminal_at,
		ROW_NUMBER() OVER (
			PARTITION BY owner_env_hash, plugin_instance_id
			ORDER BY terminal_at DESC, operation_id DESC
		) AS terminal_rank
	FROM plugin_operations
	WHERE terminal_at IS NOT NULL AND status IN (?, ?, ?, ?, ?)
)
DELETE FROM plugin_operations
WHERE operation_id IN (
	SELECT operation_id
	FROM ranked_terminal
	WHERE terminal_at < ? OR terminal_rank > ?
	ORDER BY terminal_at ASC, operation_id ASC
	LIMIT ?
)`,
		string(StatusCanceled),
		string(StatusCompleted),
		string(StatusFailed),
		string(StatusOrphanedAfterDisable),
		string(StatusOrphanedAfterUninstall),
		before.UnixNano(),
		maxRecordsPerPlugin,
		limit,
	)
	if err != nil {
		return PruneResult{}, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return PruneResult{}, err
	}
	return PruneResult{Deleted: int(deleted)}, nil
}

func (s *SQLiteStore) update(ctx context.Context, operationID string, now time.Time, mutate func(Record, time.Time) (Record, error)) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

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
	record, err = mutate(record, now)
	if err != nil {
		return Record{}, err
	}
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
	pluginInstanceID, ownerEnvHash, err := normalizePluginTransition(req)
	if err != nil {
		return nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)

	records, err := listSQLiteOperations(ctx, tx, ownerEnvHash, pluginInstanceID)
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

func (s *SQLiteStore) initializeSchema(ctx context.Context) error {
	var journalMode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return errors.New("sqlite operation store requires WAL journal mode")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_operations (
	operation_id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	method TEXT NOT NULL,
	effect TEXT NOT NULL,
	execution TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	bridge_channel_id TEXT NOT NULL,
	execution_binding_json TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL,
	cancelable INTEGER NOT NULL DEFAULT 1,
	cancel_ack_timeout_ms INTEGER NOT NULL DEFAULT 0,
	disable_behavior TEXT NOT NULL,
		uninstall_behavior TEXT NOT NULL,
		failure_code TEXT NOT NULL,
		reason TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	cancel_requested_at INTEGER,
	orphaned_at INTEGER,
	terminal_at INTEGER
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_plugin_instance ON plugin_operations(plugin_instance_id, created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_owner_plugin_instance ON plugin_operations(owner_env_hash, plugin_instance_id, created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_created ON plugin_operations(created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_owner ON plugin_operations(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_plugin_owner ON plugin_operations(plugin_instance_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_owner_plugin_session ON plugin_operations(owner_env_hash, plugin_instance_id, owner_session_hash, owner_user_hash, session_channel_id_hash, created_at DESC, operation_id DESC)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_terminal_retention ON plugin_operations(plugin_instance_id, terminal_at DESC, operation_id DESC) WHERE terminal_at IS NOT NULL`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_operations_owner_terminal_retention ON plugin_operations(owner_env_hash, plugin_instance_id, terminal_at DESC, operation_id DESC) WHERE terminal_at IS NOT NULL`); err != nil {
		return err
	}
	return tx.Commit()
}

const operationSelectColumns = `
SELECT
	operation_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash,
	bridge_channel_id, execution_binding_json, status,
	cancelable, cancel_ack_timeout_ms, disable_behavior, uninstall_behavior, failure_code, reason, created_at, updated_at,
	cancel_requested_at, orphaned_at, terminal_at`

func listSQLiteOperations(ctx context.Context, q sqliteQuerier, ownerEnvHash, pluginInstanceID string) ([]Record, error) {
	rows, err := q.QueryContext(ctx, operationSelectColumns+` FROM plugin_operations WHERE owner_env_hash = ? AND plugin_instance_id = ? ORDER BY created_at ASC, operation_id ASC`, ownerEnvHash, pluginInstanceID)
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
	bindingJSON, err := json.Marshal(record.ExecutionBinding)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_operations (
	operation_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash,
	bridge_channel_id, execution_binding_json, status,
		cancelable, cancel_ack_timeout_ms, disable_behavior, uninstall_behavior, failure_code, reason, created_at, updated_at,
		cancel_requested_at, orphaned_at, terminal_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(operation_id) DO UPDATE SET
	plugin_id = excluded.plugin_id,
	plugin_instance_id = excluded.plugin_instance_id,
	method = excluded.method,
	effect = excluded.effect,
	execution = excluded.execution,
	surface_instance_id = excluded.surface_instance_id,
	owner_session_hash = excluded.owner_session_hash,
	owner_user_hash = excluded.owner_user_hash,
	owner_env_hash = excluded.owner_env_hash,
	session_channel_id_hash = excluded.session_channel_id_hash,
	bridge_channel_id = excluded.bridge_channel_id,
	execution_binding_json = excluded.execution_binding_json,
	status = excluded.status,
	cancelable = excluded.cancelable,
	cancel_ack_timeout_ms = excluded.cancel_ack_timeout_ms,
	disable_behavior = excluded.disable_behavior,
		uninstall_behavior = excluded.uninstall_behavior,
		failure_code = excluded.failure_code,
		reason = excluded.reason,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at,
	cancel_requested_at = excluded.cancel_requested_at,
	orphaned_at = excluded.orphaned_at,
	terminal_at = excluded.terminal_at`,
		record.OperationID,
		record.PluginID,
		record.PluginInstanceID,
		record.Method,
		record.Effect,
		record.Execution,
		record.SurfaceInstanceID,
		record.OwnerSessionHash,
		record.OwnerUserHash,
		record.OwnerEnvHash,
		record.SessionChannelIDHash,
		record.BridgeChannelID,
		string(bindingJSON),
		string(record.Status),
		record.Cancelable,
		record.CancelAckTimeoutMS,
		record.DisableBehavior,
		record.UninstallBehavior,
		string(record.FailureCode),
		record.Reason,
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.CancelRequestedAt),
		timePtrToNullableUnix(record.OrphanedAt),
		timePtrToNullableUnix(record.TerminalAt),
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
	var bindingJSON string
	var cancelable int
	var createdAt int64
	var updatedAt int64
	var cancelRequestedAt sql.NullInt64
	var orphanedAt sql.NullInt64
	var terminalAt sql.NullInt64
	if err := scanner.Scan(
		&record.OperationID,
		&record.PluginID,
		&record.PluginInstanceID,
		&record.Method,
		&record.Effect,
		&record.Execution,
		&record.SurfaceInstanceID,
		&record.OwnerSessionHash,
		&record.OwnerUserHash,
		&record.OwnerEnvHash,
		&record.SessionChannelIDHash,
		&record.BridgeChannelID,
		&bindingJSON,
		&status,
		&cancelable,
		&record.CancelAckTimeoutMS,
		&record.DisableBehavior,
		&record.UninstallBehavior,
		&record.FailureCode,
		&record.Reason,
		&createdAt,
		&updatedAt,
		&cancelRequestedAt,
		&orphanedAt,
		&terminalAt,
	); err != nil {
		return Record{}, err
	}
	indexedOperationID := record.OperationID
	indexedPluginID := record.PluginID
	indexedPluginInstanceID := record.PluginInstanceID
	indexedMethod := record.Method
	indexedEffect := record.Effect
	indexedExecution := record.Execution
	indexedSurfaceInstanceID := record.SurfaceInstanceID
	indexedOwner := ownerScopeForBinding(record.ExecutionBinding)
	indexedBridgeChannelID := record.BridgeChannelID
	if strings.TrimSpace(bindingJSON) == "" || strings.TrimSpace(bindingJSON) == "{}" {
		return Record{}, ErrInvalidOperation
	}
	var decodedBinding capability.ExecutionBinding
	if err := jsonvalue.DecodeClosed([]byte(bindingJSON), &decodedBinding); err != nil {
		return Record{}, ErrInvalidOperation
	}
	binding, err := cloneExecutionBinding(decodedBinding)
	if err != nil {
		return Record{}, ErrInvalidOperation
	}
	record.ExecutionBinding = binding
	if record.ExecutionBinding.OperationID != indexedOperationID || record.PluginID != indexedPluginID || record.PluginInstanceID != indexedPluginInstanceID ||
		record.Method != indexedMethod || record.Effect != indexedEffect || record.Execution != indexedExecution ||
		record.SurfaceInstanceID != indexedSurfaceInstanceID || record.BridgeChannelID != indexedBridgeChannelID ||
		ownerScopeForBinding(record.ExecutionBinding) != indexedOwner {
		return Record{}, ErrInvalidOperation
	}
	record.Status = Status(status)
	record.Cancelable = cancelable != 0
	record.CreatedAt = unixToTime(createdAt)
	record.UpdatedAt = unixToTime(updatedAt)
	record.CancelRequestedAt = nullableUnixToTimePtr(cancelRequestedAt)
	record.OrphanedAt = nullableUnixToTimePtr(orphanedAt)
	record.TerminalAt = nullableUnixToTimePtr(terminalAt)
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
