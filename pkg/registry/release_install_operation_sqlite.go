package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func (s *SQLiteStore) StartReleaseInstallOperation(ctx context.Context, req StartReleaseInstallOperationRequest) (ReleaseInstallOperation, bool, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	requestSHA256, err := releaseInstallRequestSHA256(req)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	defer rollbackUnlessCommitted(tx)
	if existing, ok, err := getSQLiteReleaseInstallOperationByRequest(ctx, tx, ownerEnvHash, req.RequestID); err != nil {
		return ReleaseInstallOperation{}, false, err
	} else if ok {
		if existing.RequestSHA256 != requestSHA256 {
			return ReleaseInstallOperation{}, false, ErrReleaseInstallOperationConflict
		}
		return existing, false, nil
	}
	if _, ok, err := getSQLiteReleaseInstallOperation(ctx, tx, ownerEnvHash, req.OperationID); err != nil {
		return ReleaseInstallOperation{}, false, err
	} else if ok {
		return ReleaseInstallOperation{}, false, ErrReleaseInstallOperationConflict
	}
	if active, ok, err := getSQLiteActiveReleaseInstallOperation(ctx, tx, ownerEnvHash, req.PluginInstanceID); err != nil {
		return ReleaseInstallOperation{}, false, err
	} else if ok {
		return active, false, nil
	}
	releaseJSON, err := encodeRegistryJSON(req.Release)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	now := normalizedOperationTime(req.Now)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO release_install_operations (
    owner_env_hash, request_id, operation_id, plugin_instance_id, request_sha256, release_identity_json,
    status, phase, progress_kind, progress_completed, progress_total, attempt, retry_after_ms,
    mutation_outcome, failure_code, failure_retryable, plugin_record_json, revision, created_at, updated_at, terminal_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 1, 0, ?, '', 0, 'null', 1, ?, ?, NULL)`,
		ownerEnvHash, req.RequestID, req.OperationID, req.PluginInstanceID, requestSHA256, releaseJSON,
		string(ReleaseInstallQueued), "queued", string(ReleaseInstallProgressIndeterminate), string(mutation.OutcomeNotCommitted),
		now.UnixNano(), now.UnixNano(),
	); err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	op := ReleaseInstallOperation{
		RequestID: req.RequestID, OperationID: req.OperationID, PluginInstanceID: req.PluginInstanceID, RequestSHA256: requestSHA256,
		Status: ReleaseInstallQueued, Phase: "queued", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate},
		Attempt: 1, MutationOutcome: mutation.OutcomeNotCommitted, CreatedAt: now, UpdatedAt: now, Revision: 1, Release: req.Release,
	}
	return op, true, nil
}

func (s *SQLiteStore) UpdateReleaseInstallOperation(ctx context.Context, req UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	defer rollbackUnlessCommitted(tx)
	current, ok, err := getSQLiteReleaseInstallOperation(ctx, tx, ownerEnvHash, req.OperationID)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	updated, err := applyReleaseInstallOperationUpdate(current, req)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	failureCode, failureRetryable := "", 0
	if updated.Failure != nil {
		failureCode = updated.Failure.Code
		if updated.Failure.Retryable {
			failureRetryable = 1
		}
	}
	pluginRecordJSON := "null"
	if updated.PluginRecord != nil {
		pluginRecordJSON, err = encodeRegistryJSON(updated.PluginRecord)
		if err != nil {
			return ReleaseInstallOperation{}, err
		}
	}
	var terminalAt any
	if updated.TerminalAt != nil {
		terminalAt = updated.TerminalAt.UnixNano()
	}
	result, err := tx.ExecContext(ctx, `
UPDATE release_install_operations
SET status = ?, phase = ?, progress_kind = ?, progress_completed = ?, progress_total = ?, attempt = ?,
    retry_after_ms = ?, mutation_outcome = ?, failure_code = ?, failure_retryable = ?, plugin_record_json = ?,
    revision = ?, updated_at = ?, terminal_at = ?
WHERE owner_env_hash = ? AND operation_id = ? AND revision = ?`,
		string(updated.Status), updated.Phase, string(updated.Progress.Kind), updated.Progress.Completed, updated.Progress.Total, updated.Attempt,
		updated.RetryAfterMS, string(updated.MutationOutcome), failureCode, failureRetryable, pluginRecordJSON, updated.Revision,
		updated.UpdatedAt.UnixNano(), terminalAt, ownerEnvHash, req.OperationID, req.ExpectedRevision,
	)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	if affected != 1 {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationConflict
	}
	if err := tx.Commit(); err != nil {
		return ReleaseInstallOperation{}, err
	}
	return updated, nil
}

func (s *SQLiteStore) GetReleaseInstallOperation(ctx context.Context, operationID string) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok, err := getSQLiteReleaseInstallOperation(ctx, s.db, ownerEnvHash, operationID)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	return op, nil
}

func (s *SQLiteStore) GetReleaseInstallOperationByRequest(ctx context.Context, requestID string) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok, err := getSQLiteReleaseInstallOperationByRequest(ctx, s.db, ownerEnvHash, requestID)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	return op, nil
}

func (s *SQLiteStore) ListReleaseInstallOperations(ctx context.Context) ([]ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, releaseInstallOperationSelect+` WHERE owner_env_hash = ? ORDER BY created_at, operation_id`, ownerEnvHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ReleaseInstallOperation
	for rows.Next() {
		op, err := scanSQLiteReleaseInstallOperation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

const releaseInstallOperationSelect = `SELECT request_id, operation_id, plugin_instance_id, request_sha256, release_identity_json, status, phase,
       progress_kind, progress_completed, progress_total, attempt, retry_after_ms, mutation_outcome,
       failure_code, failure_retryable, plugin_record_json, revision, created_at, updated_at, terminal_at
FROM release_install_operations`

func getSQLiteReleaseInstallOperation(ctx context.Context, q sqliteQuerier, ownerEnvHash, operationID string) (ReleaseInstallOperation, bool, error) {
	if strings.TrimSpace(operationID) == "" {
		return ReleaseInstallOperation{}, false, ErrInvalidReleaseInstallOperation
	}
	return scanSQLiteReleaseInstallOperationRow(q.QueryRowContext(ctx, releaseInstallOperationSelect+` WHERE owner_env_hash = ? AND operation_id = ?`, ownerEnvHash, operationID))
}

func getSQLiteReleaseInstallOperationByRequest(ctx context.Context, q sqliteQuerier, ownerEnvHash, requestID string) (ReleaseInstallOperation, bool, error) {
	if strings.TrimSpace(requestID) == "" {
		return ReleaseInstallOperation{}, false, ErrInvalidReleaseInstallOperation
	}
	return scanSQLiteReleaseInstallOperationRow(q.QueryRowContext(ctx, releaseInstallOperationSelect+` WHERE owner_env_hash = ? AND request_id = ?`, ownerEnvHash, requestID))
}

func getSQLiteActiveReleaseInstallOperation(ctx context.Context, q sqliteQuerier, ownerEnvHash, pluginInstanceID string) (ReleaseInstallOperation, bool, error) {
	return scanSQLiteReleaseInstallOperationRow(q.QueryRowContext(ctx, releaseInstallOperationSelect+`
WHERE owner_env_hash = ? AND plugin_instance_id = ? AND status IN (?, ?, ?)
ORDER BY created_at LIMIT 1`, ownerEnvHash, pluginInstanceID, string(ReleaseInstallQueued), string(ReleaseInstallRunning), string(ReleaseInstallReconciling)))
}

type releaseInstallOperationScanner interface{ Scan(...any) error }

func scanSQLiteReleaseInstallOperationRow(row releaseInstallOperationScanner) (ReleaseInstallOperation, bool, error) {
	op, err := scanSQLiteReleaseInstallOperation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleaseInstallOperation{}, false, nil
	}
	return op, err == nil, err
}

func scanSQLiteReleaseInstallOperation(scanner releaseInstallOperationScanner) (ReleaseInstallOperation, error) {
	var op ReleaseInstallOperation
	var releaseIdentityJSON, status, progressKind, outcome, failureCode, pluginRecordJSON string
	var failureRetryable int
	var createdAt, updatedAt int64
	var terminalAt sql.NullInt64
	if err := scanner.Scan(&op.RequestID, &op.OperationID, &op.PluginInstanceID, &op.RequestSHA256, &releaseIdentityJSON, &status, &op.Phase,
		&progressKind, &op.Progress.Completed, &op.Progress.Total, &op.Attempt, &op.RetryAfterMS, &outcome,
		&failureCode, &failureRetryable, &pluginRecordJSON, &op.Revision, &createdAt, &updatedAt, &terminalAt); err != nil {
		return ReleaseInstallOperation{}, err
	}
	op.Status, op.Progress.Kind, op.MutationOutcome = ReleaseInstallOperationStatus(status), ReleaseInstallProgressKind(progressKind), mutation.Outcome(outcome)
	if err := decodeRegistryJSON(releaseIdentityJSON, &op.Release); err != nil {
		return ReleaseInstallOperation{}, err
	}
	op.CreatedAt, op.UpdatedAt = unixToTime(createdAt), unixToTime(updatedAt)
	if terminalAt.Valid {
		value := unixToTime(terminalAt.Int64)
		op.TerminalAt = &value
	}
	if failureCode != "" {
		op.Failure = &ReleaseInstallFailure{Code: failureCode, Retryable: failureRetryable == 1}
	}
	if pluginRecordJSON != "null" {
		var record PluginRecord
		if err := decodeRegistryJSON(pluginRecordJSON, &record); err != nil {
			return ReleaseInstallOperation{}, err
		}
		op.PluginRecord = &record
	}
	if err := validatePersistedReleaseInstallOperation(op); err != nil {
		return ReleaseInstallOperation{}, err
	}
	return op, nil
}

func createReleaseInstallOperationSchema(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS release_install_operations (
    owner_env_hash TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    plugin_instance_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    release_identity_json TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    progress_kind TEXT NOT NULL,
    progress_completed INTEGER NOT NULL,
    progress_total INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    retry_after_ms INTEGER NOT NULL,
    mutation_outcome TEXT NOT NULL,
    failure_code TEXT NOT NULL,
    failure_retryable INTEGER NOT NULL,
    plugin_record_json TEXT NOT NULL DEFAULT 'null',
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    terminal_at INTEGER,
    PRIMARY KEY(owner_env_hash, request_id),
    UNIQUE(owner_env_hash, operation_id)
)`)
	return err
}

func validateReleaseInstallOperationSchema(ctx context.Context, tx *sql.Tx) error {
	expected := map[string]registrySQLiteColumnSpec{
		"owner_env_hash": sqliteColumn("TEXT", 1, 1), "request_id": sqliteColumn("TEXT", 1, 2),
		"operation_id": sqliteColumn("TEXT", 1, 0), "plugin_instance_id": sqliteColumn("TEXT", 1, 0),
		"request_sha256": sqliteColumn("TEXT", 1, 0), "release_identity_json": sqliteColumn("TEXT", 1, 0),
		"status": sqliteColumn("TEXT", 1, 0), "phase": sqliteColumn("TEXT", 1, 0), "progress_kind": sqliteColumn("TEXT", 1, 0),
		"progress_completed": sqliteColumn("INTEGER", 1, 0), "progress_total": sqliteColumn("INTEGER", 1, 0),
		"attempt": sqliteColumn("INTEGER", 1, 0), "retry_after_ms": sqliteColumn("INTEGER", 1, 0),
		"mutation_outcome": sqliteColumn("TEXT", 1, 0), "failure_code": sqliteColumn("TEXT", 1, 0),
		"failure_retryable": sqliteColumn("INTEGER", 1, 0), "plugin_record_json": sqliteColumnDefault("TEXT", 1, 0, "'null'"),
		"revision": sqliteColumn("INTEGER", 1, 0), "created_at": sqliteColumn("INTEGER", 1, 0),
		"updated_at": sqliteColumn("INTEGER", 1, 0), "terminal_at": sqliteColumn("INTEGER", 0, 0),
	}
	return validateRegistrySQLiteTableColumns(ctx, tx, "release_install_operations", expected)
}

func reconcileInterruptedReleaseInstallOperations(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().UTC().UnixNano()
	_, err := tx.ExecContext(ctx, `
UPDATE release_install_operations
SET status = ?, phase = ?, progress_kind = ?, progress_completed = 0, progress_total = 0,
    retry_after_ms = 0, mutation_outcome = ?, failure_code = '', failure_retryable = 0,
    plugin_record_json = 'null', revision = revision + 1, updated_at = ?, terminal_at = NULL
WHERE status IN (?, ?)`,
		string(ReleaseInstallReconciling), "reconciling", string(ReleaseInstallProgressIndeterminate), string(mutation.OutcomeUnknown), now,
		string(ReleaseInstallQueued), string(ReleaseInstallRunning),
	)
	return err
}

func validatePersistedReleaseInstallOperation(op ReleaseInstallOperation) error {
	if op.RequestID == "" || op.OperationID == "" || op.PluginInstanceID == "" || op.RequestSHA256 == "" || op.Revision == 0 || op.Attempt < 1 {
		return fmt.Errorf("%w: persisted operation identity is incomplete", ErrInvalidReleaseInstallOperation)
	}
	if err := validateReleaseInstallProgress(op.Progress); err != nil {
		return err
	}
	wantSHA256, err := releaseInstallRequestSHA256(StartReleaseInstallOperationRequest{
		RequestID: op.RequestID, OperationID: op.OperationID, PluginInstanceID: op.PluginInstanceID, Release: op.Release,
	})
	if err != nil || wantSHA256 != op.RequestSHA256 {
		return fmt.Errorf("%w: persisted request digest is inconsistent", ErrInvalidReleaseInstallOperation)
	}
	terminal := op.Status == ReleaseInstallSucceeded || op.Status == ReleaseInstallFailed
	if terminal != (op.TerminalAt != nil) {
		return fmt.Errorf("%w: persisted terminal time is inconsistent", ErrInvalidReleaseInstallOperation)
	}
	if op.Status == ReleaseInstallSucceeded && (op.PluginRecord == nil || op.Failure != nil) {
		return ErrInvalidReleaseInstallOperation
	}
	if op.Status == ReleaseInstallFailed && (op.Failure == nil || op.PluginRecord != nil) {
		return ErrInvalidReleaseInstallOperation
	}
	return nil
}
