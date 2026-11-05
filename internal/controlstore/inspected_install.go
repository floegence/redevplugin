package controlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

const inspectedInstallKind = "inspected_install_v1"

// InspectedInstall is a payload of the existing Execution authority. Session
// identity is retained for audit; outcome recovery uses stable user/environment.
type InspectedInstall struct {
	Automatic     bool                `json:"automatic,omitempty"`
	Kind          string              `json:"kind"`
	Execution     execution.Execution `json:"-"`
	RequestID     string              `json:"request_id"`
	InspectionID  string              `json:"inspection_id"`
	PackageSHA256 string              `json:"package_sha256"`
	PluginID      string              `json:"plugin_id"`
	Version       string              `json:"version"`
	Outcome       mutation.Outcome    `json:"mutation_outcome"`
}
type InspectedInstallRecovery struct {
	Owner     ExecutionOwner
	Operation InspectedInstall
}

func InspectedInstallID(owner ExecutionOwner, requestID string) string {
	raw, _ := json.Marshal([]string{owner.OwnerUserHash, owner.OwnerEnvHash, requestID})
	sum := sha256.Sum256(raw)
	return "inspected_install_" + hex.EncodeToString(sum[:])
}
func migrateInspectedInstalls(ctx context.Context, q dataHistoryMigrator) error {
	if _, err := q.ExecContext(ctx, `CREATE UNIQUE INDEX inspected_install_claim ON execution(owner_user_hash,owner_env_hash,json_extract(operation_json,'$.inspection_id')) WHERE json_extract(operation_json,'$.kind')='inspected_install_v1'`); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, "UPDATE control_schema SET version=6 WHERE id=1 AND version=5")
	return err
}

var inspectedHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (v ExecutionView) GetInspectedInstall(ctx context.Context, owner ExecutionOwner, requestID string) (InspectedInstall, error) {
	if err := v.ready(); err != nil {
		return InspectedInstall{}, err
	}
	if !owner.Valid() || requestID == "" || len(requestID) > 160 || strings.TrimSpace(requestID) != requestID {
		return InspectedInstall{}, ErrRecordNotFound
	}
	var op InspectedInstall
	var raw string
	var created, updated int64
	var canceled, terminal sql.NullInt64
	row := v.store.db.QueryRowContext(ctx, `SELECT execution_id,plugin_instance_id,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json FROM execution WHERE execution_id=? AND owner_user_hash=? AND owner_env_hash=?`, InspectedInstallID(owner, requestID), owner.OwnerUserHash, owner.OwnerEnvHash)
	var e execution.Execution
	err := row.Scan(&e.ID, &e.PluginInstanceID, &e.Kind, &e.Status, &e.Cursor, &e.FailureCode, &e.Cancelable, &created, &updated, &canceled, &terminal, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrRecordNotFound
	}
	if err != nil {
		return op, err
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&op) != nil || decoder.Decode(new(any)) != io.EOF || op.Kind != inspectedInstallKind || op.RequestID != requestID || !inspectedHashPattern.MatchString(op.PackageSHA256) || op.InspectionID == "" || op.PluginID == "" || op.Version == "" {
		return op, ErrIncompatible
	}
	e.CreatedAt = time.Unix(0, created).UTC()
	e.UpdatedAt = time.Unix(0, updated).UTC()
	e.CancelRequestedAt = nullTimePointer(canceled)
	e.TerminalAt = nullTimePointer(terminal)
	if e.Validate() != nil || e.Kind != execution.KindOperation || e.Cancelable {
		return op, ErrIncompatible
	}
	if op.Outcome != mutation.OutcomeCommitted && op.Outcome != mutation.OutcomeNotCommitted && op.Outcome != mutation.OutcomeUnknown {
		return op, ErrIncompatible
	}
	if e.Status == execution.StatusCompleted && op.Outcome != mutation.OutcomeCommitted {
		return op, ErrIncompatible
	}
	op.Execution = e
	return op, nil
}

// ListInspectedInstalls projects existing Execution receipts, including attempts
// that never created an installed record. No separate operation store is used.
func (v ExecutionView) ListInspectedInstalls(ctx context.Context, owner ExecutionOwner, pluginInstanceID string, cursor uint64, limit int) ([]InspectedInstall, uint64, error) {
	executions, next, err := v.ListOwnedWithOperationScope(ctx, pluginInstanceID, "plugin_install", owner, cursor, limit)
	if err != nil {
		return nil, 0, err
	}
	result := make([]InspectedInstall, 0, len(executions))
	for _, item := range executions {
		var requestID string
		if err := v.store.db.QueryRowContext(ctx, `SELECT json_extract(operation_json,'$.request_id') FROM execution WHERE execution_id=? AND owner_user_hash=? AND owner_env_hash=?`, item.ID, owner.OwnerUserHash, owner.OwnerEnvHash).Scan(&requestID); err != nil {
			return nil, 0, err
		}
		op, err := v.GetInspectedInstall(ctx, owner, requestID)
		if err != nil {
			return nil, 0, err
		}
		if op.Execution.ID != item.ID {
			return nil, 0, ErrIncompatible
		}
		result = append(result, op)
	}
	return result, next, nil
}
func (v ExecutionView) StartInspectedInstall(ctx context.Context, owner ExecutionOwner, op InspectedInstall) (InspectedInstall, bool, error) {
	if err := v.ready(); err != nil {
		return op, false, err
	}
	if !owner.Valid() {
		return op, false, ErrRecordNotFound
	}
	op.Kind = inspectedInstallKind
	op.Execution.ID = InspectedInstallID(owner, op.RequestID)
	op.Outcome = mutation.OutcomeUnknown
	if op.RequestID == "" || len(op.RequestID) > 160 || strings.TrimSpace(op.RequestID) != op.RequestID || op.InspectionID == "" || !inspectedHashPattern.MatchString(op.PackageSHA256) || op.Execution.PluginInstanceID == "" || op.PluginID == "" || op.Version == "" {
		return op, false, ErrStateConflict
	}
	var err error
	op.Execution, err = execution.New(op.Execution)
	if err != nil {
		return op, false, err
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return op, false, err
	}
	result, err := v.store.db.ExecContext(ctx, `INSERT INTO execution(execution_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json,stream_json) VALUES(?,?,?,?,?,?,'operation','running',0,'',0,?,?,NULL,NULL,?,'null') ON CONFLICT(execution_id) DO NOTHING`, op.Execution.ID, op.Execution.PluginInstanceID, owner.OwnerSessionHash, owner.OwnerUserHash, owner.OwnerEnvHash, owner.SessionChannelIDHash, op.Execution.CreatedAt.UnixNano(), op.Execution.UpdatedAt.UnixNano(), string(raw))
	if err != nil {
		var claimed string
		if v.store.db.QueryRowContext(ctx, `SELECT execution_id FROM execution WHERE owner_user_hash=? AND owner_env_hash=? AND json_extract(operation_json,'$.kind')=? AND json_extract(operation_json,'$.inspection_id')=?`, owner.OwnerUserHash, owner.OwnerEnvHash, inspectedInstallKind, op.InspectionID).Scan(&claimed) == nil {
			return op, false, ErrStateConflict
		}
		return op, false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return op, false, err
	}
	if n == 1 {
		return op, true, nil
	}
	old, err := v.GetInspectedInstall(ctx, owner, op.RequestID)
	if err == nil && (old.InspectionID != op.InspectionID || old.PackageSHA256 != op.PackageSHA256 || old.Automatic != op.Automatic) {
		return old, false, ErrStateConflict
	}
	return old, false, err
}
func (v ExecutionView) FinishInspectedInstall(ctx context.Context, owner ExecutionOwner, requestID string, outcome mutation.Outcome, code string) (InspectedInstall, error) {
	if outcome != mutation.OutcomeCommitted && outcome != mutation.OutcomeNotCommitted && outcome != mutation.OutcomeUnknown {
		return InspectedInstall{}, ErrStateConflict
	}
	current, err := v.GetInspectedInstall(ctx, owner, requestID)
	if err != nil {
		return current, err
	}
	if current.Execution.Status != execution.StatusRunning {
		return current, nil
	}
	current.Outcome = outcome
	status := execution.StatusFailed
	if outcome == mutation.OutcomeCommitted && code == "" {
		status = execution.StatusCompleted
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return current, err
	}
	now := time.Now().UTC()
	event, err := execution.NewEvent(current.Execution, current.Execution.Cursor+1, execution.EventTerminal, map[string]any{"status": status, "mutation_outcome": outcome, "package_sha256": current.PackageSHA256, "request_id": requestID, "failure_code": code})
	if err != nil {
		return current, err
	}
	if err = current.Execution.Finish(status, code, event, now); err != nil {
		return current, err
	}
	tx, err := v.store.db.BeginTx(ctx, nil)
	if err != nil {
		return current, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, "UPDATE execution SET status=?,cursor=?,failure_code=?,updated_at=?,terminal_at=?,operation_json=? WHERE execution_id=? AND status='running' AND cursor=?", status, current.Execution.Cursor, code, now.UnixNano(), now.UnixNano(), string(raw), current.Execution.ID, current.Execution.Cursor-1)
	if err != nil {
		return current, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return current, err
	}
	if n != 1 {
		return current, ErrRevisionConflict
	}
	if err = insertEvent(ctx, tx, event); err != nil {
		return current, err
	}
	return current, tx.Commit()
}
func (v ExecutionView) InspectedInstallRecovery(ctx context.Context) ([]InspectedInstallRecovery, error) {
	rows, err := v.store.db.QueryContext(ctx, "SELECT owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,operation_json FROM execution WHERE status='running' AND json_extract(operation_json,'$.kind')=?", inspectedInstallKind)
	if err != nil {
		return nil, err
	}
	result := []InspectedInstallRecovery{}
	for rows.Next() {
		var r InspectedInstallRecovery
		var raw string
		if err = rows.Scan(&r.Owner.OwnerSessionHash, &r.Owner.OwnerUserHash, &r.Owner.OwnerEnvHash, &r.Owner.SessionChannelIDHash, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &r.Operation); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, r)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	for i := range result {
		result[i].Operation, err = v.GetInspectedInstall(ctx, result[i].Owner, result[i].Operation.RequestID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
