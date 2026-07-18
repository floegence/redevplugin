package observability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db                  *sql.DB
	mu                  sync.Mutex
	now                 func() time.Time
	maxAuditEvents      int
	maxDiagnosticEvents int
}

func NewSQLiteStore(ctx context.Context, path string, opts ...MemoryStoreOptions) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite observability store path is required")
	}
	options := MemoryStoreOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxAuditEvents := options.MaxAuditEvents
	if maxAuditEvents <= 0 {
		maxAuditEvents = defaultMaxEvents
	}
	maxDiagnosticEvents := options.MaxDiagnosticEvents
	if maxDiagnosticEvents <= 0 {
		maxDiagnosticEvents = defaultMaxEvents
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{
		db:                  db,
		now:                 now,
		maxAuditEvents:      maxAuditEvents,
		maxDiagnosticEvents: maxDiagnosticEvents,
	}
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

func (s *SQLiteStore) AppendPluginAudit(ctx context.Context, event AuditEvent) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	event, err := normalizeAuditEvent(event, s.now)
	if err != nil {
		return err
	}
	rawDetails, err := marshalDetails(event.Details)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if event.EventID != "" {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM plugin_audit_events WHERE event_id = ? LIMIT 1`, event.EventID).Scan(&exists)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	seq, err := nextSQLiteSequence(ctx, tx, "audit_seq")
	if err != nil {
		return err
	}
	if event.EventID == "" {
		event.EventID = eventID("audit", seq)
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO plugin_audit_events(seq, event_id, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO NOTHING`,
		seq,
		event.EventID,
		event.Type,
		event.PluginID,
		event.PluginInstanceID,
		event.SurfaceID,
		event.SurfaceInstanceID,
		event.RequestID,
		event.Actor,
		event.OccurredAt.UTC().UnixNano(),
		rawDetails,
	)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		return nil
	}
	if err := trimSQLiteEvents(ctx, tx, "plugin_audit_events", s.maxAuditEvents); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	event, err := normalizeDiagnosticEvent(event, s.now)
	if err != nil {
		return err
	}
	rawDetails, err := marshalDiagnosticDetails(event.Details)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	seq, err := nextSQLiteSequence(ctx, tx, "diagnostic_seq")
	if err != nil {
		return err
	}
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = eventID("diagnostic", seq)
	} else {
		event.EventID = strings.TrimSpace(event.EventID)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_diagnostic_events(seq, event_id, type, severity, message, plugin_id, plugin_instance_id, surface_id, surface_instance_id, active_fingerprint, request_id, correlation_id, mutation_outcome, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at, details_json, failure_code, failure_component, failure_operation)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		seq,
		event.EventID,
		event.Type,
		event.Severity,
		event.Message,
		event.PluginID,
		event.PluginInstanceID,
		event.SurfaceID,
		event.SurfaceInstanceID,
		event.ActiveFingerprint,
		event.RequestID,
		event.CorrelationID,
		event.MutationOutcome,
		event.OwnerSessionHash,
		event.OwnerUserHash,
		event.OwnerEnvHash,
		event.SessionChannelIDHash,
		event.OccurredAt.UTC().UnixNano(),
		rawDetails,
		event.Failure.Code,
		event.Failure.Component,
		event.Failure.Operation,
	); err != nil {
		return err
	}
	if err := trimSQLiteEvents(ctx, tx, "plugin_diagnostic_events", s.maxDiagnosticEvents); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListPluginDiagnostics(ctx context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	limit := normalizeLimit(req.Limit)
	pluginID := strings.TrimSpace(req.PluginID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	surfaceInstanceID := strings.TrimSpace(req.SurfaceInstanceID)
	ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash, err := diagnosticOwnerScope(req)
	if err != nil {
		return nil, err
	}
	eventType := strings.TrimSpace(req.Type)
	severity, err := normalizeOptionalDiagnosticSeverity(req.Severity)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
SELECT event_id, type, severity, message, plugin_id, plugin_instance_id, surface_id, surface_instance_id, active_fingerprint, request_id, correlation_id, mutation_outcome, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at, details_json, failure_code, failure_component, failure_operation
FROM plugin_diagnostic_events`
	args := []any{}
	conditions := []string{}
	if pluginID != "" {
		conditions = append(conditions, `plugin_id = ?`)
		args = append(args, pluginID)
	}
	if pluginInstanceID != "" {
		conditions = append(conditions, `plugin_instance_id = ?`)
		args = append(args, pluginInstanceID)
	}
	if surfaceInstanceID != "" {
		conditions = append(conditions, `surface_instance_id = ?`)
		args = append(args, surfaceInstanceID)
	}
	conditions = append(conditions,
		`owner_session_hash = ?`,
		`owner_user_hash = ?`,
		`owner_env_hash = ?`,
		`session_channel_id_hash = ?`,
	)
	args = append(args, ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash)
	if eventType != "" {
		conditions = append(conditions, `type = ?`)
		args = append(args, eventType)
	}
	if severity != "" {
		conditions = append(conditions, `severity = ?`)
		args = append(args, severity)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY occurred_at DESC, event_id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []DiagnosticEvent{}
	for rows.Next() {
		event, err := scanSQLiteDiagnosticEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
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

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_observability_meta (
	id INTEGER PRIMARY KEY CHECK(id = 1),
	audit_seq INTEGER NOT NULL,
	diagnostic_seq INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_observability_meta(id, audit_seq, diagnostic_seq) VALUES(1, 0, 0)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_security_audit_meta (
	id INTEGER PRIMARY KEY CHECK(id = 1),
	seq INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_security_audit_meta(id, seq) VALUES(1, 0)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_security_audit_journal (
	seq INTEGER PRIMARY KEY,
	event_id TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	surface_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	request_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	details_json BLOB NOT NULL,
	state TEXT NOT NULL CHECK(state IN ('pending', 'completed')),
	mutation_outcome TEXT NOT NULL,
	completion_details_json BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	completed_at INTEGER,
	exported_at INTEGER
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_audit_events (
	seq INTEGER PRIMARY KEY,
	event_id TEXT NOT NULL,
	type TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	surface_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	request_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	details_json BLOB NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_diagnostic_events (
	seq INTEGER PRIMARY KEY,
	event_id TEXT NOT NULL,
	type TEXT NOT NULL,
	severity TEXT NOT NULL,
	message TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	surface_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	active_fingerprint TEXT NOT NULL,
	request_id TEXT NOT NULL,
	correlation_id TEXT NOT NULL DEFAULT '',
	mutation_outcome TEXT NOT NULL DEFAULT '' CHECK(mutation_outcome IN ('', 'committed', 'not_committed', 'unknown')),
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	details_json BLOB NOT NULL,
	failure_code TEXT NOT NULL DEFAULT '',
	failure_component TEXT NOT NULL DEFAULT '',
	failure_operation TEXT NOT NULL DEFAULT ''
)`); err != nil {
		return err
	}
	if err := ensureDiagnosticColumns(ctx, tx); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_plugin_audit_event_id ON plugin_audit_events(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_plugin_diagnostics_plugin_instance ON plugin_diagnostic_events(plugin_instance_id, type, severity, occurred_at)`,
		`CREATE INDEX IF NOT EXISTS idx_plugin_diagnostics_surface ON plugin_diagnostic_events(surface_instance_id, severity, occurred_at)`,
		`CREATE INDEX IF NOT EXISTS idx_plugin_diagnostics_owner ON plugin_diagnostic_events(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at)`,
		`CREATE INDEX IF NOT EXISTS idx_plugin_security_audit_journal_state ON plugin_security_audit_journal(state, exported_at, seq)`,
		`CREATE INDEX IF NOT EXISTS idx_plugin_security_audit_journal_exported ON plugin_security_audit_journal(seq) WHERE exported_at IS NOT NULL`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err := validateSQLiteDiagnosticEvents(ctx, tx); err != nil {
		return err
	}
	if err := validateSQLiteAuditEvents(ctx, tx); err != nil {
		return err
	}
	if err := validateSQLiteSecurityAudits(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func validateSQLiteAuditEvents(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT event_id, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json FROM plugin_audit_events`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var event AuditEvent
		var occurredAt int64
		var rawDetails []byte
		if err := rows.Scan(&event.EventID, &event.Type, &event.PluginID, &event.PluginInstanceID, &event.SurfaceID, &event.SurfaceInstanceID, &event.RequestID, &event.Actor, &occurredAt, &rawDetails); err != nil {
			return err
		}
		details, err := unmarshalDetails(rawDetails)
		if err != nil {
			return fmt.Errorf("%w: persisted audit details are invalid", ErrInvalidEvent)
		}
		event.OccurredAt = time.Unix(0, occurredAt).UTC()
		event.Details = details
		if err := ValidateAuditEvent(event); err != nil {
			return fmt.Errorf("%w: persisted audit event is invalid", ErrInvalidEvent)
		}
	}
	return rows.Err()
}

func ensureDiagnosticColumns(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_diagnostic_events)`)
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
			rows.Close()
			return err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	statements := []struct {
		column    string
		statement string
	}{
		{column: "correlation_id", statement: `ALTER TABLE plugin_diagnostic_events ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''`},
		{column: "mutation_outcome", statement: `ALTER TABLE plugin_diagnostic_events ADD COLUMN mutation_outcome TEXT NOT NULL DEFAULT '' CHECK(mutation_outcome IN ('', 'committed', 'not_committed', 'unknown'))`},
		{column: "failure_code", statement: `ALTER TABLE plugin_diagnostic_events ADD COLUMN failure_code TEXT NOT NULL DEFAULT ''`},
		{column: "failure_component", statement: `ALTER TABLE plugin_diagnostic_events ADD COLUMN failure_component TEXT NOT NULL DEFAULT ''`},
		{column: "failure_operation", statement: `ALTER TABLE plugin_diagnostic_events ADD COLUMN failure_operation TEXT NOT NULL DEFAULT ''`},
	}
	for _, item := range statements {
		if _, exists := columns[item.column]; exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, item.statement); err != nil {
			return err
		}
	}
	return nil
}

func validateSQLiteDiagnosticEvents(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT event_id, type, severity, message, plugin_id, plugin_instance_id, surface_id, surface_instance_id, active_fingerprint, request_id, correlation_id, mutation_outcome, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at, details_json, failure_code, failure_component, failure_operation
FROM plugin_diagnostic_events`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, err := scanSQLiteDiagnosticEvent(rows); err != nil {
			return fmt.Errorf("%w: persisted diagnostic event is invalid", ErrInvalidEvent)
		}
	}
	return rows.Err()
}

func nextSQLiteSequence(ctx context.Context, tx *sql.Tx, column string) (uint64, error) {
	if column != "audit_seq" && column != "diagnostic_seq" {
		return 0, fmt.Errorf("unsupported observability sequence column %q", column)
	}
	query := fmt.Sprintf(`SELECT %s FROM plugin_observability_meta WHERE id = 1`, column)
	var current uint64
	if err := tx.QueryRowContext(ctx, query).Scan(&current); err != nil {
		return 0, err
	}
	next := current + 1
	update := fmt.Sprintf(`UPDATE plugin_observability_meta SET %s = ? WHERE id = 1`, column)
	if _, err := tx.ExecContext(ctx, update, next); err != nil {
		return 0, err
	}
	return next, nil
}

func trimSQLiteEvents(ctx context.Context, tx *sql.Tx, table string, max int) error {
	if table != "plugin_audit_events" && table != "plugin_diagnostic_events" {
		return fmt.Errorf("unsupported observability event table %q", table)
	}
	if max == 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM `+table)
		return err
	}
	var current uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM `+table).Scan(&current); err != nil {
		return err
	}
	if current <= uint64(max) {
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE seq <= ?`, current-uint64(max))
	return err
}

func scanSQLiteDiagnosticEvent(rows *sql.Rows) (DiagnosticEvent, error) {
	var event DiagnosticEvent
	var severity string
	var mutationOutcome string
	var failureCode string
	var failureComponent string
	var failureOperation string
	var occurredAt int64
	var rawDetails []byte
	if err := rows.Scan(
		&event.EventID,
		&event.Type,
		&severity,
		&event.Message,
		&event.PluginID,
		&event.PluginInstanceID,
		&event.SurfaceID,
		&event.SurfaceInstanceID,
		&event.ActiveFingerprint,
		&event.RequestID,
		&event.CorrelationID,
		&mutationOutcome,
		&event.OwnerSessionHash,
		&event.OwnerUserHash,
		&event.OwnerEnvHash,
		&event.SessionChannelIDHash,
		&occurredAt,
		&rawDetails,
		&failureCode,
		&failureComponent,
		&failureOperation,
	); err != nil {
		return DiagnosticEvent{}, err
	}
	details, err := unmarshalDiagnosticDetails(rawDetails)
	if err != nil {
		return DiagnosticEvent{}, err
	}
	event.Severity, err = normalizeDiagnosticSeverity(DiagnosticSeverity(severity))
	if err != nil {
		return DiagnosticEvent{}, err
	}
	event.OccurredAt = time.Unix(0, occurredAt).UTC()
	event.Details = details
	event.MutationOutcome = mutation.Outcome(mutationOutcome)
	event.Failure = Failure{
		Code: FailureCode(failureCode), Component: FailureComponent(failureComponent), Operation: FailureOperation(failureOperation),
	}
	if err := ValidateDiagnosticEvent(event); err != nil {
		return DiagnosticEvent{}, err
	}
	return publicDiagnosticEvent(event), nil
}

func marshalDetails(details map[string]any) ([]byte, error) {
	raw, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("encode observability details: %w", err)
	}
	return raw, nil
}

func marshalDiagnosticDetails(details DiagnosticDetails) ([]byte, error) {
	if !details.Valid() {
		return nil, ErrInvalidDiagnosticDetails
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("encode diagnostic details: %w", err)
	}
	return raw, nil
}

func unmarshalDiagnosticDetails(raw []byte) (DiagnosticDetails, error) {
	if len(raw) == 0 {
		return DiagnosticDetails{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var details DiagnosticDetails
	if err := decoder.Decode(&details); err != nil {
		return DiagnosticDetails{}, fmt.Errorf("decode diagnostic details: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return DiagnosticDetails{}, errors.New("decode diagnostic details: trailing JSON value")
	}
	if !details.Valid() {
		return DiagnosticDetails{}, ErrInvalidDiagnosticDetails
	}
	return details, nil
}

func unmarshalDetails(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var details map[string]any
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("decode observability details: %w", err)
	}
	return details, nil
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ AuditSink = (*SQLiteStore)(nil)
var _ DiagnosticsSink = (*SQLiteStore)(nil)
var _ DiagnosticLister = (*SQLiteStore)(nil)
