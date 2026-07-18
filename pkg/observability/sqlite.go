package observability

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
	event.Type = strings.TrimSpace(event.Type)
	if event.Type == "" {
		return ErrInvalidEvent
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now()
	}
	event.PluginID = strings.TrimSpace(event.PluginID)
	event.PluginInstanceID = strings.TrimSpace(event.PluginInstanceID)
	event.SurfaceID = strings.TrimSpace(event.SurfaceID)
	event.SurfaceInstanceID = strings.TrimSpace(event.SurfaceInstanceID)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.Actor = strings.TrimSpace(event.Actor)
	event.EventID = strings.TrimSpace(event.EventID)
	event.Details = cloneMap(event.Details)
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
	event.Type = strings.TrimSpace(event.Type)
	if event.Type == "" {
		return ErrInvalidEvent
	}
	severity, err := normalizeDiagnosticSeverity(event.Severity)
	if err != nil {
		return err
	}
	event.Severity = severity
	event.Message = strings.TrimSpace(event.Message)
	if event.Message == "" {
		event.Message = event.Type
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now()
	}
	event.PluginID = strings.TrimSpace(event.PluginID)
	event.PluginInstanceID = strings.TrimSpace(event.PluginInstanceID)
	event.SurfaceID = strings.TrimSpace(event.SurfaceID)
	event.SurfaceInstanceID = strings.TrimSpace(event.SurfaceInstanceID)
	event.ActiveFingerprint = strings.TrimSpace(event.ActiveFingerprint)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.OwnerSessionHash = strings.TrimSpace(event.OwnerSessionHash)
	event.OwnerUserHash = strings.TrimSpace(event.OwnerUserHash)
	event.OwnerEnvHash = strings.TrimSpace(event.OwnerEnvHash)
	event.SessionChannelIDHash = strings.TrimSpace(event.SessionChannelIDHash)
	event.Details = cloneMap(event.Details)
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
INSERT INTO plugin_diagnostic_events(seq, event_id, type, severity, message, plugin_id, plugin_instance_id, surface_id, surface_instance_id, active_fingerprint, request_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at, details_json)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		event.OwnerSessionHash,
		event.OwnerUserHash,
		event.OwnerEnvHash,
		event.SessionChannelIDHash,
		event.OccurredAt.UTC().UnixNano(),
		rawDetails,
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
SELECT event_id, type, severity, message, plugin_id, plugin_instance_id, surface_id, surface_instance_id, active_fingerprint, request_id, owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, occurred_at, details_json
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
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	details_json BLOB NOT NULL
)`); err != nil {
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
	return tx.Commit()
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
		&event.OwnerSessionHash,
		&event.OwnerUserHash,
		&event.OwnerEnvHash,
		&event.SessionChannelIDHash,
		&occurredAt,
		&rawDetails,
	); err != nil {
		return DiagnosticEvent{}, err
	}
	details, err := unmarshalDetails(rawDetails)
	if err != nil {
		return DiagnosticEvent{}, err
	}
	event.Severity, err = normalizeDiagnosticSeverity(DiagnosticSeverity(severity))
	if err != nil {
		return DiagnosticEvent{}, err
	}
	event.OccurredAt = time.Unix(0, occurredAt).UTC()
	event.Details = details
	return publicDiagnosticEvent(event), nil
}

func marshalDetails(details map[string]any) ([]byte, error) {
	raw, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("encode observability details: %w", err)
	}
	return raw, nil
}

func unmarshalDetails(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var details map[string]any
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("decode observability details: %w", err)
	}
	return cloneMap(details), nil
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ AuditSink = (*SQLiteStore)(nil)
var _ DiagnosticsSink = (*SQLiteStore)(nil)
var _ DiagnosticLister = (*SQLiteStore)(nil)
