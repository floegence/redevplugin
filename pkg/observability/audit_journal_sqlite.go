package observability

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func (s *SQLiteStore) BeginSecurityAudit(ctx context.Context, event AuditEvent) (SecurityAuditRecord, error) {
	if s == nil || s.db == nil {
		return SecurityAuditRecord{}, errors.New("observability store is nil")
	}
	event, err := normalizeJournalEvent(event, s.now)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	rawDetails, err := marshalDetails(event.Details)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)
	if event.EventID != "" {
		var existing SecurityAuditRecord
		if err := scanSecurityAuditRecord(tx.QueryRowContext(ctx, `SELECT event_id, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json, state, mutation_outcome, completion_details_json, created_at, completed_at, exported_at FROM plugin_security_audit_journal WHERE event_id = ?`, event.EventID), &existing); err == nil {
			return existing, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return SecurityAuditRecord{}, err
		}
	}
	if err := reserveSQLiteSecurityAuditCapacity(ctx, tx, s.maxAuditEvents); err != nil {
		return SecurityAuditRecord{}, err
	}
	seq, err := nextSQLiteSecurityAuditSequence(ctx, tx)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	if event.EventID == "" {
		event.EventID = eventID("audit", seq)
	}
	createdAt := event.OccurredAt.UTC().UnixNano()
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_security_audit_journal(event_id, seq, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json, state, mutation_outcome, completion_details_json, created_at, completed_at, exported_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`, event.EventID, seq, event.Type, event.PluginID, event.PluginInstanceID, event.SurfaceID, event.SurfaceInstanceID, event.RequestID, event.Actor, createdAt, rawDetails, string(SecurityAuditPending), "", []byte("null"), createdAt); err != nil {
		return SecurityAuditRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return SecurityAuditRecord{}, err
	}
	return SecurityAuditRecord{EventID: event.EventID, Event: cloneAuditEvent(event), State: SecurityAuditPending, CreatedAt: event.OccurredAt.UTC()}, nil
}

func (s *SQLiteStore) CompleteSecurityAudit(ctx context.Context, eventID string, outcome mutation.Outcome, details map[string]any) error {
	if s == nil || s.db == nil {
		return errors.New("observability store is nil")
	}
	if !validMutationOutcome(outcome) {
		return ErrInvalidMutationOutcome
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return ErrSecurityAuditNotFound
	}
	if !validAuditDetails(details) {
		return ErrInvalidAuditDetails
	}
	clonedDetails, err := cloneJSONMap(details)
	if err != nil {
		return err
	}
	if !validAuditDetails(clonedDetails) {
		return ErrInvalidAuditDetails
	}
	rawDetails, err := marshalDetails(clonedDetails)
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
	result, err := tx.ExecContext(ctx, `UPDATE plugin_security_audit_journal SET state = ?, mutation_outcome = ?, completion_details_json = ?, completed_at = ? WHERE event_id = ? AND state = ?`, string(SecurityAuditCompleted), string(outcome), rawDetails, s.now().UTC().UnixNano(), eventID, string(SecurityAuditPending))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM plugin_security_audit_journal WHERE event_id = ?`, eventID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSecurityAuditNotFound
		}
		if err != nil {
			return err
		}
		if state == string(SecurityAuditCompleted) {
			return ErrSecurityAuditCompleted
		}
		return ErrSecurityAuditNotFound
	}
	return tx.Commit()
}

func (s *SQLiteStore) ListPendingSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error) {
	return s.listSecurityAudits(ctx, string(SecurityAuditPending))
}

func (s *SQLiteStore) ListUnexportedSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error) {
	return s.listSecurityAudits(ctx, string(SecurityAuditCompleted))
}

func (s *SQLiteStore) listSecurityAudits(ctx context.Context, state string) ([]SecurityAuditRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("observability store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json, state, mutation_outcome, completion_details_json, created_at, completed_at, exported_at FROM plugin_security_audit_journal WHERE state = ? AND exported_at IS NULL ORDER BY seq`, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]SecurityAuditRecord, 0)
	for rows.Next() {
		var record SecurityAuditRecord
		if err := scanSecurityAuditRecord(rows, &record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) MarkSecurityAuditExported(ctx context.Context, eventID string) error {
	if s == nil || s.db == nil {
		return errors.New("observability store is nil")
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return ErrSecurityAuditNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE plugin_security_audit_journal SET exported_at = ? WHERE event_id = ? AND state = ? AND exported_at IS NULL`, s.now().UTC().UnixNano(), eventID, string(SecurityAuditCompleted))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var state string
		var exported sql.NullInt64
		err := s.db.QueryRowContext(ctx, `SELECT state, exported_at FROM plugin_security_audit_journal WHERE event_id = ?`, eventID).Scan(&state, &exported)
		if err == nil && state == string(SecurityAuditCompleted) && exported.Valid {
			return nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSecurityAuditNotFound
		}
		if err != nil {
			return err
		}
		return ErrSecurityAuditNotFound
	}
	return nil
}

func (s *SQLiteStore) ReconcilePendingSecurityAudits(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("observability store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_security_audit_journal SET state = ?, mutation_outcome = ?, completion_details_json = ?, completed_at = ? WHERE state = ?`, string(SecurityAuditCompleted), string(mutation.OutcomeUnknown), []byte(`{"reason":"pending_reconciled"}`), s.now().UTC().UnixNano(), string(SecurityAuditPending))
	return err
}

func nextSQLiteSecurityAuditSequence(ctx context.Context, tx *sql.Tx) (uint64, error) {
	var current uint64
	if err := tx.QueryRowContext(ctx, `SELECT seq FROM plugin_security_audit_meta WHERE id = 1`).Scan(&current); err != nil {
		return 0, err
	}
	next := current + 1
	if _, err := tx.ExecContext(ctx, `UPDATE plugin_security_audit_meta SET seq = ? WHERE id = 1`, next); err != nil {
		return 0, err
	}
	return next, nil
}

func reserveSQLiteSecurityAuditCapacity(ctx context.Context, tx *sql.Tx, max int) error {
	if max <= 0 {
		max = defaultMaxEvents
	}
	for {
		var boundary uint64
		err := tx.QueryRowContext(ctx, `SELECT seq FROM plugin_security_audit_journal ORDER BY seq LIMIT 1 OFFSET ?`, max-1).Scan(&boundary)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_audit_journal WHERE seq = (SELECT seq FROM plugin_security_audit_journal WHERE exported_at IS NOT NULL ORDER BY seq LIMIT 1)`)
		if err != nil {
			return err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if deleted != 1 {
			return ErrSecurityAuditCapacity
		}
	}
}

type securityAuditScanner interface{ Scan(dest ...any) error }

func scanSecurityAuditRecord(scanner securityAuditScanner, record *SecurityAuditRecord) error {
	var typeName, pluginID, pluginInstanceID, surfaceID, surfaceInstanceID, requestID, actor, state, outcome string
	var occurredAt, createdAt int64
	var rawDetails, rawCompletion []byte
	var completedAt, exportedAt sql.NullInt64
	if err := scanner.Scan(&record.EventID, &typeName, &pluginID, &pluginInstanceID, &surfaceID, &surfaceInstanceID, &requestID, &actor, &occurredAt, &rawDetails, &state, &outcome, &rawCompletion, &createdAt, &completedAt, &exportedAt); err != nil {
		return err
	}
	details, err := unmarshalDetails(rawDetails)
	if err != nil {
		return err
	}
	completion, err := unmarshalDetails(rawCompletion)
	if err != nil {
		return err
	}
	record.Event = AuditEvent{EventID: record.EventID, Type: typeName, PluginID: pluginID, PluginInstanceID: pluginInstanceID, SurfaceID: surfaceID, SurfaceInstanceID: surfaceInstanceID, RequestID: requestID, Actor: actor, OccurredAt: time.Unix(0, occurredAt).UTC(), Details: details}
	record.State = SecurityAuditState(state)
	record.Outcome = mutation.Outcome(outcome)
	record.CompletionDetails = completion
	record.CreatedAt = time.Unix(0, createdAt).UTC()
	if err := ValidateAuditEvent(record.Event); err != nil || !validAuditDetails(record.CompletionDetails) {
		return ErrInvalidEvent
	}
	if record.State != SecurityAuditPending && record.State != SecurityAuditCompleted {
		return ErrInvalidEvent
	}
	if record.State == SecurityAuditPending && record.Outcome != "" || record.State == SecurityAuditCompleted && !validMutationOutcome(record.Outcome) {
		return ErrInvalidMutationOutcome
	}
	if completedAt.Valid {
		value := time.Unix(0, completedAt.Int64).UTC()
		record.CompletedAt = &value
	}
	if exportedAt.Valid {
		value := time.Unix(0, exportedAt.Int64).UTC()
		record.ExportedAt = &value
	}
	return nil
}

func validateSQLiteSecurityAudits(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT event_id, type, plugin_id, plugin_instance_id, surface_id, surface_instance_id, request_id, actor, occurred_at, details_json, state, mutation_outcome, completion_details_json, created_at, completed_at, exported_at FROM plugin_security_audit_journal`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var record SecurityAuditRecord
		if err := scanSecurityAuditRecord(rows, &record); err != nil {
			return errors.Join(ErrInvalidEvent, err)
		}
	}
	return rows.Err()
}

var _ SecurityAuditJournal = (*SQLiteStore)(nil)
