package observability

import (
	"context"
	"errors"
	"time"
)

// ListAuditRequest selects retained host audit evidence in ascending sequence
// order. Sequence cursors are local to one store. Retention may leave gaps;
// this read API is not an unbounded delivery subscription.
type ListAuditRequest struct {
	AfterSequence int64
	Type          string
	Limit         int
}

// AuditEntry is an owned snapshot; modifying it never mutates stored evidence.
type AuditEntry struct {
	Sequence int64
	Event    AuditEvent
}

// ListPluginAudits exposes validated retained evidence without granting access
// to the platform-owned database layout. It is a host-only Go API.
func (s *SQLiteStore) ListPluginAudits(ctx context.Context, req ListAuditRequest) ([]AuditEntry, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	if req.AfterSequence < 0 || req.Limit < 0 || req.Limit > maxListLimit || (req.Type != "" && !validStableValue(req.Type)) {
		return nil, ErrInvalidEvent
	}
	query := `SELECT seq,event_id,type,plugin_id,plugin_instance_id,surface_id,surface_instance_id,request_id,actor,occurred_at,details_json FROM plugin_audit_events WHERE seq > ?`
	args := []any{req.AfterSequence}
	if req.Type != "" {
		query += ` AND type = ?`
		args = append(args, req.Type)
	}
	query += ` ORDER BY seq LIMIT ?`
	args = append(args, normalizeLimit(req.Limit))
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var entry AuditEntry
		var at int64
		var raw []byte
		e := &entry.Event
		if err := rows.Scan(&entry.Sequence, &e.EventID, &e.Type, &e.PluginID, &e.PluginInstanceID, &e.SurfaceID, &e.SurfaceInstanceID, &e.RequestID, &e.Actor, &at, &raw); err != nil {
			return nil, err
		}
		e.OccurredAt = time.Unix(0, at).UTC()
		e.Details, err = unmarshalDetails(raw)
		if err != nil {
			return nil, err
		}
		if err := ValidateAuditEvent(*e); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}
