package observability

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultListLimit = 100
	maxListLimit     = 1000
	defaultMaxEvents = 4096
)

var ErrInvalidEvent = errors.New("plugin observability event is invalid")

type AuditSink interface {
	AppendPluginAudit(ctx context.Context, event AuditEvent) error
}

type DiagnosticsSink interface {
	AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error
}

type AuditLister interface {
	ListPluginAudit(ctx context.Context, req ListAuditRequest) ([]AuditEvent, error)
}

type DiagnosticLister interface {
	ListPluginDiagnostics(ctx context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error)
}

type AuditEvent struct {
	EventID           string         `json:"event_id,omitempty"`
	Type              string         `json:"type"`
	PluginID          string         `json:"plugin_id"`
	PluginInstanceID  string         `json:"plugin_instance_id,omitempty"`
	SurfaceID         string         `json:"surface_id,omitempty"`
	SurfaceInstanceID string         `json:"surface_instance_id,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
	Actor             string         `json:"actor,omitempty"`
	OccurredAt        time.Time      `json:"occurred_at,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type DiagnosticEvent struct {
	EventID           string         `json:"event_id,omitempty"`
	Type              string         `json:"type"`
	Severity          string         `json:"severity"`
	Message           string         `json:"message"`
	PluginID          string         `json:"plugin_id,omitempty"`
	PluginInstanceID  string         `json:"plugin_instance_id,omitempty"`
	SurfaceID         string         `json:"surface_id,omitempty"`
	SurfaceInstanceID string         `json:"surface_instance_id,omitempty"`
	ActiveFingerprint string         `json:"active_fingerprint,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
	OccurredAt        time.Time      `json:"occurred_at,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type ListAuditRequest struct {
	PluginID         string `json:"plugin_id,omitempty"`
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	Type             string `json:"type,omitempty"`
	Limit            int    `json:"limit,omitempty"`
}

type ListDiagnosticRequest struct {
	PluginID          string `json:"plugin_id,omitempty"`
	PluginInstanceID  string `json:"plugin_instance_id,omitempty"`
	SurfaceInstanceID string `json:"surface_instance_id,omitempty"`
	Type              string `json:"type,omitempty"`
	Severity          string `json:"severity,omitempty"`
	Limit             int    `json:"limit,omitempty"`
}

type MemoryStoreOptions struct {
	Now                 func() time.Time
	MaxAuditEvents      int
	MaxDiagnosticEvents int
}

type MemoryStore struct {
	mu                  sync.RWMutex
	now                 func() time.Time
	maxAuditEvents      int
	maxDiagnosticEvents int
	nextAuditSeq        uint64
	nextDiagnosticSeq   uint64
	auditEvents         []AuditEvent
	diagnosticEvents    []DiagnosticEvent
}

func NewMemoryStore(opts ...MemoryStoreOptions) *MemoryStore {
	options := MemoryStoreOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxAuditEvents := options.MaxAuditEvents
	if maxAuditEvents == 0 {
		maxAuditEvents = defaultMaxEvents
	}
	maxDiagnosticEvents := options.MaxDiagnosticEvents
	if maxDiagnosticEvents == 0 {
		maxDiagnosticEvents = defaultMaxEvents
	}
	return &MemoryStore{
		now:                 now,
		maxAuditEvents:      maxAuditEvents,
		maxDiagnosticEvents: maxDiagnosticEvents,
	}
}

func (s *MemoryStore) AppendPluginAudit(_ context.Context, event AuditEvent) error {
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
	event.Details = cloneMap(event.Details)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAuditSeq++
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = eventID("audit", s.nextAuditSeq)
	}
	s.auditEvents = append(s.auditEvents, event)
	s.auditEvents = trimOldest(s.auditEvents, s.maxAuditEvents)
	return nil
}

func (s *MemoryStore) AppendPluginDiagnostic(_ context.Context, event DiagnosticEvent) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	event.Type = strings.TrimSpace(event.Type)
	if event.Type == "" {
		return ErrInvalidEvent
	}
	event.Severity = strings.TrimSpace(event.Severity)
	if event.Severity == "" {
		event.Severity = "info"
	}
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
	event.Details = cloneMap(event.Details)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextDiagnosticSeq++
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = eventID("diagnostic", s.nextDiagnosticSeq)
	}
	s.diagnosticEvents = append(s.diagnosticEvents, event)
	s.diagnosticEvents = trimOldest(s.diagnosticEvents, s.maxDiagnosticEvents)
	return nil
}

func (s *MemoryStore) ListPluginAudit(_ context.Context, req ListAuditRequest) ([]AuditEvent, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	limit := normalizeLimit(req.Limit)
	pluginID := strings.TrimSpace(req.PluginID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	eventType := strings.TrimSpace(req.Type)

	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]AuditEvent, 0, minInt(limit, len(s.auditEvents)))
	for _, event := range s.auditEvents {
		if pluginID != "" && event.PluginID != pluginID {
			continue
		}
		if pluginInstanceID != "" && event.PluginInstanceID != pluginInstanceID {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		events = append(events, cloneAuditEvent(event))
	}
	sortAuditEventsNewestFirst(events)
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func (s *MemoryStore) ListPluginDiagnostics(_ context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	limit := normalizeLimit(req.Limit)
	pluginID := strings.TrimSpace(req.PluginID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	surfaceInstanceID := strings.TrimSpace(req.SurfaceInstanceID)
	eventType := strings.TrimSpace(req.Type)
	severity := strings.TrimSpace(req.Severity)

	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]DiagnosticEvent, 0, minInt(limit, len(s.diagnosticEvents)))
	for _, event := range s.diagnosticEvents {
		if pluginID != "" && event.PluginID != pluginID {
			continue
		}
		if pluginInstanceID != "" && event.PluginInstanceID != pluginInstanceID {
			continue
		}
		if surfaceInstanceID != "" && event.SurfaceInstanceID != surfaceInstanceID {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if severity != "" && event.Severity != severity {
			continue
		}
		events = append(events, cloneDiagnosticEvent(event))
	}
	sortDiagnosticEventsNewestFirst(events)
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func eventID(prefix string, seq uint64) string {
	return prefix + "_" + leftPadUint(seq, 12)
}

func leftPadUint(value uint64, width int) string {
	text := strconv.FormatUint(value, 10)
	for len(text) < width {
		text = "0" + text
	}
	return text
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultListLimit
	}
	if limit > maxListLimit {
		return maxListLimit
	}
	return limit
}

func trimOldest[T any](records []T, max int) []T {
	if max < 0 || len(records) <= max {
		return records
	}
	if max == 0 {
		return nil
	}
	return append([]T(nil), records[len(records)-max:]...)
}

func sortAuditEventsNewestFirst(events []AuditEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
}

func sortDiagnosticEventsNewestFirst(events []DiagnosticEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
}

func cloneAuditEvent(event AuditEvent) AuditEvent {
	event.Details = cloneMap(event.Details)
	return event
}

func cloneDiagnosticEvent(event DiagnosticEvent) DiagnosticEvent {
	event.Details = cloneMap(event.Details)
	return event
}

func cloneMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
