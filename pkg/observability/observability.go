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

var (
	ErrInvalidEvent              = errors.New("plugin observability event is invalid")
	ErrInvalidDiagnosticSeverity = errors.New("plugin diagnostic severity is invalid")
	ErrDiagnosticScopeRequired   = errors.New("complete diagnostic owner scope is required")
)

type DiagnosticSeverity string

const (
	DiagnosticSeverityInfo    DiagnosticSeverity = "info"
	DiagnosticSeverityWarning DiagnosticSeverity = "warning"
)

func (severity DiagnosticSeverity) Valid() bool {
	return severity == DiagnosticSeverityInfo || severity == DiagnosticSeverityWarning
}

type AuditSink interface {
	AppendPluginAudit(ctx context.Context, event AuditEvent) error
}

type DiagnosticsSink interface {
	AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error
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
	EventID              string             `json:"event_id,omitempty"`
	Type                 string             `json:"type"`
	Severity             DiagnosticSeverity `json:"severity"`
	Message              string             `json:"message"`
	PluginID             string             `json:"plugin_id,omitempty"`
	PluginInstanceID     string             `json:"plugin_instance_id,omitempty"`
	SurfaceID            string             `json:"surface_id,omitempty"`
	SurfaceInstanceID    string             `json:"surface_instance_id,omitempty"`
	ActiveFingerprint    string             `json:"active_fingerprint,omitempty"`
	RequestID            string             `json:"request_id,omitempty"`
	OwnerSessionHash     string             `json:"-"`
	OwnerUserHash        string             `json:"-"`
	OwnerEnvHash         string             `json:"-"`
	SessionChannelIDHash string             `json:"-"`
	OccurredAt           time.Time          `json:"occurred_at,omitempty"`
	Details              map[string]any     `json:"details,omitempty"`
	InternalDetails      map[string]any     `json:"-"`
}

type ListDiagnosticRequest struct {
	PluginID             string             `json:"plugin_id,omitempty"`
	PluginInstanceID     string             `json:"plugin_instance_id,omitempty"`
	SurfaceInstanceID    string             `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string             `json:"-"`
	OwnerUserHash        string             `json:"-"`
	OwnerEnvHash         string             `json:"-"`
	SessionChannelIDHash string             `json:"-"`
	Type                 string             `json:"type,omitempty"`
	Severity             DiagnosticSeverity `json:"severity,omitempty"`
	Limit                int                `json:"limit,omitempty"`
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
	auditEvents         fixedRing[AuditEvent]
	diagnosticEvents    fixedRing[DiagnosticEvent]
	securityJournal     *MemorySecurityAuditJournal
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
	if maxAuditEvents <= 0 {
		maxAuditEvents = defaultMaxEvents
	}
	maxDiagnosticEvents := options.MaxDiagnosticEvents
	if maxDiagnosticEvents <= 0 {
		maxDiagnosticEvents = defaultMaxEvents
	}
	return &MemoryStore{
		now:                 now,
		maxAuditEvents:      maxAuditEvents,
		maxDiagnosticEvents: maxDiagnosticEvents,
		auditEvents:         newFixedRing[AuditEvent](maxAuditEvents),
		diagnosticEvents:    newFixedRing[DiagnosticEvent](maxDiagnosticEvents),
		securityJournal:     NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: now, MaxEntries: maxAuditEvents}),
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
	event.EventID = strings.TrimSpace(event.EventID)
	event.Details = cloneMap(event.Details)

	s.mu.Lock()
	defer s.mu.Unlock()
	if event.EventID != "" {
		for index := 0; index < s.auditEvents.count; index++ {
			stored := s.auditEvents.values[(s.auditEvents.start+index)%len(s.auditEvents.values)]
			if stored.EventID == event.EventID {
				return nil
			}
		}
	}
	s.nextAuditSeq++
	if event.EventID == "" {
		event.EventID = eventID("audit", s.nextAuditSeq)
	}
	s.auditEvents.Push(event)
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
	event.InternalDetails = cloneMap(event.InternalDetails)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextDiagnosticSeq++
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = eventID("diagnostic", s.nextDiagnosticSeq)
	}
	s.diagnosticEvents.Push(event)
	return nil
}

func (s *MemoryStore) ListPluginDiagnostics(_ context.Context, req ListDiagnosticRequest) ([]DiagnosticEvent, error) {
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

	s.mu.RLock()
	defer s.mu.RUnlock()
	diagnostics := s.diagnosticEvents.Snapshot()
	events := make([]DiagnosticEvent, 0, minInt(limit, len(diagnostics)))
	for _, event := range diagnostics {
		if pluginID != "" && event.PluginID != pluginID {
			continue
		}
		if pluginInstanceID != "" && event.PluginInstanceID != pluginInstanceID {
			continue
		}
		if surfaceInstanceID != "" && event.SurfaceInstanceID != surfaceInstanceID {
			continue
		}
		if event.OwnerSessionHash != ownerSessionHash {
			continue
		}
		if event.OwnerUserHash != ownerUserHash {
			continue
		}
		if event.OwnerEnvHash != ownerEnvHash {
			continue
		}
		if event.SessionChannelIDHash != sessionChannelIDHash {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if severity != "" && event.Severity != severity {
			continue
		}
		events = append(events, publicDiagnosticEvent(event))
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

func normalizeDiagnosticSeverity(severity DiagnosticSeverity) (DiagnosticSeverity, error) {
	normalized := DiagnosticSeverity(strings.TrimSpace(string(severity)))
	if normalized.Valid() {
		return normalized, nil
	}
	return "", ErrInvalidDiagnosticSeverity
}

func normalizeOptionalDiagnosticSeverity(severity DiagnosticSeverity) (DiagnosticSeverity, error) {
	if strings.TrimSpace(string(severity)) == "" {
		return "", nil
	}
	return normalizeDiagnosticSeverity(severity)
}

type fixedRing[T any] struct {
	values []T
	start  int
	count  int
}

func newFixedRing[T any](capacity int) fixedRing[T] {
	if capacity <= 0 {
		capacity = defaultMaxEvents
	}
	return fixedRing[T]{values: make([]T, capacity)}
}

func (r *fixedRing[T]) Push(value T) {
	if len(r.values) == 0 {
		return
	}
	if r.count < len(r.values) {
		r.values[(r.start+r.count)%len(r.values)] = value
		r.count++
		return
	}
	r.values[r.start] = value
	r.start = (r.start + 1) % len(r.values)
}

func (r fixedRing[T]) Snapshot() []T {
	result := make([]T, r.count)
	for index := 0; index < r.count; index++ {
		result[index] = r.values[(r.start+index)%len(r.values)]
	}
	return result
}

func (r fixedRing[T]) Len() int { return r.count }

func sortDiagnosticEventsNewestFirst(events []DiagnosticEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
}

func cloneDiagnosticEvent(event DiagnosticEvent) DiagnosticEvent {
	event.Details = cloneMap(event.Details)
	event.InternalDetails = cloneMap(event.InternalDetails)
	return event
}

func publicDiagnosticEvent(event DiagnosticEvent) DiagnosticEvent {
	event = cloneDiagnosticEvent(event)
	event.InternalDetails = nil
	return event
}

func diagnosticOwnerScope(req ListDiagnosticRequest) (string, string, string, string, error) {
	ownerSessionHash := strings.TrimSpace(req.OwnerSessionHash)
	ownerUserHash := strings.TrimSpace(req.OwnerUserHash)
	ownerEnvHash := strings.TrimSpace(req.OwnerEnvHash)
	sessionChannelIDHash := strings.TrimSpace(req.SessionChannelIDHash)
	if ownerSessionHash == "" || ownerUserHash == "" || ownerEnvHash == "" || sessionChannelIDHash == "" {
		return "", "", "", "", ErrDiagnosticScopeRequired
	}
	return ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash, nil
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
