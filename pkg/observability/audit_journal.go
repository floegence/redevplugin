package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

// SecurityAuditState describes the durable state of a security mutation
// audit. Pending records are written before a mutation starts and must never
// be exported as committed events until CompleteSecurityAudit is durable.
type SecurityAuditState string

const (
	SecurityAuditPending   SecurityAuditState = "pending"
	SecurityAuditCompleted SecurityAuditState = "completed"
)

var (
	ErrInvalidMutationOutcome = errors.New("invalid security audit mutation outcome")
	ErrSecurityAuditNotFound  = errors.New("security audit journal record not found")
	ErrSecurityAuditCompleted = errors.New("security audit mutation is already completed")
	ErrSecurityAuditCapacity  = errors.New("security audit journal capacity exhausted")
)

// SecurityAuditRecord is an immutable snapshot of a journal record. EventID
// is stable for the entire lifecycle and is also used for exporter
// idempotency.
type SecurityAuditRecord struct {
	EventID           string             `json:"event_id"`
	Event             AuditEvent         `json:"event"`
	State             SecurityAuditState `json:"state"`
	Outcome           mutation.Outcome   `json:"mutation_outcome,omitempty"`
	CompletionDetails map[string]any     `json:"completion_details,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty"`
	ExportedAt        *time.Time         `json:"exported_at,omitempty"`
}

// SecurityAuditJournal is the durable boundary for security mutation audit
// records. Implementations must make Begin and Complete atomic with respect
// to their own storage and must preserve records when an export fails.
type SecurityAuditJournal interface {
	BeginSecurityAudit(ctx context.Context, event AuditEvent) (SecurityAuditRecord, error)
	CompleteSecurityAudit(ctx context.Context, eventID string, outcome mutation.Outcome, details map[string]any) error
	ListPendingSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error)
	ListUnexportedSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error)
	MarkSecurityAuditExported(ctx context.Context, eventID string) error
	ReconcilePendingSecurityAudits(ctx context.Context) error
}

type MemorySecurityAuditJournalOptions struct {
	Now        func() time.Time
	MaxEntries int
}

// MemorySecurityAuditJournal is a fixed-capacity implementation for tests and
// in-memory hosts. Capacity pressure only evicts records that were exported;
// protected records make Begin fail closed. A non-positive MaxEntries uses the
// platform default and never disables retention limits.
type MemorySecurityAuditJournal struct {
	mu         sync.RWMutex
	now        func() time.Time
	maxEntries int
	nextSeq    uint64
	entries    []SecurityAuditRecord
	start      int
	count      int
}

func NewMemorySecurityAuditJournal(opts ...MemorySecurityAuditJournalOptions) *MemorySecurityAuditJournal {
	options := MemorySecurityAuditJournalOptions{}
	if len(opts) > 0 {
		options = opts[0]
	}
	maxEntries := options.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEvents
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &MemorySecurityAuditJournal{
		now:        now,
		maxEntries: maxEntries,
		entries:    make([]SecurityAuditRecord, maxEntries),
	}
}

func (j *MemorySecurityAuditJournal) BeginSecurityAudit(_ context.Context, event AuditEvent) (SecurityAuditRecord, error) {
	if j == nil {
		return SecurityAuditRecord{}, errors.New("security audit journal is nil")
	}
	event, err := normalizeJournalEvent(event, j.now)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if event.EventID != "" {
		if existing, ok := j.findLocked(event.EventID); ok {
			return cloneSecurityAuditRecord(existing), nil
		}
	}
	if j.count == j.maxEntries {
		exportedIndex := -1
		for index := 0; index < j.count; index++ {
			if j.entries[(j.start+index)%j.maxEntries].ExportedAt != nil {
				exportedIndex = index
				break
			}
		}
		if exportedIndex < 0 {
			return SecurityAuditRecord{}, ErrSecurityAuditCapacity
		}
		j.removeLocked(exportedIndex)
	}
	j.nextSeq++
	if event.EventID == "" {
		event.EventID = eventID("audit", j.nextSeq)
	}
	record := SecurityAuditRecord{
		EventID:   event.EventID,
		Event:     cloneAuditEvent(event),
		State:     SecurityAuditPending,
		CreatedAt: event.OccurredAt,
	}
	index := (j.start + j.count) % j.maxEntries
	j.entries[index] = record
	j.count++
	return cloneSecurityAuditRecord(record), nil
}

func (j *MemorySecurityAuditJournal) CompleteSecurityAudit(_ context.Context, eventID string, outcome mutation.Outcome, details map[string]any) error {
	if j == nil {
		return errors.New("security audit journal is nil")
	}
	if !validMutationOutcome(outcome) {
		return ErrInvalidMutationOutcome
	}
	if !validAuditDetails(details) {
		return ErrInvalidAuditDetails
	}
	clonedDetails, err := cloneJSONMap(details)
	if err != nil {
		return err
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return ErrSecurityAuditNotFound
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	index, ok := j.findIndexLocked(eventID)
	if !ok {
		return ErrSecurityAuditNotFound
	}
	if j.entries[index].State == SecurityAuditCompleted {
		return ErrSecurityAuditCompleted
	}
	now := j.now().UTC()
	j.entries[index].State = SecurityAuditCompleted
	j.entries[index].Outcome = outcome
	j.entries[index].CompletionDetails = clonedDetails
	j.entries[index].CompletedAt = &now
	return nil
}

func (j *MemorySecurityAuditJournal) ListPendingSecurityAudits(_ context.Context) ([]SecurityAuditRecord, error) {
	return j.listByState(SecurityAuditPending, false), nil
}

func (j *MemorySecurityAuditJournal) ListUnexportedSecurityAudits(_ context.Context) ([]SecurityAuditRecord, error) {
	if j == nil {
		return nil, errors.New("security audit journal is nil")
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	result := make([]SecurityAuditRecord, 0, j.count)
	for index := 0; index < j.count; index++ {
		record := j.entries[(j.start+index)%j.maxEntries]
		if record.State == SecurityAuditCompleted && record.ExportedAt == nil {
			result = append(result, cloneSecurityAuditRecord(record))
		}
	}
	return result, nil
}

func (j *MemorySecurityAuditJournal) MarkSecurityAuditExported(_ context.Context, eventID string) error {
	if j == nil {
		return errors.New("security audit journal is nil")
	}
	eventID = strings.TrimSpace(eventID)
	j.mu.Lock()
	defer j.mu.Unlock()
	index, ok := j.findIndexLocked(eventID)
	if !ok {
		return ErrSecurityAuditNotFound
	}
	if j.entries[index].State != SecurityAuditCompleted {
		return fmt.Errorf("%w: record %q is not complete", ErrSecurityAuditCompleted, eventID)
	}
	now := j.now().UTC()
	j.entries[index].ExportedAt = &now
	return nil
}

func (j *MemorySecurityAuditJournal) ReconcilePendingSecurityAudits(_ context.Context) error {
	if j == nil {
		return errors.New("security audit journal is nil")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now().UTC()
	for index := 0; index < j.count; index++ {
		record := &j.entries[(j.start+index)%j.maxEntries]
		if record.State != SecurityAuditPending {
			continue
		}
		record.State = SecurityAuditCompleted
		record.Outcome = mutation.OutcomeUnknown
		record.CompletionDetails = map[string]any{"reason": "pending_reconciled"}
		record.CompletedAt = &now
	}
	return nil
}

func (j *MemorySecurityAuditJournal) listByState(state SecurityAuditState, exported bool) []SecurityAuditRecord {
	if j == nil {
		return nil
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	result := make([]SecurityAuditRecord, 0, j.count)
	for index := 0; index < j.count; index++ {
		record := j.entries[(j.start+index)%j.maxEntries]
		if record.State == state && (exported || record.ExportedAt == nil) {
			result = append(result, cloneSecurityAuditRecord(record))
		}
	}
	return result
}

func (j *MemorySecurityAuditJournal) findIndexLocked(eventID string) (int, bool) {
	for index := 0; index < j.count; index++ {
		physical := (j.start + index) % j.maxEntries
		if j.entries[physical].EventID == eventID {
			return physical, true
		}
	}
	return 0, false
}

func (j *MemorySecurityAuditJournal) findLocked(eventID string) (SecurityAuditRecord, bool) {
	index, ok := j.findIndexLocked(eventID)
	if !ok {
		return SecurityAuditRecord{}, false
	}
	return j.entries[index], true
}

func (j *MemorySecurityAuditJournal) removeLocked(logicalIndex int) {
	for index := logicalIndex; index < j.count-1; index++ {
		current := (j.start + index) % j.maxEntries
		next := (j.start + index + 1) % j.maxEntries
		j.entries[current] = j.entries[next]
	}
	last := (j.start + j.count - 1) % j.maxEntries
	j.entries[last] = SecurityAuditRecord{}
	j.count--
}

// SecurityAuditExporter delivers complete journal records to a host sink.
// Marking a record exported happens only after the sink acknowledges it.
type SecurityAuditExporter struct {
	journal SecurityAuditJournal
	sink    AuditSink
}

func NewSecurityAuditExporter(journal SecurityAuditJournal, sink AuditSink) *SecurityAuditExporter {
	return &SecurityAuditExporter{journal: journal, sink: sink}
}

func (e *SecurityAuditExporter) Export(ctx context.Context) error {
	if e == nil || nilInterface(e.journal) || nilInterface(e.sink) {
		return errors.New("security audit exporter dependencies are required")
	}
	records, err := e.journal.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.State != SecurityAuditCompleted || !validMutationOutcome(record.Outcome) || record.EventID != record.Event.EventID {
			return ErrInvalidEvent
		}
		if err := ValidateAuditEvent(record.Event); err != nil || !validAuditDetails(record.CompletionDetails) {
			return ErrInvalidEvent
		}
		event := record.Event
		event.Details, err = cloneJSONMap(record.Event.Details)
		if err != nil {
			return err
		}
		completionDetails, err := cloneJSONMap(record.CompletionDetails)
		if err != nil {
			return err
		}
		if event.Details == nil {
			event.Details = map[string]any{}
		}
		for key, value := range completionDetails {
			event.Details[key] = value
		}
		event.Details["mutation_outcome"] = string(record.Outcome)
		if err := e.sink.AppendPluginAudit(ctx, event); err != nil {
			return err
		}
		if err := e.journal.MarkSecurityAuditExported(ctx, record.EventID); err != nil {
			return err
		}
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func normalizeJournalEvent(event AuditEvent, now func() time.Time) (AuditEvent, error) {
	return normalizeAuditEvent(event, now)
}

func validMutationOutcome(outcome mutation.Outcome) bool {
	return outcome == mutation.OutcomeCommitted || outcome == mutation.OutcomeNotCommitted || outcome == mutation.OutcomeUnknown
}

func cloneAuditEvent(event AuditEvent) AuditEvent {
	cloned := event
	cloned.Details, _ = cloneJSONMap(event.Details)
	return cloned
}

func cloneSecurityAuditRecord(record SecurityAuditRecord) SecurityAuditRecord {
	cloned := record
	cloned.Event = cloneAuditEvent(record.Event)
	cloned.CompletionDetails, _ = cloneJSONMap(record.CompletionDetails)
	if record.CompletedAt != nil {
		value := *record.CompletedAt
		cloned.CompletedAt = &value
	}
	if record.ExportedAt != nil {
		value := *record.ExportedAt
		cloned.ExportedAt = &value
	}
	return cloned
}

func cloneJSONMap(values map[string]any) (map[string]any, error) {
	if values == nil {
		return nil, nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("security audit details must be JSON: %w", err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, fmt.Errorf("decode security audit details: %w", err)
	}
	return cloned, nil
}

var _ SecurityAuditJournal = (*MemorySecurityAuditJournal)(nil)

// MemoryStore exposes the journal contract as well as the ordinary audit
// sink, allowing a host configured with one in-memory observability adapter
// to retain the same mutation semantics as a persistent store.
func (s *MemoryStore) BeginSecurityAudit(ctx context.Context, event AuditEvent) (SecurityAuditRecord, error) {
	if s == nil {
		return SecurityAuditRecord{}, errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.BeginSecurityAudit(ctx, event)
}

func (s *MemoryStore) CompleteSecurityAudit(ctx context.Context, eventID string, outcome mutation.Outcome, details map[string]any) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.CompleteSecurityAudit(ctx, eventID, outcome, details)
}

func (s *MemoryStore) ListPendingSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.ListPendingSecurityAudits(ctx)
}

func (s *MemoryStore) ListUnexportedSecurityAudits(ctx context.Context) ([]SecurityAuditRecord, error) {
	if s == nil {
		return nil, errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.ListUnexportedSecurityAudits(ctx)
}

func (s *MemoryStore) MarkSecurityAuditExported(ctx context.Context, eventID string) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.MarkSecurityAuditExported(ctx, eventID)
}

func (s *MemoryStore) ReconcilePendingSecurityAudits(ctx context.Context) error {
	if s == nil {
		return errors.New("observability store is nil")
	}
	if s.securityJournal == nil {
		s.securityJournal = NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{Now: s.now, MaxEntries: s.maxAuditEvents})
	}
	return s.securityJournal.ReconcilePendingSecurityAudits(ctx)
}

var _ SecurityAuditJournal = (*MemoryStore)(nil)
