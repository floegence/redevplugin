package observability

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
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
			return cloneSecurityAuditRecord(existing)
		}
	}
	nextSeq := j.nextSeq + 1
	if event.EventID == "" {
		event.EventID = eventID("audit", nextSeq)
	}
	record := SecurityAuditRecord{
		EventID:   event.EventID,
		Event:     event,
		State:     SecurityAuditPending,
		CreatedAt: event.OccurredAt,
	}
	snapshot, err := cloneSecurityAuditRecord(record)
	if err != nil {
		return SecurityAuditRecord{}, err
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
	j.nextSeq = nextSeq
	index := (j.start + j.count) % j.maxEntries
	j.entries[index] = record
	j.count++
	return snapshot, nil
}

func (j *MemorySecurityAuditJournal) CompleteSecurityAudit(_ context.Context, eventID string, outcome mutation.Outcome, details map[string]any) error {
	if j == nil {
		return errors.New("security audit journal is nil")
	}
	if !validMutationOutcome(outcome) {
		return ErrInvalidMutationOutcome
	}
	clonedDetails, err := cloneAuditDetails(details)
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
	return j.listByState(SecurityAuditPending)
}

func (j *MemorySecurityAuditJournal) ListUnexportedSecurityAudits(_ context.Context) ([]SecurityAuditRecord, error) {
	return j.listByState(SecurityAuditCompleted)
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

func (j *MemorySecurityAuditJournal) listByState(state SecurityAuditState) ([]SecurityAuditRecord, error) {
	if j == nil {
		return nil, errors.New("security audit journal is nil")
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	result := make([]SecurityAuditRecord, 0, j.count)
	for index := 0; index < j.count; index++ {
		record := j.entries[(j.start+index)%j.maxEntries]
		if record.State == state && record.ExportedAt == nil {
			cloned, err := cloneSecurityAuditRecord(record)
			if err != nil {
				return nil, err
			}
			result = append(result, cloned)
		}
	}
	return result, nil
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
		record, err = cloneSecurityAuditRecord(record)
		if err != nil {
			return errors.Join(ErrInvalidEvent, err)
		}
		if record.State != SecurityAuditCompleted || !validMutationOutcome(record.Outcome) || record.EventID != record.Event.EventID {
			return ErrInvalidEvent
		}
		if err := ValidateAuditEvent(record.Event); err != nil || !validAuditDetails(record.CompletionDetails) {
			return ErrInvalidEvent
		}
		event := record.Event
		completionDetails := record.CompletionDetails
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

func cloneAuditEvent(event AuditEvent) (AuditEvent, error) {
	cloned := event
	var err error
	cloned.Details, err = cloneAuditDetails(event.Details)
	if err != nil {
		return AuditEvent{}, err
	}
	return cloned, nil
}

func cloneSecurityAuditRecord(record SecurityAuditRecord) (SecurityAuditRecord, error) {
	cloned := record
	var err error
	cloned.Event, err = cloneAuditEvent(record.Event)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	cloned.CompletionDetails, err = cloneAuditDetails(record.CompletionDetails)
	if err != nil {
		return SecurityAuditRecord{}, err
	}
	if record.CompletedAt != nil {
		value := *record.CompletedAt
		cloned.CompletedAt = &value
	}
	if record.ExportedAt != nil {
		value := *record.ExportedAt
		cloned.ExportedAt = &value
	}
	return cloned, nil
}

func cloneAuditDetails(values map[string]any) (map[string]any, error) {
	if values == nil {
		return nil, nil
	}
	if hashes, ok := values["target_descriptor_hashes"]; ok {
		switch typed := hashes.(type) {
		case []string:
			if len(typed) > jsonvalue.MaxCanonicalNodes {
				return nil, ErrInvalidAuditDetails
			}
		case []any:
			if len(typed) > jsonvalue.MaxCanonicalNodes {
				return nil, ErrInvalidAuditDetails
			}
		}
	}
	if !validAuditDetails(values) {
		return nil, ErrInvalidAuditDetails
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		clonedValue, err := cloneAuditDetail(key, value)
		if err != nil {
			return nil, err
		}
		cloned[key] = clonedValue
	}
	if !validAuditDetails(cloned) {
		return nil, ErrInvalidAuditDetails
	}
	if err := jsonvalue.ValidateCanonical(cloned); err != nil {
		return nil, ErrInvalidAuditDetails
	}
	return cloned, nil
}

func cloneAuditDetail(key string, value any) (any, error) {
	switch key {
	case "audit_correlation_id", "effect", "execution", "intent_id", "invocation_id", "method", "operation_id",
		"plan_hash", "preflight_method", "route_kind", "runtime_generation_id", "runtime_instance_id",
		"source_plugin_instance_id", "status", "stream_id", "target_descriptor_sha256", "capability_contract_artifact",
		"reason", "mutation_outcome":
		text, ok := auditString(value)
		if !ok {
			return nil, ErrInvalidAuditDetails
		}
		return text, nil
	case "channel_scoped", "delete_data", "runtime_revoked", "runtime_stopped":
		flag, ok := value.(bool)
		if !ok {
			return nil, ErrInvalidAuditDetails
		}
		return flag, nil
	case "closed_socket_count", "closed_storage_handle_count", "closed_stream_count", "confirmation_count",
		"execution_count", "expires_at_unix_ms", "management_revision", "policy_revision", "revoke_epoch",
		"revoked_surface_count", "surface_count", "token_count":
		number, ok := auditIntegerFloat64(value)
		if !ok {
			return nil, ErrInvalidAuditDetails
		}
		return number, nil
	case "target_descriptor_hashes":
		return cloneAuditStringArray(value)
	case "failure":
		return clonePersistedFailure(value)
	default:
		return nil, ErrInvalidAuditDetails
	}
}

func auditIntegerFloat64(value any) (float64, bool) {
	if !validAuditInteger(value) {
		return 0, false
	}
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

func cloneAuditStringArray(value any) ([]any, error) {
	switch values := value.(type) {
	case []string:
		if values == nil {
			return []any{}, nil
		}
		cloned := make([]any, len(values))
		for index, item := range values {
			cloned[index] = item
		}
		return cloned, nil
	case []any:
		if values == nil {
			return []any{}, nil
		}
		cloned := make([]any, len(values))
		for index, item := range values {
			text, ok := item.(string)
			if !ok {
				return nil, ErrInvalidAuditDetails
			}
			cloned[index] = text
		}
		return cloned, nil
	default:
		return nil, ErrInvalidAuditDetails
	}
}

func clonePersistedFailure(value any) (map[string]any, error) {
	var failure Failure
	switch typed := value.(type) {
	case Failure:
		failure = typed
	case *Failure:
		if typed == nil {
			return nil, ErrInvalidAuditDetails
		}
		failure = *typed
	case map[string]any:
		if len(typed) != 3 {
			return nil, ErrInvalidAuditDetails
		}
		code, codeOK := typed["code"].(string)
		component, componentOK := typed["component"].(string)
		operation, operationOK := typed["operation"].(string)
		if !codeOK || !componentOK || !operationOK {
			return nil, ErrInvalidAuditDetails
		}
		failure = Failure{Code: FailureCode(code), Component: FailureComponent(component), Operation: FailureOperation(operation)}
	default:
		return nil, ErrInvalidAuditDetails
	}
	if !failure.Valid() {
		return nil, ErrInvalidAuditDetails
	}
	return map[string]any{
		"code": string(failure.Code), "component": string(failure.Component), "operation": string(failure.Operation),
	}, nil
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
