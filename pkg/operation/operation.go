package operation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/executionbinding"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type Status string

const (
	StatusRunning                Status = "running"
	StatusCancelRequested        Status = "cancel_requested"
	StatusCanceled               Status = "canceled"
	StatusCompleted              Status = "completed"
	StatusFailed                 Status = "failed"
	StatusOrphanedAfterDisable   Status = "orphaned_after_disable"
	StatusOrphanedAfterUninstall Status = "orphaned_after_uninstall"
)

const (
	DisableBehaviorCancel = "cancel"
	DisableBehaviorOrphan = "orphan"
	DisableBehaviorWait   = "wait"

	UninstallBehaviorCancelThenBlockDelete = "cancel_then_block_delete"
	UninstallBehaviorForceCleanupAllowed   = "force_cleanup_allowed"

	DefaultListLimit                   = 100
	MaxListLimit                       = 500
	DefaultPruneLimit                  = 500
	MaxPruneLimit                      = 5000
	DefaultMaxTerminalRecordsPerPlugin = 1000
	MaxTerminalRecordsPerPlugin        = 100_000

	DefaultTerminalRetention = 7 * 24 * time.Hour
	SessionRevokedReason     = "session revoked"
)

var (
	ErrNotFound         = errors.New("operation not found")
	ErrInvalidOperation = errors.New("operation is invalid")
	ErrAlreadyExists    = errors.New("operation already exists")
	ErrDeleteBlocked    = errors.New("operation blocks data deletion")
	ErrNotCancelable    = errors.New("operation is not cancelable")
)

type Record struct {
	OperationID string `json:"operation_id"`
	capability.ExecutionBinding
	Status             Status                          `json:"status"`
	Cancelable         bool                            `json:"cancelable"`
	CancelAckTimeoutMS int                             `json:"cancel_ack_timeout_ms,omitempty"`
	DisableBehavior    string                          `json:"disable_behavior,omitempty"`
	UninstallBehavior  string                          `json:"uninstall_behavior,omitempty"`
	FailureCode        capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Reason             string                          `json:"reason,omitempty"`
	CreatedAt          time.Time                       `json:"created_at"`
	UpdatedAt          time.Time                       `json:"updated_at"`
	CancelRequestedAt  *time.Time                      `json:"cancel_requested_at,omitempty"`
	OrphanedAt         *time.Time                      `json:"orphaned_at,omitempty"`
	TerminalAt         *time.Time                      `json:"terminal_at,omitempty"`
}

type RegisterRequest struct {
	OperationID        string                      `json:"operation_id"`
	ExecutionBinding   capability.ExecutionBinding `json:"execution_binding"`
	Cancelable         *bool                       `json:"cancelable,omitempty"`
	CancelAckTimeoutMS int                         `json:"cancel_ack_timeout_ms,omitempty"`
	DisableBehavior    string                      `json:"disable_behavior,omitempty"`
	UninstallBehavior  string                      `json:"uninstall_behavior,omitempty"`
	Now                time.Time                   `json:"-"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	Cursor           *Cursor
	Limit            int        `json:"limit"`
	Owner            OwnerScope `json:"-"`
	AllOwners        bool       `json:"-"`
}

type OwnerScope = capability.ExecutionOwnerScope

func ownerScopeForBinding(binding capability.ExecutionBinding) OwnerScope {
	return binding.OwnerScope()
}

type pluginOwnerKey struct {
	PluginInstanceID string
	OwnerScope
}

type Cursor struct {
	CreatedAt   time.Time
	OperationID string
}

type Page struct {
	Records    []Record
	NextCursor *Cursor
}

type CancelRequest struct {
	OperationID string    `json:"operation_id"`
	Reason      string    `json:"reason,omitempty"`
	Now         time.Time `json:"-"`
}

type FinishRequest struct {
	OperationID string                          `json:"operation_id"`
	Status      Status                          `json:"status"`
	FailureCode capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Reason      string                          `json:"reason,omitempty"`
	Now         time.Time                       `json:"-"`
}

type PluginTransitionRequest struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope `json:"-"`
	Reason           string                   `json:"reason,omitempty"`
	Now              time.Time                `json:"-"`
}

type RevokeSessionScopeRequest struct {
	SessionScope sessionctx.SessionScope `json:"-"`
	Now          time.Time               `json:"-"`
}

type RevokeSessionScopeResult struct {
	Revoked int `json:"revoked"`
}

type PruneRequest struct {
	Before                      time.Time `json:"before"`
	Limit                       int       `json:"limit,omitempty"`
	MaxTerminalRecordsPerPlugin int       `json:"max_terminal_records_per_plugin,omitempty"`
}

type PruneResult struct {
	Deleted int `json:"deleted"`
}

type Store interface {
	Durable() bool
	Register(ctx context.Context, req RegisterRequest) (Record, error)
	List(ctx context.Context, req ListRequest) (Page, error)
	Get(ctx context.Context, operationID string) (Record, error)
	RequestCancel(ctx context.Context, req CancelRequest) (Record, error)
	Finish(ctx context.Context, req FinishRequest) (Record, error)
	MarkPluginDisabled(ctx context.Context, req PluginTransitionRequest) ([]Record, error)
	MarkPluginUninstalled(ctx context.Context, req PluginTransitionRequest) ([]Record, error)
	RevokeSessionScope(ctx context.Context, req RevokeSessionScopeRequest) (RevokeSessionScopeResult, error)
	Prune(ctx context.Context, req PruneRequest) (PruneResult, error)
}

type MemoryStore struct {
	mu                   sync.RWMutex
	now                  func() time.Time
	records              map[string]Record
	order                []string
	pluginOrder          map[string][]string
	ownerOrder           map[OwnerScope][]string
	pluginOwnerOrder     map[pluginOwnerKey][]string
	sessionRevokeScanned uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:              func() time.Time { return time.Now().UTC() },
		records:          map[string]Record{},
		pluginOrder:      map[string][]string{},
		ownerOrder:       map[OwnerScope][]string{},
		pluginOwnerOrder: map[pluginOwnerKey][]string{},
	}
}

func (*MemoryStore) Durable() bool { return false }

func (s *MemoryStore) Register(_ context.Context, req RegisterRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	operationID := strings.TrimSpace(req.OperationID)
	pluginInstanceID := strings.TrimSpace(req.ExecutionBinding.PluginInstanceID)
	method := strings.TrimSpace(req.ExecutionBinding.Method)
	owner := ownerScopeForBinding(req.ExecutionBinding).Normalized()
	if operationID == "" || pluginInstanceID == "" || method == "" || !owner.Valid() {
		return Record{}, ErrInvalidOperation
	}
	if req.CancelAckTimeoutMS < 0 || !registerCancelable(req.Cancelable) && req.CancelAckTimeoutMS != 0 {
		return Record{}, ErrInvalidOperation
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[operationID]; ok {
		return Record{}, ErrAlreadyExists
	}
	binding, err := cloneExecutionBinding(req.ExecutionBinding)
	if err != nil {
		return Record{}, ErrInvalidOperation
	}
	if embeddedID := strings.TrimSpace(binding.OperationID); embeddedID != "" && embeddedID != operationID {
		return Record{}, ErrInvalidOperation
	}
	binding.OperationID = operationID
	record := Record{
		OperationID:        operationID,
		ExecutionBinding:   binding,
		Status:             StatusRunning,
		Cancelable:         registerCancelable(req.Cancelable),
		CancelAckTimeoutMS: req.CancelAckTimeoutMS,
		DisableBehavior:    normalizeDisableBehavior(req.DisableBehavior),
		UninstallBehavior:  normalizeUninstallBehavior(req.UninstallBehavior),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	record.OwnerSessionHash = owner.OwnerSessionHash
	record.OwnerUserHash = owner.OwnerUserHash
	record.OwnerEnvHash = owner.OwnerEnvHash
	record.SessionChannelIDHash = owner.SessionChannelIDHash
	s.records[operationID] = record
	s.order = insertOperationOrder(s.order, s.records, record)
	s.pluginOrder[record.PluginInstanceID] = insertOperationOrder(s.pluginOrder[record.PluginInstanceID], s.records, record)
	s.ownerOrder[owner] = insertOperationOrder(s.ownerOrder[owner], s.records, record)
	pluginOwner := pluginOwnerKey{PluginInstanceID: record.PluginInstanceID, OwnerScope: owner}
	s.pluginOwnerOrder[pluginOwner] = insertOperationOrder(s.pluginOwnerOrder[pluginOwner], s.records, record)
	return cloneRecord(record)
}

func registerCancelable(value *bool) bool {
	if value == nil {
		return true
	}
	return *value
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) (Page, error) {
	if s == nil {
		return Page{}, errors.New("operation store is nil")
	}
	limit, err := normalizeListRequest(&req)
	if err != nil {
		return Page{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	order := s.order
	if !req.AllOwners && req.PluginInstanceID != "" {
		order = s.pluginOwnerOrder[pluginOwnerKey{PluginInstanceID: req.PluginInstanceID, OwnerScope: req.Owner}]
	} else if !req.AllOwners {
		order = s.ownerOrder[req.Owner]
	} else if req.PluginInstanceID != "" {
		order = s.pluginOrder[req.PluginInstanceID]
	}
	start := 0
	if req.Cursor != nil {
		start = sort.Search(len(order), func(index int) bool {
			return recordAfterCursor(s.records[order[index]], *req.Cursor)
		})
	}
	end := min(len(order), start+limit+1)
	records := make([]Record, 0, end-start)
	for _, operationID := range order[start:end] {
		record, err := cloneRecord(s.records[operationID])
		if err != nil {
			return Page{}, err
		}
		records = append(records, record)
	}
	return pageRecords(records, limit), nil
}

func insertOperationOrder(order []string, records map[string]Record, record Record) []string {
	index := sort.Search(len(order), func(index int) bool {
		candidate := records[order[index]]
		return candidate.CreatedAt.Before(record.CreatedAt) || candidate.CreatedAt.Equal(record.CreatedAt) && candidate.OperationID < record.OperationID
	})
	order = append(order, "")
	copy(order[index+1:], order[index:])
	order[index] = record.OperationID
	return order
}

func EncodeCursor(cursor *Cursor) (string, error) {
	if cursor == nil {
		return "", nil
	}
	if err := validateCursor(*cursor); err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
		OperationID       string `json:"operation_id"`
	}{CreatedAtUnixNano: cursor.CreatedAt.UTC().UnixNano(), OperationID: cursor.OperationID})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeCursor(value string) (*Cursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > 1024 {
		return nil, ErrInvalidOperation
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidOperation
	}
	var decoded struct {
		CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
		OperationID       string `json:"operation_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, ErrInvalidOperation
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidOperation
	}
	cursor := &Cursor{CreatedAt: time.Unix(0, decoded.CreatedAtUnixNano).UTC(), OperationID: decoded.OperationID}
	if err := validateCursor(*cursor); err != nil {
		return nil, err
	}
	return cursor, nil
}

func normalizeListRequest(req *ListRequest) (int, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.Owner = req.Owner.Normalized()
	if (req.AllOwners && req.Owner.Valid()) || (!req.AllOwners && !req.Owner.Valid()) {
		return 0, ErrInvalidOperation
	}
	limit := req.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 1 || limit > MaxListLimit {
		return 0, ErrInvalidOperation
	}
	if req.Cursor != nil {
		if err := validateCursor(*req.Cursor); err != nil {
			return 0, err
		}
	}
	return limit, nil
}

func validateCursor(cursor Cursor) error {
	if cursor.CreatedAt.IsZero() || strings.TrimSpace(cursor.OperationID) == "" {
		return ErrInvalidOperation
	}
	return nil
}

func recordAfterCursor(record Record, cursor Cursor) bool {
	return record.CreatedAt.Before(cursor.CreatedAt) || record.CreatedAt.Equal(cursor.CreatedAt) && record.OperationID < cursor.OperationID
}

func pageRecords(records []Record, limit int) Page {
	page := Page{Records: records}
	if len(records) <= limit {
		return page
	}
	page.Records = records[:limit]
	last := page.Records[len(page.Records)-1]
	page.NextCursor = &Cursor{CreatedAt: last.CreatedAt, OperationID: last.OperationID}
	return page
}

func (s *MemoryStore) Get(_ context.Context, operationID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[strings.TrimSpace(operationID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record)
}

func (s *MemoryStore) RequestCancel(_ context.Context, req CancelRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(req.OperationID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if !terminal(record.Status) && !record.Cancelable {
		return Record{}, ErrNotCancelable
	}
	record = requestCancel(record, now, req.Reason)
	s.records[record.OperationID] = record
	return cloneRecord(record)
}

func (s *MemoryStore) Finish(_ context.Context, req FinishRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	if !finishStatus(req.Status) {
		return Record{}, ErrInvalidOperation
	}
	failureCode, reason, err := normalizeFinishOutcome(req.Status, req.FailureCode, req.Reason)
	if err != nil {
		return Record{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(req.OperationID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if terminal(record.Status) {
		return cloneRecord(record)
	}
	record.Status = req.Status
	record.FailureCode = failureCode
	record.Reason = reason
	record.UpdatedAt = now
	record.TerminalAt = &now
	s.records[record.OperationID] = record
	return cloneRecord(record)
}

func normalizeFinishOutcome(status Status, failureCode capability.ExecutionFailureCode, reason string) (capability.ExecutionFailureCode, string, error) {
	if status == StatusFailed {
		if !failureCode.Valid() || strings.TrimSpace(reason) != "" {
			return "", "", ErrInvalidOperation
		}
		return failureCode, capability.ExecutionFailureMessage, nil
	}
	if failureCode != "" {
		return "", "", ErrInvalidOperation
	}
	return "", reason, nil
}

func (s *MemoryStore) MarkPluginDisabled(_ context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	pluginInstanceID, ownerEnvHash, err := normalizePluginTransition(req)
	if err != nil {
		return nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var changed []Record
	for id, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID || record.OwnerEnvHash != ownerEnvHash || terminal(record.Status) {
			continue
		}
		switch record.DisableBehavior {
		case DisableBehaviorWait:
			continue
		case DisableBehaviorOrphan:
			record = markOrphaned(record, StatusOrphanedAfterDisable, now, req.Reason)
		default:
			record = requestCancel(record, now, req.Reason)
		}
		s.records[id] = record
		cloned, err := cloneRecord(record)
		if err != nil {
			return nil, err
		}
		changed = append(changed, cloned)
	}
	return changed, nil
}

func (s *MemoryStore) MarkPluginUninstalled(_ context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	pluginInstanceID, ownerEnvHash, err := normalizePluginTransition(req)
	if err != nil {
		return nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var changed []Record
	for id, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID || record.OwnerEnvHash != ownerEnvHash || terminal(record.Status) {
			continue
		}
		if record.UninstallBehavior == UninstallBehaviorForceCleanupAllowed {
			record = markOrphaned(record, StatusOrphanedAfterUninstall, now, req.Reason)
		} else {
			record = requestCancel(record, now, req.Reason)
		}
		s.records[id] = record
		cloned, err := cloneRecord(record)
		if err != nil {
			return nil, err
		}
		changed = append(changed, cloned)
	}
	return changed, nil
}

func (s *MemoryStore) RevokeSessionScope(_ context.Context, req RevokeSessionScopeRequest) (RevokeSessionScopeResult, error) {
	if s == nil {
		return RevokeSessionScopeResult{}, errors.New("operation store is nil")
	}
	if err := req.SessionScope.Validate(); err != nil {
		return RevokeSessionScopeResult{}, ErrInvalidOperation
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	owner := OwnerScope{
		OwnerSessionHash:     req.SessionScope.OwnerSessionHash,
		OwnerUserHash:        req.SessionScope.OwnerUserHash,
		OwnerEnvHash:         req.SessionScope.OwnerEnvHash,
		SessionChannelIDHash: req.SessionScope.SessionChannelIDHash,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionRevokeScanned = 0
	revoked := 0
	for _, operationID := range s.ownerOrder[owner] {
		s.sessionRevokeScanned++
		record, ok := s.records[operationID]
		if !ok {
			continue
		}
		if !terminal(record.Status) {
			record.Status = StatusCanceled
			record.FailureCode = ""
			record.Reason = SessionRevokedReason
			record.UpdatedAt = now
			record.TerminalAt = &now
			s.records[operationID] = record
		}
		if record.Status == StatusCanceled && record.Reason == SessionRevokedReason {
			revoked++
		}
	}
	return RevokeSessionScopeResult{Revoked: revoked}, nil
}

func (s *MemoryStore) Prune(_ context.Context, req PruneRequest) (PruneResult, error) {
	if s == nil {
		return PruneResult{}, errors.New("operation store is nil")
	}
	before, limit, maxRecordsPerPlugin, err := normalizePruneRequest(req)
	if err != nil {
		return PruneResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type retentionKey struct {
		OwnerEnvHash     string
		PluginInstanceID string
	}
	terminalByPlugin := make(map[retentionKey][]Record)
	for _, record := range s.records {
		if terminal(record.Status) && record.TerminalAt != nil {
			key := retentionKey{OwnerEnvHash: record.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID}
			terminalByPlugin[key] = append(terminalByPlugin[key], record)
		}
	}
	candidates := make([]Record, 0)
	for _, records := range terminalByPlugin {
		sort.Slice(records, func(i, j int) bool {
			if records[i].TerminalAt.Equal(*records[j].TerminalAt) {
				return records[i].OperationID > records[j].OperationID
			}
			return records[i].TerminalAt.After(*records[j].TerminalAt)
		})
		for index, record := range records {
			if record.TerminalAt.Before(before) || index >= maxRecordsPerPlugin {
				candidates = append(candidates, record)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].TerminalAt.Equal(*candidates[j].TerminalAt) {
			return candidates[i].OperationID < candidates[j].OperationID
		}
		return candidates[i].TerminalAt.Before(*candidates[j].TerminalAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	if len(candidates) == 0 {
		return PruneResult{}, nil
	}
	deleted := make(map[string]struct{}, len(candidates))
	for _, record := range candidates {
		delete(s.records, record.OperationID)
		deleted[record.OperationID] = struct{}{}
	}
	s.order = removeOperationIDs(s.order, deleted)
	for pluginInstanceID, order := range s.pluginOrder {
		order = removeOperationIDs(order, deleted)
		if len(order) == 0 {
			delete(s.pluginOrder, pluginInstanceID)
		} else {
			s.pluginOrder[pluginInstanceID] = order
		}
	}
	for owner, order := range s.ownerOrder {
		order = removeOperationIDs(order, deleted)
		if len(order) == 0 {
			delete(s.ownerOrder, owner)
		} else {
			s.ownerOrder[owner] = order
		}
	}
	for owner, order := range s.pluginOwnerOrder {
		order = removeOperationIDs(order, deleted)
		if len(order) == 0 {
			delete(s.pluginOwnerOrder, owner)
		} else {
			s.pluginOwnerOrder[owner] = order
		}
	}
	return PruneResult{Deleted: len(candidates)}, nil
}

func normalizePluginTransition(req PluginTransitionRequest) (string, string, error) {
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" || req.ResourceScope.Kind != sessionctx.ScopeEnvironment || req.ResourceScope.Validate() != nil {
		return "", "", ErrInvalidOperation
	}
	return pluginInstanceID, req.ResourceScope.OwnerEnvHash, nil
}

func removeOperationIDs(order []string, deleted map[string]struct{}) []string {
	kept := order[:0]
	for _, operationID := range order {
		if _, ok := deleted[operationID]; !ok {
			kept = append(kept, operationID)
		}
	}
	return kept
}

func normalizePruneRequest(req PruneRequest) (time.Time, int, int, error) {
	if req.Before.IsZero() {
		return time.Time{}, 0, 0, ErrInvalidOperation
	}
	limit := req.Limit
	if limit == 0 {
		limit = DefaultPruneLimit
	}
	if limit < 1 || limit > MaxPruneLimit {
		return time.Time{}, 0, 0, ErrInvalidOperation
	}
	maxRecordsPerPlugin := req.MaxTerminalRecordsPerPlugin
	if maxRecordsPerPlugin == 0 {
		maxRecordsPerPlugin = DefaultMaxTerminalRecordsPerPlugin
	}
	if maxRecordsPerPlugin < 1 || maxRecordsPerPlugin > MaxTerminalRecordsPerPlugin {
		return time.Time{}, 0, 0, ErrInvalidOperation
	}
	return req.Before.UTC(), limit, maxRecordsPerPlugin, nil
}

func requestCancel(record Record, now time.Time, reason string) Record {
	if terminal(record.Status) {
		return record
	}
	record.Status = StatusCancelRequested
	record.Reason = reason
	record.UpdatedAt = now
	record.CancelRequestedAt = &now
	return record
}

func markOrphaned(record Record, status Status, now time.Time, reason string) Record {
	record.Status = status
	record.Reason = reason
	record.UpdatedAt = now
	record.OrphanedAt = &now
	record.TerminalAt = &now
	return record
}

func terminal(status Status) bool {
	switch status {
	case StatusCanceled, StatusCompleted, StatusFailed, StatusOrphanedAfterDisable, StatusOrphanedAfterUninstall:
		return true
	default:
		return false
	}
}

func finishStatus(status Status) bool {
	switch status {
	case StatusCanceled, StatusCompleted, StatusFailed:
		return true
	default:
		return false
	}
}

func normalizeDisableBehavior(behavior string) string {
	switch behavior {
	case DisableBehaviorOrphan, DisableBehaviorWait:
		return behavior
	default:
		return DisableBehaviorCancel
	}
}

func normalizeUninstallBehavior(behavior string) string {
	switch behavior {
	case UninstallBehaviorForceCleanupAllowed:
		return behavior
	default:
		return UninstallBehaviorCancelThenBlockDelete
	}
}

func cloneExecutionBinding(binding capability.ExecutionBinding) (capability.ExecutionBinding, error) {
	return capability.CloneExecutionBinding(binding)
}

func cloneRecord(record Record) (Record, error) {
	record.ExecutionBinding = executionbinding.CloneTrusted(record.ExecutionBinding)
	if record.CancelRequestedAt != nil {
		value := *record.CancelRequestedAt
		record.CancelRequestedAt = &value
	}
	if record.OrphanedAt != nil {
		value := *record.OrphanedAt
		record.OrphanedAt = &value
	}
	if record.TerminalAt != nil {
		value := *record.TerminalAt
		record.TerminalAt = &value
	}
	return record, nil
}
