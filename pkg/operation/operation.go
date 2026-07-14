package operation

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
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
	Status             Status     `json:"status"`
	Cancelable         bool       `json:"cancelable"`
	CancelAckTimeoutMS int        `json:"cancel_ack_timeout_ms,omitempty"`
	DisableBehavior    string     `json:"disable_behavior,omitempty"`
	UninstallBehavior  string     `json:"uninstall_behavior,omitempty"`
	Reason             string     `json:"reason,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	CancelRequestedAt  *time.Time `json:"cancel_requested_at,omitempty"`
	OrphanedAt         *time.Time `json:"orphaned_at,omitempty"`
}

type RegisterRequest struct {
	OperationID        string                      `json:"operation_id"`
	ExecutionBinding   capability.ExecutionBinding `json:"execution_binding"`
	Cancelable         *bool                       `json:"cancelable,omitempty"`
	CancelAckTimeoutMS int                         `json:"cancel_ack_timeout_ms,omitempty"`
	DisableBehavior    string                      `json:"disable_behavior,omitempty"`
	UninstallBehavior  string                      `json:"uninstall_behavior,omitempty"`
	Now                time.Time                   `json:"now,omitempty"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type CancelRequest struct {
	OperationID string    `json:"operation_id"`
	Reason      string    `json:"reason,omitempty"`
	Now         time.Time `json:"now,omitempty"`
}

type FinishRequest struct {
	OperationID string    `json:"operation_id"`
	Status      Status    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	Now         time.Time `json:"now,omitempty"`
}

type PluginTransitionRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type Store interface {
	Register(ctx context.Context, req RegisterRequest) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	Get(ctx context.Context, operationID string) (Record, error)
	RequestCancel(ctx context.Context, req CancelRequest) (Record, error)
	Finish(ctx context.Context, req FinishRequest) (Record, error)
	MarkPluginDisabled(ctx context.Context, req PluginTransitionRequest) ([]Record, error)
	MarkPluginUninstalled(ctx context.Context, req PluginTransitionRequest) ([]Record, error)
}

type MemoryStore struct {
	mu      sync.RWMutex
	now     func() time.Time
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:     func() time.Time { return time.Now().UTC() },
		records: map[string]Record{},
	}
}

func (s *MemoryStore) Register(_ context.Context, req RegisterRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	operationID := strings.TrimSpace(req.OperationID)
	pluginInstanceID := strings.TrimSpace(req.ExecutionBinding.PluginInstanceID)
	method := strings.TrimSpace(req.ExecutionBinding.Method)
	if operationID == "" || pluginInstanceID == "" || method == "" {
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
	s.records[operationID] = record
	return cloneRecord(record), nil
}

func registerCancelable(value *bool) bool {
	if value == nil {
		return true
	}
	return *value
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if req.PluginInstanceID != "" && record.PluginInstanceID != req.PluginInstanceID {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].OperationID < records[j].OperationID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	return records, nil
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
	return cloneRecord(record), nil
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
	return cloneRecord(record), nil
}

func (s *MemoryStore) Finish(_ context.Context, req FinishRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("operation store is nil")
	}
	if !finishStatus(req.Status) {
		return Record{}, ErrInvalidOperation
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
		return cloneRecord(record), nil
	}
	record.Status = req.Status
	record.Reason = req.Reason
	record.UpdatedAt = now
	s.records[record.OperationID] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) MarkPluginDisabled(_ context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var changed []Record
	for id, record := range s.records {
		if record.PluginInstanceID != req.PluginInstanceID || terminal(record.Status) {
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
		changed = append(changed, cloneRecord(record))
	}
	return changed, nil
}

func (s *MemoryStore) MarkPluginUninstalled(_ context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("operation store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var changed []Record
	for id, record := range s.records {
		if record.PluginInstanceID != req.PluginInstanceID || terminal(record.Status) {
			continue
		}
		if record.UninstallBehavior == UninstallBehaviorForceCleanupAllowed {
			record = markOrphaned(record, StatusOrphanedAfterUninstall, now, req.Reason)
		} else {
			record = requestCancel(record, now, req.Reason)
		}
		s.records[id] = record
		changed = append(changed, cloneRecord(record))
	}
	return changed, nil
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
	raw, err := json.Marshal(binding)
	if err != nil {
		return capability.ExecutionBinding{}, err
	}
	var cloned capability.ExecutionBinding
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return capability.ExecutionBinding{}, err
	}
	return cloned, nil
}

func cloneRecord(record Record) Record {
	binding, err := cloneExecutionBinding(record.ExecutionBinding)
	if err == nil {
		record.ExecutionBinding = binding
	}
	if record.CancelRequestedAt != nil {
		value := *record.CancelRequestedAt
		record.CancelRequestedAt = &value
	}
	if record.OrphanedAt != nil {
		value := *record.OrphanedAt
		record.OrphanedAt = &value
	}
	return record
}
