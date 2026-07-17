package secrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ScopeUser        = "user"
	ScopeEnvironment = "environment"
)

var ErrInvalidSecretRef = errors.New("secret_ref is invalid")

type Store interface {
	BindSecretRef(ctx context.Context, req BindRequest) error
	DeleteSecretRef(ctx context.Context, req DeleteRequest) error
	TestSecretRef(ctx context.Context, req TestRequest) error
}

type Lister interface {
	List(ctx context.Context, req ListRequest) ([]Record, error)
}

type PluginDeleter interface {
	DeletePlugin(ctx context.Context, pluginInstanceID string) error
}

type BindRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	SecretRef        string `json:"secret_ref"`
	Scope            string `json:"scope"`
}

type DeleteRequest = BindRequest
type TestRequest = BindRequest

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	Scope            string `json:"scope,omitempty"`
	BoundOnly        bool   `json:"bound_only,omitempty"`
}

type Record struct {
	PluginInstanceID string     `json:"plugin_instance_id"`
	SecretRef        string     `json:"secret_ref"`
	Scope            string     `json:"scope"`
	Bound            bool       `json:"bound"`
	LastTestStatus   string     `json:"last_test_status,omitempty"`
	BoundAt          *time.Time `json:"bound_at,omitempty"`
	TestedAt         *time.Time `json:"tested_at,omitempty"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type MemoryStoreOptions struct {
	Now func() time.Time
}

type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]Record
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
	return &MemoryStore{
		now:     now,
		records: map[string]Record{},
	}
}

func (s *MemoryStore) BindSecretRef(_ context.Context, req BindRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(req)
	if err != nil {
		return err
	}
	now := s.now()
	record := Record{
		PluginInstanceID: normalized.PluginInstanceID,
		SecretRef:        normalized.SecretRef,
		Scope:            normalized.Scope,
		Bound:            true,
		BoundAt:          &now,
		UpdatedAt:        now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[recordKey(normalized)] = record
	return nil
}

func (s *MemoryStore) TestSecretRef(_ context.Context, req TestRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(BindRequest(req))
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[recordKey(normalized)]
	if !ok || !record.Bound {
		return fmt.Errorf("%w: secret_ref must be bound before testing", ErrInvalidSecretRef)
	}
	record.PluginInstanceID = normalized.PluginInstanceID
	record.SecretRef = normalized.SecretRef
	record.Scope = normalized.Scope
	record.Bound = true
	if record.BoundAt == nil {
		record.BoundAt = &now
	}
	record.LastTestStatus = "passed"
	record.TestedAt = &now
	record.DeletedAt = nil
	record.UpdatedAt = now
	s.records[recordKey(normalized)] = record
	return nil
}

func (s *MemoryStore) DeleteSecretRef(_ context.Context, req DeleteRequest) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	normalized, err := normalizeRequest(BindRequest(req))
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[recordKey(normalized)]
	record.PluginInstanceID = normalized.PluginInstanceID
	record.SecretRef = normalized.SecretRef
	record.Scope = normalized.Scope
	record.Bound = false
	record.LastTestStatus = ""
	record.DeletedAt = &now
	record.UpdatedAt = now
	s.records[recordKey(normalized)] = record
	return nil
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("secret store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	scope := strings.TrimSpace(req.Scope)
	if scope != "" && scope != ScopeUser && scope != ScopeEnvironment {
		return nil, ErrInvalidSecretRef
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		if scope != "" && record.Scope != scope {
			continue
		}
		if req.BoundOnly && !record.Bound {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func (s *MemoryStore) DeletePlugin(_ context.Context, pluginInstanceID string) error {
	if s == nil {
		return errors.New("secret store is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidSecretRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.records {
		if record.PluginInstanceID == pluginInstanceID {
			delete(s.records, key)
		}
	}
	return nil
}

func normalizeRequest(req BindRequest) (BindRequest, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.SecretRef = strings.TrimSpace(req.SecretRef)
	req.Scope = strings.TrimSpace(req.Scope)
	if req.PluginInstanceID == "" || req.SecretRef == "" {
		return BindRequest{}, ErrInvalidSecretRef
	}
	if req.Scope != ScopeUser && req.Scope != ScopeEnvironment {
		return BindRequest{}, fmt.Errorf("%w: scope must be user or environment", ErrInvalidSecretRef)
	}
	return req, nil
}

func recordKey(req BindRequest) string {
	return req.PluginInstanceID + "\x00" + req.Scope + "\x00" + req.SecretRef
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginInstanceID != records[j].PluginInstanceID {
			return records[i].PluginInstanceID < records[j].PluginInstanceID
		}
		if records[i].Scope != records[j].Scope {
			return records[i].Scope < records[j].Scope
		}
		return records[i].SecretRef < records[j].SecretRef
	})
}

func cloneRecord(record Record) Record {
	record.BoundAt = cloneTimePointer(record.BoundAt)
	record.TestedAt = cloneTimePointer(record.TestedAt)
	record.DeletedAt = cloneTimePointer(record.DeletedAt)
	return record
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

var _ Store = (*MemoryStore)(nil)
var _ Lister = (*MemoryStore)(nil)
var _ PluginDeleter = (*MemoryStore)(nil)
