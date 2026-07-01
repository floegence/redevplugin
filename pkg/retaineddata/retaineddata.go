package retaineddata

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type State string

const (
	StateRetained              State = "retained"
	StateExpired               State = "expired"
	StateBound                 State = "bound"
	StateDeleted               State = "deleted"
	StateDeleteFailedRetryable State = "delete_failed_retryable"
)

var (
	ErrNotFound      = errors.New("retained data record not found")
	ErrInvalidRecord = errors.New("retained data record is invalid")
)

type Record struct {
	RetainedID             string            `json:"retained_id"`
	SourcePluginInstanceID string            `json:"source_plugin_instance_id"`
	BoundPluginInstanceID  string            `json:"bound_plugin_instance_id,omitempty"`
	PublisherID            string            `json:"publisher_id"`
	PluginID               string            `json:"plugin_id"`
	Version                string            `json:"version"`
	PackageHash            string            `json:"package_hash"`
	ManifestHash           string            `json:"manifest_hash"`
	State                  State             `json:"state"`
	StorageRetained        bool              `json:"storage_retained"`
	SettingsRetained       bool              `json:"settings_retained"`
	BrowserSiteRetained    bool              `json:"browser_site_retained"`
	UsageBytes             int64             `json:"usage_bytes,omitempty"`
	DeleteAfter            *time.Time        `json:"delete_after,omitempty"`
	DeleteError            string            `json:"delete_error,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	RetainedAt             time.Time         `json:"retained_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
	BoundAt                *time.Time        `json:"bound_at,omitempty"`
	DeletedAt              *time.Time        `json:"deleted_at,omitempty"`
	LastAccessedAt         *time.Time        `json:"last_accessed_at,omitempty"`
}

type RetainRequest struct {
	RetainedID             string            `json:"retained_id"`
	SourcePluginInstanceID string            `json:"source_plugin_instance_id"`
	PublisherID            string            `json:"publisher_id"`
	PluginID               string            `json:"plugin_id"`
	Version                string            `json:"version"`
	PackageHash            string            `json:"package_hash"`
	ManifestHash           string            `json:"manifest_hash"`
	StorageRetained        bool              `json:"storage_retained"`
	SettingsRetained       bool              `json:"settings_retained"`
	BrowserSiteRetained    bool              `json:"browser_site_retained"`
	UsageBytes             int64             `json:"usage_bytes,omitempty"`
	DeleteAfter            *time.Time        `json:"delete_after,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	Now                    time.Time         `json:"now,omitempty"`
}

type BindRequest struct {
	RetainedID            string    `json:"retained_id"`
	BoundPluginInstanceID string    `json:"bound_plugin_instance_id"`
	Now                   time.Time `json:"now,omitempty"`
}

type DeleteRequest struct {
	RetainedID string    `json:"retained_id"`
	Now        time.Time `json:"now,omitempty"`
}

type DeleteFailedRequest struct {
	RetainedID  string    `json:"retained_id"`
	DeleteError string    `json:"delete_error,omitempty"`
	Now         time.Time `json:"now,omitempty"`
}

type TouchRequest struct {
	RetainedID string    `json:"retained_id"`
	Now        time.Time `json:"now,omitempty"`
}

type ListRequest struct {
	PublisherID            string `json:"publisher_id,omitempty"`
	PluginID               string `json:"plugin_id,omitempty"`
	SourcePluginInstanceID string `json:"source_plugin_instance_id,omitempty"`
	State                  State  `json:"state,omitempty"`
}

type Store interface {
	Retain(ctx context.Context, req RetainRequest) (Record, error)
	Get(ctx context.Context, retainedID string) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	MarkBound(ctx context.Context, req BindRequest) (Record, error)
	MarkDeleted(ctx context.Context, req DeleteRequest) (Record, error)
	MarkDeleteFailed(ctx context.Context, req DeleteFailedRequest) (Record, error)
	Touch(ctx context.Context, req TouchRequest) (Record, error)
	ExpireBefore(ctx context.Context, now time.Time) ([]Record, error)
	Delete(ctx context.Context, retainedID string) error
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

func NewRetainedID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "retained_" + hex.EncodeToString(buf[:]), nil
}

func (s *MemoryStore) Retain(_ context.Context, req RetainRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	record, err := recordFromRetain(req, now)
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[record.RetainedID]; ok {
		return cloneRecord(existing), nil
	}
	s.records[record.RetainedID] = cloneRecord(record)
	return record, nil
}

func (s *MemoryStore) Get(_ context.Context, retainedID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	retainedID = normalizeID(retainedID)
	if retainedID == "" {
		return Record{}, ErrInvalidRecord
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[retainedID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("retained data store is nil")
	}
	if req.State != "" && !validState(req.State) {
		return nil, ErrInvalidRecord
	}
	publisherID := normalizeID(req.PublisherID)
	pluginID := normalizeID(req.PluginID)
	sourcePluginInstanceID := normalizeID(req.SourcePluginInstanceID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if publisherID != "" && record.PublisherID != publisherID {
			continue
		}
		if pluginID != "" && record.PluginID != pluginID {
			continue
		}
		if sourcePluginInstanceID != "" && record.SourcePluginInstanceID != sourcePluginInstanceID {
			continue
		}
		if req.State != "" && record.State != req.State {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func (s *MemoryStore) MarkBound(_ context.Context, req BindRequest) (Record, error) {
	return s.update(normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State != StateRetained {
			return record, nil
		}
		boundPluginInstanceID := normalizeID(req.BoundPluginInstanceID)
		if boundPluginInstanceID == "" {
			return Record{}, ErrInvalidRecord
		}
		record.State = StateBound
		record.BoundPluginInstanceID = boundPluginInstanceID
		record.DeleteError = ""
		record.UpdatedAt = now
		record.BoundAt = &now
		return record, nil
	})
}

func (s *MemoryStore) MarkDeleted(_ context.Context, req DeleteRequest) (Record, error) {
	return s.update(normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateBound || record.State == StateDeleted {
			return record, nil
		}
		record.State = StateDeleted
		record.DeleteError = ""
		record.UpdatedAt = now
		record.DeletedAt = &now
		return record, nil
	})
}

func (s *MemoryStore) MarkDeleteFailed(_ context.Context, req DeleteFailedRequest) (Record, error) {
	return s.update(normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateBound || record.State == StateDeleted {
			return record, nil
		}
		record.State = StateDeleteFailedRetryable
		record.DeleteError = strings.TrimSpace(req.DeleteError)
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *MemoryStore) Touch(_ context.Context, req TouchRequest) (Record, error) {
	return s.update(normalizeID(req.RetainedID), req.Now, func(record Record, now time.Time) (Record, error) {
		if record.State == StateDeleted {
			return record, nil
		}
		record.LastAccessedAt = &now
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *MemoryStore) ExpireBefore(_ context.Context, now time.Time) ([]Record, error) {
	if s == nil {
		return nil, errors.New("retained data store is nil")
	}
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := []Record{}
	for id, record := range s.records {
		if record.State != StateRetained || record.DeleteAfter == nil || record.DeleteAfter.After(now) {
			continue
		}
		record.State = StateExpired
		record.UpdatedAt = now
		s.records[id] = cloneRecord(record)
		changed = append(changed, cloneRecord(record))
	}
	sortRecords(changed)
	return changed, nil
}

func (s *MemoryStore) Delete(_ context.Context, retainedID string) error {
	if s == nil {
		return errors.New("retained data store is nil")
	}
	retainedID = normalizeID(retainedID)
	if retainedID == "" {
		return ErrInvalidRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[retainedID]; !ok {
		return ErrNotFound
	}
	delete(s.records, retainedID)
	return nil
}

func (s *MemoryStore) update(retainedID string, now time.Time, mutate func(Record, time.Time) (Record, error)) (Record, error) {
	if s == nil {
		return Record{}, errors.New("retained data store is nil")
	}
	if retainedID == "" {
		return Record{}, ErrInvalidRecord
	}
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[retainedID]
	if !ok {
		return Record{}, ErrNotFound
	}
	updated, err := mutate(cloneRecord(record), now.UTC())
	if err != nil {
		return Record{}, err
	}
	s.records[retainedID] = cloneRecord(updated)
	return updated, nil
}

func recordFromRetain(req RetainRequest, now time.Time) (Record, error) {
	retainedID := normalizeID(req.RetainedID)
	sourcePluginInstanceID := normalizeID(req.SourcePluginInstanceID)
	publisherID := normalizeID(req.PublisherID)
	pluginID := normalizeID(req.PluginID)
	version := normalizeID(req.Version)
	packageHash := normalizeID(req.PackageHash)
	manifestHash := normalizeID(req.ManifestHash)
	if retainedID == "" || sourcePluginInstanceID == "" || publisherID == "" || pluginID == "" || version == "" || packageHash == "" || manifestHash == "" {
		return Record{}, ErrInvalidRecord
	}
	if !req.StorageRetained && !req.SettingsRetained && !req.BrowserSiteRetained {
		return Record{}, ErrInvalidRecord
	}
	if req.UsageBytes < 0 {
		return Record{}, ErrInvalidRecord
	}
	return Record{
		RetainedID:             retainedID,
		SourcePluginInstanceID: sourcePluginInstanceID,
		PublisherID:            publisherID,
		PluginID:               pluginID,
		Version:                version,
		PackageHash:            packageHash,
		ManifestHash:           manifestHash,
		State:                  StateRetained,
		StorageRetained:        req.StorageRetained,
		SettingsRetained:       req.SettingsRetained,
		BrowserSiteRetained:    req.BrowserSiteRetained,
		UsageBytes:             req.UsageBytes,
		DeleteAfter:            cloneTimePtr(req.DeleteAfter),
		Metadata:               cloneStringMap(req.Metadata),
		RetainedAt:             now.UTC(),
		UpdatedAt:              now.UTC(),
	}, nil
}

func validState(state State) bool {
	switch state {
	case StateRetained, StateExpired, StateBound, StateDeleted, StateDeleteFailedRetryable:
		return true
	default:
		return false
	}
}

func normalizeID(value string) string {
	return strings.TrimSpace(value)
}

func cloneRecord(record Record) Record {
	record.DeleteAfter = cloneTimePtr(record.DeleteAfter)
	record.BoundAt = cloneTimePtr(record.BoundAt)
	record.DeletedAt = cloneTimePtr(record.DeletedAt)
	record.LastAccessedAt = cloneTimePtr(record.LastAccessedAt)
	record.Metadata = cloneStringMap(record.Metadata)
	return record
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		key = normalizeID(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].RetainedAt.Equal(records[j].RetainedAt) {
			return records[i].RetainedID < records[j].RetainedID
		}
		return records[i].RetainedAt.Before(records[j].RetainedAt)
	})
}

var _ Store = (*MemoryStore)(nil)
