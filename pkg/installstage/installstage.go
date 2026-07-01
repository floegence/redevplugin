package installstage

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

type Action string

const (
	ActionInstall Action = "install"
	ActionUpdate  Action = "update"
)

type Status string

const (
	StatusStaged    Status = "staged"
	StatusPrepared  Status = "prepared"
	StatusCommitted Status = "committed"
	StatusFailed    Status = "failed"
	StatusExpired   Status = "expired"
)

var (
	ErrNotFound     = errors.New("install stage not found")
	ErrInvalidStage = errors.New("install stage is invalid")
)

type Record struct {
	StageID           string            `json:"stage_id"`
	Action            Action            `json:"action"`
	Status            Status            `json:"status"`
	PluginInstanceID  string            `json:"plugin_instance_id"`
	PublisherID       string            `json:"publisher_id"`
	PluginID          string            `json:"plugin_id"`
	Version           string            `json:"version"`
	PackageHash       string            `json:"package_hash"`
	ManifestHash      string            `json:"manifest_hash"`
	EntriesHash       string            `json:"entries_hash"`
	RequestedTrust    string            `json:"requested_trust,omitempty"`
	ResolvedTrust     string            `json:"resolved_trust,omitempty"`
	ValidationSummary map[string]string `json:"validation_summary,omitempty"`
	ErrorCode         string            `json:"error_code,omitempty"`
	ErrorMessage      string            `json:"error_message,omitempty"`
	ExpiresAt         time.Time         `json:"expires_at"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	FinishedAt        *time.Time        `json:"finished_at,omitempty"`
}

type CreateRequest struct {
	StageID           string            `json:"stage_id"`
	Action            Action            `json:"action"`
	PluginInstanceID  string            `json:"plugin_instance_id"`
	PublisherID       string            `json:"publisher_id"`
	PluginID          string            `json:"plugin_id"`
	Version           string            `json:"version"`
	PackageHash       string            `json:"package_hash"`
	ManifestHash      string            `json:"manifest_hash"`
	EntriesHash       string            `json:"entries_hash"`
	RequestedTrust    string            `json:"requested_trust,omitempty"`
	ValidationSummary map[string]string `json:"validation_summary,omitempty"`
	ExpiresAt         time.Time         `json:"expires_at"`
	Now               time.Time         `json:"now,omitempty"`
}

type MarkPreparedRequest struct {
	StageID           string            `json:"stage_id"`
	ResolvedTrust     string            `json:"resolved_trust,omitempty"`
	ValidationSummary map[string]string `json:"validation_summary,omitempty"`
	Now               time.Time         `json:"now,omitempty"`
}

type MarkCommittedRequest struct {
	StageID string    `json:"stage_id"`
	Now     time.Time `json:"now,omitempty"`
}

type MarkFailedRequest struct {
	StageID      string    `json:"stage_id"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	Now          time.Time `json:"now,omitempty"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	Status           Status `json:"status,omitempty"`
}

type Store interface {
	Create(ctx context.Context, req CreateRequest) (Record, error)
	Get(ctx context.Context, stageID string) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	MarkPrepared(ctx context.Context, req MarkPreparedRequest) (Record, error)
	MarkCommitted(ctx context.Context, req MarkCommittedRequest) (Record, error)
	MarkFailed(ctx context.Context, req MarkFailedRequest) (Record, error)
	ExpireBefore(ctx context.Context, now time.Time) ([]Record, error)
	Delete(ctx context.Context, stageID string) error
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

func NewStageID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "stage_" + hex.EncodeToString(buf[:]), nil
}

func (s *MemoryStore) Create(_ context.Context, req CreateRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	record, err := recordFromCreate(req, now)
	if err != nil {
		return Record{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[record.StageID]; ok {
		return cloneRecord(existing), nil
	}
	s.records[record.StageID] = cloneRecord(record)
	return record, nil
}

func (s *MemoryStore) Get(_ context.Context, stageID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	stageID = normalizeID(stageID)
	if stageID == "" {
		return Record{}, ErrInvalidStage
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[stageID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("install stage store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	if req.Status != "" && !validStatus(req.Status) {
		return nil, ErrInvalidStage
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		if req.Status != "" && record.Status != req.Status {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func (s *MemoryStore) MarkPrepared(_ context.Context, req MarkPreparedRequest) (Record, error) {
	return s.update(normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusPrepared
		record.ResolvedTrust = normalizeID(req.ResolvedTrust)
		record.ValidationSummary = mergeStringMap(record.ValidationSummary, req.ValidationSummary)
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *MemoryStore) MarkCommitted(_ context.Context, req MarkCommittedRequest) (Record, error) {
	return s.update(normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusCommitted
		record.UpdatedAt = now
		record.FinishedAt = &now
		return record, nil
	})
}

func (s *MemoryStore) MarkFailed(_ context.Context, req MarkFailedRequest) (Record, error) {
	return s.update(normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusFailed
		record.ErrorCode = normalizeID(req.ErrorCode)
		record.ErrorMessage = strings.TrimSpace(req.ErrorMessage)
		record.UpdatedAt = now
		record.FinishedAt = &now
		return record, nil
	})
}

func (s *MemoryStore) ExpireBefore(_ context.Context, now time.Time) ([]Record, error) {
	if s == nil {
		return nil, errors.New("install stage store is nil")
	}
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := []Record{}
	for id, record := range s.records {
		if terminalStatus(record.Status) || record.ExpiresAt.After(now) {
			continue
		}
		record.Status = StatusExpired
		record.ErrorCode = "stage_expired"
		record.ErrorMessage = "install stage expired"
		record.UpdatedAt = now
		record.FinishedAt = &now
		s.records[id] = cloneRecord(record)
		changed = append(changed, cloneRecord(record))
	}
	sortRecords(changed)
	return changed, nil
}

func (s *MemoryStore) Delete(_ context.Context, stageID string) error {
	if s == nil {
		return errors.New("install stage store is nil")
	}
	stageID = normalizeID(stageID)
	if stageID == "" {
		return ErrInvalidStage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[stageID]; !ok {
		return ErrNotFound
	}
	delete(s.records, stageID)
	return nil
}

func (s *MemoryStore) update(stageID string, now time.Time, mutate func(Record, time.Time) (Record, error)) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	if stageID == "" {
		return Record{}, ErrInvalidStage
	}
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[stageID]
	if !ok {
		return Record{}, ErrNotFound
	}
	updated, err := mutate(cloneRecord(record), now)
	if err != nil {
		return Record{}, err
	}
	s.records[stageID] = cloneRecord(updated)
	return updated, nil
}

func recordFromCreate(req CreateRequest, now time.Time) (Record, error) {
	action := req.Action
	if !validAction(action) {
		return Record{}, ErrInvalidStage
	}
	stageID := normalizeID(req.StageID)
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	publisherID := normalizeID(req.PublisherID)
	pluginID := normalizeID(req.PluginID)
	version := normalizeID(req.Version)
	packageHash := normalizeID(req.PackageHash)
	manifestHash := normalizeID(req.ManifestHash)
	entriesHash := normalizeID(req.EntriesHash)
	if stageID == "" || pluginInstanceID == "" || publisherID == "" || pluginID == "" || version == "" || packageHash == "" || manifestHash == "" || entriesHash == "" {
		return Record{}, ErrInvalidStage
	}
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(now) {
		return Record{}, ErrInvalidStage
	}
	return Record{
		StageID:           stageID,
		Action:            action,
		Status:            StatusStaged,
		PluginInstanceID:  pluginInstanceID,
		PublisherID:       publisherID,
		PluginID:          pluginID,
		Version:           version,
		PackageHash:       packageHash,
		ManifestHash:      manifestHash,
		EntriesHash:       entriesHash,
		RequestedTrust:    normalizeID(req.RequestedTrust),
		ValidationSummary: cloneStringMap(req.ValidationSummary),
		ExpiresAt:         req.ExpiresAt.UTC(),
		CreatedAt:         now.UTC(),
		UpdatedAt:         now.UTC(),
	}, nil
}

func validAction(action Action) bool {
	switch action {
	case ActionInstall, ActionUpdate:
		return true
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case StatusStaged, StatusPrepared, StatusCommitted, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

func terminalStatus(status Status) bool {
	switch status {
	case StatusCommitted, StatusFailed, StatusExpired:
		return true
	default:
		return false
	}
}

func normalizeID(value string) string {
	return strings.TrimSpace(value)
}

func cloneRecord(record Record) Record {
	record.ValidationSummary = cloneStringMap(record.ValidationSummary)
	if record.FinishedAt != nil {
		finishedAt := *record.FinishedAt
		record.FinishedAt = &finishedAt
	}
	return record
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

func mergeStringMap(base map[string]string, next map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = map[string]string{}
	}
	for key, value := range cloneStringMap(next) {
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].StageID < records[j].StageID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
}

var _ Store = (*MemoryStore)(nil)
