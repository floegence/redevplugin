package browsersite

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type OriginState string

const (
	StateActive          OriginState = "active"
	StateRetained        OriginState = "retained"
	StateCleanupPending  OriginState = "cleanup_pending"
	StateCleanupComplete OriginState = "cleanup_complete"
	StateCleanupFailed   OriginState = "cleanup_failed_retryable"
)

type RegisterRequest struct {
	PluginInstanceID  string    `json:"plugin_instance_id"`
	PluginID          string    `json:"plugin_id,omitempty"`
	ActiveFingerprint string    `json:"active_fingerprint"`
	SurfaceID         string    `json:"surface_id,omitempty"`
	SurfaceInstanceID string    `json:"surface_instance_id,omitempty"`
	Origin            string    `json:"origin"`
	OwnerSessionHash  string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash     string    `json:"owner_user_hash,omitempty"`
	Now               time.Time `json:"now,omitempty"`
}

type CleanupRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	DeleteData       bool      `json:"delete_data"`
	RequireRetained  bool      `json:"require_retained,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type CleanupResult struct {
	Records []OriginRecord `json:"records"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	State            string `json:"state,omitempty"`
}

type OriginRecord struct {
	OriginKey          string      `json:"origin_key"`
	PluginInstanceID   string      `json:"plugin_instance_id"`
	PluginID           string      `json:"plugin_id,omitempty"`
	ActiveFingerprint  string      `json:"active_fingerprint"`
	SurfaceID          string      `json:"surface_id,omitempty"`
	SurfaceInstanceID  string      `json:"surface_instance_id,omitempty"`
	Origin             string      `json:"origin"`
	OwnerSessionHash   string      `json:"owner_session_hash,omitempty"`
	OwnerUserHash      string      `json:"owner_user_hash,omitempty"`
	State              OriginState `json:"state"`
	CleanupReason      string      `json:"cleanup_reason,omitempty"`
	CleanupError       string      `json:"cleanup_error,omitempty"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
	LastSeenAt         time.Time   `json:"last_seen_at"`
	CleanupRequestedAt *time.Time  `json:"cleanup_requested_at,omitempty"`
	CleanedAt          *time.Time  `json:"cleaned_at,omitempty"`
	RetainedAt         *time.Time  `json:"retained_at,omitempty"`
}

type Store interface {
	RegisterOrigin(ctx context.Context, req RegisterRequest) (OriginRecord, error)
	CleanupPluginOrigins(ctx context.Context, req CleanupRequest) (CleanupResult, error)
	ListOrigins(ctx context.Context, req ListRequest) ([]OriginRecord, error)
}

type Cleaner interface {
	ClearOriginData(ctx context.Context, origin string) error
}

var (
	ErrInvalidOrigin     = errors.New("browser site origin is invalid")
	ErrCleanupFailed     = errors.New("browser site cleanup failed")
	ErrCleanerRequired   = errors.New("browser site cleaner is required")
	ErrOriginNotFound    = errors.New("browser site origin not found")
	ErrOriginNotRetained = errors.New("browser site origin is not retained")
)

type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	cleaner Cleaner
	records map[string]OriginRecord
}

type MemoryStoreOptions struct {
	Now     func() time.Time
	Cleaner Cleaner
}

func NewMemoryStore(options ...MemoryStoreOptions) *MemoryStore {
	opts := MemoryStoreOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &MemoryStore{
		now:     now,
		cleaner: opts.Cleaner,
		records: map[string]OriginRecord{},
	}
}

func (s *MemoryStore) RegisterOrigin(_ context.Context, req RegisterRequest) (OriginRecord, error) {
	if s == nil {
		return OriginRecord{}, errors.New("browser site store is nil")
	}
	normalized, err := normalizeRegisterRequest(req)
	if err != nil {
		return OriginRecord{}, err
	}
	now := normalized.Now
	if now.IsZero() {
		now = s.now()
	}
	key := originKey(normalized.PluginInstanceID, normalized.ActiveFingerprint, normalized.OwnerSessionHash, normalized.Origin)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.records[key]; ok {
		existing.PluginID = normalized.PluginID
		existing.SurfaceID = normalized.SurfaceID
		existing.SurfaceInstanceID = normalized.SurfaceInstanceID
		existing.OwnerUserHash = normalized.OwnerUserHash
		existing.State = StateActive
		existing.CleanupReason = ""
		existing.CleanupError = ""
		existing.UpdatedAt = now
		existing.LastSeenAt = now
		existing.CleanupRequestedAt = nil
		existing.CleanedAt = nil
		existing.RetainedAt = nil
		s.records[key] = existing
		return cloneRecord(existing), nil
	}

	record := OriginRecord{
		OriginKey:         key,
		PluginInstanceID:  normalized.PluginInstanceID,
		PluginID:          normalized.PluginID,
		ActiveFingerprint: normalized.ActiveFingerprint,
		SurfaceID:         normalized.SurfaceID,
		SurfaceInstanceID: normalized.SurfaceInstanceID,
		Origin:            normalized.Origin,
		OwnerSessionHash:  normalized.OwnerSessionHash,
		OwnerUserHash:     normalized.OwnerUserHash,
		State:             StateActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastSeenAt:        now,
	}
	s.records[key] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) CleanupPluginOrigins(ctx context.Context, req CleanupRequest) (CleanupResult, error) {
	if s == nil {
		return CleanupResult{}, errors.New("browser site store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return CleanupResult{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidOrigin)
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		if req.DeleteData {
			reason = "delete_data"
		} else {
			reason = "retain_data"
		}
	}

	pending := make([]OriginRecord, 0)
	retained := make([]OriginRecord, 0)
	var missingCleanerErr error

	s.mu.Lock()
	if req.DeleteData && req.RequireRetained {
		for _, record := range s.records {
			if record.PluginInstanceID != pluginInstanceID {
				continue
			}
			switch record.State {
			case StateRetained, StateCleanupPending, StateCleanupFailed, StateCleanupComplete:
			default:
				s.mu.Unlock()
				return CleanupResult{}, fmt.Errorf("%w: %s is %s", ErrOriginNotRetained, record.Origin, record.State)
			}
		}
	}
	for key, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID {
			continue
		}
		record.UpdatedAt = now
		record.CleanupReason = reason
		if !req.DeleteData {
			record.State = StateRetained
			record.RetainedAt = &now
			record.CleanupRequestedAt = nil
			record.CleanedAt = nil
			record.CleanupError = ""
			s.records[key] = record
			retained = append(retained, cloneRecord(record))
			continue
		}
		record.State = StateCleanupPending
		record.CleanupRequestedAt = &now
		record.CleanedAt = nil
		record.RetainedAt = nil
		record.CleanupError = ""
		if s.cleaner == nil {
			record.State = StateCleanupFailed
			record.CleanupError = ErrCleanerRequired.Error()
			record.UpdatedAt = now
			if missingCleanerErr == nil {
				missingCleanerErr = fmt.Errorf("%w: %w", ErrCleanupFailed, ErrCleanerRequired)
			}
		}
		s.records[key] = record
		pending = append(pending, cloneRecord(record))
	}
	s.mu.Unlock()

	if !req.DeleteData {
		sortRecords(retained)
		return CleanupResult{Records: retained}, nil
	}
	if missingCleanerErr != nil {
		sortRecords(pending)
		return CleanupResult{Records: pending}, missingCleanerErr
	}
	sortRecords(pending)

	records := make([]OriginRecord, 0, len(pending))
	var firstErr error
	for _, record := range pending {
		if err := s.cleaner.ClearOriginData(ctx, record.Origin); err != nil {
			record.State = StateCleanupFailed
			record.CleanupError = err.Error()
			record.UpdatedAt = now
			s.mu.Lock()
			s.records[record.OriginKey] = record
			s.mu.Unlock()
			records = append(records, cloneRecord(record))
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: %s: %v", ErrCleanupFailed, record.Origin, err)
			}
			continue
		}
		record.State = StateCleanupComplete
		record.CleanupError = ""
		record.CleanedAt = &now
		record.UpdatedAt = now
		s.mu.Lock()
		s.records[record.OriginKey] = record
		s.mu.Unlock()
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	if firstErr != nil {
		return CleanupResult{Records: records}, firstErr
	}
	return CleanupResult{Records: records}, nil
}

func (s *MemoryStore) ListOrigins(_ context.Context, req ListRequest) ([]OriginRecord, error) {
	if s == nil {
		return nil, errors.New("browser site store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	state := OriginState(strings.TrimSpace(req.State))

	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]OriginRecord, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		if state != "" && record.State != state {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func normalizeRegisterRequest(req RegisterRequest) (RegisterRequest, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.PluginID = strings.TrimSpace(req.PluginID)
	req.ActiveFingerprint = strings.TrimSpace(req.ActiveFingerprint)
	req.SurfaceID = strings.TrimSpace(req.SurfaceID)
	req.SurfaceInstanceID = strings.TrimSpace(req.SurfaceInstanceID)
	req.OwnerSessionHash = strings.TrimSpace(req.OwnerSessionHash)
	req.OwnerUserHash = strings.TrimSpace(req.OwnerUserHash)
	req.Origin = strings.TrimRight(strings.TrimSpace(req.Origin), "/")
	if req.PluginInstanceID == "" || req.ActiveFingerprint == "" || req.Origin == "" {
		return RegisterRequest{}, fmt.Errorf("%w: plugin_instance_id, active_fingerprint, and origin are required", ErrInvalidOrigin)
	}
	if err := validateOrigin(req.Origin); err != nil {
		return RegisterRequest{}, err
	}
	return req, nil
}

func validateOrigin(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse origin: %v", ErrInvalidOrigin, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidOrigin)
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: origin must not contain credentials, path, query, or fragment", ErrInvalidOrigin)
	}
	return nil
}

func originKey(pluginInstanceID string, activeFingerprint string, ownerSessionHash string, origin string) string {
	return pluginInstanceID + "\x00" + activeFingerprint + "\x00" + ownerSessionHash + "\x00" + origin
}

func cloneRecord(record OriginRecord) OriginRecord {
	if record.CleanupRequestedAt != nil {
		value := *record.CleanupRequestedAt
		record.CleanupRequestedAt = &value
	}
	if record.CleanedAt != nil {
		value := *record.CleanedAt
		record.CleanedAt = &value
	}
	if record.RetainedAt != nil {
		value := *record.RetainedAt
		record.RetainedAt = &value
	}
	return record
}

func sortRecords(records []OriginRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginInstanceID == records[j].PluginInstanceID {
			if records[i].Origin == records[j].Origin {
				return records[i].ActiveFingerprint < records[j].ActiveFingerprint
			}
			return records[i].Origin < records[j].Origin
		}
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
}
