package permissions

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

type Effect string

const (
	EffectGrant Effect = "grant"
	EffectDeny  Effect = "deny"
)

type Record struct {
	PluginInstanceID string     `json:"plugin_instance_id"`
	PermissionID     string     `json:"permission_id"`
	Effect           Effect     `json:"effect"`
	GrantedBy        string     `json:"granted_by,omitempty"`
	GrantedAt        time.Time  `json:"granted_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
}

type MemoryState struct {
	Records []Record `json:"records,omitempty"`
}

type GrantRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	GrantedBy        string    `json:"granted_by,omitempty"`
	Now              time.Time `json:"now,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type RevokeRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	RevokedBy        string    `json:"revoked_by,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	ActiveOnly       bool   `json:"active_only,omitempty"`
}

type CheckRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionIDs    []string  `json:"permission_ids"`
	Now              time.Time `json:"now,omitempty"`
}

type Store interface {
	Grant(ctx context.Context, req GrantRequest) (Record, error)
	Revoke(ctx context.Context, req RevokeRequest) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	IsGranted(ctx context.Context, req CheckRequest) (bool, []string, error)
	DeletePluginGrants(ctx context.Context, pluginInstanceID string) error
}

var (
	ErrInvalidPermission = errors.New("permission grant is invalid")
	ErrPermissionDenied  = errors.New("plugin permission grant is required")
	ErrGrantNotFound     = errors.New("permission grant not found")
)

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}}
}

func NewMemoryStoreFromState(state MemoryState) *MemoryStore {
	store := NewMemoryStore()
	for _, record := range state.Records {
		record.PluginInstanceID = normalizeID(record.PluginInstanceID)
		record.PermissionID = normalizeID(record.PermissionID)
		if record.PluginInstanceID == "" || record.PermissionID == "" {
			continue
		}
		store.records[recordKey(record.PluginInstanceID, record.PermissionID)] = cloneRecord(record)
	}
	return store
}

func (s *MemoryStore) State() MemoryState {
	if s == nil {
		return MemoryState{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return MemoryState{Records: records}
}

func (s *MemoryStore) Grant(_ context.Context, req GrantRequest) (Record, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	permissionID := normalizeID(req.PermissionID)
	if pluginInstanceID == "" || permissionID == "" {
		return Record{}, ErrInvalidPermission
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record := Record{
		PluginInstanceID: pluginInstanceID,
		PermissionID:     permissionID,
		Effect:           EffectGrant,
		GrantedBy:        strings.TrimSpace(req.GrantedBy),
		GrantedAt:        now,
	}
	if !req.ExpiresAt.IsZero() {
		expiresAt := req.ExpiresAt.UTC()
		record.ExpiresAt = &expiresAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[recordKey(pluginInstanceID, permissionID)] = record
	return record, nil
}

func (s *MemoryStore) Revoke(_ context.Context, req RevokeRequest) (Record, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	permissionID := normalizeID(req.PermissionID)
	if pluginInstanceID == "" || permissionID == "" {
		return Record{}, ErrInvalidPermission
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := recordKey(pluginInstanceID, permissionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	if !ok {
		return Record{}, ErrGrantNotFound
	}
	revokedAt := now
	record.RevokedAt = &revokedAt
	record.RevokedBy = strings.TrimSpace(req.RevokedBy)
	record.RevokedReason = strings.TrimSpace(req.Reason)
	s.records[key] = record
	return record, nil
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	now := time.Now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		if req.ActiveOnly && !record.activeAt(now) {
			continue
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	return records, nil
}

func (s *MemoryStore) IsGranted(_ context.Context, req CheckRequest) (bool, []string, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return false, nil, ErrInvalidPermission
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	required := normalizePermissionIDs(req.PermissionIDs)
	if len(required) == 0 {
		return true, nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	missing := make([]string, 0)
	for _, permissionID := range required {
		record, ok := s.records[recordKey(pluginInstanceID, permissionID)]
		if !ok || !record.activeAt(now) {
			missing = append(missing, permissionID)
		}
	}
	return len(missing) == 0, missing, nil
}

func (s *MemoryStore) DeletePluginGrants(_ context.Context, pluginInstanceID string) error {
	pluginInstanceID = normalizeID(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidPermission
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

func (r Record) activeAt(now time.Time) bool {
	if r.Effect != EffectGrant || r.RevokedAt != nil {
		return false
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
		return false
	}
	return true
}

func normalizePermissionIDs(permissionIDs []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		permissionID = normalizeID(permissionID)
		if permissionID == "" {
			continue
		}
		if _, ok := seen[permissionID]; ok {
			continue
		}
		seen[permissionID] = struct{}{}
		normalized = append(normalized, permissionID)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeID(value string) string {
	return strings.TrimSpace(value)
}

func recordKey(pluginInstanceID string, permissionID string) string {
	return pluginInstanceID + "\x00" + permissionID
}

func cloneRecord(record Record) Record {
	if record.ExpiresAt != nil {
		expiresAt := *record.ExpiresAt
		record.ExpiresAt = &expiresAt
	}
	if record.RevokedAt != nil {
		revokedAt := *record.RevokedAt
		record.RevokedAt = &revokedAt
	}
	return record
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginInstanceID == records[j].PluginInstanceID {
			return records[i].PermissionID < records[j].PermissionID
		}
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
}
