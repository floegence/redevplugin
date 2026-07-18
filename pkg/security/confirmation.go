package security

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const DefaultMaxPendingConfirmationIntentsPerPlugin = 64

var (
	ErrInvalidConfirmationIntent       = errors.New("plugin confirmation intent is invalid")
	ErrConfirmationIntentNotFound      = errors.New("plugin confirmation intent not found")
	ErrConfirmationIntentExpired       = errors.New("plugin confirmation intent expired")
	ErrConfirmationIntentScopeMismatch = errors.New("plugin confirmation intent scope mismatch")
)

type ConfirmationIntentRecord struct {
	ConfirmationID      string            `json:"confirmation_id"`
	ConfirmationTokenID string            `json:"confirmation_token_id"`
	PluginID            string            `json:"plugin_id"`
	PluginInstanceID    string            `json:"plugin_instance_id"`
	SurfaceInstanceID   string            `json:"surface_instance_id"`
	BridgeChannelID     string            `json:"bridge_channel_id"`
	Method              string            `json:"method"`
	RequestHash         string            `json:"request_hash"`
	PlanHash            string            `json:"plan_hash"`
	Scope               ConfirmationScope `json:"scope"`
	IssuedAt            time.Time         `json:"issued_at"`
	ExpiresAt           time.Time         `json:"expires_at"`
}

type PutConfirmationIntentRequest struct {
	ConfirmationID      string            `json:"confirmation_id"`
	ConfirmationTokenID string            `json:"confirmation_token_id"`
	PluginID            string            `json:"plugin_id"`
	PluginInstanceID    string            `json:"plugin_instance_id"`
	SurfaceInstanceID   string            `json:"surface_instance_id"`
	BridgeChannelID     string            `json:"bridge_channel_id"`
	Method              string            `json:"method"`
	RequestHash         string            `json:"request_hash"`
	PlanHash            string            `json:"plan_hash"`
	Scope               ConfirmationScope `json:"scope"`
	IssuedAt            time.Time         `json:"issued_at,omitempty"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Now                 time.Time         `json:"-"`
	MaxPendingPerPlugin int               `json:"max_pending_per_plugin,omitempty"`
}

type ConfirmationScope struct {
	ActiveFingerprint      string `json:"active_fingerprint"`
	OwnerSessionHash       string `json:"owner_session_hash"`
	OwnerUserHash          string `json:"owner_user_hash"`
	OwnerEnvHash           string `json:"owner_env_hash"`
	SessionChannelIDHash   string `json:"session_channel_id_hash"`
	PolicyRevision         uint64 `json:"policy_revision"`
	ManagementRevision     uint64 `json:"management_revision"`
	RevokeEpoch            uint64 `json:"revoke_epoch"`
	TargetDescriptorSHA256 string `json:"target_descriptor_sha256"`
}

type ConsumeConfirmationIntentRequest struct {
	ConfirmationID string    `json:"confirmation_id"`
	Now            time.Time `json:"-"`
}

type RejectConfirmationIntentRequest struct {
	ConfirmationID       string    `json:"confirmation_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	BridgeChannelID      string    `json:"bridge_channel_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	OwnerSessionHash     string    `json:"owner_session_hash"`
	OwnerUserHash        string    `json:"owner_user_hash"`
	OwnerEnvHash         string    `json:"owner_env_hash"`
	SessionChannelIDHash string    `json:"session_channel_id_hash"`
	PolicyRevision       uint64    `json:"policy_revision"`
	ManagementRevision   uint64    `json:"management_revision"`
	RevokeEpoch          uint64    `json:"revoke_epoch"`
	Now                  time.Time `json:"-"`
}

type ListConfirmationIntentsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type RevokePluginConfirmationIntentsRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	Now              time.Time `json:"-"`
}

type ConfirmationIntentStore interface {
	PutConfirmationIntent(ctx context.Context, req PutConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	ConsumeConfirmationIntent(ctx context.Context, req ConsumeConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	RejectConfirmationIntent(ctx context.Context, req RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	ListConfirmationIntents(ctx context.Context, req ListConfirmationIntentsRequest) ([]ConfirmationIntentRecord, error)
	RevokePluginConfirmationIntents(ctx context.Context, req RevokePluginConfirmationIntentsRequest) (int, error)
}

type MemoryConfirmationIntentStore struct {
	mu      sync.RWMutex
	now     func() time.Time
	records map[string]ConfirmationIntentRecord
}

func NewMemoryConfirmationIntentStore() *MemoryConfirmationIntentStore {
	return &MemoryConfirmationIntentStore{
		now:     func() time.Time { return time.Now().UTC() },
		records: map[string]ConfirmationIntentRecord{},
	}
}

func (s *MemoryConfirmationIntentStore) PutConfirmationIntent(_ context.Context, req PutConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	record, err := confirmationIntentFromPut(req, now)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	maxPending := normalizeMaxPendingConfirmationIntents(req.MaxPendingPerPlugin)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteExpiredLocked(now)
	for confirmationIntentCount(s.records, record.PluginInstanceID) >= maxPending {
		oldestID := oldestConfirmationIntentID(s.records, record.PluginInstanceID)
		if oldestID == "" {
			break
		}
		delete(s.records, oldestID)
	}
	s.records[record.ConfirmationID] = cloneConfirmationIntentRecord(record)
	return record, nil
}

func (s *MemoryConfirmationIntentStore) ConsumeConfirmationIntent(_ context.Context, req ConsumeConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	confirmationID := strings.TrimSpace(req.ConfirmationID)
	if confirmationID == "" {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[confirmationID]
	if ok {
		delete(s.records, confirmationID)
	}
	if !ok {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !record.ExpiresAt.After(now) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	return cloneConfirmationIntentRecord(record), nil
}

func (s *MemoryConfirmationIntentStore) RejectConfirmationIntent(_ context.Context, req RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error) {
	if s == nil {
		return ConfirmationIntentRecord{}, errors.New("confirmation intent store is nil")
	}
	normalized, err := normalizeRejectConfirmationIntentRequest(req)
	if err != nil {
		return ConfirmationIntentRecord{}, err
	}
	if normalized.Now.IsZero() {
		normalized.Now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[normalized.ConfirmationID]
	if !ok {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !record.ExpiresAt.After(normalized.Now) {
		delete(s.records, normalized.ConfirmationID)
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	if !confirmationIntentMatchesRejection(record, normalized) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentScopeMismatch
	}
	delete(s.records, normalized.ConfirmationID)
	return cloneConfirmationIntentRecord(record), nil
}

func (s *MemoryConfirmationIntentStore) ListConfirmationIntents(_ context.Context, req ListConfirmationIntentsRequest) ([]ConfirmationIntentRecord, error) {
	if s == nil {
		return nil, errors.New("confirmation intent store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]ConfirmationIntentRecord, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		records = append(records, cloneConfirmationIntentRecord(record))
	}
	sortConfirmationIntentRecords(records)
	return records, nil
}

func (s *MemoryConfirmationIntentStore) RevokePluginConfirmationIntents(_ context.Context, req RevokePluginConfirmationIntentsRequest) (int, error) {
	if s == nil {
		return 0, errors.New("confirmation intent store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return 0, ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID {
			continue
		}
		delete(s.records, id)
		count++
	}
	return count, nil
}

func (s *MemoryConfirmationIntentStore) deleteExpiredLocked(now time.Time) {
	for id, record := range s.records {
		if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now) {
			delete(s.records, id)
		}
	}
}

func confirmationIntentFromPut(req PutConfirmationIntentRequest, now time.Time) (ConfirmationIntentRecord, error) {
	record := ConfirmationIntentRecord{
		ConfirmationID:      strings.TrimSpace(req.ConfirmationID),
		ConfirmationTokenID: strings.TrimSpace(req.ConfirmationTokenID),
		PluginID:            strings.TrimSpace(req.PluginID),
		PluginInstanceID:    strings.TrimSpace(req.PluginInstanceID),
		SurfaceInstanceID:   strings.TrimSpace(req.SurfaceInstanceID),
		BridgeChannelID:     strings.TrimSpace(req.BridgeChannelID),
		Method:              strings.TrimSpace(req.Method),
		RequestHash:         strings.TrimSpace(req.RequestHash),
		PlanHash:            strings.TrimSpace(req.PlanHash),
		Scope:               req.Scope,
		IssuedAt:            req.IssuedAt,
		ExpiresAt:           req.ExpiresAt,
	}
	if record.IssuedAt.IsZero() {
		record.IssuedAt = now
	}
	if record.ConfirmationID == "" ||
		record.ConfirmationTokenID == "" ||
		record.PluginID == "" ||
		record.PluginInstanceID == "" ||
		record.SurfaceInstanceID == "" ||
		record.BridgeChannelID == "" ||
		record.Method == "" ||
		record.RequestHash == "" ||
		record.PlanHash == "" ||
		strings.TrimSpace(record.Scope.ActiveFingerprint) == "" ||
		strings.TrimSpace(record.Scope.OwnerSessionHash) == "" ||
		strings.TrimSpace(record.Scope.OwnerUserHash) == "" ||
		strings.TrimSpace(record.Scope.OwnerEnvHash) == "" ||
		strings.TrimSpace(record.Scope.SessionChannelIDHash) == "" ||
		record.Scope.PolicyRevision == 0 || record.Scope.ManagementRevision == 0 ||
		strings.TrimSpace(record.Scope.TargetDescriptorSHA256) == "" ||
		record.ExpiresAt.IsZero() ||
		!record.ExpiresAt.After(now) {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	return record, nil
}

func normalizeRejectConfirmationIntentRequest(req RejectConfirmationIntentRequest) (RejectConfirmationIntentRequest, error) {
	req.ConfirmationID = strings.TrimSpace(req.ConfirmationID)
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.SurfaceInstanceID = strings.TrimSpace(req.SurfaceInstanceID)
	req.BridgeChannelID = strings.TrimSpace(req.BridgeChannelID)
	req.ActiveFingerprint = strings.TrimSpace(req.ActiveFingerprint)
	req.OwnerSessionHash = strings.TrimSpace(req.OwnerSessionHash)
	req.OwnerUserHash = strings.TrimSpace(req.OwnerUserHash)
	req.OwnerEnvHash = strings.TrimSpace(req.OwnerEnvHash)
	req.SessionChannelIDHash = strings.TrimSpace(req.SessionChannelIDHash)
	if req.ConfirmationID == "" || req.PluginInstanceID == "" || req.SurfaceInstanceID == "" ||
		req.BridgeChannelID == "" || req.ActiveFingerprint == "" || req.OwnerSessionHash == "" ||
		req.OwnerUserHash == "" || req.OwnerEnvHash == "" || req.SessionChannelIDHash == "" || req.PolicyRevision == 0 || req.ManagementRevision == 0 {
		return RejectConfirmationIntentRequest{}, ErrInvalidConfirmationIntent
	}
	return req, nil
}

func confirmationIntentMatchesRejection(record ConfirmationIntentRecord, req RejectConfirmationIntentRequest) bool {
	return record.PluginInstanceID == req.PluginInstanceID &&
		record.SurfaceInstanceID == req.SurfaceInstanceID &&
		record.BridgeChannelID == req.BridgeChannelID &&
		record.Scope.ActiveFingerprint == req.ActiveFingerprint &&
		record.Scope.OwnerSessionHash == req.OwnerSessionHash &&
		record.Scope.OwnerUserHash == req.OwnerUserHash &&
		record.Scope.OwnerEnvHash == req.OwnerEnvHash &&
		record.Scope.SessionChannelIDHash == req.SessionChannelIDHash &&
		record.Scope.PolicyRevision == req.PolicyRevision &&
		record.Scope.ManagementRevision == req.ManagementRevision &&
		record.Scope.RevokeEpoch == req.RevokeEpoch
}

func normalizeMaxPendingConfirmationIntents(maxPending int) int {
	if maxPending <= 0 {
		return DefaultMaxPendingConfirmationIntentsPerPlugin
	}
	return maxPending
}

func confirmationIntentCount(records map[string]ConfirmationIntentRecord, pluginInstanceID string) int {
	count := 0
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			count++
		}
	}
	return count
}

func oldestConfirmationIntentID(records map[string]ConfirmationIntentRecord, pluginInstanceID string) string {
	var oldestID string
	var oldestTime time.Time
	for id, record := range records {
		if record.PluginInstanceID != pluginInstanceID {
			continue
		}
		when := record.IssuedAt
		if when.IsZero() {
			when = record.ExpiresAt
		}
		if oldestID == "" || when.Before(oldestTime) {
			oldestID = id
			oldestTime = when
		}
	}
	return oldestID
}

func cloneConfirmationIntentRecord(record ConfirmationIntentRecord) ConfirmationIntentRecord {
	return record
}

func sortConfirmationIntentRecords(records []ConfirmationIntentRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].IssuedAt.Equal(records[j].IssuedAt) {
			return records[i].ConfirmationID < records[j].ConfirmationID
		}
		return records[i].IssuedAt.Before(records[j].IssuedAt)
	})
}

var _ ConfirmationIntentStore = (*MemoryConfirmationIntentStore)(nil)
