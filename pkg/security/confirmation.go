package security

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const (
	DefaultMaxPendingConfirmationIntents               = 4_096
	DefaultMaxPendingConfirmationIntentsPerOwnerPlugin = 64
	DefaultMaxPendingConfirmationIntentsPerSession     = 16
	HardMaxPendingConfirmationIntents                  = 65_536
	HardMaxPendingConfirmationIntentsPerOwnerPlugin    = 1_024
	HardMaxPendingConfirmationIntentsPerSession        = 64
	DefaultMaxConfirmationSessionRevocations           = 4_096
	HardMaxConfirmationSessionRevocations              = 65_536
)

var (
	ErrInvalidConfirmationIntent       = errors.New("plugin confirmation intent is invalid")
	ErrConfirmationIntentNotFound      = errors.New("plugin confirmation intent not found")
	ErrConfirmationIntentExpired       = errors.New("plugin confirmation intent expired")
	ErrConfirmationIntentScopeMismatch = errors.New("plugin confirmation intent scope mismatch")
	ErrConfirmationIntentCapacity      = errors.New("plugin confirmation intent capacity is exhausted")
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
}

type ConfirmationScope struct {
	ActiveFingerprint      string `json:"active_fingerprint"`
	OwnerSessionHash       string `json:"-"`
	OwnerUserHash          string `json:"-"`
	OwnerEnvHash           string `json:"-"`
	SessionChannelIDHash   string `json:"-"`
	PolicyRevision         uint64 `json:"policy_revision"`
	ManagementRevision     uint64 `json:"management_revision"`
	RevokeEpoch            uint64 `json:"revoke_epoch"`
	TargetDescriptorSHA256 string `json:"target_descriptor_sha256"`
}

type ConsumeConfirmationIntentRequest struct {
	ConfirmationID string                  `json:"confirmation_id"`
	SessionScope   sessionctx.SessionScope `json:"-"`
	Now            time.Time               `json:"-"`
}

type RejectConfirmationIntentRequest struct {
	ConfirmationID       string    `json:"confirmation_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	BridgeChannelID      string    `json:"bridge_channel_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	OwnerSessionHash     string    `json:"-"`
	OwnerUserHash        string    `json:"-"`
	OwnerEnvHash         string    `json:"-"`
	SessionChannelIDHash string    `json:"-"`
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
	OwnerEnvHash     string    `json:"-"`
	Now              time.Time `json:"-"`
}

type RevokeSessionConfirmationIntentsRequest struct {
	SessionScope        sessionctx.SessionScope `json:"-"`
	TeardownOperationID string                  `json:"-"`
	Now                 time.Time               `json:"-"`
}

type FinalizeSessionConfirmationRevocationRequest struct {
	SessionScope        sessionctx.SessionScope `json:"-"`
	TeardownOperationID string                  `json:"-"`
}

type ConfirmationIntentStore interface {
	Durable() bool
	PutConfirmationIntent(ctx context.Context, req PutConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	ConsumeConfirmationIntent(ctx context.Context, req ConsumeConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	RejectConfirmationIntent(ctx context.Context, req RejectConfirmationIntentRequest) (ConfirmationIntentRecord, error)
	ListConfirmationIntents(ctx context.Context, req ListConfirmationIntentsRequest) ([]ConfirmationIntentRecord, error)
	RevokePluginConfirmationIntents(ctx context.Context, req RevokePluginConfirmationIntentsRequest) (int, error)
	RevokeSessionConfirmationIntents(ctx context.Context, req RevokeSessionConfirmationIntentsRequest) (int, error)
	FinalizeSessionConfirmationRevocation(ctx context.Context, req FinalizeSessionConfirmationRevocationRequest) error
}

type ConfirmationIntentStoreOptions struct {
	MaxTotal              int
	MaxPerOwnerPlugin     int
	MaxPerSession         int
	MaxSessionRevocations int
}

func normalizeConfirmationIntentStoreOptions(options ConfirmationIntentStoreOptions) (ConfirmationIntentStoreOptions, error) {
	if options.MaxTotal == 0 {
		options.MaxTotal = DefaultMaxPendingConfirmationIntents
	}
	if options.MaxPerOwnerPlugin == 0 {
		options.MaxPerOwnerPlugin = DefaultMaxPendingConfirmationIntentsPerOwnerPlugin
	}
	if options.MaxPerSession == 0 {
		options.MaxPerSession = DefaultMaxPendingConfirmationIntentsPerSession
	}
	if options.MaxSessionRevocations == 0 {
		options.MaxSessionRevocations = DefaultMaxConfirmationSessionRevocations
	}
	if options.MaxTotal < 1 || options.MaxTotal > HardMaxPendingConfirmationIntents ||
		options.MaxPerOwnerPlugin < 1 || options.MaxPerOwnerPlugin > HardMaxPendingConfirmationIntentsPerOwnerPlugin ||
		options.MaxPerSession < 1 || options.MaxPerSession > HardMaxPendingConfirmationIntentsPerSession ||
		options.MaxSessionRevocations < 1 || options.MaxSessionRevocations > HardMaxConfirmationSessionRevocations ||
		options.MaxPerOwnerPlugin > options.MaxTotal || options.MaxPerSession > options.MaxPerOwnerPlugin {
		return ConfirmationIntentStoreOptions{}, ErrConfirmationIntentCapacity
	}
	return options, nil
}

type confirmationOwnerPluginKey struct {
	OwnerEnvHash     string
	PluginInstanceID string
}

type MemoryConfirmationIntentStore struct {
	mu                 sync.RWMutex
	now                func() time.Time
	options            ConfirmationIntentStoreOptions
	records            map[string]ConfirmationIntentRecord
	ownerPluginCount   map[confirmationOwnerPluginKey]int
	ownerPluginIndex   map[confirmationOwnerPluginKey]map[string]struct{}
	sessionCount       map[sessionctx.SessionScope]int
	sessionIndex       map[sessionctx.SessionScope]map[string]struct{}
	sessionRevocations map[confirmationSessionRevocationKey]int
}

type confirmationSessionRevocationKey struct {
	Scope       sessionctx.SessionScope
	OperationID string
}

func NewMemoryConfirmationIntentStore() *MemoryConfirmationIntentStore {
	store, err := NewMemoryConfirmationIntentStoreWithOptions(ConfirmationIntentStoreOptions{})
	if err != nil {
		panic(err)
	}
	return store
}

func NewMemoryConfirmationIntentStoreWithOptions(options ConfirmationIntentStoreOptions) (*MemoryConfirmationIntentStore, error) {
	normalized, err := normalizeConfirmationIntentStoreOptions(options)
	if err != nil {
		return nil, err
	}
	return &MemoryConfirmationIntentStore{
		now:                func() time.Time { return time.Now().UTC() },
		options:            normalized,
		records:            map[string]ConfirmationIntentRecord{},
		ownerPluginCount:   map[confirmationOwnerPluginKey]int{},
		ownerPluginIndex:   map[confirmationOwnerPluginKey]map[string]struct{}{},
		sessionCount:       map[sessionctx.SessionScope]int{},
		sessionIndex:       map[sessionctx.SessionScope]map[string]struct{}{},
		sessionRevocations: map[confirmationSessionRevocationKey]int{},
	}, nil
}

func (*MemoryConfirmationIntentStore) Durable() bool { return false }

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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteExpiredLocked(now)
	if _, exists := s.records[record.ConfirmationID]; exists {
		return ConfirmationIntentRecord{}, ErrInvalidConfirmationIntent
	}
	scope := confirmationSessionScope(record.Scope)
	ownerPlugin := confirmationOwnerPluginKey{OwnerEnvHash: scope.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID}
	if len(s.records) >= s.options.MaxTotal ||
		s.ownerPluginCount[ownerPlugin] >= s.options.MaxPerOwnerPlugin ||
		s.sessionCount[scope] >= s.options.MaxPerSession {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentCapacity
	}
	s.addRecordLocked(record)
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
	if !ok {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentNotFound
	}
	if !confirmationIntentMatchesSessionScope(record, req.SessionScope) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentScopeMismatch
	}
	s.removeRecordLocked(record)
	if !record.ExpiresAt.After(now) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	return cloneConfirmationIntentRecord(record), nil
}

func confirmationIntentMatchesSessionScope(record ConfirmationIntentRecord, scope sessionctx.SessionScope) bool {
	return scope.Valid() &&
		record.Scope.OwnerSessionHash == scope.OwnerSessionHash &&
		record.Scope.OwnerUserHash == scope.OwnerUserHash &&
		record.Scope.OwnerEnvHash == scope.OwnerEnvHash &&
		record.Scope.SessionChannelIDHash == scope.SessionChannelIDHash
}

func confirmationSessionScope(scope ConfirmationScope) sessionctx.SessionScope {
	return sessionctx.SessionScope{
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		OwnerEnvHash:         scope.OwnerEnvHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	}
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
		s.removeRecordLocked(record)
		return ConfirmationIntentRecord{}, ErrConfirmationIntentExpired
	}
	if !confirmationIntentMatchesRejection(record, normalized) {
		return ConfirmationIntentRecord{}, ErrConfirmationIntentScopeMismatch
	}
	s.removeRecordLocked(record)
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
	ownerEnvHash := strings.TrimSpace(req.OwnerEnvHash)
	if pluginInstanceID == "" || !(sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEnvHash}).Valid() {
		return 0, ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	ownerPlugin := confirmationOwnerPluginKey{OwnerEnvHash: ownerEnvHash, PluginInstanceID: pluginInstanceID}
	for confirmationID := range s.ownerPluginIndex[ownerPlugin] {
		record, ok := s.records[confirmationID]
		if ok {
			s.removeRecordLocked(record)
			count++
		}
	}
	return count, nil
}

func (s *MemoryConfirmationIntentStore) RevokeSessionConfirmationIntents(_ context.Context, req RevokeSessionConfirmationIntentsRequest) (int, error) {
	if s == nil {
		return 0, errors.New("confirmation intent store is nil")
	}
	if err := req.SessionScope.Validate(); err != nil {
		return 0, ErrInvalidConfirmationIntent
	}
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if operationID == "" || len(operationID) > 256 {
		return 0, ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := confirmationSessionRevocationKey{Scope: req.SessionScope, OperationID: operationID}
	if previous, ok := s.sessionRevocations[key]; ok {
		return previous, nil
	}
	if len(s.sessionRevocations) >= s.options.MaxSessionRevocations {
		return 0, ErrConfirmationIntentCapacity
	}
	ids := s.sessionIndex[req.SessionScope]
	count := 0
	for id := range ids {
		record, ok := s.records[id]
		if !ok {
			continue
		}
		s.removeRecordLocked(record)
		count++
	}
	s.sessionRevocations[key] = count
	return count, nil
}

func (s *MemoryConfirmationIntentStore) FinalizeSessionConfirmationRevocation(_ context.Context, req FinalizeSessionConfirmationRevocationRequest) error {
	if s == nil || req.SessionScope.Validate() != nil {
		return ErrInvalidConfirmationIntent
	}
	operationID := strings.TrimSpace(req.TeardownOperationID)
	if operationID == "" || len(operationID) > 256 {
		return ErrInvalidConfirmationIntent
	}
	s.mu.Lock()
	delete(s.sessionRevocations, confirmationSessionRevocationKey{Scope: req.SessionScope, OperationID: operationID})
	s.mu.Unlock()
	return nil
}

func (s *MemoryConfirmationIntentStore) deleteExpiredLocked(now time.Time) {
	for _, record := range s.records {
		if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now) {
			s.removeRecordLocked(record)
		}
	}
}

func (s *MemoryConfirmationIntentStore) addRecordLocked(record ConfirmationIntentRecord) {
	s.records[record.ConfirmationID] = cloneConfirmationIntentRecord(record)
	scope := confirmationSessionScope(record.Scope)
	ownerPlugin := confirmationOwnerPluginKey{OwnerEnvHash: scope.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID}
	s.ownerPluginCount[ownerPlugin]++
	ownerPluginIDs := s.ownerPluginIndex[ownerPlugin]
	if ownerPluginIDs == nil {
		ownerPluginIDs = map[string]struct{}{}
		s.ownerPluginIndex[ownerPlugin] = ownerPluginIDs
	}
	ownerPluginIDs[record.ConfirmationID] = struct{}{}
	s.sessionCount[scope]++
	ids := s.sessionIndex[scope]
	if ids == nil {
		ids = map[string]struct{}{}
		s.sessionIndex[scope] = ids
	}
	ids[record.ConfirmationID] = struct{}{}
}

func (s *MemoryConfirmationIntentStore) removeRecordLocked(record ConfirmationIntentRecord) {
	delete(s.records, record.ConfirmationID)
	scope := confirmationSessionScope(record.Scope)
	ownerPlugin := confirmationOwnerPluginKey{OwnerEnvHash: scope.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID}
	if count := s.ownerPluginCount[ownerPlugin]; count <= 1 {
		delete(s.ownerPluginCount, ownerPlugin)
	} else {
		s.ownerPluginCount[ownerPlugin] = count - 1
	}
	ownerPluginIDs := s.ownerPluginIndex[ownerPlugin]
	delete(ownerPluginIDs, record.ConfirmationID)
	if len(ownerPluginIDs) == 0 {
		delete(s.ownerPluginIndex, ownerPlugin)
	}
	if count := s.sessionCount[scope]; count <= 1 {
		delete(s.sessionCount, scope)
	} else {
		s.sessionCount[scope] = count - 1
	}
	ids := s.sessionIndex[scope]
	delete(ids, record.ConfirmationID)
	if len(ids) == 0 {
		delete(s.sessionIndex, scope)
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
