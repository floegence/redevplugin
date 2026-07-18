package bridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type TokenKind string

const (
	TokenKindAssetTicket        TokenKind = "asset_ticket"
	TokenKindAssetSession       TokenKind = "asset_session"
	TokenKindPluginGatewayToken TokenKind = "plugin_gateway_token"
	TokenKindConfirmationToken  TokenKind = "confirmation_token"
	TokenKindHandleGrant        TokenKind = "handle_grant"
	TokenKindStreamTicket       TokenKind = "stream_ticket"
)

type TokenUse string

const (
	TokenUseSingleUse TokenUse = "single_use"
	TokenUseReusable  TokenUse = "reusable"
)

var (
	ErrTokenInvalid             = errors.New("token is invalid")
	ErrTokenExpired             = errors.New("token is expired")
	ErrTokenReplay              = errors.New("token has already been consumed")
	ErrTokenAudience            = errors.New("token audience mismatch")
	ErrTokenKind                = errors.New("token kind mismatch")
	ErrTokenRevoked             = errors.New("token has been revoked")
	ErrTokenAlreadyBound        = errors.New("token is already bound to a different channel")
	ErrMissingTokenAudience     = errors.New("token audience is incomplete")
	ErrTokenCapacity            = errors.New("token manager capacity is exhausted")
	ErrTokenPluginCapacity      = errors.New("plugin token capacity is exhausted")
	ErrTokenTTLExceeded         = errors.New("token TTL exceeds the configured maximum")
	ErrTokenRevokeFloorCapacity = errors.New("token revoke-floor capacity is exhausted")
	ErrTokenRevision            = errors.New("token revision binding is invalid")
	ErrTokenLimits              = errors.New("token limits are invalid")
)

const (
	DefaultMaxTokenRecords          = 16_384
	DefaultMaxTokenRecordsPerPlugin = 2_048
	DefaultMaxTokenRevokeFloors     = 4_096
	DefaultMaxTokenTTL              = 15 * time.Minute
)

type SurfaceSession struct {
	PluginID             string    `json:"plugin_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	PluginVersion        string    `json:"plugin_version"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	SurfaceID            string    `json:"surface_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	EntryPath            string    `json:"entry_path"`
	EntrySHA256          string    `json:"entry_sha256"`
	AssetSessionNonce    string    `json:"asset_session_nonce"`
	RouteRole            string    `json:"route_role"`
	RuntimeGenerationID  string    `json:"runtime_generation_id,omitempty"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	OwnerEnvHash         string    `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	BridgeNonce          string    `json:"bridge_nonce"`
	PolicyRevision       uint64    `json:"policy_revision"`
	ManagementRevision   uint64    `json:"management_revision"`
	RevokeEpoch          uint64    `json:"revoke_epoch"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type AssetTicket struct {
	TicketID           string    `json:"ticket_id"`
	PluginInstanceID   string    `json:"plugin_instance_id"`
	SurfaceInstanceID  string    `json:"surface_instance_id"`
	ActiveFingerprint  string    `json:"active_fingerprint"`
	OwnerSessionHash   string    `json:"owner_session_hash,omitempty"`
	OwnerEnvHash       string    `json:"owner_env_hash,omitempty"`
	PolicyRevision     uint64    `json:"policy_revision"`
	ManagementRevision uint64    `json:"management_revision"`
	RevokeEpoch        uint64    `json:"revoke_epoch"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type GatewayToken struct {
	TokenID            string    `json:"token_id"`
	PluginInstanceID   string    `json:"plugin_instance_id"`
	SurfaceInstanceID  string    `json:"surface_instance_id"`
	BridgeChannelID    string    `json:"bridge_channel_id"`
	ActiveFingerprint  string    `json:"active_fingerprint"`
	OwnerSessionHash   string    `json:"owner_session_hash,omitempty"`
	OwnerEnvHash       string    `json:"owner_env_hash,omitempty"`
	PolicyRevision     uint64    `json:"policy_revision"`
	ManagementRevision uint64    `json:"management_revision"`
	RevokeEpoch        uint64    `json:"revoke_epoch"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type Handshake struct {
	PluginID           string `json:"plugin_id"`
	SurfaceID          string `json:"surface_id"`
	SurfaceInstanceID  string `json:"surface_instance_id"`
	ActiveFingerprint  string `json:"active_fingerprint"`
	BridgeNonce        string `json:"bridge_nonce"`
	AssetSessionNonce  string `json:"asset_session_nonce"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
	UIProtocolVersion  string `json:"ui_protocol_version"`
}

type CallRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type Audience struct {
	PluginID               string                   `json:"plugin_id,omitempty"`
	PluginInstanceID       string                   `json:"plugin_instance_id"`
	PluginVersion          string                   `json:"plugin_version,omitempty"`
	ActiveFingerprint      string                   `json:"active_fingerprint"`
	SurfaceID              string                   `json:"surface_id,omitempty"`
	SurfaceInstanceID      string                   `json:"surface_instance_id,omitempty"`
	EntryPath              string                   `json:"entry_path,omitempty"`
	EntrySHA256            string                   `json:"entry_sha256,omitempty"`
	AssetSessionNonce      string                   `json:"asset_session_nonce,omitempty"`
	RouteRole              string                   `json:"route_role,omitempty"`
	OwnerSessionHash       string                   `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string                   `json:"owner_user_hash,omitempty"`
	OwnerEnvHash           string                   `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash   string                   `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string                   `json:"bridge_channel_id,omitempty"`
	RuntimeInstanceID      string                   `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID    string                   `json:"runtime_generation_id,omitempty"`
	RuntimeShardID         string                   `json:"runtime_shard_id,omitempty"`
	IPCChannelID           string                   `json:"ipc_channel_id,omitempty"`
	ConnectionNonce        string                   `json:"connection_nonce,omitempty"`
	StreamID               string                   `json:"stream_id,omitempty"`
	StreamDirection        string                   `json:"stream_direction,omitempty"`
	OperationID            string                   `json:"operation_id,omitempty"`
	AuditCorrelationID     string                   `json:"audit_correlation_id,omitempty"`
	HandleID               string                   `json:"handle_id,omitempty"`
	ConfirmationID         string                   `json:"confirmation_id,omitempty"`
	Method                 string                   `json:"method,omitempty"`
	RequestHash            string                   `json:"request_hash,omitempty"`
	PlanHash               string                   `json:"plan_hash,omitempty"`
	TargetDescriptorSHA256 string                   `json:"target_descriptor_sha256,omitempty"`
	ResourceScope          sessionctx.ResourceScope `json:"resource_scope,omitzero"`
}

type RevisionBinding struct {
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

type Limits struct {
	MaxBytesPerSecond int64 `json:"max_bytes_per_second,omitempty"`
	MaxTotalBytes     int64 `json:"max_total_bytes,omitempty"`
}

type MintRequest struct {
	Kind      TokenKind       `json:"kind"`
	Use       TokenUse        `json:"use,omitempty"`
	Audience  Audience        `json:"-"`
	Revision  RevisionBinding `json:"revision"`
	ExpiresAt time.Time       `json:"expires_at"`
	Now       time.Time       `json:"-"`
	Limits    Limits          `json:"limits,omitzero"`
}

type MintedToken struct {
	Kind      TokenKind       `json:"token_kind"`
	TokenID   string          `json:"token_id"`
	Token     string          `json:"token"`
	Audience  Audience        `json:"audience"`
	Revision  RevisionBinding `json:"revision"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Nonce     string          `json:"nonce"`
	Use       TokenUse        `json:"use"`
	Limits    Limits          `json:"limits,omitzero"`
}

type ValidateRequest struct {
	Kind     TokenKind       `json:"kind"`
	Token    string          `json:"token"`
	Audience Audience        `json:"-"`
	Revision RevisionBinding `json:"revision"`
	Now      time.Time       `json:"-"`
	Consume  bool            `json:"consume,omitempty"`
	Bind     *ChannelBinding `json:"bind,omitempty"`
}

type ValidateTokenIDRequest struct {
	Kind     TokenKind       `json:"kind"`
	TokenID  string          `json:"token_id"`
	Audience Audience        `json:"-"`
	Revision RevisionBinding `json:"revision"`
	Now      time.Time       `json:"-"`
	Consume  bool            `json:"consume,omitempty"`
}

type InspectRequest struct {
	Kind  TokenKind `json:"kind"`
	Token string    `json:"token"`
	Now   time.Time `json:"-"`
}

type ChannelBinding struct {
	BridgeChannelID string `json:"bridge_channel_id,omitempty"`
}

type TokenRecord struct {
	Kind                 TokenKind       `json:"token_kind"`
	TokenID              string          `json:"token_id"`
	TokenHash            string          `json:"token_hash"`
	Audience             Audience        `json:"audience"`
	Revision             RevisionBinding `json:"revision"`
	IssuedAt             time.Time       `json:"issued_at"`
	ExpiresAt            time.Time       `json:"expires_at"`
	Nonce                string          `json:"nonce"`
	Use                  TokenUse        `json:"use"`
	Limits               Limits          `json:"limits,omitzero"`
	Consumed             bool            `json:"consumed"`
	ConsumedAt           *time.Time      `json:"consumed_at,omitempty"`
	Revoked              bool            `json:"revoked"`
	RevokedAt            *time.Time      `json:"revoked_at,omitempty"`
	BoundBridgeChannelID string          `json:"bound_bridge_channel_id,omitempty"`
}

type TokenManagerOptions struct {
	MaxRecords          int
	MaxRecordsPerPlugin int
	MaxRevokeFloors     int
	MaxTTL              time.Duration
}

type TokenManager struct {
	mu                    sync.Mutex
	options               TokenManagerOptions
	records               map[string]TokenRecord
	idIndex               map[string]string
	pluginIndex           map[string]map[string]struct{}
	surfaceIndex          map[string]map[string]struct{}
	pluginRevokeFloors    map[string]uint64
	revokeFloorsSaturated bool
}

func NewTokenManager(options ...TokenManagerOptions) *TokenManager {
	configured := TokenManagerOptions{}
	if len(options) > 0 {
		configured = options[0]
	}
	configured = normalizeTokenManagerOptions(configured)
	return &TokenManager{
		options:            configured,
		records:            map[string]TokenRecord{},
		idIndex:            map[string]string{},
		pluginIndex:        map[string]map[string]struct{}{},
		surfaceIndex:       map[string]map[string]struct{}{},
		pluginRevokeFloors: map[string]uint64{},
	}
}

func normalizeTokenManagerOptions(options TokenManagerOptions) TokenManagerOptions {
	if options.MaxRecords <= 0 {
		options.MaxRecords = DefaultMaxTokenRecords
	}
	if options.MaxRecordsPerPlugin <= 0 {
		options.MaxRecordsPerPlugin = DefaultMaxTokenRecordsPerPlugin
	}
	if options.MaxRecordsPerPlugin > options.MaxRecords {
		options.MaxRecordsPerPlugin = options.MaxRecords
	}
	if options.MaxRevokeFloors <= 0 {
		options.MaxRevokeFloors = DefaultMaxTokenRevokeFloors
	}
	if options.MaxTTL <= 0 {
		options.MaxTTL = DefaultMaxTokenTTL
	}
	return options
}

func (m *TokenManager) Mint(req MintRequest) (MintedToken, error) {
	if m == nil {
		return MintedToken{}, errors.New("token manager is nil")
	}
	record, cleartext, err := m.prepareMint(req)
	if err != nil {
		return MintedToken{}, err
	}
	now := record.IssuedAt
	pluginKey, err := tokenPluginIndexKey(record.Kind, record.Audience)
	if err != nil {
		return MintedToken{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredRecordsLocked(now)
	if m.revokeFloorsSaturated {
		if _, tracked := m.pluginRevokeFloors[pluginKey]; !tracked {
			return MintedToken{}, ErrTokenRevokeFloorCapacity
		}
	}
	if floor := m.pluginRevokeFloors[pluginKey]; floor > 0 && record.Revision.RevokeEpoch < floor {
		return MintedToken{}, ErrTokenRevoked
	}
	if len(m.records) >= m.options.MaxRecords {
		return MintedToken{}, ErrTokenCapacity
	}
	if len(m.pluginIndex[pluginKey]) >= m.options.MaxRecordsPerPlugin {
		return MintedToken{}, ErrTokenPluginCapacity
	}
	if _, exists := m.records[record.TokenHash]; exists {
		return MintedToken{}, errors.New("generated token hash collision")
	}
	if _, exists := m.idIndex[tokenIDIndexKey(record.Kind, record.TokenID)]; exists {
		return MintedToken{}, errors.New("generated token ID collision")
	}
	m.addRecordLocked(record)

	return mintedToken(record, cleartext), nil
}

func (m *TokenManager) prepareMint(req MintRequest) (TokenRecord, string, error) {
	if err := validateMintRequest(req); err != nil {
		return TokenRecord{}, "", err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if req.ExpiresAt.Sub(now) > m.options.MaxTTL {
		return TokenRecord{}, "", ErrTokenTTLExceeded
	}
	tokenID, err := prefixedID(req.Kind)
	if err != nil {
		return TokenRecord{}, "", err
	}
	nonce, err := randomString(24)
	if err != nil {
		return TokenRecord{}, "", err
	}
	secret, err := randomString(32)
	if err != nil {
		return TokenRecord{}, "", err
	}
	cleartext := string(req.Kind) + "." + tokenID + "." + secret
	return TokenRecord{
		Kind:      req.Kind,
		TokenID:   tokenID,
		TokenHash: hashToken(cleartext),
		Audience:  req.Audience,
		Revision:  req.Revision,
		IssuedAt:  now,
		ExpiresAt: req.ExpiresAt.UTC(),
		Nonce:     nonce,
		Use:       defaultTokenUse(req.Kind),
		Limits:    req.Limits,
	}, cleartext, nil
}

func mintedToken(record TokenRecord, cleartext string) MintedToken {
	return MintedToken{
		Kind:      record.Kind,
		TokenID:   record.TokenID,
		Token:     cleartext,
		Audience:  record.Audience,
		Revision:  record.Revision,
		IssuedAt:  record.IssuedAt,
		ExpiresAt: record.ExpiresAt,
		Nonce:     record.Nonce,
		Use:       record.Use,
		Limits:    record.Limits,
	}
}

func (m *TokenManager) pruneExpiredRecordsLocked(now time.Time) {
	for tokenHash, record := range m.records {
		if !now.Before(record.ExpiresAt) {
			m.removeRecordLocked(tokenHash, record)
		}
	}
}

func (m *TokenManager) addRecordLocked(record TokenRecord) {
	m.records[record.TokenHash] = record
	m.idIndex[tokenIDIndexKey(record.Kind, record.TokenID)] = record.TokenHash
	pluginKey, _ := tokenPluginIndexKey(record.Kind, record.Audience)
	addTokenIndexEntry(m.pluginIndex, pluginKey, record.TokenHash)
	addTokenIndexEntry(m.surfaceIndex, tokenSurfaceIndexKey(record.Audience), record.TokenHash)
}

func (m *TokenManager) removeRecordLocked(tokenHash string, record TokenRecord) {
	delete(m.records, tokenHash)
	delete(m.idIndex, tokenIDIndexKey(record.Kind, record.TokenID))
	pluginKey, _ := tokenPluginIndexKey(record.Kind, record.Audience)
	removeTokenIndexEntry(m.pluginIndex, pluginKey, tokenHash)
	removeTokenIndexEntry(m.surfaceIndex, tokenSurfaceIndexKey(record.Audience), tokenHash)
}

func addTokenIndexEntry(index map[string]map[string]struct{}, key string, tokenHash string) {
	if strings.TrimSpace(key) == "" {
		return
	}
	entries := index[key]
	if entries == nil {
		entries = map[string]struct{}{}
		index[key] = entries
	}
	entries[tokenHash] = struct{}{}
}

func removeTokenIndexEntry(index map[string]map[string]struct{}, key string, tokenHash string) {
	entries := index[key]
	if entries == nil {
		return
	}
	delete(entries, tokenHash)
	if len(entries) == 0 {
		delete(index, key)
	}
}

func tokenIDIndexKey(kind TokenKind, tokenID string) string {
	return string(kind) + "\x00" + tokenID
}

func (m *TokenManager) Validate(req ValidateRequest) (TokenRecord, error) {
	if m == nil {
		return TokenRecord{}, errors.New("token manager is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tokenHash := hashToken(req.Token)

	m.mu.Lock()
	defer m.mu.Unlock()

	record, err := m.loadTokenRecordLocked(InspectRequest{Kind: req.Kind, Token: req.Token, Now: now}, tokenHash)
	if err != nil {
		return TokenRecord{}, err
	}
	if req.Bind != nil && record.Audience.BridgeChannelID != "" && req.Bind.BridgeChannelID != "" && record.Audience.BridgeChannelID != req.Bind.BridgeChannelID {
		return TokenRecord{}, ErrTokenAlreadyBound
	}
	if !audienceMatches(record.Audience, req.Audience) {
		return TokenRecord{}, ErrTokenAudience
	}
	if record.Revision != req.Revision {
		return TokenRecord{}, ErrTokenRevoked
	}
	if req.Bind != nil {
		if req.Bind.BridgeChannelID == "" {
			return TokenRecord{}, ErrMissingTokenAudience
		}
		if record.BoundBridgeChannelID != "" && record.BoundBridgeChannelID != req.Bind.BridgeChannelID {
			return TokenRecord{}, ErrTokenAlreadyBound
		}
		record.BoundBridgeChannelID = req.Bind.BridgeChannelID
	}
	if req.Consume {
		if record.Use != TokenUseSingleUse {
			return TokenRecord{}, fmt.Errorf("token kind %s is not single-use", record.Kind)
		}
		record.Consumed = true
		record.ConsumedAt = &now
	}
	m.records[tokenHash] = record
	return record, nil
}

func (m *TokenManager) ValidateID(req ValidateTokenIDRequest) (TokenRecord, error) {
	if m == nil {
		return TokenRecord{}, errors.New("token manager is nil")
	}
	tokenID := strings.TrimSpace(req.TokenID)
	if tokenID == "" {
		return TokenRecord{}, ErrTokenInvalid
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tokenHash, record, err := m.loadTokenRecordByIDLocked(req.Kind, tokenID, now)
	if err != nil {
		return TokenRecord{}, err
	}
	if !audienceMatches(record.Audience, req.Audience) {
		return TokenRecord{}, ErrTokenAudience
	}
	if record.Revision != req.Revision {
		return TokenRecord{}, ErrTokenRevoked
	}
	if req.Consume {
		if record.Use != TokenUseSingleUse {
			return TokenRecord{}, fmt.Errorf("token kind %s is not single-use", record.Kind)
		}
		record.Consumed = true
		record.ConsumedAt = &now
	}
	m.records[tokenHash] = record
	return record, nil
}

func (m *TokenManager) Inspect(req InspectRequest) (TokenRecord, error) {
	if m == nil {
		return TokenRecord{}, errors.New("token manager is nil")
	}
	if strings.TrimSpace(req.Token) == "" {
		return TokenRecord{}, ErrTokenInvalid
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	req.Now = now
	tokenHash := hashToken(req.Token)

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadTokenRecordLocked(req, tokenHash)
}

func (m *TokenManager) loadTokenRecordByIDLocked(kind TokenKind, tokenID string, now time.Time) (string, TokenRecord, error) {
	tokenHash, ok := m.idIndex[tokenIDIndexKey(kind, tokenID)]
	if !ok {
		return "", TokenRecord{}, ErrTokenInvalid
	}
	record, ok := m.records[tokenHash]
	if !ok {
		delete(m.idIndex, tokenIDIndexKey(kind, tokenID))
		return "", TokenRecord{}, ErrTokenInvalid
	}
	if record.Kind != kind {
		return "", TokenRecord{}, ErrTokenKind
	}
	if record.Revoked {
		return "", TokenRecord{}, ErrTokenRevoked
	}
	if !now.Before(record.ExpiresAt) {
		return "", TokenRecord{}, ErrTokenExpired
	}
	if record.Consumed {
		return "", TokenRecord{}, ErrTokenReplay
	}
	return tokenHash, record, nil
}

func (m *TokenManager) loadTokenRecordLocked(req InspectRequest, tokenHash string) (TokenRecord, error) {
	record, ok := m.records[tokenHash]
	if !ok {
		return TokenRecord{}, ErrTokenInvalid
	}
	if record.Kind != req.Kind {
		return TokenRecord{}, ErrTokenKind
	}
	if record.Revoked {
		return TokenRecord{}, ErrTokenRevoked
	}
	if !req.Now.Before(record.ExpiresAt) {
		return TokenRecord{}, ErrTokenExpired
	}
	if record.Consumed {
		return TokenRecord{}, ErrTokenReplay
	}
	return record, nil
}

func (m *TokenManager) RevokePlugin(ownerEnvHash string, pluginInstanceID string, minimumRevokeEpoch uint64, now time.Time) (int, error) {
	if m == nil {
		return 0, nil
	}
	pluginKey, err := ownerPluginIndexKey(ownerEnvHash, pluginInstanceID)
	if err != nil {
		return 0, err
	}
	if !jsonvalue.IsPositiveSafeUnsignedInteger(minimumRevokeEpoch) {
		return 0, ErrTokenRevision
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var floorErr error
	if minimumRevokeEpoch > m.pluginRevokeFloors[pluginKey] {
		if _, exists := m.pluginRevokeFloors[pluginKey]; !exists && len(m.pluginRevokeFloors) >= m.options.MaxRevokeFloors {
			m.revokeFloorsSaturated = true
			floorErr = ErrTokenRevokeFloorCapacity
		} else {
			m.pluginRevokeFloors[pluginKey] = minimumRevokeEpoch
		}
	}

	count := 0
	for key := range m.pluginIndex[pluginKey] {
		record, ok := m.records[key]
		if !ok {
			continue
		}
		if record.Revision.RevokeEpoch < minimumRevokeEpoch {
			if record.Revoked {
				continue
			}
			record.Revoked = true
			record.RevokedAt = &now
			m.records[key] = record
			count++
		}
	}
	return count, floorErr
}

func (m *TokenManager) RevokeSurface(ownerEnvHash string, pluginInstanceID string, surfaceInstanceID string, now time.Time) int {
	if m == nil {
		return 0
	}
	surfaceKey, err := ownerSurfaceIndexKey(ownerEnvHash, pluginInstanceID, surfaceInstanceID)
	if err != nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key := range m.surfaceIndex[surfaceKey] {
		record, ok := m.records[key]
		if !ok || record.Revoked {
			continue
		}
		record.Revoked = true
		record.RevokedAt = &now
		m.records[key] = record
		count++
	}
	return count
}

func (m *TokenManager) RevokeTokenID(kind TokenKind, tokenID string, now time.Time) bool {
	if m == nil || strings.TrimSpace(tokenID) == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.idIndex[tokenIDIndexKey(kind, tokenID)]
	if !ok {
		return false
	}
	record, ok := m.records[key]
	if !ok || record.Kind != kind || record.TokenID != tokenID || record.Revoked {
		return false
	}
	record.Revoked = true
	record.RevokedAt = &now
	m.records[key] = record
	return true
}

func (m *TokenManager) Snapshot() []TokenRecord {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	records := make([]TokenRecord, 0, len(m.records))
	for _, record := range m.records {
		records = append(records, record)
	}
	return records
}

func validateMintRequest(req MintRequest) error {
	if !validTokenKind(req.Kind) {
		return ErrTokenKind
	}
	expectedUse := defaultTokenUse(req.Kind)
	if req.Use != "" && req.Use != expectedUse {
		return fmt.Errorf("token kind %q requires use %q", req.Kind, expectedUse)
	}
	if strings.TrimSpace(req.Audience.PluginInstanceID) == "" || strings.TrimSpace(req.Audience.ActiveFingerprint) == "" {
		return ErrMissingTokenAudience
	}
	if err := validateTokenAudience(req.Kind, req.Audience); err != nil {
		return err
	}
	if err := validateRevisionBinding(req.Revision); err != nil {
		return err
	}
	if !validNonnegativeSafeInt64(req.Limits.MaxBytesPerSecond) ||
		!validNonnegativeSafeInt64(req.Limits.MaxTotalBytes) {
		return ErrTokenLimits
	}
	if req.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !req.ExpiresAt.After(now) {
		return ErrTokenExpired
	}
	return nil
}

func validateRevisionBinding(revision RevisionBinding) error {
	if !jsonvalue.IsSafeUnsignedInteger(revision.PolicyRevision) ||
		!jsonvalue.IsSafeUnsignedInteger(revision.ManagementRevision) ||
		!jsonvalue.IsPositiveSafeUnsignedInteger(revision.RevokeEpoch) {
		return ErrTokenRevision
	}
	return nil
}

func validNonnegativeSafeInt64(value int64) bool {
	return value >= 0 && uint64(value) <= jsonvalue.MaxSafeInteger
}

func validateTokenAudience(kind TokenKind, audience Audience) error {
	if _, err := tokenAudienceOwnerEnvHash(kind, audience); err != nil {
		return err
	}
	require := func(values ...string) error {
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				return ErrMissingTokenAudience
			}
		}
		return nil
	}
	if strings.TrimSpace(audience.OwnerUserHash) != "" && strings.TrimSpace(audience.OwnerEnvHash) != "" {
		if err := (sessionctx.ResourceScope{
			Kind:          sessionctx.ScopeUser,
			OwnerEnvHash:  audience.OwnerEnvHash,
			OwnerUserHash: audience.OwnerUserHash,
		}).Validate(); err != nil {
			return ErrTokenAudience
		}
	}
	switch kind {
	case TokenKindAssetTicket, TokenKindAssetSession:
		return require(
			audience.PluginID,
			audience.PluginVersion,
			audience.SurfaceID,
			audience.SurfaceInstanceID,
			audience.EntryPath,
			audience.EntrySHA256,
			audience.AssetSessionNonce,
			audience.RouteRole,
			audience.OwnerSessionHash,
			audience.OwnerUserHash,
			audience.OwnerEnvHash,
			audience.SessionChannelIDHash,
			audience.RuntimeGenerationID,
		)
	case TokenKindPluginGatewayToken:
		return require(
			audience.PluginID,
			audience.PluginVersion,
			audience.SurfaceID,
			audience.SurfaceInstanceID,
			audience.EntryPath,
			audience.EntrySHA256,
			audience.AssetSessionNonce,
			audience.RouteRole,
			audience.OwnerSessionHash,
			audience.OwnerUserHash,
			audience.OwnerEnvHash,
			audience.SessionChannelIDHash,
			audience.BridgeChannelID,
			audience.RuntimeGenerationID,
		)
	case TokenKindConfirmationToken:
		return require(
			audience.PluginID,
			audience.PluginVersion,
			audience.SurfaceID,
			audience.SurfaceInstanceID,
			audience.EntryPath,
			audience.EntrySHA256,
			audience.AssetSessionNonce,
			audience.RouteRole,
			audience.OwnerSessionHash,
			audience.OwnerUserHash,
			audience.OwnerEnvHash,
			audience.SessionChannelIDHash,
			audience.BridgeChannelID,
			audience.ConfirmationID,
			audience.Method,
			audience.RequestHash,
			audience.PlanHash,
			audience.TargetDescriptorSHA256,
			audience.RuntimeGenerationID,
		)
	case TokenKindHandleGrant:
		if err := require(
			audience.RuntimeGenerationID,
			audience.OwnerSessionHash,
			audience.OwnerUserHash,
			audience.OwnerEnvHash,
			audience.SessionChannelIDHash,
			audience.HandleID,
			audience.Method,
		); err != nil {
			return err
		}
		if audience.ResourceScope.OwnerEnvHash != audience.OwnerEnvHash ||
			(audience.ResourceScope.Kind == sessionctx.ScopeUser && audience.ResourceScope.OwnerUserHash != audience.OwnerUserHash) {
			return ErrTokenAudience
		}
		return nil
	case TokenKindStreamTicket:
		if err := require(
			audience.PluginID,
			audience.PluginVersion,
			audience.RouteRole,
			audience.OwnerSessionHash,
			audience.OwnerUserHash,
			audience.OwnerEnvHash,
			audience.SessionChannelIDHash,
			audience.StreamID,
			audience.StreamDirection,
			audience.Method,
		); err != nil {
			return err
		}
		switch audience.RouteRole {
		case RouteRoleTrustedParent:
			return require(
				audience.SurfaceID,
				audience.SurfaceInstanceID,
				audience.EntryPath,
				audience.EntrySHA256,
				audience.AssetSessionNonce,
				audience.BridgeChannelID,
				audience.RuntimeGenerationID,
			)
		case RouteRoleTrustedIntent:
			return nil
		default:
			return ErrMissingTokenAudience
		}
	default:
		return ErrTokenKind
	}
}

func defaultTokenUse(kind TokenKind) TokenUse {
	switch kind {
	case TokenKindAssetTicket, TokenKindConfirmationToken:
		return TokenUseSingleUse
	default:
		return TokenUseReusable
	}
}

func validTokenKind(kind TokenKind) bool {
	switch kind {
	case TokenKindAssetTicket, TokenKindAssetSession, TokenKindPluginGatewayToken, TokenKindConfirmationToken, TokenKindHandleGrant, TokenKindStreamTicket:
		return true
	default:
		return false
	}
}

func audienceMatches(expected Audience, got Audience) bool {
	return expected.PluginID == got.PluginID &&
		expected.PluginInstanceID == got.PluginInstanceID &&
		expected.PluginVersion == got.PluginVersion &&
		expected.ActiveFingerprint == got.ActiveFingerprint &&
		expected.SurfaceID == got.SurfaceID &&
		expected.SurfaceInstanceID == got.SurfaceInstanceID &&
		expected.EntryPath == got.EntryPath &&
		expected.EntrySHA256 == got.EntrySHA256 &&
		expected.AssetSessionNonce == got.AssetSessionNonce &&
		expected.RouteRole == got.RouteRole &&
		expected.OwnerSessionHash == got.OwnerSessionHash &&
		expected.OwnerUserHash == got.OwnerUserHash &&
		expected.OwnerEnvHash == got.OwnerEnvHash &&
		expected.SessionChannelIDHash == got.SessionChannelIDHash &&
		expected.BridgeChannelID == got.BridgeChannelID &&
		expected.RuntimeInstanceID == got.RuntimeInstanceID &&
		expected.RuntimeGenerationID == got.RuntimeGenerationID &&
		expected.RuntimeShardID == got.RuntimeShardID &&
		expected.IPCChannelID == got.IPCChannelID &&
		expected.ConnectionNonce == got.ConnectionNonce &&
		expected.StreamID == got.StreamID &&
		expected.StreamDirection == got.StreamDirection &&
		expected.OperationID == got.OperationID &&
		expected.AuditCorrelationID == got.AuditCorrelationID &&
		expected.HandleID == got.HandleID &&
		expected.ConfirmationID == got.ConfirmationID &&
		expected.Method == got.Method &&
		expected.RequestHash == got.RequestHash &&
		expected.PlanHash == got.PlanHash &&
		expected.TargetDescriptorSHA256 == got.TargetDescriptorSHA256 &&
		expected.ResourceScope == got.ResourceScope
}

func tokenPluginIndexKey(kind TokenKind, audience Audience) (string, error) {
	ownerEnvHash, err := tokenAudienceOwnerEnvHash(kind, audience)
	if err != nil {
		return "", err
	}
	return ownerPluginIndexKey(ownerEnvHash, audience.PluginInstanceID)
}

func tokenAudienceOwnerEnvHash(kind TokenKind, audience Audience) (string, error) {
	switch kind {
	case TokenKindHandleGrant:
		if err := audience.ResourceScope.Validate(); err != nil {
			return "", err
		}
		return audience.ResourceScope.OwnerEnvHash, nil
	case TokenKindAssetTicket, TokenKindAssetSession, TokenKindPluginGatewayToken, TokenKindConfirmationToken, TokenKindStreamTicket:
		if audience.ResourceScope != (sessionctx.ResourceScope{}) {
			return "", ErrTokenAudience
		}
		return strings.TrimSpace(audience.OwnerEnvHash), nil
	default:
		return "", ErrTokenKind
	}
}

func tokenSurfaceIndexKey(audience Audience) string {
	key, _ := ownerSurfaceIndexKey(audience.OwnerEnvHash, audience.PluginInstanceID, audience.SurfaceInstanceID)
	return key
}

func ownerPluginIndexKey(ownerEnvHash string, pluginInstanceID string) (string, error) {
	ownerEnvHash = strings.TrimSpace(ownerEnvHash)
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if ownerEnvHash == "" || pluginInstanceID == "" {
		return "", ErrMissingTokenAudience
	}
	return ownerEnvHash + "\x00" + pluginInstanceID, nil
}

func ownerSurfaceIndexKey(ownerEnvHash string, pluginInstanceID string, surfaceInstanceID string) (string, error) {
	pluginKey, err := ownerPluginIndexKey(ownerEnvHash, pluginInstanceID)
	if err != nil {
		return "", err
	}
	surfaceInstanceID = strings.TrimSpace(surfaceInstanceID)
	if surfaceInstanceID == "" {
		return "", ErrMissingTokenAudience
	}
	return pluginKey + "\x00" + surfaceInstanceID, nil
}

func prefixedID(kind TokenKind) (string, error) {
	suffix, err := randomString(18)
	if err != nil {
		return "", err
	}
	switch kind {
	case TokenKindAssetTicket:
		return "at_" + suffix, nil
	case TokenKindAssetSession:
		return "as_" + suffix, nil
	case TokenKindPluginGatewayToken:
		return "pgt_" + suffix, nil
	case TokenKindConfirmationToken:
		return "ct_" + suffix, nil
	case TokenKindHandleGrant:
		return "hg_" + suffix, nil
	case TokenKindStreamTicket:
		return "st_" + suffix, nil
	default:
		return "tok_" + suffix, nil
	}
}

func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}
