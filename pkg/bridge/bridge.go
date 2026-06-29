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
)

type TokenKind string

const (
	TokenKindAssetTicket           TokenKind = "asset_ticket"
	TokenKindAssetSession          TokenKind = "asset_session"
	TokenKindPluginGatewayToken    TokenKind = "plugin_gateway_token"
	TokenKindConfirmationToken     TokenKind = "confirmation_token"
	TokenKindRuntimeExecutionLease TokenKind = "runtime_execution_lease"
	TokenKindHandleGrant           TokenKind = "handle_grant"
	TokenKindStreamTicket          TokenKind = "stream_ticket"
)

type TokenUse string

const (
	TokenUseSingleUse TokenUse = "single_use"
	TokenUseReusable  TokenUse = "reusable"
)

var (
	ErrTokenInvalid         = errors.New("token is invalid")
	ErrTokenExpired         = errors.New("token is expired")
	ErrTokenReplay          = errors.New("token has already been consumed")
	ErrTokenAudience        = errors.New("token audience mismatch")
	ErrTokenKind            = errors.New("token kind mismatch")
	ErrTokenRevoked         = errors.New("token has been revoked")
	ErrTokenAlreadyBound    = errors.New("token is already bound to a different channel")
	ErrMissingTokenAudience = errors.New("token audience is incomplete")
)

type SurfaceSession struct {
	PluginID             string    `json:"plugin_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	SurfaceID            string    `json:"surface_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
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
	PolicyRevision     uint64    `json:"policy_revision"`
	ManagementRevision uint64    `json:"management_revision"`
	RevokeEpoch        uint64    `json:"revoke_epoch"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type Handshake struct {
	PluginID          string `json:"plugin_id"`
	SurfaceID         string `json:"surface_id"`
	SurfaceInstanceID string `json:"surface_instance_id"`
	ActiveFingerprint string `json:"active_fingerprint"`
	BridgeNonce       string `json:"bridge_nonce"`
	UIProtocolVersion string `json:"ui_protocol_version"`
}

type CallRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type Audience struct {
	PluginInstanceID     string `json:"plugin_instance_id"`
	ActiveFingerprint    string `json:"active_fingerprint"`
	SurfaceInstanceID    string `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string `json:"bridge_channel_id,omitempty"`
	RuntimeInstanceID    string `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID  string `json:"runtime_generation_id,omitempty"`
	RuntimeShardID       string `json:"runtime_shard_id,omitempty"`
	StreamID             string `json:"stream_id,omitempty"`
	StreamDirection      string `json:"stream_direction,omitempty"`
	HandleID             string `json:"handle_id,omitempty"`
	ConfirmationID       string `json:"confirmation_id,omitempty"`
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
	Audience  Audience        `json:"audience"`
	Revision  RevisionBinding `json:"revision"`
	ExpiresAt time.Time       `json:"expires_at"`
	Now       time.Time       `json:"now,omitempty"`
	Limits    Limits          `json:"limits,omitempty"`
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
	Limits    Limits          `json:"limits,omitempty"`
}

type ValidateRequest struct {
	Kind     TokenKind       `json:"kind"`
	Token    string          `json:"token"`
	Audience Audience        `json:"audience"`
	Revision RevisionBinding `json:"revision"`
	Now      time.Time       `json:"now,omitempty"`
	Consume  bool            `json:"consume,omitempty"`
	Bind     *ChannelBinding `json:"bind,omitempty"`
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
	Limits               Limits          `json:"limits,omitempty"`
	Consumed             bool            `json:"consumed"`
	ConsumedAt           *time.Time      `json:"consumed_at,omitempty"`
	Revoked              bool            `json:"revoked"`
	RevokedAt            *time.Time      `json:"revoked_at,omitempty"`
	BoundBridgeChannelID string          `json:"bound_bridge_channel_id,omitempty"`
}

type TokenManager struct {
	mu      sync.Mutex
	records map[string]TokenRecord
}

func NewTokenManager() *TokenManager {
	return &TokenManager{records: map[string]TokenRecord{}}
}

func (m *TokenManager) Mint(req MintRequest) (MintedToken, error) {
	if m == nil {
		return MintedToken{}, errors.New("token manager is nil")
	}
	if err := validateMintRequest(req); err != nil {
		return MintedToken{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	use := req.Use
	if use == "" {
		use = defaultTokenUse(req.Kind)
	}
	tokenID, err := prefixedID(req.Kind)
	if err != nil {
		return MintedToken{}, err
	}
	nonce, err := randomString(24)
	if err != nil {
		return MintedToken{}, err
	}
	cleartext, err := randomString(32)
	if err != nil {
		return MintedToken{}, err
	}
	cleartext = string(req.Kind) + "." + tokenID + "." + cleartext
	record := TokenRecord{
		Kind:      req.Kind,
		TokenID:   tokenID,
		TokenHash: hashToken(cleartext),
		Audience:  req.Audience,
		Revision:  req.Revision,
		IssuedAt:  now,
		ExpiresAt: req.ExpiresAt.UTC(),
		Nonce:     nonce,
		Use:       use,
		Limits:    req.Limits,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[record.TokenHash] = record

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
	}, nil
}

func (m *TokenManager) Validate(req ValidateRequest) (TokenRecord, error) {
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
	tokenHash := hashToken(req.Token)

	m.mu.Lock()
	defer m.mu.Unlock()

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
	if !now.Before(record.ExpiresAt) {
		return TokenRecord{}, ErrTokenExpired
	}
	if record.Consumed {
		return TokenRecord{}, ErrTokenReplay
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

func (m *TokenManager) RevokePlugin(pluginInstanceID string, minimumRevokeEpoch uint64, now time.Time) int {
	if m == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key, record := range m.records {
		if record.Audience.PluginInstanceID != pluginInstanceID {
			continue
		}
		if record.Revision.RevokeEpoch < minimumRevokeEpoch || minimumRevokeEpoch == 0 {
			record.Revoked = true
			record.RevokedAt = &now
			m.records[key] = record
			count++
		}
	}
	return count
}

func (m *TokenManager) RevokeSurface(surfaceInstanceID string, now time.Time) int {
	if m == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key, record := range m.records {
		if record.Audience.SurfaceInstanceID != surfaceInstanceID || record.Revoked {
			continue
		}
		record.Revoked = true
		record.RevokedAt = &now
		m.records[key] = record
		count++
	}
	return count
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
	if req.Use != "" && req.Use != TokenUseSingleUse && req.Use != TokenUseReusable {
		return fmt.Errorf("unsupported token use %q", req.Use)
	}
	if strings.TrimSpace(req.Audience.PluginInstanceID) == "" || strings.TrimSpace(req.Audience.ActiveFingerprint) == "" {
		return ErrMissingTokenAudience
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

func defaultTokenUse(kind TokenKind) TokenUse {
	switch kind {
	case TokenKindAssetTicket, TokenKindConfirmationToken, TokenKindStreamTicket:
		return TokenUseSingleUse
	default:
		return TokenUseReusable
	}
}

func validTokenKind(kind TokenKind) bool {
	switch kind {
	case TokenKindAssetTicket, TokenKindAssetSession, TokenKindPluginGatewayToken, TokenKindConfirmationToken, TokenKindRuntimeExecutionLease, TokenKindHandleGrant, TokenKindStreamTicket:
		return true
	default:
		return false
	}
}

func audienceMatches(expected Audience, got Audience) bool {
	return expected.PluginInstanceID == got.PluginInstanceID &&
		expected.ActiveFingerprint == got.ActiveFingerprint &&
		expected.SurfaceInstanceID == got.SurfaceInstanceID &&
		expected.OwnerSessionHash == got.OwnerSessionHash &&
		expected.OwnerUserHash == got.OwnerUserHash &&
		expected.SessionChannelIDHash == got.SessionChannelIDHash &&
		expected.BridgeChannelID == got.BridgeChannelID &&
		expected.RuntimeInstanceID == got.RuntimeInstanceID &&
		expected.RuntimeGenerationID == got.RuntimeGenerationID &&
		expected.RuntimeShardID == got.RuntimeShardID &&
		expected.StreamID == got.StreamID &&
		expected.StreamDirection == got.StreamDirection &&
		expected.HandleID == got.HandleID &&
		expected.ConfirmationID == got.ConfirmationID
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
	case TokenKindRuntimeExecutionLease:
		return "rel_" + suffix, nil
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
