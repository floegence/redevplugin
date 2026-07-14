package bridge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAssetTicketTTL                   = 15 * time.Second
	MaxAssetTicketTTL                       = 60 * time.Second
	DefaultAssetSessionTTL                  = 10 * time.Minute
	MaxAssetSessionTTL                      = 15 * time.Minute
	DefaultGatewayTokenTTL                  = 10 * time.Minute
	MaxGatewayTokenTTL                      = 15 * time.Minute
	DefaultMaxActiveSurfaceSessions         = 4096
	DefaultMaxActiveSurfaceSessionsPerOwner = 64
	DefaultConfirmationTTL                  = 2 * time.Minute
	MaxConfirmationTTL                      = 5 * time.Minute
	MaxStreamTicketTTL                      = 5 * time.Minute
	DefaultRuntimeLeaseTTL                  = 30 * time.Second
	MaxRuntimeLeaseTTL                      = 5 * time.Minute
	DefaultHandleGrantTTL                   = 30 * time.Second
	MaxHandleGrantTTL                       = 60 * time.Second
	RouteRoleTrustedParent                  = "trusted_parent"
	RouteRoleTrustedIntent                  = "trusted_intent"
)

var (
	ErrSurfaceSessionNotFound      = errors.New("surface session not found")
	ErrSurfaceSessionExpired       = errors.New("surface session expired")
	ErrSurfaceSessionAlreadyExists = errors.New("surface session already exists")
	ErrSurfaceSessionLimitReached  = errors.New("surface session limit reached")
	ErrHandshakeMismatch           = errors.New("bridge handshake mismatch")
	ErrAssetSessionRequired        = errors.New("asset session is required before bridge token mint")
)

var requestHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type SurfaceTokenService struct {
	mu       sync.Mutex
	tokens   *TokenManager
	options  SurfaceTokenOptions
	sessions map[string]surfaceState
}

type SurfaceTokenOptions struct {
	AssetTicketTTL            time.Duration `json:"asset_ticket_ttl,omitempty"`
	AssetSessionTTL           time.Duration `json:"asset_session_ttl,omitempty"`
	GatewayTokenTTL           time.Duration `json:"gateway_token_ttl,omitempty"`
	MaxActiveSessions         int           `json:"max_active_sessions,omitempty"`
	MaxActiveSessionsPerOwner int           `json:"max_active_sessions_per_owner,omitempty"`
}

type OpenSurfaceRequest struct {
	PluginID             string          `json:"plugin_id"`
	PluginInstanceID     string          `json:"plugin_instance_id"`
	PluginVersion        string          `json:"plugin_version"`
	SurfaceID            string          `json:"surface_id"`
	SurfaceInstanceID    string          `json:"surface_instance_id"`
	ActiveFingerprint    string          `json:"active_fingerprint"`
	EntryPath            string          `json:"entry_path"`
	EntrySHA256          string          `json:"entry_sha256"`
	RouteRole            string          `json:"route_role"`
	RuntimeGenerationID  string          `json:"runtime_generation_id,omitempty"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
}

type SurfaceBootstrap struct {
	PluginID             string    `json:"plugin_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	PluginVersion        string    `json:"plugin_version"`
	SurfaceID            string    `json:"surface_id"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	EntryPath            string    `json:"entry_path"`
	EntrySHA256          string    `json:"entry_sha256"`
	AssetSessionNonce    string    `json:"asset_session_nonce"`
	PluginStateVersion   uint64    `json:"plugin_state_version"`
	RevokeEpoch          uint64    `json:"revoke_epoch"`
	RuntimeGenerationID  string    `json:"runtime_generation_id,omitempty"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	AssetTicket          string    `json:"asset_ticket"`
	AssetTicketID        string    `json:"asset_ticket_id"`
	BridgeNonce          string    `json:"bridge_nonce"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type ExchangeAssetTicketRequest struct {
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	AssetTicket          string    `json:"asset_ticket"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	Now                  time.Time `json:"now,omitempty"`
}

type AssetSessionResult struct {
	AssetSession       string    `json:"asset_session"`
	AssetSessionID     string    `json:"asset_session_id"`
	AssetSessionNonce  string    `json:"asset_session_nonce"`
	EntryPath          string    `json:"entry_path"`
	EntrySHA256        string    `json:"entry_sha256"`
	PluginStateVersion uint64    `json:"plugin_state_version"`
	RevokeEpoch        uint64    `json:"revoke_epoch"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type ValidateAssetSessionRequest struct {
	AssetSession         string    `json:"asset_session"`
	AssetSessionID       string    `json:"asset_session_id,omitempty"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	Now                  time.Time `json:"now,omitempty"`
}

type MarkSurfacePreparedRequest struct {
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	AssetSessionID       string    `json:"asset_session_id"`
	BridgeNonce          string    `json:"bridge_nonce"`
	OwnerSessionHash     string    `json:"owner_session_hash"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash"`
	Now                  time.Time `json:"now,omitempty"`
}

type DisposeSurfaceRequest struct {
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	BridgeNonce          string    `json:"bridge_nonce"`
	OwnerSessionHash     string    `json:"owner_session_hash"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash"`
	Now                  time.Time `json:"now,omitempty"`
}

type RevokeSurfaceScopeRequest struct {
	OwnerSessionHash     string    `json:"owner_session_hash"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	Now                  time.Time `json:"now,omitempty"`
}

type AssetSessionValidation struct {
	Session SurfaceSession `json:"session"`
	TokenID string         `json:"token_id"`
}

type BridgeHandshakeValidation struct {
	Session SurfaceSession `json:"session"`
}

type MintGatewayTokenRequest struct {
	Handshake                 Handshake `json:"handshake"`
	BridgeChannelID           string    `json:"bridge_channel_id"`
	HandshakeTranscriptSHA256 string    `json:"handshake_transcript_sha256"`
	PreviousGatewayToken      string    `json:"previous_plugin_gateway_token,omitempty"`
	Now                       time.Time `json:"now,omitempty"`
}

type GatewayTokenResult struct {
	GatewayToken   string    `json:"plugin_gateway_token"`
	GatewayTokenID string    `json:"plugin_gateway_token_id"`
	AssetSession   string    `json:"asset_session"`
	AssetSessionID string    `json:"asset_session_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type MintConfirmationTokenRequest struct {
	PluginID               string          `json:"plugin_id,omitempty"`
	PluginInstanceID       string          `json:"plugin_instance_id"`
	PluginVersion          string          `json:"plugin_version,omitempty"`
	ActiveFingerprint      string          `json:"active_fingerprint"`
	SurfaceID              string          `json:"surface_id,omitempty"`
	SurfaceInstanceID      string          `json:"surface_instance_id"`
	EntryPath              string          `json:"entry_path,omitempty"`
	EntrySHA256            string          `json:"entry_sha256,omitempty"`
	AssetSessionNonce      string          `json:"asset_session_nonce,omitempty"`
	RouteRole              string          `json:"route_role,omitempty"`
	ConfirmationID         string          `json:"confirmation_id"`
	OwnerSessionHash       string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash   string          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string          `json:"bridge_channel_id"`
	RuntimeGenerationID    string          `json:"runtime_generation_id,omitempty"`
	Method                 string          `json:"method"`
	RequestHash            string          `json:"request_hash"`
	PlanHash               string          `json:"plan_hash"`
	TargetDescriptorSHA256 string          `json:"target_descriptor_sha256"`
	Revision               RevisionBinding `json:"revision"`
	Now                    time.Time       `json:"now,omitempty"`
	ExpiresAt              time.Time       `json:"expires_at,omitempty"`
}

type ConfirmationTokenResult struct {
	ConfirmationToken   string    `json:"confirmation_token"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	PlanHash            string    `json:"plan_hash"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type ValidateConfirmationTokenRequest struct {
	ConfirmationToken string          `json:"confirmation_token"`
	Audience          Audience        `json:"audience"`
	Revision          RevisionBinding `json:"revision"`
	Now               time.Time       `json:"now,omitempty"`
}

type ValidateConfirmationTokenIDRequest struct {
	ConfirmationTokenID string          `json:"confirmation_token_id"`
	Audience            Audience        `json:"audience"`
	Revision            RevisionBinding `json:"revision"`
	Now                 time.Time       `json:"now,omitempty"`
}

type ValidateSurfaceGatewayTokenRequest struct {
	GatewayToken         string          `json:"plugin_gateway_token"`
	PluginInstanceID     string          `json:"plugin_instance_id"`
	SurfaceInstanceID    string          `json:"surface_instance_id"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string          `json:"bridge_channel_id"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
}

type MintRuntimeExecutionLeaseRequest struct {
	PluginInstanceID       string                      `json:"plugin_instance_id"`
	PluginID               string                      `json:"plugin_id,omitempty"`
	PluginVersion          string                      `json:"plugin_version,omitempty"`
	ActiveFingerprint      string                      `json:"active_fingerprint"`
	SurfaceInstanceID      string                      `json:"surface_instance_id,omitempty"`
	OwnerSessionHash       string                      `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string                      `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash   string                      `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string                      `json:"bridge_channel_id,omitempty"`
	RuntimeInstanceID      string                      `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID    string                      `json:"runtime_generation_id"`
	RuntimeShardID         string                      `json:"runtime_shard_id,omitempty"`
	IPCChannelID           string                      `json:"ipc_channel_id,omitempty"`
	ConnectionNonce        string                      `json:"connection_nonce,omitempty"`
	Method                 string                      `json:"method"`
	Effect                 string                      `json:"effect,omitempty"`
	Execution              string                      `json:"execution,omitempty"`
	OperationID            string                      `json:"operation_id,omitempty"`
	StreamID               string                      `json:"stream_id,omitempty"`
	AuditCorrelationID     string                      `json:"audit_correlation_id"`
	TargetDescriptorHashes []string                    `json:"target_descriptor_hashes,omitempty"`
	Limits                 RuntimeExecutionLeaseLimits `json:"limits,omitempty"`
	Revision               RevisionBinding             `json:"revision"`
	Now                    time.Time                   `json:"now,omitempty"`
	ExpiresAt              time.Time                   `json:"expires_at,omitempty"`
}

type RuntimeExecutionLeaseLimits struct {
	TimeoutMillis           int64 `json:"timeout_ms,omitempty"`
	MemoryBytes             int64 `json:"memory_bytes,omitempty"`
	MaxPayloadBytes         int64 `json:"max_payload_bytes,omitempty"`
	MaxStreamBytesPerSecond int64 `json:"max_stream_bytes_per_sec,omitempty"`
}

type RuntimeExecutionLeaseResult struct {
	TokenKind              TokenKind                   `json:"token_kind"`
	TokenID                string                      `json:"token_id"`
	LeaseToken             string                      `json:"lease_token"`
	LeaseID                string                      `json:"lease_id"`
	LeaseNonce             string                      `json:"lease_nonce"`
	PluginInstanceID       string                      `json:"plugin_instance_id"`
	PluginID               string                      `json:"plugin_id,omitempty"`
	PluginVersion          string                      `json:"plugin_version,omitempty"`
	ActiveFingerprint      string                      `json:"active_fingerprint"`
	SurfaceInstanceID      string                      `json:"surface_instance_id,omitempty"`
	OwnerSessionHash       string                      `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string                      `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash   string                      `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string                      `json:"bridge_channel_id,omitempty"`
	RuntimeInstanceID      string                      `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID    string                      `json:"runtime_generation_id"`
	RuntimeShardID         string                      `json:"runtime_shard_id,omitempty"`
	IPCChannelID           string                      `json:"ipc_channel_id,omitempty"`
	ConnectionNonce        string                      `json:"connection_nonce,omitempty"`
	Method                 string                      `json:"method"`
	Effect                 string                      `json:"effect,omitempty"`
	Execution              string                      `json:"execution,omitempty"`
	OperationID            string                      `json:"operation_id,omitempty"`
	StreamID               string                      `json:"stream_id,omitempty"`
	AuditCorrelationID     string                      `json:"audit_correlation_id"`
	TargetDescriptorHashes []string                    `json:"target_descriptor_hashes,omitempty"`
	Limits                 RuntimeExecutionLeaseLimits `json:"limits,omitempty"`
	PolicyRevision         uint64                      `json:"policy_revision"`
	ManagementRevision     uint64                      `json:"management_revision"`
	RevokeEpoch            uint64                      `json:"revoke_epoch"`
	IssuedAt               time.Time                   `json:"issued_at"`
	IssuedAtUnixMillis     int64                       `json:"issued_at_unix_ms"`
	ExpiresAt              time.Time                   `json:"expires_at"`
	ExpiresAtUnixMillis    int64                       `json:"expires_at_unix_ms"`
}

type MintHandleGrantRequest struct {
	PluginInstanceID    string          `json:"plugin_instance_id"`
	ActiveFingerprint   string          `json:"active_fingerprint"`
	RuntimeInstanceID   string          `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string          `json:"runtime_generation_id"`
	RuntimeShardID      string          `json:"runtime_shard_id,omitempty"`
	HandleID            string          `json:"handle_id"`
	Method              string          `json:"method"`
	Revision            RevisionBinding `json:"revision"`
	Limits              Limits          `json:"limits,omitempty"`
	Now                 time.Time       `json:"now,omitempty"`
	ExpiresAt           time.Time       `json:"expires_at,omitempty"`
}

type HandleGrantResult struct {
	HandleGrantToken    string    `json:"handle_grant_token"`
	HandleGrantID       string    `json:"handle_grant_id"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	HandleID            string    `json:"handle_id"`
	Limits              Limits    `json:"limits,omitempty"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type ValidateHandleGrantRequest struct {
	HandleGrantToken string          `json:"handle_grant_token"`
	Audience         Audience        `json:"audience"`
	Revision         RevisionBinding `json:"revision"`
	Now              time.Time       `json:"now,omitempty"`
}

type MintStreamTicketRequest struct {
	PluginID             string          `json:"plugin_id,omitempty"`
	PluginInstanceID     string          `json:"plugin_instance_id"`
	PluginVersion        string          `json:"plugin_version,omitempty"`
	ActiveFingerprint    string          `json:"active_fingerprint"`
	SurfaceID            string          `json:"surface_id,omitempty"`
	SurfaceInstanceID    string          `json:"surface_instance_id"`
	EntryPath            string          `json:"entry_path,omitempty"`
	EntrySHA256          string          `json:"entry_sha256,omitempty"`
	AssetSessionNonce    string          `json:"asset_session_nonce,omitempty"`
	RouteRole            string          `json:"route_role,omitempty"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string          `json:"bridge_channel_id"`
	RuntimeGenerationID  string          `json:"runtime_generation_id,omitempty"`
	StreamID             string          `json:"stream_id"`
	OperationID          string          `json:"operation_id"`
	StreamDirection      string          `json:"stream_direction"`
	Method               string          `json:"method"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
	ExpiresAt            time.Time       `json:"expires_at,omitempty"`
}

type StreamTicketResult struct {
	StreamTicket   string    `json:"stream_ticket"`
	StreamTicketID string    `json:"stream_ticket_id"`
	StreamID       string    `json:"stream_id"`
	OperationID    string    `json:"operation_id"`
	Direction      string    `json:"stream_direction"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type ValidateStreamTicketRequest struct {
	StreamTicket string          `json:"stream_ticket"`
	Audience     Audience        `json:"audience"`
	Revision     RevisionBinding `json:"revision"`
	Now          time.Time       `json:"now,omitempty"`
}

type ValidateBoundStreamTicketRequest struct {
	StreamTicket         string          `json:"stream_ticket"`
	PluginID             string          `json:"plugin_id"`
	PluginInstanceID     string          `json:"plugin_instance_id"`
	PluginVersion        string          `json:"plugin_version"`
	ActiveFingerprint    string          `json:"active_fingerprint"`
	SurfaceID            string          `json:"surface_id,omitempty"`
	SurfaceInstanceID    string          `json:"surface_instance_id,omitempty"`
	EntryPath            string          `json:"entry_path,omitempty"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string          `json:"bridge_channel_id,omitempty"`
	StreamID             string          `json:"stream_id"`
	OperationID          string          `json:"operation_id"`
	StreamDirection      string          `json:"stream_direction"`
	Method               string          `json:"method"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
}

type RotateBoundStreamTicketResult struct {
	Current TokenRecord
	Next    *StreamTicketResult
}

type surfaceState struct {
	session             SurfaceSession
	assetSessionIssued  bool
	assetSessionTokenID string
	surfacePrepared     bool
	liveBridgeChannelID string
	liveGatewayTokenID  string
}

func NewSurfaceTokenService(tokens *TokenManager, options SurfaceTokenOptions) *SurfaceTokenService {
	if tokens == nil {
		tokens = NewTokenManager()
	}
	if options.AssetTicketTTL <= 0 {
		options.AssetTicketTTL = DefaultAssetTicketTTL
	}
	if options.AssetTicketTTL > MaxAssetTicketTTL {
		options.AssetTicketTTL = MaxAssetTicketTTL
	}
	if options.AssetSessionTTL <= 0 {
		options.AssetSessionTTL = DefaultAssetSessionTTL
	}
	if options.AssetSessionTTL > MaxAssetSessionTTL {
		options.AssetSessionTTL = MaxAssetSessionTTL
	}
	if options.GatewayTokenTTL <= 0 {
		options.GatewayTokenTTL = DefaultGatewayTokenTTL
	}
	if options.GatewayTokenTTL > MaxGatewayTokenTTL {
		options.GatewayTokenTTL = MaxGatewayTokenTTL
	}
	if options.MaxActiveSessions <= 0 {
		options.MaxActiveSessions = DefaultMaxActiveSurfaceSessions
	}
	if options.MaxActiveSessionsPerOwner <= 0 {
		options.MaxActiveSessionsPerOwner = DefaultMaxActiveSurfaceSessionsPerOwner
	}
	if options.MaxActiveSessionsPerOwner > options.MaxActiveSessions {
		options.MaxActiveSessionsPerOwner = options.MaxActiveSessions
	}
	return &SurfaceTokenService{
		tokens:   tokens,
		options:  options,
		sessions: map[string]surfaceState{},
	}
}

func (s *SurfaceTokenService) OpenSurface(req OpenSurfaceRequest) (SurfaceBootstrap, error) {
	if s == nil {
		return SurfaceBootstrap{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.PluginID) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.PluginVersion) == "" ||
		strings.TrimSpace(req.SurfaceID) == "" ||
		strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.EntryPath) == "" ||
		strings.TrimSpace(req.EntrySHA256) == "" ||
		strings.TrimSpace(req.RouteRole) == "" ||
		strings.TrimSpace(req.RuntimeGenerationID) == "" ||
		strings.TrimSpace(req.OwnerSessionHash) == "" ||
		strings.TrimSpace(req.SessionChannelIDHash) == "" {
		return SurfaceBootstrap{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	bridgeNonce, err := randomString(24)
	if err != nil {
		return SurfaceBootstrap{}, err
	}
	assetSessionNonce, err := randomString(24)
	if err != nil {
		return SurfaceBootstrap{}, err
	}
	session := SurfaceSession{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		PluginVersion:        req.PluginVersion,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
		EntryPath:            req.EntryPath,
		EntrySHA256:          req.EntrySHA256,
		AssetSessionNonce:    assetSessionNonce,
		RouteRole:            req.RouteRole,
		RuntimeGenerationID:  req.RuntimeGenerationID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeNonce:          bridgeNonce,
		PolicyRevision:       req.Revision.PolicyRevision,
		ManagementRevision:   req.Revision.ManagementRevision,
		RevokeEpoch:          req.Revision.RevokeEpoch,
		CreatedAt:            now,
		ExpiresAt:            now.Add(s.options.AssetSessionTTL),
	}
	audience := Audience{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		PluginVersion:        req.PluginVersion,
		ActiveFingerprint:    req.ActiveFingerprint,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		EntryPath:            req.EntryPath,
		EntrySHA256:          req.EntrySHA256,
		AssetSessionNonce:    assetSessionNonce,
		RouteRole:            req.RouteRole,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		RuntimeGenerationID:  req.RuntimeGenerationID,
	}
	if err := s.reserveSurfaceSession(session, now); err != nil {
		return SurfaceBootstrap{}, err
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  audience,
		Revision:  req.Revision,
		ExpiresAt: now.Add(s.options.AssetTicketTTL),
		Now:       now,
	})
	if err != nil {
		s.releaseSurfaceReservation(session)
		return SurfaceBootstrap{}, err
	}

	return SurfaceBootstrap{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		PluginVersion:        req.PluginVersion,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
		EntryPath:            req.EntryPath,
		EntrySHA256:          req.EntrySHA256,
		AssetSessionNonce:    assetSessionNonce,
		PluginStateVersion:   req.Revision.ManagementRevision,
		RevokeEpoch:          req.Revision.RevokeEpoch,
		RuntimeGenerationID:  req.RuntimeGenerationID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		AssetTicket:          minted.Token,
		AssetTicketID:        minted.TokenID,
		BridgeNonce:          bridgeNonce,
		IssuedAt:             minted.IssuedAt,
		ExpiresAt:            minted.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) reserveSurfaceSession(session SurfaceSession, now time.Time) error {
	revokedSurfaceIDs := make([]string, 0)
	s.mu.Lock()
	for surfaceInstanceID, state := range s.sessions {
		if !now.Before(state.session.ExpiresAt) {
			delete(s.sessions, surfaceInstanceID)
			revokedSurfaceIDs = append(revokedSurfaceIDs, surfaceInstanceID)
		}
	}

	var reserveErr error
	if existing, exists := s.sessions[session.SurfaceInstanceID]; exists {
		if surfaceSessionCanReplaceStaleBinding(existing.session, session) {
			delete(s.sessions, session.SurfaceInstanceID)
			revokedSurfaceIDs = append(revokedSurfaceIDs, session.SurfaceInstanceID)
		} else {
			reserveErr = ErrSurfaceSessionAlreadyExists
		}
	}
	if reserveErr == nil && len(s.sessions) >= s.options.MaxActiveSessions {
		reserveErr = ErrSurfaceSessionLimitReached
	} else if reserveErr == nil {
		ownerSessions := 0
		for _, state := range s.sessions {
			if state.session.OwnerSessionHash == session.OwnerSessionHash {
				ownerSessions++
			}
		}
		if ownerSessions >= s.options.MaxActiveSessionsPerOwner {
			reserveErr = ErrSurfaceSessionLimitReached
		} else {
			s.sessions[session.SurfaceInstanceID] = surfaceState{session: session}
		}
	}
	s.mu.Unlock()

	for _, surfaceInstanceID := range revokedSurfaceIDs {
		s.tokens.RevokeSurface(surfaceInstanceID, now)
	}
	return reserveErr
}

func surfaceSessionCanReplaceStaleBinding(current SurfaceSession, next SurfaceSession) bool {
	if current.PluginInstanceID != next.PluginInstanceID ||
		current.SurfaceID != next.SurfaceID ||
		current.OwnerSessionHash != next.OwnerSessionHash ||
		current.OwnerUserHash != next.OwnerUserHash ||
		current.SessionChannelIDHash != next.SessionChannelIDHash {
		return false
	}
	return current.ActiveFingerprint != next.ActiveFingerprint ||
		current.EntryPath != next.EntryPath ||
		current.EntrySHA256 != next.EntrySHA256 ||
		current.RuntimeGenerationID != next.RuntimeGenerationID ||
		current.revision() != next.revision()
}

func (s *SurfaceTokenService) releaseSurfaceReservation(session SurfaceSession) {
	s.mu.Lock()
	state, ok := s.sessions[session.SurfaceInstanceID]
	if ok && state == (surfaceState{session: session}) {
		delete(s.sessions, session.SurfaceInstanceID)
	}
	s.mu.Unlock()
}

func (s *SurfaceTokenService) ExchangeAssetTicket(req ExchangeAssetTicketRequest) (AssetSessionResult, error) {
	if s == nil {
		return AssetSessionResult{}, errors.New("surface token service is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state, err := s.getState(req.SurfaceInstanceID, now)
	if err != nil {
		return AssetSessionResult{}, err
	}
	if !state.session.matchesScope(req.OwnerSessionHash, req.OwnerUserHash, req.SessionChannelIDHash) {
		return AssetSessionResult{}, ErrTokenAudience
	}
	audience := state.session.audience("")
	revision := state.session.revision()
	if _, err := s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindAssetTicket,
		Token:    req.AssetTicket,
		Audience: audience,
		Revision: revision,
		Now:      now,
		Consume:  true,
	}); err != nil {
		return AssetSessionResult{}, err
	}
	assetSession, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindAssetSession,
		Audience:  audience,
		Revision:  revision,
		ExpiresAt: now.Add(s.options.AssetSessionTTL),
		Now:       now,
	})
	if err != nil {
		return AssetSessionResult{}, err
	}

	s.mu.Lock()
	current, ok := s.sessions[req.SurfaceInstanceID]
	if !ok || current != state {
		s.mu.Unlock()
		s.tokens.RevokeSurface(req.SurfaceInstanceID, now)
		return AssetSessionResult{}, ErrTokenRevoked
	}
	state.assetSessionIssued = true
	state.assetSessionTokenID = assetSession.TokenID
	s.sessions[req.SurfaceInstanceID] = state
	s.mu.Unlock()

	return AssetSessionResult{
		AssetSession:       assetSession.Token,
		AssetSessionID:     assetSession.TokenID,
		AssetSessionNonce:  state.session.AssetSessionNonce,
		EntryPath:          state.session.EntryPath,
		EntrySHA256:        state.session.EntrySHA256,
		PluginStateVersion: state.session.ManagementRevision,
		RevokeEpoch:        state.session.RevokeEpoch,
		IssuedAt:           assetSession.IssuedAt,
		ExpiresAt:          assetSession.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) ValidateAssetSession(req ValidateAssetSessionRequest) (AssetSessionValidation, error) {
	if s == nil {
		return AssetSessionValidation{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.AssetSessionID) == "" {
		return AssetSessionValidation{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := s.tokens.Inspect(InspectRequest{
		Kind:  TokenKindAssetSession,
		Token: req.AssetSession,
		Now:   now,
	})
	if err != nil {
		return AssetSessionValidation{}, err
	}
	if req.AssetSessionID != record.TokenID {
		return AssetSessionValidation{}, ErrTokenAudience
	}
	state, err := s.getState(record.Audience.SurfaceInstanceID, now)
	if err != nil {
		return AssetSessionValidation{}, err
	}
	if !state.assetSessionIssued {
		return AssetSessionValidation{}, ErrAssetSessionRequired
	}
	if state.assetSessionTokenID != record.TokenID {
		return AssetSessionValidation{}, ErrTokenRevoked
	}
	if state.session.audience("") != record.Audience {
		return AssetSessionValidation{}, ErrTokenAudience
	}
	if !state.session.matchesScope(req.OwnerSessionHash, req.OwnerUserHash, req.SessionChannelIDHash) {
		return AssetSessionValidation{}, ErrTokenAudience
	}
	if state.session.revision() != record.Revision {
		return AssetSessionValidation{}, ErrTokenRevoked
	}
	return AssetSessionValidation{Session: state.session, TokenID: record.TokenID}, nil
}

func (s *SurfaceTokenService) MarkSurfacePrepared(req MarkSurfacePreparedRequest) error {
	if s == nil {
		return errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.SurfaceInstanceID) == "" || strings.TrimSpace(req.AssetSessionID) == "" ||
		strings.TrimSpace(req.BridgeNonce) == "" || strings.TrimSpace(req.OwnerSessionHash) == "" ||
		strings.TrimSpace(req.SessionChannelIDHash) == "" {
		return ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	state, ok := s.sessions[req.SurfaceInstanceID]
	if !ok {
		s.mu.Unlock()
		return ErrSurfaceSessionNotFound
	}
	if !now.Before(state.session.ExpiresAt) {
		delete(s.sessions, req.SurfaceInstanceID)
		s.mu.Unlock()
		s.tokens.RevokeSurface(req.SurfaceInstanceID, now)
		return ErrSurfaceSessionExpired
	}
	if !state.assetSessionIssued || state.assetSessionTokenID != req.AssetSessionID {
		s.mu.Unlock()
		return ErrAssetSessionRequired
	}
	if state.session.BridgeNonce != req.BridgeNonce ||
		!state.session.matchesScope(req.OwnerSessionHash, req.OwnerUserHash, req.SessionChannelIDHash) {
		s.mu.Unlock()
		return ErrTokenAudience
	}
	state.surfacePrepared = true
	s.sessions[req.SurfaceInstanceID] = state
	s.mu.Unlock()
	return nil
}

func (s *SurfaceTokenService) MintGatewayToken(req MintGatewayTokenRequest) (GatewayTokenResult, error) {
	state, now, err := s.validateBridgeHandshake(req)
	if err != nil {
		return GatewayTokenResult{}, err
	}
	leaseTTL := s.options.AssetSessionTTL
	if s.options.GatewayTokenTTL < leaseTTL {
		leaseTTL = s.options.GatewayTokenTTL
	}
	expiresAt := now.Add(leaseTTL)
	assetSession, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindAssetSession,
		Audience:  state.session.audience(""),
		Revision:  state.session.revision(),
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		return GatewayTokenResult{}, err
	}
	audience := state.session.audience(req.BridgeChannelID)
	minted, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  audience,
		Revision:  state.session.revision(),
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		s.tokens.RevokeTokenID(TokenKindAssetSession, assetSession.TokenID, now)
		return GatewayTokenResult{}, err
	}

	s.mu.Lock()
	current, ok := s.sessions[req.Handshake.SurfaceInstanceID]
	if !ok || current != state {
		s.mu.Unlock()
		s.tokens.RevokeTokenID(TokenKindAssetSession, assetSession.TokenID, now)
		s.tokens.RevokeTokenID(TokenKindPluginGatewayToken, minted.TokenID, now)
		return GatewayTokenResult{}, ErrTokenRevoked
	}
	previousAssetSessionTokenID := state.assetSessionTokenID
	previousGatewayTokenID := state.liveGatewayTokenID
	state.session.ExpiresAt = expiresAt
	state.assetSessionIssued = true
	state.assetSessionTokenID = assetSession.TokenID
	state.liveBridgeChannelID = req.BridgeChannelID
	state.liveGatewayTokenID = minted.TokenID
	s.sessions[req.Handshake.SurfaceInstanceID] = state
	s.mu.Unlock()
	s.tokens.RevokeTokenID(TokenKindAssetSession, previousAssetSessionTokenID, now)
	s.tokens.RevokeTokenID(TokenKindPluginGatewayToken, previousGatewayTokenID, now)

	return GatewayTokenResult{
		GatewayToken:   minted.Token,
		GatewayTokenID: minted.TokenID,
		AssetSession:   assetSession.Token,
		AssetSessionID: assetSession.TokenID,
		IssuedAt:       minted.IssuedAt,
		ExpiresAt:      minted.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) ValidateBridgeHandshake(req MintGatewayTokenRequest) (BridgeHandshakeValidation, error) {
	state, _, err := s.validateBridgeHandshake(req)
	if err != nil {
		return BridgeHandshakeValidation{}, err
	}
	return BridgeHandshakeValidation{Session: state.session}, nil
}

func (s *SurfaceTokenService) validateBridgeHandshake(req MintGatewayTokenRequest) (surfaceState, time.Time, error) {
	if s == nil {
		return surfaceState{}, time.Time{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.BridgeChannelID) == "" {
		return surfaceState{}, time.Time{}, ErrMissingTokenAudience
	}
	if strings.TrimSpace(req.HandshakeTranscriptSHA256) == "" {
		return surfaceState{}, time.Time{}, ErrMissingTokenAudience
	}
	if req.HandshakeTranscriptSHA256 != HandshakeTranscriptSHA256(req.Handshake, req.BridgeChannelID) {
		return surfaceState{}, time.Time{}, ErrTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state, err := s.getState(req.Handshake.SurfaceInstanceID, now)
	if err != nil {
		return surfaceState{}, time.Time{}, err
	}
	if !state.assetSessionIssued || !state.surfacePrepared {
		return surfaceState{}, time.Time{}, ErrAssetSessionRequired
	}
	if err := state.session.validateHandshake(req.Handshake); err != nil {
		return surfaceState{}, time.Time{}, err
	}
	if state.liveBridgeChannelID == "" {
		if strings.TrimSpace(req.PreviousGatewayToken) != "" {
			return surfaceState{}, time.Time{}, ErrTokenAudience
		}
		return state, now, nil
	}
	if state.liveBridgeChannelID != req.BridgeChannelID || strings.TrimSpace(req.PreviousGatewayToken) == "" {
		return surfaceState{}, time.Time{}, ErrTokenAlreadyBound
	}
	previous, err := s.tokens.Inspect(InspectRequest{Kind: TokenKindPluginGatewayToken, Token: req.PreviousGatewayToken, Now: now})
	if err != nil {
		return surfaceState{}, time.Time{}, err
	}
	if previous.TokenID != state.liveGatewayTokenID || previous.Audience != state.session.audience(req.BridgeChannelID) || previous.Revision != state.session.revision() {
		return surfaceState{}, time.Time{}, ErrTokenAudience
	}
	return state, now, nil
}

func HandshakeTranscriptSHA256(handshake Handshake, bridgeChannelID string) string {
	hash := sha256.New()
	for _, field := range []string{
		"redevplugin.bridge.handshake.v2",
		handshake.PluginID,
		handshake.SurfaceID,
		handshake.SurfaceInstanceID,
		handshake.ActiveFingerprint,
		handshake.BridgeNonce,
		handshake.AssetSessionNonce,
		strconv.FormatUint(handshake.PluginStateVersion, 10),
		strconv.FormatUint(handshake.RevokeEpoch, 10),
		handshake.UIProtocolVersion,
		bridgeChannelID,
	} {
		data := []byte(field)
		hash.Write([]byte(strconv.Itoa(len(data))))
		hash.Write([]byte{':'})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func (s *SurfaceTokenService) ValidateGatewayToken(token string, audience Audience, revision RevisionBinding, now time.Time) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	return s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindPluginGatewayToken,
		Token:    token,
		Audience: audience,
		Revision: revision,
		Now:      now,
		Bind:     &ChannelBinding{BridgeChannelID: audience.BridgeChannelID},
	})
}

func (s *SurfaceTokenService) ValidateSurfaceGatewayToken(req ValidateSurfaceGatewayTokenRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.GatewayToken) == "" || strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.SurfaceInstanceID) == "" || strings.TrimSpace(req.BridgeChannelID) == "" {
		return TokenRecord{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := s.tokens.Inspect(InspectRequest{
		Kind:  TokenKindPluginGatewayToken,
		Token: req.GatewayToken,
		Now:   now,
	})
	if err != nil {
		return TokenRecord{}, err
	}
	if record.Revision != req.Revision {
		return TokenRecord{}, ErrTokenRevoked
	}
	if record.Audience.PluginInstanceID != req.PluginInstanceID ||
		record.Audience.SurfaceInstanceID != req.SurfaceInstanceID ||
		record.Audience.OwnerSessionHash != req.OwnerSessionHash ||
		record.Audience.OwnerUserHash != req.OwnerUserHash ||
		record.Audience.SessionChannelIDHash != req.SessionChannelIDHash ||
		record.Audience.BridgeChannelID != req.BridgeChannelID {
		return TokenRecord{}, ErrTokenAudience
	}
	state, err := s.getState(req.SurfaceInstanceID, now)
	if err != nil {
		if errors.Is(err, ErrSurfaceSessionNotFound) || errors.Is(err, ErrSurfaceSessionExpired) {
			return TokenRecord{}, ErrTokenRevoked
		}
		return TokenRecord{}, err
	}
	if state.session.revision() != req.Revision {
		return TokenRecord{}, ErrTokenRevoked
	}
	if state.liveBridgeChannelID != req.BridgeChannelID || state.liveGatewayTokenID != record.TokenID {
		return TokenRecord{}, ErrTokenRevoked
	}
	if state.session.PluginInstanceID != req.PluginInstanceID ||
		state.session.OwnerSessionHash != req.OwnerSessionHash ||
		state.session.OwnerUserHash != req.OwnerUserHash ||
		state.session.SessionChannelIDHash != req.SessionChannelIDHash {
		return TokenRecord{}, ErrTokenAudience
	}
	return s.ValidateGatewayToken(req.GatewayToken, state.session.audience(req.BridgeChannelID), req.Revision, now)
}

func (s *SurfaceTokenService) MintConfirmationToken(req MintConfirmationTokenRequest) (ConfirmationTokenResult, error) {
	if s == nil {
		return ConfirmationTokenResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.ConfirmationID) == "" ||
		strings.TrimSpace(req.BridgeChannelID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return ConfirmationTokenResult{}, ErrMissingTokenAudience
	}
	if !requestHashPattern.MatchString(req.RequestHash) || !requestHashPattern.MatchString(req.PlanHash) || !requestHashPattern.MatchString(req.TargetDescriptorSHA256) {
		return ConfirmationTokenResult{}, ErrTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultConfirmationTTL)
	}
	if expiresAt.After(now.Add(MaxConfirmationTTL)) {
		expiresAt = now.Add(MaxConfirmationTTL)
	}
	audience := Audience{
		PluginID:               req.PluginID,
		PluginInstanceID:       req.PluginInstanceID,
		PluginVersion:          req.PluginVersion,
		ActiveFingerprint:      req.ActiveFingerprint,
		SurfaceID:              req.SurfaceID,
		SurfaceInstanceID:      req.SurfaceInstanceID,
		EntryPath:              req.EntryPath,
		EntrySHA256:            req.EntrySHA256,
		AssetSessionNonce:      req.AssetSessionNonce,
		RouteRole:              req.RouteRole,
		ConfirmationID:         req.ConfirmationID,
		OwnerSessionHash:       req.OwnerSessionHash,
		OwnerUserHash:          req.OwnerUserHash,
		SessionChannelIDHash:   req.SessionChannelIDHash,
		BridgeChannelID:        req.BridgeChannelID,
		RuntimeGenerationID:    req.RuntimeGenerationID,
		Method:                 req.Method,
		RequestHash:            req.RequestHash,
		PlanHash:               req.PlanHash,
		TargetDescriptorSHA256: req.TargetDescriptorSHA256,
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindConfirmationToken,
		Audience:  audience,
		Revision:  req.Revision,
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		return ConfirmationTokenResult{}, err
	}
	return ConfirmationTokenResult{
		ConfirmationToken:   minted.Token,
		ConfirmationTokenID: minted.TokenID,
		RequestHash:         req.RequestHash,
		PlanHash:            req.PlanHash,
		IssuedAt:            minted.IssuedAt,
		ExpiresAt:           minted.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) ValidateConfirmationToken(req ValidateConfirmationTokenRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	return s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindConfirmationToken,
		Token:    req.ConfirmationToken,
		Audience: req.Audience,
		Revision: req.Revision,
		Now:      req.Now,
		Consume:  true,
	})
}

func (s *SurfaceTokenService) ValidateConfirmationTokenID(req ValidateConfirmationTokenIDRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	return s.tokens.ValidateID(ValidateTokenIDRequest{
		Kind:     TokenKindConfirmationToken,
		TokenID:  req.ConfirmationTokenID,
		Audience: req.Audience,
		Revision: req.Revision,
		Now:      req.Now,
		Consume:  true,
	})
}

func (s *SurfaceTokenService) MintRuntimeExecutionLease(req MintRuntimeExecutionLeaseRequest) (RuntimeExecutionLeaseResult, error) {
	if s == nil {
		return RuntimeExecutionLeaseResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.RuntimeInstanceID) == "" ||
		strings.TrimSpace(req.RuntimeGenerationID) == "" ||
		strings.TrimSpace(req.IPCChannelID) == "" ||
		strings.TrimSpace(req.ConnectionNonce) == "" ||
		strings.TrimSpace(req.AuditCorrelationID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return RuntimeExecutionLeaseResult{}, ErrMissingTokenAudience
	}
	switch strings.TrimSpace(req.Execution) {
	case "sync":
		if strings.TrimSpace(req.OperationID) != "" || strings.TrimSpace(req.StreamID) != "" {
			return RuntimeExecutionLeaseResult{}, ErrTokenAudience
		}
	case "operation":
		if strings.TrimSpace(req.OperationID) == "" || strings.TrimSpace(req.StreamID) != "" {
			return RuntimeExecutionLeaseResult{}, ErrMissingTokenAudience
		}
	case "subscription":
		if strings.TrimSpace(req.OperationID) == "" || strings.TrimSpace(req.StreamID) == "" {
			return RuntimeExecutionLeaseResult{}, ErrMissingTokenAudience
		}
	default:
		return RuntimeExecutionLeaseResult{}, ErrTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultRuntimeLeaseTTL)
	}
	if expiresAt.After(now.Add(MaxRuntimeLeaseTTL)) {
		expiresAt = now.Add(MaxRuntimeLeaseTTL)
	}
	leaseID, err := runtimeExecutionLeaseID()
	if err != nil {
		return RuntimeExecutionLeaseResult{}, err
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind: TokenKindRuntimeExecutionLease,
		Audience: Audience{
			PluginID:             req.PluginID,
			PluginInstanceID:     req.PluginInstanceID,
			PluginVersion:        req.PluginVersion,
			ActiveFingerprint:    req.ActiveFingerprint,
			SurfaceInstanceID:    req.SurfaceInstanceID,
			OwnerSessionHash:     req.OwnerSessionHash,
			OwnerUserHash:        req.OwnerUserHash,
			SessionChannelIDHash: req.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
			RuntimeInstanceID:    req.RuntimeInstanceID,
			RuntimeGenerationID:  req.RuntimeGenerationID,
			RuntimeShardID:       req.RuntimeShardID,
			IPCChannelID:         req.IPCChannelID,
			ConnectionNonce:      req.ConnectionNonce,
			OperationID:          req.OperationID,
			StreamID:             req.StreamID,
			AuditCorrelationID:   req.AuditCorrelationID,
			Method:               req.Method,
		},
		Revision:  req.Revision,
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		return RuntimeExecutionLeaseResult{}, err
	}
	return RuntimeExecutionLeaseResult{
		TokenKind:              minted.Kind,
		TokenID:                minted.TokenID,
		LeaseToken:             minted.Token,
		LeaseID:                leaseID,
		LeaseNonce:             minted.Nonce,
		PluginInstanceID:       strings.TrimSpace(req.PluginInstanceID),
		PluginID:               strings.TrimSpace(req.PluginID),
		PluginVersion:          strings.TrimSpace(req.PluginVersion),
		ActiveFingerprint:      strings.TrimSpace(req.ActiveFingerprint),
		SurfaceInstanceID:      strings.TrimSpace(req.SurfaceInstanceID),
		OwnerSessionHash:       strings.TrimSpace(req.OwnerSessionHash),
		OwnerUserHash:          strings.TrimSpace(req.OwnerUserHash),
		SessionChannelIDHash:   strings.TrimSpace(req.SessionChannelIDHash),
		BridgeChannelID:        strings.TrimSpace(req.BridgeChannelID),
		RuntimeInstanceID:      strings.TrimSpace(req.RuntimeInstanceID),
		RuntimeGenerationID:    strings.TrimSpace(req.RuntimeGenerationID),
		RuntimeShardID:         strings.TrimSpace(req.RuntimeShardID),
		IPCChannelID:           strings.TrimSpace(req.IPCChannelID),
		ConnectionNonce:        strings.TrimSpace(req.ConnectionNonce),
		Method:                 strings.TrimSpace(req.Method),
		Effect:                 strings.TrimSpace(req.Effect),
		Execution:              strings.TrimSpace(req.Execution),
		OperationID:            strings.TrimSpace(req.OperationID),
		StreamID:               strings.TrimSpace(req.StreamID),
		AuditCorrelationID:     strings.TrimSpace(req.AuditCorrelationID),
		TargetDescriptorHashes: normalizeStringSlice(req.TargetDescriptorHashes),
		Limits:                 req.Limits,
		PolicyRevision:         minted.Revision.PolicyRevision,
		ManagementRevision:     minted.Revision.ManagementRevision,
		RevokeEpoch:            minted.Revision.RevokeEpoch,
		IssuedAt:               minted.IssuedAt,
		IssuedAtUnixMillis:     unixMillis(minted.IssuedAt),
		ExpiresAt:              minted.ExpiresAt,
		ExpiresAtUnixMillis:    unixMillis(minted.ExpiresAt),
	}, nil
}

func (s *SurfaceTokenService) MintHandleGrant(req MintHandleGrantRequest) (HandleGrantResult, error) {
	if s == nil {
		return HandleGrantResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.RuntimeGenerationID) == "" ||
		strings.TrimSpace(req.HandleID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return HandleGrantResult{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultHandleGrantTTL)
	}
	if expiresAt.After(now.Add(MaxHandleGrantTTL)) {
		expiresAt = now.Add(MaxHandleGrantTTL)
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind: TokenKindHandleGrant,
		Audience: Audience{
			PluginInstanceID:    req.PluginInstanceID,
			ActiveFingerprint:   req.ActiveFingerprint,
			RuntimeInstanceID:   req.RuntimeInstanceID,
			RuntimeGenerationID: req.RuntimeGenerationID,
			RuntimeShardID:      req.RuntimeShardID,
			HandleID:            req.HandleID,
			Method:              req.Method,
		},
		Revision:  req.Revision,
		ExpiresAt: expiresAt,
		Now:       now,
		Limits:    req.Limits,
	})
	if err != nil {
		return HandleGrantResult{}, err
	}
	return HandleGrantResult{
		HandleGrantToken:    minted.Token,
		HandleGrantID:       minted.TokenID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		HandleID:            req.HandleID,
		Limits:              minted.Limits,
		IssuedAt:            minted.IssuedAt,
		ExpiresAt:           minted.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) ValidateHandleGrant(req ValidateHandleGrantRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.Audience.PluginInstanceID) == "" ||
		strings.TrimSpace(req.Audience.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.Audience.RuntimeGenerationID) == "" ||
		strings.TrimSpace(req.Audience.HandleID) == "" ||
		strings.TrimSpace(req.Audience.Method) == "" {
		return TokenRecord{}, ErrMissingTokenAudience
	}
	return s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindHandleGrant,
		Token:    req.HandleGrantToken,
		Audience: req.Audience,
		Revision: req.Revision,
		Now:      req.Now,
	})
}

func runtimeExecutionLeaseID() (string, error) {
	suffix, err := randomString(18)
	if err != nil {
		return "", err
	}
	return "lease_" + suffix, nil
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func unixMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	utc := value.UTC()
	return utc.Unix()*1000 + int64(utc.Nanosecond()/int(time.Millisecond))
}

func (s *SurfaceTokenService) MintStreamTicket(req MintStreamTicketRequest) (StreamTicketResult, error) {
	if s == nil {
		return StreamTicketResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.PluginID) == "" ||
		strings.TrimSpace(req.PluginVersion) == "" ||
		strings.TrimSpace(req.RouteRole) == "" ||
		strings.TrimSpace(req.OwnerSessionHash) == "" ||
		strings.TrimSpace(req.SessionChannelIDHash) == "" ||
		strings.TrimSpace(req.StreamID) == "" ||
		strings.TrimSpace(req.OperationID) == "" ||
		!validStreamDirection(req.StreamDirection) ||
		strings.TrimSpace(req.Method) == "" {
		return StreamTicketResult{}, ErrMissingTokenAudience
	}
	if req.RouteRole == RouteRoleTrustedParent && (strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.SurfaceID) == "" || strings.TrimSpace(req.EntryPath) == "" ||
		strings.TrimSpace(req.EntrySHA256) == "" || strings.TrimSpace(req.AssetSessionNonce) == "" ||
		strings.TrimSpace(req.BridgeChannelID) == "") {
		return StreamTicketResult{}, ErrMissingTokenAudience
	}
	if req.RouteRole != RouteRoleTrustedParent && req.RouteRole != RouteRoleTrustedIntent {
		return StreamTicketResult{}, ErrTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultConfirmationTTL)
	}
	if expiresAt.After(now.Add(MaxStreamTicketTTL)) {
		expiresAt = now.Add(MaxStreamTicketTTL)
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind: TokenKindStreamTicket,
		Audience: Audience{
			PluginID:             req.PluginID,
			PluginInstanceID:     req.PluginInstanceID,
			PluginVersion:        req.PluginVersion,
			ActiveFingerprint:    req.ActiveFingerprint,
			SurfaceID:            req.SurfaceID,
			SurfaceInstanceID:    req.SurfaceInstanceID,
			EntryPath:            req.EntryPath,
			EntrySHA256:          req.EntrySHA256,
			AssetSessionNonce:    req.AssetSessionNonce,
			RouteRole:            req.RouteRole,
			OwnerSessionHash:     req.OwnerSessionHash,
			OwnerUserHash:        req.OwnerUserHash,
			SessionChannelIDHash: req.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
			RuntimeGenerationID:  req.RuntimeGenerationID,
			StreamID:             req.StreamID,
			OperationID:          req.OperationID,
			StreamDirection:      req.StreamDirection,
			Method:               req.Method,
		},
		Revision:  req.Revision,
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		return StreamTicketResult{}, err
	}
	return StreamTicketResult{
		StreamTicket:   minted.Token,
		StreamTicketID: minted.TokenID,
		StreamID:       req.StreamID,
		OperationID:    req.OperationID,
		Direction:      req.StreamDirection,
		IssuedAt:       minted.IssuedAt,
		ExpiresAt:      minted.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) ValidateStreamTicket(req ValidateStreamTicketRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.Audience.PluginInstanceID) == "" ||
		strings.TrimSpace(req.Audience.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.Audience.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.Audience.BridgeChannelID) == "" ||
		strings.TrimSpace(req.Audience.StreamID) == "" ||
		strings.TrimSpace(req.Audience.OperationID) == "" ||
		!validStreamDirection(req.Audience.StreamDirection) ||
		strings.TrimSpace(req.Audience.Method) == "" {
		return TokenRecord{}, ErrMissingTokenAudience
	}
	return s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindStreamTicket,
		Token:    req.StreamTicket,
		Audience: req.Audience,
		Revision: req.Revision,
		Now:      req.Now,
		Consume:  true,
	})
}

func (s *SurfaceTokenService) ValidateBoundStreamTicket(req ValidateBoundStreamTicketRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if err := validateBoundStreamTicketRequest(req); err != nil {
		return TokenRecord{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	req.Now = now
	record, err := s.InspectBoundStreamTicket(req)
	if err != nil {
		return TokenRecord{}, err
	}
	return s.tokens.Validate(ValidateRequest{
		Kind:     TokenKindStreamTicket,
		Token:    req.StreamTicket,
		Audience: record.Audience,
		Revision: req.Revision,
		Now:      now,
		Consume:  true,
	})
}

func (s *SurfaceTokenService) InspectBoundStreamTicket(req ValidateBoundStreamTicketRequest) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if err := validateBoundStreamTicketRequest(req); err != nil {
		return TokenRecord{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	req.Now = now
	record, err := s.tokens.Inspect(InspectRequest{Kind: TokenKindStreamTicket, Token: req.StreamTicket, Now: now})
	if err != nil {
		return TokenRecord{}, err
	}
	if err := validateBoundStreamTicketRecord(req, record); err != nil {
		return TokenRecord{}, err
	}
	if req.SurfaceInstanceID == "" {
		return record, nil
	}
	state, err := s.getState(req.SurfaceInstanceID, now)
	if err != nil {
		if errors.Is(err, ErrSurfaceSessionNotFound) || errors.Is(err, ErrSurfaceSessionExpired) {
			return TokenRecord{}, ErrTokenRevoked
		}
		return TokenRecord{}, err
	}
	if !streamTicketSurfaceStateMatches(state, record, req) {
		return TokenRecord{}, ErrTokenRevoked
	}
	return record, nil
}

// RotateBoundStreamTicket serializes the final stream mutation with ticket
// consumption. A failed commit leaves the current ticket reusable.
func (s *SurfaceTokenService) RotateBoundStreamTicket(req ValidateBoundStreamTicketRequest, commit func() (bool, error)) (RotateBoundStreamTicketResult, error) {
	if s == nil {
		return RotateBoundStreamTicketResult{}, errors.New("surface token service is nil")
	}
	if err := validateBoundStreamTicketRequest(req); err != nil {
		return RotateBoundStreamTicketResult{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := now.Add(DefaultConfirmationTTL)
	if expiresAt.After(now.Add(MaxStreamTicketTTL)) {
		expiresAt = now.Add(MaxStreamTicketTTL)
	}
	state, hasState, unlock, err := s.lockBoundStreamTicketState(req, now)
	if err != nil {
		return RotateBoundStreamTicketResult{}, err
	}
	defer unlock()
	rotated, err := s.tokens.RotateSingleUse(RotateSingleUseRequest{
		Kind:          TokenKindStreamTicket,
		Token:         req.StreamTicket,
		Now:           now,
		NextExpiresAt: expiresAt,
		Validate: func(record TokenRecord) error {
			if err := validateBoundStreamTicketRecord(req, record); err != nil {
				return err
			}
			if hasState && !streamTicketSurfaceStateMatches(state, record, req) {
				return ErrTokenRevoked
			}
			return nil
		},
	}, commit)
	if err != nil {
		return RotateBoundStreamTicketResult{}, err
	}
	result := RotateBoundStreamTicketResult{Current: rotated.Current}
	if rotated.Next != nil {
		result.Next = &StreamTicketResult{
			StreamTicket:   rotated.Next.Token,
			StreamTicketID: rotated.Next.TokenID,
			StreamID:       rotated.Next.Audience.StreamID,
			OperationID:    rotated.Next.Audience.OperationID,
			Direction:      rotated.Next.Audience.StreamDirection,
			IssuedAt:       rotated.Next.IssuedAt,
			ExpiresAt:      rotated.Next.ExpiresAt,
		}
	}
	return result, nil
}

// CommitBoundStreamTicket serializes a terminal stream mutation with ticket
// consumption without reserving a replacement credential.
func (s *SurfaceTokenService) CommitBoundStreamTicket(req ValidateBoundStreamTicketRequest, commit func() error) (TokenRecord, error) {
	if s == nil {
		return TokenRecord{}, errors.New("surface token service is nil")
	}
	if err := validateBoundStreamTicketRequest(req); err != nil {
		return TokenRecord{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state, hasState, unlock, err := s.lockBoundStreamTicketState(req, now)
	if err != nil {
		return TokenRecord{}, err
	}
	defer unlock()
	return s.tokens.CommitSingleUse(CommitSingleUseRequest{
		Kind:  TokenKindStreamTicket,
		Token: req.StreamTicket,
		Now:   now,
		Validate: func(record TokenRecord) error {
			if err := validateBoundStreamTicketRecord(req, record); err != nil {
				return err
			}
			if hasState && !streamTicketSurfaceStateMatches(state, record, req) {
				return ErrTokenRevoked
			}
			return nil
		},
	}, commit)
}

func (s *SurfaceTokenService) lockBoundStreamTicketState(req ValidateBoundStreamTicketRequest, now time.Time) (surfaceState, bool, func(), error) {
	if req.SurfaceInstanceID == "" {
		return surfaceState{}, false, func() {}, nil
	}
	s.mu.Lock()
	current, ok := s.sessions[req.SurfaceInstanceID]
	if !ok {
		s.mu.Unlock()
		return surfaceState{}, false, func() {}, ErrTokenRevoked
	}
	if !now.Before(current.session.ExpiresAt) {
		delete(s.sessions, req.SurfaceInstanceID)
		s.tokens.RevokeSurface(req.SurfaceInstanceID, now)
		s.mu.Unlock()
		return surfaceState{}, false, func() {}, ErrTokenRevoked
	}
	return current, true, s.mu.Unlock, nil
}

func validateBoundStreamTicketRequest(req ValidateBoundStreamTicketRequest) error {
	if strings.TrimSpace(req.StreamTicket) == "" ||
		strings.TrimSpace(req.PluginID) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.PluginVersion) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.StreamID) == "" ||
		strings.TrimSpace(req.OperationID) == "" ||
		!validStreamDirection(req.StreamDirection) ||
		strings.TrimSpace(req.Method) == "" {
		return ErrMissingTokenAudience
	}
	return nil
}

func validateBoundStreamTicketRecord(req ValidateBoundStreamTicketRequest, record TokenRecord) error {
	if record.Revision != req.Revision {
		return ErrTokenRevoked
	}
	if record.Audience.PluginID != req.PluginID ||
		record.Audience.PluginInstanceID != req.PluginInstanceID ||
		record.Audience.PluginVersion != req.PluginVersion ||
		record.Audience.ActiveFingerprint != req.ActiveFingerprint ||
		record.Audience.SurfaceInstanceID != req.SurfaceInstanceID ||
		record.Audience.OwnerSessionHash != req.OwnerSessionHash ||
		record.Audience.OwnerUserHash != req.OwnerUserHash ||
		record.Audience.SessionChannelIDHash != req.SessionChannelIDHash ||
		record.Audience.BridgeChannelID != req.BridgeChannelID ||
		record.Audience.StreamID != req.StreamID ||
		record.Audience.OperationID != req.OperationID ||
		record.Audience.StreamDirection != req.StreamDirection ||
		record.Audience.Method != req.Method {
		return ErrTokenAudience
	}
	return nil
}

func streamTicketSurfaceStateMatches(state surfaceState, record TokenRecord, req ValidateBoundStreamTicketRequest) bool {
	expected := record.Audience
	expected.StreamID = ""
	expected.OperationID = ""
	expected.StreamDirection = ""
	expected.Method = ""
	return state.session.audience(req.BridgeChannelID) == expected && state.session.revision() == req.Revision
}

func (s *SurfaceTokenService) RevokeStreamTicketID(tokenID string, now time.Time) bool {
	if s == nil || strings.TrimSpace(tokenID) == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return s.tokens.RevokeTokenID(TokenKindStreamTicket, tokenID, now)
}

func (s *SurfaceTokenService) DisposeSurface(surfaceInstanceID string, now time.Time) bool {
	if s == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	_, ok := s.sessions[surfaceInstanceID]
	if ok {
		delete(s.sessions, surfaceInstanceID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	s.tokens.RevokeSurface(surfaceInstanceID, now)
	return true
}

func (s *SurfaceTokenService) DisposeBoundSurface(req DisposeSurfaceRequest) error {
	if s == nil {
		return errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.BridgeNonce) == "" ||
		strings.TrimSpace(req.OwnerSessionHash) == "" ||
		strings.TrimSpace(req.SessionChannelIDHash) == "" {
		return ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	state, ok := s.sessions[req.SurfaceInstanceID]
	if !ok {
		s.mu.Unlock()
		return ErrSurfaceSessionNotFound
	}
	if !now.Before(state.session.ExpiresAt) {
		delete(s.sessions, req.SurfaceInstanceID)
		s.mu.Unlock()
		s.tokens.RevokeSurface(req.SurfaceInstanceID, now)
		return ErrSurfaceSessionExpired
	}
	if state.session.BridgeNonce != req.BridgeNonce ||
		!state.session.matchesScope(req.OwnerSessionHash, req.OwnerUserHash, req.SessionChannelIDHash) {
		s.mu.Unlock()
		return ErrTokenAudience
	}
	delete(s.sessions, req.SurfaceInstanceID)
	s.mu.Unlock()
	s.tokens.RevokeSurface(req.SurfaceInstanceID, now)
	return nil
}

func (s *SurfaceTokenService) DisposeAssetSession(req ValidateAssetSessionRequest) error {
	validation, err := s.ValidateAssetSession(req)
	if err != nil {
		return err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	state, ok := s.sessions[validation.Session.SurfaceInstanceID]
	if !ok || state.session != validation.Session || state.assetSessionTokenID != validation.TokenID {
		s.mu.Unlock()
		return ErrTokenRevoked
	}
	delete(s.sessions, validation.Session.SurfaceInstanceID)
	s.mu.Unlock()
	s.tokens.RevokeSurface(validation.Session.SurfaceInstanceID, now)
	return nil
}

func (s *SurfaceTokenService) RevokeSurfaceScope(req RevokeSurfaceScopeRequest) (int, error) {
	if s == nil {
		return 0, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.OwnerSessionHash) == "" {
		return 0, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	revokedSurfaceIDs := make([]string, 0)
	s.mu.Lock()
	for surfaceInstanceID, state := range s.sessions {
		if state.session.OwnerSessionHash != req.OwnerSessionHash ||
			(req.OwnerUserHash != "" && state.session.OwnerUserHash != req.OwnerUserHash) ||
			(req.SessionChannelIDHash != "" && state.session.SessionChannelIDHash != req.SessionChannelIDHash) {
			continue
		}
		delete(s.sessions, surfaceInstanceID)
		revokedSurfaceIDs = append(revokedSurfaceIDs, surfaceInstanceID)
	}
	s.mu.Unlock()
	for _, surfaceInstanceID := range revokedSurfaceIDs {
		s.tokens.RevokeSurface(surfaceInstanceID, now)
	}
	return len(revokedSurfaceIDs), nil
}

func (s *SurfaceTokenService) RevokeAllSurfaces(now time.Time) int {
	if s == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	revokedSurfaceIDs := make([]string, 0)
	s.mu.Lock()
	for surfaceInstanceID := range s.sessions {
		delete(s.sessions, surfaceInstanceID)
		revokedSurfaceIDs = append(revokedSurfaceIDs, surfaceInstanceID)
	}
	s.mu.Unlock()
	for _, surfaceInstanceID := range revokedSurfaceIDs {
		s.tokens.RevokeSurface(surfaceInstanceID, now)
	}
	return len(revokedSurfaceIDs)
}

func (s *SurfaceTokenService) RevokePlugin(pluginInstanceID string, minimumRevokeEpoch uint64, now time.Time) (int, error) {
	if s == nil {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	for surfaceInstanceID, state := range s.sessions {
		if state.session.PluginInstanceID == pluginInstanceID {
			delete(s.sessions, surfaceInstanceID)
		}
	}
	s.mu.Unlock()
	return s.tokens.RevokePlugin(pluginInstanceID, minimumRevokeEpoch, now)
}

func (s *SurfaceTokenService) getState(surfaceInstanceID string, now time.Time) (surfaceState, error) {
	s.mu.Lock()
	state, ok := s.sessions[surfaceInstanceID]
	if !ok {
		s.mu.Unlock()
		return surfaceState{}, ErrSurfaceSessionNotFound
	}
	if !now.Before(state.session.ExpiresAt) {
		delete(s.sessions, surfaceInstanceID)
		s.tokens.RevokeSurface(surfaceInstanceID, now)
		s.mu.Unlock()
		return surfaceState{}, ErrSurfaceSessionExpired
	}
	s.mu.Unlock()
	return state, nil
}

func (s SurfaceSession) audience(bridgeChannelID string) Audience {
	return Audience{
		PluginID:             s.PluginID,
		PluginInstanceID:     s.PluginInstanceID,
		PluginVersion:        s.PluginVersion,
		ActiveFingerprint:    s.ActiveFingerprint,
		SurfaceID:            s.SurfaceID,
		SurfaceInstanceID:    s.SurfaceInstanceID,
		EntryPath:            s.EntryPath,
		EntrySHA256:          s.EntrySHA256,
		AssetSessionNonce:    s.AssetSessionNonce,
		RouteRole:            s.RouteRole,
		OwnerSessionHash:     s.OwnerSessionHash,
		OwnerUserHash:        s.OwnerUserHash,
		SessionChannelIDHash: s.SessionChannelIDHash,
		BridgeChannelID:      bridgeChannelID,
		RuntimeGenerationID:  s.RuntimeGenerationID,
	}
}

func (s SurfaceSession) revision() RevisionBinding {
	return RevisionBinding{
		PolicyRevision:     s.PolicyRevision,
		ManagementRevision: s.ManagementRevision,
		RevokeEpoch:        s.RevokeEpoch,
	}
}

func (s SurfaceSession) matchesScope(ownerSessionHash string, ownerUserHash string, sessionChannelIDHash string) bool {
	return s.OwnerSessionHash == ownerSessionHash &&
		s.OwnerUserHash == ownerUserHash &&
		s.SessionChannelIDHash == sessionChannelIDHash
}

func (s SurfaceSession) validateHandshake(handshake Handshake) error {
	if handshake.PluginID != s.PluginID ||
		handshake.SurfaceID != s.SurfaceID ||
		handshake.SurfaceInstanceID != s.SurfaceInstanceID ||
		handshake.ActiveFingerprint != s.ActiveFingerprint ||
		handshake.BridgeNonce != s.BridgeNonce ||
		handshake.AssetSessionNonce != s.AssetSessionNonce ||
		handshake.PluginStateVersion != s.ManagementRevision ||
		handshake.RevokeEpoch != s.RevokeEpoch ||
		handshake.UIProtocolVersion != "plugin-ui-v2" {
		return ErrHandshakeMismatch
	}
	return nil
}

func validStreamDirection(direction string) bool {
	switch strings.TrimSpace(direction) {
	case "read", "write", "duplex":
		return true
	default:
		return false
	}
}
