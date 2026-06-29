package bridge

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAssetTicketTTL  = 15 * time.Second
	MaxAssetTicketTTL      = 60 * time.Second
	DefaultAssetSessionTTL = 10 * time.Minute
	DefaultGatewayTokenTTL = 10 * time.Minute
	DefaultConfirmationTTL = 2 * time.Minute
	DefaultRuntimeLeaseTTL = 30 * time.Second
	MaxRuntimeLeaseTTL     = 5 * time.Minute
)

var (
	ErrSurfaceSessionNotFound = errors.New("surface session not found")
	ErrSurfaceSessionExpired  = errors.New("surface session expired")
	ErrHandshakeMismatch      = errors.New("bridge handshake mismatch")
	ErrAssetSessionRequired   = errors.New("asset session is required before bridge token mint")
)

var requestHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type SurfaceTokenService struct {
	mu       sync.Mutex
	tokens   *TokenManager
	options  SurfaceTokenOptions
	sessions map[string]surfaceState
}

type SurfaceTokenOptions struct {
	AssetTicketTTL  time.Duration `json:"asset_ticket_ttl,omitempty"`
	AssetSessionTTL time.Duration `json:"asset_session_ttl,omitempty"`
	GatewayTokenTTL time.Duration `json:"gateway_token_ttl,omitempty"`
}

type OpenSurfaceRequest struct {
	PluginID             string          `json:"plugin_id"`
	PluginInstanceID     string          `json:"plugin_instance_id"`
	SurfaceID            string          `json:"surface_id"`
	SurfaceInstanceID    string          `json:"surface_instance_id"`
	ActiveFingerprint    string          `json:"active_fingerprint"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
}

type SurfaceBootstrap struct {
	PluginID             string    `json:"plugin_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	SurfaceID            string    `json:"surface_id"`
	SurfaceInstanceID    string    `json:"surface_instance_id"`
	ActiveFingerprint    string    `json:"active_fingerprint"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	AssetTicket          string    `json:"asset_ticket"`
	AssetTicketID        string    `json:"asset_ticket_id"`
	BridgeNonce          string    `json:"bridge_nonce"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type ExchangeAssetTicketRequest struct {
	SurfaceInstanceID string    `json:"surface_instance_id"`
	AssetTicket       string    `json:"asset_ticket"`
	Now               time.Time `json:"now,omitempty"`
}

type AssetSessionResult struct {
	AssetSession   string    `json:"asset_session"`
	AssetSessionID string    `json:"asset_session_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type MintGatewayTokenRequest struct {
	Handshake       Handshake `json:"handshake"`
	BridgeChannelID string    `json:"bridge_channel_id"`
	Now             time.Time `json:"now,omitempty"`
}

type GatewayTokenResult struct {
	GatewayToken   string    `json:"plugin_gateway_token"`
	GatewayTokenID string    `json:"plugin_gateway_token_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type MintConfirmationTokenRequest struct {
	PluginInstanceID     string          `json:"plugin_instance_id"`
	ActiveFingerprint    string          `json:"active_fingerprint"`
	SurfaceInstanceID    string          `json:"surface_instance_id"`
	OwnerSessionHash     string          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string          `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string          `json:"bridge_channel_id"`
	Method               string          `json:"method"`
	RequestHash          string          `json:"request_hash"`
	Revision             RevisionBinding `json:"revision"`
	Now                  time.Time       `json:"now,omitempty"`
	ExpiresAt            time.Time       `json:"expires_at,omitempty"`
}

type ConfirmationTokenResult struct {
	ConfirmationToken   string    `json:"confirmation_token"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type ValidateConfirmationTokenRequest struct {
	ConfirmationToken string          `json:"confirmation_token"`
	Audience          Audience        `json:"audience"`
	Revision          RevisionBinding `json:"revision"`
	Now               time.Time       `json:"now,omitempty"`
}

type MintRuntimeExecutionLeaseRequest struct {
	PluginInstanceID    string          `json:"plugin_instance_id"`
	ActiveFingerprint   string          `json:"active_fingerprint"`
	RuntimeInstanceID   string          `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string          `json:"runtime_generation_id"`
	RuntimeShardID      string          `json:"runtime_shard_id,omitempty"`
	Method              string          `json:"method"`
	Revision            RevisionBinding `json:"revision"`
	Now                 time.Time       `json:"now,omitempty"`
	ExpiresAt           time.Time       `json:"expires_at,omitempty"`
}

type RuntimeExecutionLeaseResult struct {
	LeaseToken          string    `json:"lease_token"`
	LeaseID             string    `json:"lease_id"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type surfaceState struct {
	session             SurfaceSession
	assetSessionIssued  bool
	liveBridgeChannelID string
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
	if options.GatewayTokenTTL <= 0 {
		options.GatewayTokenTTL = DefaultGatewayTokenTTL
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
	if strings.TrimSpace(req.PluginID) == "" || strings.TrimSpace(req.SurfaceID) == "" || strings.TrimSpace(req.SurfaceInstanceID) == "" {
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
	session := SurfaceSession{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
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
		PluginInstanceID:     req.PluginInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
	}
	minted, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindAssetTicket,
		Audience:  audience,
		Revision:  req.Revision,
		ExpiresAt: now.Add(s.options.AssetTicketTTL),
		Now:       now,
	})
	if err != nil {
		return SurfaceBootstrap{}, err
	}

	s.mu.Lock()
	s.sessions[req.SurfaceInstanceID] = surfaceState{session: session}
	s.mu.Unlock()

	return SurfaceBootstrap{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
		OwnerSessionHash:     req.OwnerSessionHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		AssetTicket:          minted.Token,
		AssetTicketID:        minted.TokenID,
		BridgeNonce:          bridgeNonce,
		IssuedAt:             minted.IssuedAt,
		ExpiresAt:            minted.ExpiresAt,
	}, nil
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
	state.assetSessionIssued = true
	s.sessions[req.SurfaceInstanceID] = state
	s.mu.Unlock()

	return AssetSessionResult{
		AssetSession:   assetSession.Token,
		AssetSessionID: assetSession.TokenID,
		IssuedAt:       assetSession.IssuedAt,
		ExpiresAt:      assetSession.ExpiresAt,
	}, nil
}

func (s *SurfaceTokenService) MintGatewayToken(req MintGatewayTokenRequest) (GatewayTokenResult, error) {
	if s == nil {
		return GatewayTokenResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.BridgeChannelID) == "" {
		return GatewayTokenResult{}, ErrMissingTokenAudience
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state, err := s.getState(req.Handshake.SurfaceInstanceID, now)
	if err != nil {
		return GatewayTokenResult{}, err
	}
	if !state.assetSessionIssued {
		return GatewayTokenResult{}, ErrAssetSessionRequired
	}
	if err := state.session.validateHandshake(req.Handshake); err != nil {
		return GatewayTokenResult{}, err
	}
	if state.liveBridgeChannelID != "" && state.liveBridgeChannelID != req.BridgeChannelID {
		return GatewayTokenResult{}, ErrTokenAlreadyBound
	}
	audience := state.session.audience(req.BridgeChannelID)
	minted, err := s.tokens.Mint(MintRequest{
		Kind:      TokenKindPluginGatewayToken,
		Audience:  audience,
		Revision:  state.session.revision(),
		ExpiresAt: now.Add(s.options.GatewayTokenTTL),
		Now:       now,
	})
	if err != nil {
		return GatewayTokenResult{}, err
	}

	s.mu.Lock()
	state.liveBridgeChannelID = req.BridgeChannelID
	s.sessions[req.Handshake.SurfaceInstanceID] = state
	s.mu.Unlock()

	return GatewayTokenResult{
		GatewayToken:   minted.Token,
		GatewayTokenID: minted.TokenID,
		IssuedAt:       minted.IssuedAt,
		ExpiresAt:      minted.ExpiresAt,
	}, nil
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

func (s *SurfaceTokenService) MintConfirmationToken(req MintConfirmationTokenRequest) (ConfirmationTokenResult, error) {
	if s == nil {
		return ConfirmationTokenResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.BridgeChannelID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return ConfirmationTokenResult{}, ErrMissingTokenAudience
	}
	if !requestHashPattern.MatchString(req.RequestHash) {
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
	audience := Audience{
		PluginInstanceID:     req.PluginInstanceID,
		ActiveFingerprint:    req.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Method:               req.Method,
		RequestHash:          req.RequestHash,
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

func (s *SurfaceTokenService) MintRuntimeExecutionLease(req MintRuntimeExecutionLeaseRequest) (RuntimeExecutionLeaseResult, error) {
	if s == nil {
		return RuntimeExecutionLeaseResult{}, errors.New("surface token service is nil")
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.RuntimeGenerationID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return RuntimeExecutionLeaseResult{}, ErrMissingTokenAudience
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
	minted, err := s.tokens.Mint(MintRequest{
		Kind: TokenKindRuntimeExecutionLease,
		Audience: Audience{
			PluginInstanceID:    req.PluginInstanceID,
			ActiveFingerprint:   req.ActiveFingerprint,
			RuntimeInstanceID:   req.RuntimeInstanceID,
			RuntimeGenerationID: req.RuntimeGenerationID,
			RuntimeShardID:      req.RuntimeShardID,
			Method:              req.Method,
		},
		Revision:  req.Revision,
		ExpiresAt: expiresAt,
		Now:       now,
	})
	if err != nil {
		return RuntimeExecutionLeaseResult{}, err
	}
	return RuntimeExecutionLeaseResult{
		LeaseToken:          minted.Token,
		LeaseID:             minted.TokenID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		IssuedAt:            minted.IssuedAt,
		ExpiresAt:           minted.ExpiresAt,
	}, nil
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

func (s *SurfaceTokenService) getState(surfaceInstanceID string, now time.Time) (surfaceState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.sessions[surfaceInstanceID]
	if !ok {
		return surfaceState{}, ErrSurfaceSessionNotFound
	}
	if !now.Before(state.session.ExpiresAt) {
		return surfaceState{}, ErrSurfaceSessionExpired
	}
	return state, nil
}

func (s SurfaceSession) audience(bridgeChannelID string) Audience {
	return Audience{
		PluginInstanceID:     s.PluginInstanceID,
		ActiveFingerprint:    s.ActiveFingerprint,
		SurfaceInstanceID:    s.SurfaceInstanceID,
		OwnerSessionHash:     s.OwnerSessionHash,
		OwnerUserHash:        s.OwnerUserHash,
		SessionChannelIDHash: s.SessionChannelIDHash,
		BridgeChannelID:      bridgeChannelID,
	}
}

func (s SurfaceSession) revision() RevisionBinding {
	return RevisionBinding{
		PolicyRevision:     s.PolicyRevision,
		ManagementRevision: s.ManagementRevision,
		RevokeEpoch:        s.RevokeEpoch,
	}
}

func (s SurfaceSession) validateHandshake(handshake Handshake) error {
	if handshake.PluginID != s.PluginID ||
		handshake.SurfaceID != s.SurfaceID ||
		handshake.SurfaceInstanceID != s.SurfaceInstanceID ||
		handshake.ActiveFingerprint != s.ActiveFingerprint ||
		handshake.BridgeNonce != s.BridgeNonce ||
		handshake.UIProtocolVersion != "plugin-ui-v1" {
		return ErrHandshakeMismatch
	}
	return nil
}
