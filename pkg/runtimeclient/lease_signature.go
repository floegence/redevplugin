package runtimeclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	RuntimeLeaseSignatureSchemaVersion = "redevplugin.runtime_execution_lease.v1"
	RuntimeLeaseTokenKind              = "runtime_execution_lease"
	RuntimeLeaseSignatureAlgorithm     = "ed25519"
	runtimeLeaseSignaturePrefix        = RuntimeLeaseSignatureAlgorithm + ":"
)

var (
	ErrRuntimeLeaseSignatureKeyringRequired = errors.New("runtime lease signing keyring is required")
	ErrRuntimeLeaseSigningKeyNotFound       = errors.New("runtime lease signing key not found")
	ErrRuntimeLeaseSigningKeyRevoked        = errors.New("runtime lease signing key is revoked")
	ErrRuntimeLeasePublicKeyInvalid         = errors.New("runtime lease signing public key is invalid")
	ErrRuntimeLeaseSignatureRequired        = errors.New("runtime execution lease signature is required")
	ErrRuntimeLeaseSignatureInvalid         = errors.New("runtime execution lease signature is invalid")
)

type RuntimeLeasePublicKey struct {
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type RuntimeLeaseVerifier interface {
	VerifyRuntimeLease(ctx context.Context, req RuntimeLeaseVerificationRequest) error
}

type RuntimeLeaseVerificationRequest struct {
	Lease  Lease     `json:"lease"`
	Method string    `json:"method"`
	Now    time.Time `json:"now,omitempty"`
}

type RuntimeLeaseSigningKeyLookupRequest struct {
	KeyID               string `json:"key_id"`
	RuntimeShardID      string `json:"runtime_shard_id,omitempty"`
	RuntimeInstanceID   string `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	IPCChannelID        string `json:"ipc_channel_id,omitempty"`
	ConnectionNonce     string `json:"connection_nonce,omitempty"`
	PluginInstanceID    string `json:"plugin_instance_id,omitempty"`
	Method              string `json:"method,omitempty"`
}

type RuntimeLeaseSigningKey struct {
	KeyID               string            `json:"key_id"`
	PublicKey           ed25519.PublicKey `json:"-"`
	RuntimeShardID      string            `json:"runtime_shard_id,omitempty"`
	RuntimeInstanceID   string            `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string            `json:"runtime_generation_id,omitempty"`
	IPCChannelID        string            `json:"ipc_channel_id,omitempty"`
	ConnectionNonce     string            `json:"connection_nonce,omitempty"`
	Revoked             bool              `json:"revoked,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

type RuntimeLeaseSigningKeyring interface {
	LookupRuntimeLeaseSigningKey(ctx context.Context, req RuntimeLeaseSigningKeyLookupRequest) (RuntimeLeaseSigningKey, error)
}

type StaticRuntimeLeaseSigningKeyring struct {
	Keys []RuntimeLeaseSigningKey
}

func (k StaticRuntimeLeaseSigningKeyring) LookupRuntimeLeaseSigningKey(ctx context.Context, req RuntimeLeaseSigningKeyLookupRequest) (RuntimeLeaseSigningKey, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeLeaseSigningKey{}, err
	}
	for _, key := range k.Keys {
		if key.KeyID != req.KeyID {
			continue
		}
		if key.RuntimeShardID != "" && key.RuntimeShardID != req.RuntimeShardID {
			continue
		}
		if key.RuntimeInstanceID != "" && key.RuntimeInstanceID != req.RuntimeInstanceID {
			continue
		}
		if key.RuntimeGenerationID != "" && key.RuntimeGenerationID != req.RuntimeGenerationID {
			continue
		}
		if key.IPCChannelID != "" && key.IPCChannelID != req.IPCChannelID {
			continue
		}
		if key.ConnectionNonce != "" && key.ConnectionNonce != req.ConnectionNonce {
			continue
		}
		return key, nil
	}
	return RuntimeLeaseSigningKey{}, ErrRuntimeLeaseSigningKeyNotFound
}

type Ed25519RuntimeLeaseVerifier struct {
	Keyring RuntimeLeaseSigningKeyring
	Now     func() time.Time
}

func RuntimeLeasePublicKeyFromEd25519(keyID string, publicKey ed25519.PublicKey) (RuntimeLeasePublicKey, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return RuntimeLeasePublicKey{}, ErrRuntimeLeasePublicKeyInvalid
	}
	return RuntimeLeasePublicKey{
		Algorithm:       RuntimeLeaseSignatureAlgorithm,
		KeyID:           strings.TrimSpace(keyID),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

func NormalizeRuntimeLeasePublicKeys(keys []RuntimeLeasePublicKey) ([]RuntimeLeasePublicKey, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	normalized := make([]RuntimeLeasePublicKey, 0, len(keys))
	for _, key := range keys {
		keyID := strings.TrimSpace(key.KeyID)
		algorithm := strings.TrimSpace(key.Algorithm)
		if algorithm == "" {
			algorithm = RuntimeLeaseSignatureAlgorithm
		}
		if keyID == "" || algorithm != RuntimeLeaseSignatureAlgorithm {
			return nil, ErrRuntimeLeasePublicKeyInvalid
		}
		if _, exists := seen[keyID]; exists {
			return nil, ErrRuntimeLeasePublicKeyInvalid
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key.PublicKeyBase64))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, ErrRuntimeLeasePublicKeyInvalid
		}
		seen[keyID] = struct{}{}
		normalized = append(normalized, RuntimeLeasePublicKey{
			Algorithm:       algorithm,
			KeyID:           keyID,
			PublicKeyBase64: base64.StdEncoding.EncodeToString(raw),
		})
	}
	return normalized, nil
}

func (v Ed25519RuntimeLeaseVerifier) VerifyRuntimeLease(ctx context.Context, req RuntimeLeaseVerificationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := req.Now
	if now.IsZero() {
		now = v.now()
	}
	if err := validateRuntimeLeaseSignatureInput(req.Lease, req.Method, now); err != nil {
		return err
	}
	if v.Keyring == nil {
		return ErrRuntimeLeaseSignatureKeyringRequired
	}
	key, err := v.Keyring.LookupRuntimeLeaseSigningKey(ctx, RuntimeLeaseSigningKeyLookupRequest{
		KeyID:               strings.TrimSpace(req.Lease.KeyID),
		RuntimeShardID:      strings.TrimSpace(req.Lease.RuntimeShardID),
		RuntimeInstanceID:   strings.TrimSpace(req.Lease.RuntimeInstanceID),
		RuntimeGenerationID: strings.TrimSpace(req.Lease.RuntimeGenerationID),
		IPCChannelID:        strings.TrimSpace(req.Lease.IPCChannelID),
		ConnectionNonce:     strings.TrimSpace(req.Lease.ConnectionNonce),
		PluginInstanceID:    strings.TrimSpace(req.Lease.PluginInstanceID),
		Method:              runtimeLeaseSignatureMethod(req.Lease, req.Method),
	})
	if err != nil {
		return err
	}
	if key.Revoked {
		return ErrRuntimeLeaseSigningKeyRevoked
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return ErrRuntimeLeasePublicKeyInvalid
	}
	payload, err := CanonicalRuntimeLeaseSignaturePayload(req.Lease, req.Method)
	if err != nil {
		return err
	}
	signature, err := decodeRuntimeLeaseSignature(req.Lease.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key.PublicKey, payload, signature) {
		return ErrRuntimeLeaseSignatureInvalid
	}
	return nil
}

func SignRuntimeLease(lease Lease, method string, keyID string, privateKey ed25519.PrivateKey) (Lease, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Lease{}, errors.New("runtime lease signing private key is invalid")
	}
	lease = normalizeRuntimeLeaseForIPC(lease)
	lease.KeyID = strings.TrimSpace(keyID)
	lease.Signature = ""
	payload, err := CanonicalRuntimeLeaseSignaturePayload(lease, method)
	if err != nil {
		return Lease{}, err
	}
	lease.Signature = runtimeLeaseSignaturePrefix + base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return lease, nil
}

type runtimeLeaseSignaturePayload struct {
	SchemaVersion          string       `json:"schema_version"`
	TokenKind              string       `json:"token_kind"`
	LeaseID                string       `json:"lease_id"`
	TokenID                string       `json:"token_id,omitempty"`
	LeaseNonce             string       `json:"lease_nonce"`
	PluginInstanceID       string       `json:"plugin_instance_id"`
	PluginID               string       `json:"plugin_id,omitempty"`
	PluginVersion          string       `json:"plugin_version,omitempty"`
	ActiveFingerprint      string       `json:"active_fingerprint,omitempty"`
	IssuedAtUnixMillis     int64        `json:"issued_at_unix_ms,omitempty"`
	Method                 string       `json:"method"`
	Effect                 string       `json:"effect,omitempty"`
	Execution              string       `json:"execution,omitempty"`
	OperationID            string       `json:"operation_id,omitempty"`
	StreamID               string       `json:"stream_id,omitempty"`
	AuditCorrelationID     string       `json:"audit_correlation_id"`
	SurfaceInstanceID      string       `json:"surface_instance_id,omitempty"`
	OwnerSessionHash       string       `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string       `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash   string       `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string       `json:"bridge_channel_id,omitempty"`
	TargetDescriptorHashes []string     `json:"target_descriptor_hashes,omitempty"`
	Limits                 *LeaseLimits `json:"limits,omitempty"`
	PolicyRevision         uint64       `json:"policy_revision"`
	ManagementRevision     uint64       `json:"management_revision"`
	RevokeEpoch            uint64       `json:"revoke_epoch"`
	ExpiresAtUnixMillis    int64        `json:"expires_at_unix_ms"`
	RuntimeShardID         string       `json:"runtime_shard_id,omitempty"`
	RuntimeInstanceID      string       `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID    string       `json:"runtime_generation_id"`
	IPCChannelID           string       `json:"ipc_channel_id,omitempty"`
	ConnectionNonce        string       `json:"connection_nonce,omitempty"`
	KeyID                  string       `json:"key_id"`
}

func CanonicalRuntimeLeaseSignaturePayload(lease Lease, method string) ([]byte, error) {
	resolvedMethod := runtimeLeaseSignatureMethod(lease, method)
	if lease.Method != "" && method != "" && strings.TrimSpace(lease.Method) != strings.TrimSpace(method) {
		return nil, fmt.Errorf("%w: method mismatch", ErrRuntimeLeaseSignatureInvalid)
	}
	return json.Marshal(runtimeLeaseSignaturePayload{
		SchemaVersion:          RuntimeLeaseSignatureSchemaVersion,
		TokenKind:              RuntimeLeaseTokenKind,
		LeaseID:                strings.TrimSpace(lease.LeaseID),
		TokenID:                strings.TrimSpace(runtimeLeaseTokenID(lease)),
		LeaseNonce:             strings.TrimSpace(lease.LeaseNonce),
		PluginInstanceID:       strings.TrimSpace(lease.PluginInstanceID),
		PluginID:               strings.TrimSpace(lease.PluginID),
		PluginVersion:          strings.TrimSpace(lease.PluginVersion),
		ActiveFingerprint:      strings.TrimSpace(lease.ActiveFingerprint),
		IssuedAtUnixMillis:     runtimeLeaseIssuedAtUnixMillis(lease),
		Method:                 resolvedMethod,
		Effect:                 strings.TrimSpace(lease.Effect),
		Execution:              strings.TrimSpace(lease.Execution),
		OperationID:            strings.TrimSpace(lease.OperationID),
		StreamID:               strings.TrimSpace(lease.StreamID),
		AuditCorrelationID:     strings.TrimSpace(lease.AuditCorrelationID),
		SurfaceInstanceID:      strings.TrimSpace(lease.SurfaceInstanceID),
		OwnerSessionHash:       strings.TrimSpace(lease.OwnerSessionHash),
		OwnerUserHash:          strings.TrimSpace(lease.OwnerUserHash),
		SessionChannelIDHash:   strings.TrimSpace(lease.SessionChannelIDHash),
		BridgeChannelID:        strings.TrimSpace(lease.BridgeChannelID),
		TargetDescriptorHashes: append([]string(nil), lease.TargetDescriptorHashes...),
		Limits:                 runtimeLeaseLimitsPointer(lease.Limits),
		PolicyRevision:         lease.PolicyRevision,
		ManagementRevision:     lease.ManagementRevision,
		RevokeEpoch:            lease.RevokeEpoch,
		ExpiresAtUnixMillis:    unixMillis(lease.ExpiresAt),
		RuntimeShardID:         strings.TrimSpace(lease.RuntimeShardID),
		RuntimeInstanceID:      strings.TrimSpace(lease.RuntimeInstanceID),
		RuntimeGenerationID:    strings.TrimSpace(lease.RuntimeGenerationID),
		IPCChannelID:           strings.TrimSpace(lease.IPCChannelID),
		ConnectionNonce:        strings.TrimSpace(lease.ConnectionNonce),
		KeyID:                  strings.TrimSpace(lease.KeyID),
	})
}

func validateRuntimeLeaseSignatureInput(lease Lease, method string, now time.Time) error {
	if strings.TrimSpace(lease.KeyID) == "" {
		return ErrRuntimeLeaseSignatureRequired
	}
	if strings.TrimSpace(lease.Signature) == "" {
		return ErrRuntimeLeaseSignatureRequired
	}
	resolvedMethod := runtimeLeaseSignatureMethod(lease, method)
	if strings.TrimSpace(lease.LeaseID) == "" ||
		strings.TrimSpace(lease.LeaseNonce) == "" ||
		strings.TrimSpace(lease.PluginInstanceID) == "" ||
		strings.TrimSpace(lease.RuntimeGenerationID) == "" ||
		strings.TrimSpace(lease.AuditCorrelationID) == "" ||
		resolvedMethod == "" {
		return ErrRuntimeLeaseInvalid
	}
	switch strings.TrimSpace(lease.Execution) {
	case "sync":
		if strings.TrimSpace(lease.OperationID) != "" || strings.TrimSpace(lease.StreamID) != "" {
			return ErrRuntimeLeaseInvalid
		}
	case "operation":
		if strings.TrimSpace(lease.OperationID) == "" || strings.TrimSpace(lease.StreamID) != "" {
			return ErrRuntimeLeaseInvalid
		}
	case "subscription":
		if strings.TrimSpace(lease.OperationID) == "" || strings.TrimSpace(lease.StreamID) == "" {
			return ErrRuntimeLeaseInvalid
		}
	default:
		return ErrRuntimeLeaseInvalid
	}
	expiresAt := lease.ExpiresAt.UTC()
	if expiresAt.IsZero() || !expiresAt.After(now.UTC()) {
		return ErrRuntimeLeaseInvalid
	}
	if _, err := CanonicalRuntimeLeaseSignaturePayload(lease, method); err != nil {
		return err
	}
	return nil
}

func runtimeLeaseTokenID(lease Lease) string {
	if trimmed := strings.TrimSpace(lease.TokenID); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(lease.LeaseID)
}

func runtimeLeaseIssuedAtUnixMillis(lease Lease) int64 {
	if lease.IssuedAtUnixMillis != 0 {
		return lease.IssuedAtUnixMillis
	}
	return unixMillis(lease.IssuedAt)
}

func runtimeLeaseLimitsPointer(limits LeaseLimits) *LeaseLimits {
	if limits.TimeoutMillis == 0 &&
		limits.MemoryBytes == 0 &&
		limits.MaxPayloadBytes == 0 &&
		limits.MaxStreamBytesPerSecond == 0 {
		return nil
	}
	return &limits
}

func decodeRuntimeLeaseSignature(value string) ([]byte, error) {
	raw := strings.TrimSpace(value)
	if !strings.HasPrefix(raw, runtimeLeaseSignaturePrefix) {
		return nil, ErrRuntimeLeaseSignatureInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, runtimeLeaseSignaturePrefix))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrRuntimeLeaseSignatureInvalid
	}
	return signature, nil
}

func runtimeLeaseSignatureMethod(lease Lease, method string) string {
	if trimmed := strings.TrimSpace(method); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(lease.Method)
}

func (v Ed25519RuntimeLeaseVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func unixMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	utc := value.UTC()
	return utc.Unix()*1000 + int64(utc.Nanosecond()/int(time.Millisecond))
}
