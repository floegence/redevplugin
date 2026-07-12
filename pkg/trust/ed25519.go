package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
)

const AlgorithmEd25519 = pluginpkg.PackageSignatureAlgorithmEd25519

var (
	ErrKeyringRequired      = errors.New("package signing keyring is required")
	ErrKeyNotFound          = errors.New("package signing key not found")
	ErrKeyRevoked           = errors.New("package signing key is revoked")
	ErrPublicKeyInvalid     = errors.New("package signing public key is invalid")
	ErrSignatureRequired    = errors.New("package signature is required")
	ErrUnsupportedAlgorithm = errors.New("package signature algorithm is unsupported")
	ErrSignatureInvalid     = errors.New("package signature is invalid")
)

type KeyLookupRequest struct {
	Algorithm   string `json:"algorithm"`
	KeyID       string `json:"key_id"`
	PublisherID string `json:"publisher_id,omitempty"`
	PluginID    string `json:"plugin_id,omitempty"`
}

type SigningKey struct {
	Algorithm   string            `json:"algorithm"`
	KeyID       string            `json:"key_id"`
	PublisherID string            `json:"publisher_id,omitempty"`
	PluginID    string            `json:"plugin_id,omitempty"`
	PublicKey   ed25519.PublicKey `json:"-"`
	Revoked     bool              `json:"revoked,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Keyring interface {
	LookupPackageSigningKey(ctx context.Context, req KeyLookupRequest) (SigningKey, error)
}

type StaticKeyring struct {
	Keys []SigningKey
}

func (k StaticKeyring) LookupPackageSigningKey(_ context.Context, req KeyLookupRequest) (SigningKey, error) {
	for _, key := range k.Keys {
		if key.KeyID != req.KeyID {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != req.Algorithm {
			continue
		}
		if key.PublisherID != "" && key.PublisherID != req.PublisherID {
			continue
		}
		if key.PluginID != "" && key.PluginID != req.PluginID {
			continue
		}
		return key, nil
	}
	return SigningKey{}, ErrKeyNotFound
}

type Ed25519Verifier struct {
	Keyring Keyring
	Now     func() time.Time
}

func (v Ed25519Verifier) VerifyPackageTrust(ctx context.Context, req host.PackageTrustVerificationRequest) (host.PackageTrustVerificationResult, error) {
	requested, requireSignature, err := trustRequestFromPolicy(req)
	if err != nil {
		return host.PackageTrustVerificationResult{}, err
	}
	if !requireSignature {
		return host.PackageTrustVerificationResult{TrustState: requested}, nil
	}
	if v.Keyring == nil {
		return host.PackageTrustVerificationResult{}, ErrKeyringRequired
	}
	sig := req.Package.PackageSignature
	if sig == nil {
		return host.PackageTrustVerificationResult{}, ErrSignatureRequired
	}
	if sig.Algorithm != AlgorithmEd25519 {
		return host.PackageTrustVerificationResult{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, sig.Algorithm)
	}
	if !sourcePolicyAllowsKey(req.SourcePolicySnapshot, sig.KeyID) {
		return host.PackageTrustVerificationResult{}, ErrKeyNotFound
	}
	if err := validateSignatureHashes(req.Package, *sig); err != nil {
		return host.PackageTrustVerificationResult{}, err
	}
	key, err := v.Keyring.LookupPackageSigningKey(ctx, KeyLookupRequest{
		Algorithm:   sig.Algorithm,
		KeyID:       sig.KeyID,
		PublisherID: sig.PublisherID,
		PluginID:    sig.PluginID,
	})
	if err != nil {
		return host.PackageTrustVerificationResult{}, err
	}
	if key.Revoked {
		return host.PackageTrustVerificationResult{}, ErrKeyRevoked
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return host.PackageTrustVerificationResult{}, ErrPublicKeyInvalid
	}
	if err := validateSourcePolicyPublicKey(req.SourcePolicySnapshot, sig.KeyID, key.PublicKey); err != nil {
		return host.PackageTrustVerificationResult{}, err
	}
	payload, err := CanonicalPackageSignaturePayload(*sig)
	if err != nil {
		return host.PackageTrustVerificationResult{}, err
	}
	signature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return host.PackageTrustVerificationResult{}, ErrSignatureInvalid
	}
	if !ed25519.Verify(key.PublicKey, payload, signature) {
		return host.PackageTrustVerificationResult{}, ErrSignatureInvalid
	}
	return host.PackageTrustVerificationResult{
		TrustState:  requested,
		ReasonCodes: []string{"ed25519_signature_verified"},
		Metadata:    verifiedMetadata(req.Package, *sig, key, v.now()),
	}, nil
}

func (v Ed25519Verifier) VerifyReleaseMetadata(ctx context.Context, req host.ReleaseMetadataVerificationRequest) (host.ReleaseMetadataVerificationResult, error) {
	sig := req.Release.ReleaseMetadataSignature
	if sig == nil {
		return host.ReleaseMetadataVerificationResult{}, ErrSignatureRequired
	}
	if sig.Algorithm != AlgorithmEd25519 {
		return host.ReleaseMetadataVerificationResult{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, sig.Algorithm)
	}
	if !sourcePolicyAllowsKey(&req.SourcePolicySnapshot, sig.KeyID) {
		return host.ReleaseMetadataVerificationResult{}, ErrKeyNotFound
	}
	if len(req.ReleaseMetadataBytes) == 0 {
		return host.ReleaseMetadataVerificationResult{}, ErrSignatureInvalid
	}
	if len(req.ReleaseMetadataSignature) != ed25519.SignatureSize {
		return host.ReleaseMetadataVerificationResult{}, ErrSignatureInvalid
	}
	if v.Keyring == nil {
		return host.ReleaseMetadataVerificationResult{}, ErrKeyringRequired
	}
	key, err := v.Keyring.LookupPackageSigningKey(ctx, KeyLookupRequest{
		Algorithm:   sig.Algorithm,
		KeyID:       sig.KeyID,
		PublisherID: req.Release.PublisherID,
		PluginID:    req.Release.PluginID,
	})
	if err != nil {
		return host.ReleaseMetadataVerificationResult{}, err
	}
	if key.Revoked {
		return host.ReleaseMetadataVerificationResult{}, ErrKeyRevoked
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return host.ReleaseMetadataVerificationResult{}, ErrPublicKeyInvalid
	}
	if err := validateSourcePolicyPublicKey(&req.SourcePolicySnapshot, sig.KeyID, key.PublicKey); err != nil {
		return host.ReleaseMetadataVerificationResult{}, err
	}
	if !ed25519.Verify(key.PublicKey, req.ReleaseMetadataBytes, req.ReleaseMetadataSignature) {
		return host.ReleaseMetadataVerificationResult{}, ErrSignatureInvalid
	}
	return host.ReleaseMetadataVerificationResult{
		Metadata: map[string]string{
			"algorithm":   sig.Algorithm,
			"key_id":      sig.KeyID,
			"verified_at": v.now().Format(time.RFC3339),
		},
	}, nil
}

func (v Ed25519Verifier) VerifySourceRevocationEvidence(ctx context.Context, req host.SourceRevocationEvidenceVerificationRequest) (host.SourceRevocationEvidenceVerificationResult, error) {
	evidence := req.RevocationEvidence
	if evidence.SignatureKeyID == "" {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrSignatureRequired
	}
	if !sourcePolicyAllowsKey(&req.SourcePolicySnapshot, evidence.SignatureKeyID) {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrKeyNotFound
	}
	if len(req.RevocationMetadataBytes) == 0 || len(req.RevocationMetadataSignature) != ed25519.SignatureSize {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrSignatureInvalid
	}
	if v.Keyring == nil {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrKeyringRequired
	}
	key, err := v.Keyring.LookupPackageSigningKey(ctx, KeyLookupRequest{
		Algorithm: AlgorithmEd25519,
		KeyID:     evidence.SignatureKeyID,
	})
	if err != nil {
		return host.SourceRevocationEvidenceVerificationResult{}, err
	}
	if key.Revoked {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrKeyRevoked
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrPublicKeyInvalid
	}
	if err := validateSourcePolicyPublicKey(&req.SourcePolicySnapshot, evidence.SignatureKeyID, key.PublicKey); err != nil {
		return host.SourceRevocationEvidenceVerificationResult{}, err
	}
	if !ed25519.Verify(key.PublicKey, req.RevocationMetadataBytes, req.RevocationMetadataSignature) {
		return host.SourceRevocationEvidenceVerificationResult{}, ErrSignatureInvalid
	}
	return host.SourceRevocationEvidenceVerificationResult{
		Metadata: map[string]string{
			"algorithm":          AlgorithmEd25519,
			"key_id":             evidence.SignatureKeyID,
			"highest_seen_epoch": req.RevocationMetadata.HighestSeenEpoch,
			"verified_at":        v.now().Format(time.RFC3339),
		},
	}, nil
}

func trustRequestFromPolicy(req host.PackageTrustVerificationRequest) (registry.TrustState, bool, error) {
	if req.LocalImport {
		if req.Package.PackageSignature != nil {
			return registry.TrustVerified, true, nil
		}
		return registry.TrustUnsignedLocal, false, nil
	}
	if req.SourcePolicySnapshot == nil {
		return registry.TrustUntrusted, false, nil
	}
	policy := req.SourcePolicySnapshot
	if policy.RequireSignature {
		return registry.TrustVerified, true, nil
	}
	switch policy.UnsignedPolicy {
	case host.PackageUnsignedDevOnly:
		return "", false, ErrSignatureRequired
	case host.PackageUnsignedReviewRequired:
		return registry.TrustNeedsReview, false, nil
	case host.PackageUnsignedBlock, "":
		return "", false, ErrSignatureRequired
	default:
		return "", false, ErrSignatureRequired
	}
}

func sourcePolicyAllowsKey(policy *host.SourcePolicySnapshot, keyID string) bool {
	if policy == nil || (len(policy.TrustedKeyIDs) == 0 && len(policy.TrustedKeys) == 0) {
		return true
	}
	for _, trustedKeyID := range policy.TrustedKeyIDs {
		if trustedKeyID == keyID {
			return true
		}
	}
	for _, trustedKey := range policy.TrustedKeys {
		if trustedKey.KeyID == keyID {
			return true
		}
	}
	return false
}

func validateSourcePolicyPublicKey(policy *host.SourcePolicySnapshot, keyID string, publicKey ed25519.PublicKey) error {
	if policy == nil {
		return nil
	}
	for _, trustedKey := range policy.TrustedKeys {
		if trustedKey.KeyID != keyID {
			continue
		}
		expected := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(trustedKey.PublicKeySHA256)), "sha256:")
		if expected == "" {
			return ErrPublicKeyInvalid
		}
		sum := sha256.Sum256(publicKey)
		if hex.EncodeToString(sum[:]) != expected {
			return ErrPublicKeyInvalid
		}
		return nil
	}
	return nil
}

type packageSignaturePayload struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id,omitempty"`
	PluginID      string `json:"plugin_id,omitempty"`
	PackageHash   string `json:"package_hash"`
	ManifestHash  string `json:"manifest_hash"`
	EntriesHash   string `json:"entries_hash"`
	SignedAt      string `json:"signed_at,omitempty"`
}

func CanonicalPackageSignaturePayload(sig pluginpkg.PackageSignature) ([]byte, error) {
	return json.Marshal(packageSignaturePayload{
		SchemaVersion: sig.SchemaVersion,
		Algorithm:     sig.Algorithm,
		KeyID:         sig.KeyID,
		PublisherID:   sig.PublisherID,
		PluginID:      sig.PluginID,
		PackageHash:   sig.PackageHash,
		ManifestHash:  sig.ManifestHash,
		EntriesHash:   sig.EntriesHash,
		SignedAt:      sig.SignedAt,
	})
}

func SignatureForPackage(pkg pluginpkg.Package, keyID string, publisherID string, pluginID string, privateKey ed25519.PrivateKey, signedAt time.Time) (pluginpkg.PackageSignature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return pluginpkg.PackageSignature{}, errors.New("package signing private key is invalid")
	}
	if publisherID == "" {
		publisherID = pkg.Manifest.Publisher.PublisherID
	}
	if pluginID == "" {
		pluginID = pkg.Manifest.PluginID()
	}
	sig := pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion,
		Algorithm:     AlgorithmEd25519,
		KeyID:         keyID,
		PublisherID:   publisherID,
		PluginID:      pluginID,
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
	}
	if !signedAt.IsZero() {
		sig.SignedAt = signedAt.UTC().Format(time.RFC3339)
	}
	payload, err := CanonicalPackageSignaturePayload(sig)
	if err != nil {
		return pluginpkg.PackageSignature{}, err
	}
	signature := ed25519.Sign(privateKey, payload)
	sig.Signature = base64.StdEncoding.EncodeToString(signature)
	return sig, nil
}

func validateSignatureHashes(pkg pluginpkg.Package, sig pluginpkg.PackageSignature) error {
	if sig.PackageHash != pkg.PackageHash {
		return fmt.Errorf("%w: package_hash mismatch", ErrSignatureInvalid)
	}
	if sig.ManifestHash != pkg.ManifestHash {
		return fmt.Errorf("%w: manifest_hash mismatch", ErrSignatureInvalid)
	}
	if sig.EntriesHash != pkg.EntriesHash {
		return fmt.Errorf("%w: entries_hash mismatch", ErrSignatureInvalid)
	}
	if sig.PublisherID != "" && sig.PublisherID != pkg.Manifest.Publisher.PublisherID {
		return fmt.Errorf("%w: publisher_id mismatch", ErrSignatureInvalid)
	}
	if sig.PluginID != "" && sig.PluginID != pkg.Manifest.PluginID() {
		return fmt.Errorf("%w: plugin_id mismatch", ErrSignatureInvalid)
	}
	return nil
}

func (v Ed25519Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func verifiedMetadata(pkg pluginpkg.Package, sig pluginpkg.PackageSignature, key SigningKey, now time.Time) map[string]string {
	metadata := map[string]string{
		"trust.algorithm":     sig.Algorithm,
		"trust.key_id":        sig.KeyID,
		"trust.package_hash":  pkg.PackageHash,
		"trust.manifest_hash": pkg.ManifestHash,
		"trust.entries_hash":  pkg.EntriesHash,
		"trust.verified_at":   now.Format(time.RFC3339),
	}
	if sig.SignedAt != "" {
		metadata["trust.signed_at"] = sig.SignedAt
	}
	for name, value := range key.Metadata {
		metadata["trust.key."+name] = value
	}
	return metadata
}
