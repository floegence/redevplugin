package trust

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	requested := req.RequestedTrustState
	if requested == "" {
		requested = registry.TrustUntrusted
	}
	if !requiresSignature(requested) {
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
		TrustState: requested,
		Metadata:   verifiedMetadata(req.Package, *sig, key, v.now()),
	}, nil
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

func requiresSignature(state registry.TrustState) bool {
	switch state {
	case registry.TrustBundled, registry.TrustVerified:
		return true
	default:
		return false
	}
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
