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
		TrustState:  requested,
		ReasonCodes: []string{"ed25519_signature_verified"},
		Metadata:    verifiedMetadata(req.Package, *sig, key, v.now()),
	}, nil
}

// AssessExternalPackageSignature classifies signature evidence without turning
// optional signature verification into an installation gate. Integrity
// failures are returned as explicit closed states; only dependency failures use
// the unavailable state.
func (v Ed25519Verifier) AssessExternalPackageSignature(ctx context.Context, req host.ExternalPackageSignatureAssessmentRequest) (registry.SignatureAssessment, error) {
	pkg := req.Package
	now := req.Now.UTC()
	if now.IsZero() {
		now = v.now()
	}
	result := registry.SignatureAssessment{AssessedAt: now}
	if pkg.PackageSignature == nil {
		result.Status = registry.SignatureAbsent
		result.ReasonCodes = []string{"signature_not_present"}
		return result, nil
	}
	sig := *pkg.PackageSignature
	result.Algorithm = sig.Algorithm
	result.KeyID = sig.KeyID
	setStatus := func(status registry.SignatureAssessmentStatus, reason string) (registry.SignatureAssessment, error) {
		result.Status = status
		result.ReasonCodes = []string{reason}
		result.AssessmentEpoch = externalAssessmentEpoch(result, pkg.PackageHash)
		return result, nil
	}
	if sig.Algorithm != AlgorithmEd25519 || sig.SchemaVersion != pluginpkg.PackageSignatureSchemaVersion {
		return setStatus(registry.SignatureInvalid, "signature_envelope_unsupported")
	}
	if err := validateSignatureHashes(pkg, sig); err != nil {
		return setStatus(registry.SignatureInvalid, "signature_hash_binding_invalid")
	}
	if v.Keyring == nil {
		return setStatus(registry.SignatureUnavailable, "keyring_unavailable")
	}
	key, err := v.Keyring.LookupPackageSigningKey(ctx, KeyLookupRequest{
		Algorithm: sig.Algorithm, KeyID: sig.KeyID, PublisherID: sig.PublisherID, PluginID: sig.PluginID,
	})
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return setStatus(registry.SignatureUnknownSigner, "signing_key_unknown")
		}
		return setStatus(registry.SignatureUnavailable, "keyring_lookup_unavailable")
	}
	if key.Revoked {
		return setStatus(registry.SignatureRevoked, "signing_key_revoked")
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return setStatus(registry.SignatureUnavailable, "signing_key_material_invalid")
	}
	payload, err := CanonicalPackageSignaturePayload(sig)
	if err != nil {
		return setStatus(registry.SignatureInvalid, "signature_payload_invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, payload, signature) {
		return setStatus(registry.SignatureInvalid, "signature_verification_failed")
	}
	result.Status = registry.SignatureVerified
	result.ReasonCodes = []string{"ed25519_signature_verified"}
	result.EvidenceReference = publicKeyEvidence(key.PublicKey)
	result.KeyringGeneration = key.Metadata["keyring_generation"]
	result.RevocationGeneration = key.Metadata["revocation_generation"]
	result.AssessmentEpoch = externalAssessmentEpoch(result, pkg.PackageHash)
	return result, nil
}

func (v Ed25519Verifier) AssessExternalPackageSignatureFreshness(ctx context.Context, req host.ExternalPackageSignatureFreshnessRequest) (registry.SignatureAssessment, error) {
	now := req.Now.UTC()
	if now.IsZero() {
		now = v.now()
	}
	result := req.Assessment
	result.AssessedAt = now
	result.PackageSHA256 = req.PackageSHA256
	result.ManifestSHA256 = req.ManifestSHA256
	result.EntriesSHA256 = req.EntriesSHA256
	result.AssessedHashes = registry.TrustHashSet{
		PackageSHA256: req.PackageSHA256, ManifestSHA256: req.ManifestSHA256, EntriesSHA256: req.EntriesSHA256,
	}
	setStatus := func(status registry.SignatureAssessmentStatus, reason string) (registry.SignatureAssessment, error) {
		result.Status = status
		result.ReasonCodes = []string{reason}
		result.AssessmentEpoch = externalAssessmentEpoch(result, req.PackageSHA256)
		return result, nil
	}
	if req.Assessment.Status != registry.SignatureVerified || req.Assessment.Algorithm != AlgorithmEd25519 || strings.TrimSpace(req.Assessment.KeyID) == "" {
		return setStatus(registry.SignatureUnavailable, "verified_signature_evidence_incomplete")
	}
	if req.Assessment.PackageSHA256 != req.PackageSHA256 || req.Assessment.ManifestSHA256 != req.ManifestSHA256 || req.Assessment.EntriesSHA256 != req.EntriesSHA256 {
		return setStatus(registry.SignatureInvalid, "signature_hash_binding_changed")
	}
	if v.Keyring == nil {
		return setStatus(registry.SignatureUnavailable, "keyring_unavailable")
	}
	key, err := v.Keyring.LookupPackageSigningKey(ctx, KeyLookupRequest{
		Algorithm: req.Assessment.Algorithm, KeyID: req.Assessment.KeyID,
		PublisherID: req.PublisherID, PluginID: req.PluginID,
	})
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return setStatus(registry.SignatureUnknownSigner, "signing_key_unknown")
		}
		return setStatus(registry.SignatureUnavailable, "keyring_lookup_unavailable")
	}
	result.KeyringGeneration = key.Metadata["keyring_generation"]
	result.RevocationGeneration = key.Metadata["revocation_generation"]
	if key.Revoked {
		return setStatus(registry.SignatureRevoked, "signing_key_revoked")
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return setStatus(registry.SignatureUnavailable, "signing_key_material_invalid")
	}
	currentEvidence := publicKeyEvidence(key.PublicKey)
	if strings.TrimSpace(req.Assessment.EvidenceReference) == "" {
		return setStatus(registry.SignatureUnavailable, "signing_key_fingerprint_unavailable")
	}
	if currentEvidence != req.Assessment.EvidenceReference {
		result.EvidenceReference = currentEvidence
		return setStatus(registry.SignatureInvalid, "signing_key_replaced")
	}
	result.Status = registry.SignatureVerified
	result.ReasonCodes = []string{"ed25519_signing_key_fresh"}
	result.EvidenceReference = currentEvidence
	result.AssessmentEpoch = externalAssessmentEpoch(result, req.PackageSHA256)
	return result, nil
}

func externalAssessmentEpoch(assessment registry.SignatureAssessment, packageHash string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		string(assessment.Status), assessment.Algorithm, assessment.KeyID,
		assessment.EvidenceReference, assessment.KeyringGeneration, assessment.RevocationGeneration, packageHash,
	}, "\x00")))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func publicKeyEvidence(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519-public-key:sha256:" + hex.EncodeToString(digest[:])
}

func trustRequestFromPolicy(req host.PackageTrustVerificationRequest) (registry.TrustState, bool, error) {
	if req.LocalImport {
		if req.Package.PackageSignature != nil {
			return registry.TrustVerified, true, nil
		}
		return registry.TrustUnsignedLocal, false, nil
	}
	if req.Package.PackageSignature == nil {
		return registry.TrustUntrusted, false, nil
	}
	return registry.TrustVerified, true, nil
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
