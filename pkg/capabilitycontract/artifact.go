package capabilitycontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	platformversion "github.com/floegence/redevplugin/pkg/version"
)

const (
	MaxArtifactFileBytes   int64 = 4 << 20
	MaxArtifactBundleBytes int64 = 8 << 20
)

const (
	manifestSchemaVersion      = "redevplugin.host_capability_manifest.v1"
	compatibilitySchemaVersion = "redevplugin.host_capability_compatibility.v1"
	signatureSchemaVersion     = "redevplugin.host_capability_signature.v1"
	signatureAlgorithm         = "ed25519"
)

var (
	canonicalDecimalPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	sha256HexPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	artifactRefSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

type BuildRequest struct {
	Contract                 Contract
	PublisherID              string
	ArtifactBaseRef          string
	GeneratedAt              time.Time
	SourceCommit             string
	MinReDevPluginVersion    string
	SignatureKeyID           string
	SignaturePolicyEpoch     string
	SignatureRevocationEpoch string
	PrivateKey               ed25519.PrivateKey
	Notices                  []Notice
}

type PrepareRequest struct {
	Contract                 Contract
	PublisherID              string
	ArtifactBaseRef          string
	GeneratedAt              time.Time
	SourceCommit             string
	MinReDevPluginVersion    string
	SignatureKeyID           string
	SignaturePolicyEpoch     string
	SignatureRevocationEpoch string
	Notices                  []Notice
}

type VerifyRequest struct {
	Bundle                    Bundle
	ExpectedPin               Pin
	TrustedKey                TrustedKey
	CurrentReDevPluginVersion string
}

func Build(req BuildRequest) (Bundle, error) {
	prepared, err := Prepare(PrepareRequest{
		Contract: req.Contract, PublisherID: req.PublisherID, ArtifactBaseRef: req.ArtifactBaseRef,
		GeneratedAt: req.GeneratedAt, SourceCommit: req.SourceCommit, MinReDevPluginVersion: req.MinReDevPluginVersion,
		SignatureKeyID: req.SignatureKeyID, SignaturePolicyEpoch: req.SignaturePolicyEpoch,
		SignatureRevocationEpoch: req.SignatureRevocationEpoch, Notices: req.Notices,
	})
	if err != nil {
		return Bundle{}, err
	}
	if len(req.PrivateKey) != ed25519.PrivateKeySize {
		return Bundle{}, invalid("private key is invalid")
	}
	publicKey := req.PrivateKey.Public().(ed25519.PublicKey)
	return Finalize(prepared, ed25519.Sign(req.PrivateKey, prepared.Manifest), publicKey)
}

func Prepare(req PrepareRequest) (PreparedBundle, error) {
	if err := Validate(req.Contract); err != nil {
		return PreparedBundle{}, err
	}
	if req.Contract.PublisherID != req.PublisherID || strings.TrimSpace(req.PublisherID) == "" {
		return PreparedBundle{}, invalid("publisher_id does not match contract")
	}
	if err := ValidateArtifactRef(req.ArtifactBaseRef + "/placeholder"); err != nil {
		return PreparedBundle{}, err
	}
	if req.GeneratedAt.IsZero() || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(req.SourceCommit) {
		return PreparedBundle{}, invalid("generated_at and a 40-character lowercase source_commit are required")
	}
	if _, err := platformversion.ParseSemVer(req.MinReDevPluginVersion); err != nil || !idPattern.MatchString(req.SignatureKeyID) ||
		!canonicalDecimalPattern.MatchString(req.SignaturePolicyEpoch) || !canonicalDecimalPattern.MatchString(req.SignatureRevocationEpoch) {
		return PreparedBundle{}, invalid("compatibility and signature identity are required")
	}
	if err := validateNotices(req.Notices); err != nil {
		return PreparedBundle{}, err
	}
	base := strings.TrimSuffix(req.ArtifactBaseRef, "/")
	prefix := base + "/" + req.Contract.ContractID
	artifactRef := prefix + ".schema.json"
	manifestRef := prefix + ".manifest.json"
	signatureRef := prefix + ".sig"
	compatibilityRef := prefix + ".compatibility.json"
	clientRef := prefix + ".client.ts"
	noticesRef := prefix + ".notices.json"
	for _, ref := range []string{artifactRef, manifestRef, signatureRef, compatibilityRef, clientRef, noticesRef} {
		if err := ValidateArtifactRef(ref); err != nil {
			return PreparedBundle{}, err
		}
	}
	artifactBytes, err := canonicalJSON(req.Contract)
	if err != nil {
		return PreparedBundle{}, err
	}
	compatibility := Compatibility{
		SchemaVersion:         compatibilitySchemaVersion,
		ContractID:            req.Contract.ContractID,
		ContractVersion:       req.Contract.ContractVersion,
		CapabilityID:          req.Contract.CapabilityID,
		CapabilityVersion:     req.Contract.CapabilityVersion,
		MinReDevPluginVersion: req.MinReDevPluginVersion,
	}
	compatibilityBytes, err := canonicalJSON(compatibility)
	if err != nil {
		return PreparedBundle{}, err
	}
	clientBytes, err := GenerateTypeScript(req.Contract)
	if err != nil {
		return PreparedBundle{}, err
	}
	notices := append([]Notice(nil), req.Notices...)
	if notices == nil {
		notices = []Notice{}
	}
	noticesBytes, err := canonicalJSON(notices)
	if err != nil {
		return PreparedBundle{}, err
	}
	entries := []ManifestEntry{
		manifestEntry("contract", artifactRef, "application/schema+json", artifactBytes),
		manifestEntry("compatibility", compatibilityRef, "application/json", compatibilityBytes),
		manifestEntry("generated_client", clientRef, "text/typescript", clientBytes),
		manifestEntry("notices", noticesRef, "application/json", noticesBytes),
	}
	manifest := Manifest{
		SchemaVersion:            manifestSchemaVersion,
		PublisherID:              req.PublisherID,
		ContractID:               req.Contract.ContractID,
		ContractVersion:          req.Contract.ContractVersion,
		CapabilityID:             req.Contract.CapabilityID,
		CapabilityVersion:        req.Contract.CapabilityVersion,
		GeneratedAt:              req.GeneratedAt.UTC().Format(time.RFC3339),
		SourceCommit:             req.SourceCommit,
		SignatureAlgorithm:       signatureAlgorithm,
		SignatureKeyID:           req.SignatureKeyID,
		SignaturePolicyEpoch:     req.SignaturePolicyEpoch,
		SignatureRevocationEpoch: req.SignatureRevocationEpoch,
		Entries:                  entries,
	}
	manifestBytes, err := canonicalJSON(manifest)
	if err != nil {
		return PreparedBundle{}, err
	}
	manifestHash := sha256Hex(manifestBytes)
	pin := Pin{
		PublisherID:              req.PublisherID,
		ContractID:               req.Contract.ContractID,
		ContractVersion:          req.Contract.ContractVersion,
		ArtifactRef:              artifactRef,
		ArtifactSHA256:           sha256Hex(artifactBytes),
		ManifestRef:              manifestRef,
		ManifestSHA256:           manifestHash,
		SignatureRef:             signatureRef,
		SignatureKeyID:           req.SignatureKeyID,
		SignaturePolicyEpoch:     req.SignaturePolicyEpoch,
		SignatureRevocationEpoch: req.SignatureRevocationEpoch,
		CompatibilityRef:         compatibilityRef,
		CompatibilitySHA256:      sha256Hex(compatibilityBytes),
		GeneratedClientRef:       clientRef,
		GeneratedClientSHA256:    sha256Hex(clientBytes),
		NoticesRef:               noticesRef,
		NoticesSHA256:            sha256Hex(noticesBytes),
	}
	return PreparedBundle{
		Pin: pin,
		Files: map[string][]byte{
			artifactRef:      artifactBytes,
			manifestRef:      manifestBytes,
			compatibilityRef: compatibilityBytes,
			clientRef:        clientBytes,
			noticesRef:       noticesBytes,
		},
		Manifest: manifestBytes,
	}, nil
}

// Finalize verifies an externally produced Ed25519 signature over the exact
// canonical manifest bytes and returns the immutable v1 bundle.
func Finalize(prepared PreparedBundle, signature []byte, publicKey ed25519.PublicKey) (Bundle, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, prepared.Manifest, signature) {
		return Bundle{}, ErrSignature
	}
	if err := validatePreparedBundle(prepared); err != nil {
		return Bundle{}, err
	}
	signatureEnvelope := SignatureEnvelope{
		SchemaVersion:   signatureSchemaVersion,
		Algorithm:       signatureAlgorithm,
		KeyID:           prepared.Pin.SignatureKeyID,
		ManifestSHA256:  prepared.Pin.ManifestSHA256,
		SignatureBase64: base64.StdEncoding.EncodeToString(signature),
	}
	signatureBytes, err := canonicalJSON(signatureEnvelope)
	if err != nil {
		return Bundle{}, err
	}
	files := make(map[string][]byte)
	for ref, content := range prepared.Files {
		files[ref] = append([]byte(nil), content...)
	}
	files[prepared.Pin.SignatureRef] = signatureBytes
	pin := prepared.Pin
	pin.SignatureSHA256 = sha256Hex(signatureBytes)
	return Bundle{Pin: pin, Files: files}, nil
}

func validatePreparedBundle(prepared PreparedBundle) error {
	pinForValidation := prepared.Pin
	pinForValidation.SignatureSHA256 = strings.Repeat("0", 64)
	if err := validatePin(pinForValidation); err != nil {
		return err
	}
	if prepared.Pin.SignatureSHA256 != "" || sha256Hex(prepared.Manifest) != prepared.Pin.ManifestSHA256 ||
		!bytes.Equal(prepared.Files[prepared.Pin.ManifestRef], prepared.Manifest) {
		return fmt.Errorf("%w: prepared manifest mismatch", ErrInvalidBundle)
	}
	expected := map[string]string{
		prepared.Pin.ArtifactRef:        prepared.Pin.ArtifactSHA256,
		prepared.Pin.ManifestRef:        prepared.Pin.ManifestSHA256,
		prepared.Pin.CompatibilityRef:   prepared.Pin.CompatibilitySHA256,
		prepared.Pin.GeneratedClientRef: prepared.Pin.GeneratedClientSHA256,
		prepared.Pin.NoticesRef:         prepared.Pin.NoticesSHA256,
	}
	if len(prepared.Files) != len(expected) {
		return fmt.Errorf("%w: prepared file set is not exact", ErrInvalidBundle)
	}
	for ref, digest := range expected {
		if err := ValidateArtifactRef(ref); err != nil || !sha256HexPattern.MatchString(digest) || sha256Hex(prepared.Files[ref]) != digest {
			return fmt.Errorf("%w: prepared file %q mismatch", ErrInvalidBundle, ref)
		}
	}
	if err := ValidateArtifactRef(prepared.Pin.SignatureRef); err != nil {
		return err
	}
	return nil
}

func Verify(req VerifyRequest) (VerifiedContract, error) {
	if err := validatePin(req.ExpectedPin); err != nil {
		return VerifiedContract{}, err
	}
	if req.Bundle.Files == nil {
		return VerifiedContract{}, fmt.Errorf("%w: files are required", ErrInvalidBundle)
	}
	if req.Bundle.Pin != (Pin{}) && req.Bundle.Pin != req.ExpectedPin {
		return VerifiedContract{}, fmt.Errorf("%w: bundle pin does not match expected pin", ErrPinMismatch)
	}
	if req.TrustedKey.PublisherID != req.ExpectedPin.PublisherID || req.TrustedKey.KeyID != req.ExpectedPin.SignatureKeyID ||
		req.TrustedKey.PolicyEpoch != req.ExpectedPin.SignaturePolicyEpoch ||
		req.TrustedKey.RevocationEpoch != req.ExpectedPin.SignatureRevocationEpoch {
		return VerifiedContract{}, fmt.Errorf("%w: trusted key identity or epoch mismatch", ErrSignature)
	}
	if len(req.TrustedKey.PublicKey) != ed25519.PublicKeySize {
		return VerifiedContract{}, fmt.Errorf("%w: public key is invalid", ErrSignature)
	}
	refs := pinRefs(req.ExpectedPin)
	if len(req.Bundle.Files) != len(refs) {
		return VerifiedContract{}, fmt.Errorf("%w: bundle file set is not exact", ErrInvalidBundle)
	}
	var totalBytes int64
	for ref, wantHash := range refs {
		if err := ValidateArtifactRef(ref); err != nil {
			return VerifiedContract{}, err
		}
		content, ok := req.Bundle.Files[ref]
		if !ok {
			return VerifiedContract{}, fmt.Errorf("%w: missing %s", ErrInvalidBundle, ref)
		}
		if int64(len(content)) > MaxArtifactFileBytes {
			return VerifiedContract{}, fmt.Errorf("%w: %s exceeds the per-file byte budget", ErrInvalidBundle, ref)
		}
		totalBytes += int64(len(content))
		if totalBytes > MaxArtifactBundleBytes {
			return VerifiedContract{}, fmt.Errorf("%w: bundle exceeds the total byte budget", ErrInvalidBundle)
		}
		if sha256Hex(content) != wantHash {
			return VerifiedContract{}, fmt.Errorf("%w: %s sha256 mismatch", ErrPinMismatch, ref)
		}
	}
	manifestBytes := req.Bundle.Files[req.ExpectedPin.ManifestRef]
	var manifest Manifest
	if err := strictJSON(manifestBytes, &manifest); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: manifest decode: %v", ErrInvalidBundle, err)
	}
	if err := validateManifest(manifest, req.ExpectedPin, req.Bundle.Files); err != nil {
		return VerifiedContract{}, err
	}
	var signature SignatureEnvelope
	if err := strictJSON(req.Bundle.Files[req.ExpectedPin.SignatureRef], &signature); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: signature decode: %v", ErrSignature, err)
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature.SignatureBase64)
	if err != nil || signature.SchemaVersion != signatureSchemaVersion || signature.Algorithm != signatureAlgorithm ||
		signature.KeyID != req.ExpectedPin.SignatureKeyID || signature.ManifestSHA256 != req.ExpectedPin.ManifestSHA256 ||
		!ed25519.Verify(ed25519.PublicKey(req.TrustedKey.PublicKey), manifestBytes, signatureBytes) {
		return VerifiedContract{}, ErrSignature
	}
	var contract Contract
	if err := strictJSON(req.Bundle.Files[req.ExpectedPin.ArtifactRef], &contract); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: contract decode: %v", ErrInvalidContract, err)
	}
	if err := Validate(contract); err != nil {
		return VerifiedContract{}, err
	}
	if contract.PublisherID != req.ExpectedPin.PublisherID || contract.ContractID != req.ExpectedPin.ContractID ||
		contract.ContractVersion != req.ExpectedPin.ContractVersion || contract.CapabilityID != manifest.CapabilityID ||
		contract.CapabilityVersion != manifest.CapabilityVersion {
		return VerifiedContract{}, fmt.Errorf("%w: contract identity mismatch", ErrPinMismatch)
	}
	generatedClient, err := GenerateTypeScript(contract)
	if err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: regenerate TypeScript client: %v", ErrInvalidBundle, err)
	}
	if !bytes.Equal(generatedClient, req.Bundle.Files[req.ExpectedPin.GeneratedClientRef]) {
		return VerifiedContract{}, fmt.Errorf("%w: generated client diverges from signed contract", ErrInvalidBundle)
	}
	var compatibility Compatibility
	if err := strictJSON(req.Bundle.Files[req.ExpectedPin.CompatibilityRef], &compatibility); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: compatibility decode: %v", ErrCompatibility, err)
	}
	if compatibility.SchemaVersion != compatibilitySchemaVersion || compatibility.ContractID != contract.ContractID ||
		compatibility.ContractVersion != contract.ContractVersion || compatibility.CapabilityID != contract.CapabilityID ||
		compatibility.CapabilityVersion != contract.CapabilityVersion {
		return VerifiedContract{}, fmt.Errorf("%w: compatibility identity mismatch", ErrCompatibility)
	}
	minimumVersion, err := platformversion.ParseSemVer(compatibility.MinReDevPluginVersion)
	if err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: min_redevplugin_version is invalid", ErrCompatibility)
	}
	currentVersion, err := platformversion.ParseSemVer(req.CurrentReDevPluginVersion)
	if err != nil || req.CurrentReDevPluginVersion == "0.0.0-dev" || currentVersion.Compare(minimumVersion) < 0 {
		return VerifiedContract{}, fmt.Errorf("%w: requires redevplugin %s", ErrCompatibility, compatibility.MinReDevPluginVersion)
	}
	var notices []Notice
	if err := strictJSON(req.Bundle.Files[req.ExpectedPin.NoticesRef], &notices); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: notices decode: %v", ErrInvalidBundle, err)
	}
	if err := validateNotices(notices); err != nil {
		return VerifiedContract{}, err
	}
	verified := VerifiedContract{
		Contract:        contract,
		Pin:             req.ExpectedPin,
		Manifest:        manifest,
		Compatibility:   compatibility,
		GeneratedClient: generatedClient,
		Notices:         append([]Notice(nil), notices...),
		publicKeySHA256: sha256Hex(req.TrustedKey.PublicKey),
	}
	if err := verified.seal(); err != nil {
		return VerifiedContract{}, fmt.Errorf("%w: seal verified contract: %v", ErrInvalidBundle, err)
	}
	return verified, nil
}

func ValidateArtifactRef(ref string) error {
	if ref == "" || len(ref) > 1024 || strings.TrimSpace(ref) != ref || strings.ContainsAny(ref, "\\%?#") || !isASCII(ref) {
		return fmt.Errorf("%w: artifact ref is invalid", ErrInvalidBundle)
	}
	if strings.Contains(ref, ":") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") || path.Clean(ref) != ref {
		return fmt.Errorf("%w: artifact ref must be a canonical relative path", ErrInvalidBundle)
	}
	for _, segment := range strings.Split(ref, "/") {
		if segment == "" || segment == "." || segment == ".." || !artifactRefSegmentPattern.MatchString(segment) {
			return fmt.Errorf("%w: artifact ref contains an unsafe segment", ErrInvalidBundle)
		}
	}
	return nil
}

func ValidatePin(pin Pin) error {
	return validatePin(pin)
}

func validatePin(pin Pin) error {
	for name, value := range map[string]string{
		"publisher_id":     pin.PublisherID,
		"contract_id":      pin.ContractID,
		"signature_key_id": pin.SignatureKeyID,
	} {
		if !idPattern.MatchString(value) || strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: %s is required", ErrInvalidBundle, name)
		}
	}
	if _, err := platformversion.ParseSemVer(pin.ContractVersion); err != nil {
		return fmt.Errorf("%w: contract_version is invalid", ErrInvalidBundle)
	}
	if !canonicalDecimalPattern.MatchString(pin.SignaturePolicyEpoch) || !canonicalDecimalPattern.MatchString(pin.SignatureRevocationEpoch) {
		return fmt.Errorf("%w: signature epochs are invalid", ErrInvalidBundle)
	}
	refs := []struct {
		ref  string
		hash string
	}{
		{ref: pin.ArtifactRef, hash: pin.ArtifactSHA256},
		{ref: pin.ManifestRef, hash: pin.ManifestSHA256},
		{ref: pin.SignatureRef, hash: pin.SignatureSHA256},
		{ref: pin.CompatibilityRef, hash: pin.CompatibilitySHA256},
		{ref: pin.GeneratedClientRef, hash: pin.GeneratedClientSHA256},
		{ref: pin.NoticesRef, hash: pin.NoticesSHA256},
	}
	seenRefs := make(map[string]struct{}, len(refs))
	for _, item := range refs {
		if err := ValidateArtifactRef(item.ref); err != nil {
			return err
		}
		if _, exists := seenRefs[item.ref]; exists {
			return fmt.Errorf("%w: artifact refs must be unique", ErrInvalidBundle)
		}
		seenRefs[item.ref] = struct{}{}
		if !sha256HexPattern.MatchString(item.hash) {
			return fmt.Errorf("%w: sha256 is invalid", ErrInvalidBundle)
		}
	}
	return nil
}

func pinRefs(pin Pin) map[string]string {
	return map[string]string{
		pin.ArtifactRef:        pin.ArtifactSHA256,
		pin.ManifestRef:        pin.ManifestSHA256,
		pin.SignatureRef:       pin.SignatureSHA256,
		pin.CompatibilityRef:   pin.CompatibilitySHA256,
		pin.GeneratedClientRef: pin.GeneratedClientSHA256,
		pin.NoticesRef:         pin.NoticesSHA256,
	}
}

func validateManifest(manifest Manifest, pin Pin, files map[string][]byte) error {
	if manifest.SchemaVersion != manifestSchemaVersion || manifest.PublisherID != pin.PublisherID ||
		manifest.ContractID != pin.ContractID || manifest.ContractVersion != pin.ContractVersion ||
		manifest.SignatureAlgorithm != signatureAlgorithm || manifest.SignatureKeyID != pin.SignatureKeyID ||
		manifest.SignaturePolicyEpoch != pin.SignaturePolicyEpoch || manifest.SignatureRevocationEpoch != pin.SignatureRevocationEpoch {
		return fmt.Errorf("%w: manifest identity mismatch", ErrPinMismatch)
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(manifest.SourceCommit) {
		return fmt.Errorf("%w: manifest provenance is invalid", ErrInvalidBundle)
	}
	want := map[string]struct {
		ref       string
		mediaType string
	}{
		"contract":         {ref: pin.ArtifactRef, mediaType: "application/schema+json"},
		"compatibility":    {ref: pin.CompatibilityRef, mediaType: "application/json"},
		"generated_client": {ref: pin.GeneratedClientRef, mediaType: "text/typescript"},
		"notices":          {ref: pin.NoticesRef, mediaType: "application/json"},
	}
	if len(manifest.Entries) != len(want) {
		return fmt.Errorf("%w: manifest entry set is not exact", ErrInvalidBundle)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		expected, ok := want[entry.Role]
		if !ok || seen[entry.Role] || entry.Ref != expected.ref || entry.Size != int64(len(files[expected.ref])) ||
			entry.SHA256 != sha256Hex(files[expected.ref]) || entry.MediaType != expected.mediaType {
			return fmt.Errorf("%w: manifest entry %q mismatch", ErrPinMismatch, entry.Role)
		}
		seen[entry.Role] = true
	}
	return nil
}

func manifestEntry(role, ref, mediaType string, content []byte) ManifestEntry {
	return ManifestEntry{Role: role, Ref: ref, MediaType: mediaType, SHA256: sha256Hex(content), Size: int64(len(content))}
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validateNotices(notices []Notice) error {
	seen := make(map[string]struct{}, len(notices))
	for index, notice := range notices {
		if strings.TrimSpace(notice.Name) == "" || strings.TrimSpace(notice.Version) == "" || strings.TrimSpace(notice.License) == "" ||
			strings.TrimSpace(notice.Name) != notice.Name || strings.TrimSpace(notice.Version) != notice.Version || strings.TrimSpace(notice.License) != notice.License {
			return fmt.Errorf("%w: notices[%d] identity is invalid", ErrInvalidBundle, index)
		}
		if notice.SourceURL != "" {
			parsed, err := url.ParseRequestURI(notice.SourceURL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return fmt.Errorf("%w: notices[%d].source_url is invalid", ErrInvalidBundle, index)
			}
		}
		key := notice.Name + "\x00" + notice.Version + "\x00" + notice.License + "\x00" + notice.SourceURL
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: notices[%d] is duplicated", ErrInvalidBundle, index)
		}
		seen[key] = struct{}{}
	}
	return nil
}
