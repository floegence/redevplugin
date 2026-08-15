package releasetrust

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
)

var (
	ErrInvalidReleaseIdentity = errors.New("release trust release identity is invalid")
	ErrReleasePolicyDenied    = errors.New("release trust source policy denied the release")
)

type ReleaseIdentity struct {
	SourceID              string
	Channel               string
	ReleaseMetadataRef    string
	ReleaseMetadataSHA256 string
	PublisherID           string
	PluginID              string
	Version               string
}

type PreparedRelease struct {
	service  *ReleaseTrustService
	identity ReleaseIdentity
	snapshot VerifiedSourceSnapshot
}

func (prepared PreparedRelease) SourceTrustKey() SourceTrustKey { return prepared.snapshot.key }
func (prepared PreparedRelease) VerifiedAt() time.Time          { return prepared.snapshot.verifiedAt }
func (prepared PreparedRelease) Identity() ReleaseIdentity      { return prepared.identity }
func (prepared PreparedRelease) SourcePolicy() releasecontract.SourcePolicyV2 {
	return prepared.snapshot.SourcePolicy()
}

// AllowsPackageSigningKey reports whether the freshly prepared source state
// still authorizes a package signing key and has not revoked it.
func (prepared PreparedRelease) AllowsPackageSigningKey(keyID string) bool {
	return keyID != "" && slices.Contains(prepared.snapshot.policy.ActiveKeys.Package, keyID) &&
		!slices.Contains(prepared.snapshot.revocation.RevokedKeyIDs, keyID)
}

type VerifiedReleaseMetadata struct {
	prepared PreparedRelease
	document releasecontract.ReleaseMetadataV8
	raw      []byte
}

func (verified VerifiedReleaseMetadata) PreparedRelease() PreparedRelease {
	return clonePreparedRelease(verified.prepared)
}
func (verified VerifiedReleaseMetadata) Document() releasecontract.ReleaseMetadataV8 {
	value, _ := releasecontract.BuildReleaseMetadata(verified.document)
	return value
}
func (verified VerifiedReleaseMetadata) CanonicalBytes() []byte { return slices.Clone(verified.raw) }

type VerifiedPackage struct {
	metadata  VerifiedReleaseMetadata
	signature releasecontract.PackageSignatureV1
}

func (verified VerifiedPackage) ReleaseMetadata() VerifiedReleaseMetadata {
	return cloneVerifiedReleaseMetadata(verified.metadata)
}
func (verified VerifiedPackage) PackageSignature() releasecontract.PackageSignatureV1 {
	return verified.signature
}

type ServiceSet struct {
	services map[string]*ReleaseTrustService
}

func NewServiceSet(services ...*ReleaseTrustService) (*ServiceSet, error) {
	if len(services) == 0 || len(services) > 64 {
		return nil, ErrInvalidReleaseTrustOptions
	}
	result := &ServiceSet{services: make(map[string]*ReleaseTrustService, len(services))}
	for _, service := range services {
		if service == nil || !service.options.valid() {
			return nil, ErrInvalidReleaseTrustOptions
		}
		sourceID := service.options.sourceConfiguration.sourceID
		if _, exists := result.services[sourceID]; exists {
			return nil, ErrInvalidReleaseTrustOptions
		}
		result.services[sourceID] = service
	}
	return result, nil
}

func (set *ServiceSet) PrepareRelease(ctx context.Context, identity ReleaseIdentity) (PreparedRelease, error) {
	if set == nil || ctx == nil || !validReleaseIdentity(identity) {
		return PreparedRelease{}, ErrInvalidReleaseIdentity
	}
	service := set.services[identity.SourceID]
	if service == nil {
		return PreparedRelease{}, ErrInvalidReleaseIdentity
	}
	key, err := service.options.sourceConfiguration.TrustKey(identity.Channel)
	if err != nil {
		return PreparedRelease{}, err
	}
	snapshot, err := service.RefreshSource(ctx, key)
	if err != nil {
		return PreparedRelease{}, err
	}
	if !slices.Contains(snapshot.policy.AllowedPublishers, identity.PublisherID) || snapshot.policy.InstallPolicy == "block" {
		return PreparedRelease{}, ErrReleasePolicyDenied
	}
	if releaseRevoked(snapshot.revocation, identity, "") {
		return PreparedRelease{}, ErrReleaseTrustRevoked
	}
	return PreparedRelease{service: service, identity: identity, snapshot: snapshot}, nil
}

func (set *ServiceSet) VerifyReleaseMetadata(
	ctx context.Context,
	prepared PreparedRelease,
	raw []byte,
	signature []byte,
) (VerifiedReleaseMetadata, error) {
	if set == nil || ctx == nil || !prepared.validFor(set) || len(raw) == 0 || len(signature) != 64 {
		return VerifiedReleaseMetadata{}, ErrInvalidReleaseIdentity
	}
	document, err := releasecontract.DecodeReleaseMetadata(raw)
	if err != nil {
		return VerifiedReleaseMetadata{}, err
	}
	identity := prepared.identity
	if document.SourceID != identity.SourceID || document.ReleaseMetadataRef != identity.ReleaseMetadataRef ||
		document.PublisherID != identity.PublisherID || document.PluginID != identity.PluginID || document.Version != identity.Version ||
		digestHex(raw) != identity.ReleaseMetadataSHA256 {
		return VerifiedReleaseMetadata{}, ErrInvalidReleaseIdentity
	}
	policy := prepared.snapshot.policy
	revocation := prepared.snapshot.revocation
	keyID := document.ReleaseMetadataSignature.KeyID
	if !slices.Contains(policy.ActiveKeys.ReleaseMetadata, keyID) ||
		document.ReleaseMetadataSignature.SourcePolicyEpoch != policy.Epoch ||
		document.ReleaseMetadataSignature.RevocationEpoch != revocation.Epoch || releaseRevoked(revocation, identity, keyID) {
		return VerifiedReleaseMetadata{}, ErrReleasePolicyDenied
	}
	verifier, err := delegatedVerifier(prepared.snapshot.root, releasecontract.DelegatedKeyUsageReleaseMetadata, identity.Channel, prepared.snapshot.verifiedAt, []string{keyID})
	if err != nil || releasecontract.VerifyReleaseMetadata(identity.Channel, document, signature, verifier) != nil {
		return VerifiedReleaseMetadata{}, ErrReleaseTrustVerification
	}
	return VerifiedReleaseMetadata{prepared: clonePreparedRelease(prepared), document: document, raw: slices.Clone(raw)}, nil
}

func (set *ServiceSet) VerifyPackage(
	ctx context.Context,
	metadata VerifiedReleaseMetadata,
	signature releasecontract.PackageSignatureV1,
) (VerifiedPackage, error) {
	prepared := metadata.prepared
	if set == nil || ctx == nil || !prepared.validFor(set) {
		return VerifiedPackage{}, ErrInvalidReleaseIdentity
	}
	document := metadata.document
	identity := prepared.identity
	if signature.KeyID != document.PackageSignature.KeyID || !slices.Contains(prepared.snapshot.policy.ActiveKeys.Package, signature.KeyID) ||
		document.PackageSignature.SourcePolicyEpoch != prepared.snapshot.policy.Epoch ||
		document.PackageSignature.RevocationEpoch != prepared.snapshot.revocation.Epoch ||
		releaseRevoked(prepared.snapshot.revocation, identity, signature.KeyID) {
		return VerifiedPackage{}, ErrReleasePolicyDenied
	}
	context := releasecontract.PackageVerificationContext{SourceID: identity.SourceID, Channel: identity.Channel, Version: identity.Version}
	verifier, err := delegatedVerifier(prepared.snapshot.root, releasecontract.DelegatedKeyUsagePackage, identity.Channel, prepared.snapshot.verifiedAt, []string{signature.KeyID})
	if err != nil || releasecontract.VerifyPackageSignature(context, signature, verifier) != nil {
		return VerifiedPackage{}, ErrReleaseTrustVerification
	}
	if !releaseHashEqual(signature.PackageHash, document.Hashes.PackageSHA256) ||
		!releaseHashEqual(signature.ManifestHash, document.Hashes.ManifestSHA256) ||
		!releaseHashEqual(signature.EntriesHash, document.Hashes.EntriesSHA256) ||
		signature.PublisherID != identity.PublisherID || signature.PluginID != identity.PluginID {
		return VerifiedPackage{}, ErrInvalidReleaseIdentity
	}
	return VerifiedPackage{metadata: cloneVerifiedReleaseMetadata(metadata), signature: signature}, nil
}

func (prepared PreparedRelease) validFor(set *ServiceSet) bool {
	if prepared.service == nil || !validReleaseIdentity(prepared.identity) || set.services[prepared.identity.SourceID] != prepared.service ||
		prepared.snapshot.key.sourceID != prepared.identity.SourceID || prepared.snapshot.key.channel != prepared.identity.Channel {
		return false
	}
	return prepared.snapshot.service == prepared.service && !prepared.snapshot.verifiedAt.IsZero()
}

func validReleaseIdentity(identity ReleaseIdentity) bool {
	if !contractIDPattern.MatchString(identity.SourceID) || !contractIDPattern.MatchString(identity.Channel) ||
		identity.PublisherID == "" || identity.PluginID == "" || identity.Version == "" || !sha256Pattern.MatchString(identity.ReleaseMetadataSHA256) {
		return false
	}
	locator, err := newSourceRelativeLocator(identity.ReleaseMetadataRef)
	if err != nil || locator.String() != identity.ReleaseMetadataRef {
		return false
	}
	return true
}

func releaseRevoked(revocation releasecontract.RevocationV2, identity ReleaseIdentity, keyID string) bool {
	if keyID != "" && slices.Contains(revocation.RevokedKeyIDs, keyID) {
		return true
	}
	for _, release := range revocation.RevokedReleases {
		if release.PublisherID == identity.PublisherID && release.PluginID == identity.PluginID && release.Version == identity.Version &&
			release.ReleaseMetadataSHA256 == identity.ReleaseMetadataSHA256 {
			return true
		}
	}
	return false
}

func releaseHashEqual(left, right string) bool {
	return normalizeReleaseSHA256(left) == normalizeReleaseSHA256(right)
}

func normalizeReleaseSHA256(value string) string {
	return strings.TrimPrefix(value, "sha256:")
}

func clonePreparedRelease(prepared PreparedRelease) PreparedRelease {
	prepared.snapshot = cloneVerifiedSourceSnapshot(prepared.snapshot)
	return prepared
}

func cloneVerifiedReleaseMetadata(verified VerifiedReleaseMetadata) VerifiedReleaseMetadata {
	verified.prepared = clonePreparedRelease(verified.prepared)
	verified.document, _ = releasecontract.BuildReleaseMetadata(verified.document)
	verified.raw = slices.Clone(verified.raw)
	return verified
}
