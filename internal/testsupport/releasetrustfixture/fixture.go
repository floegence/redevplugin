package releasetrustfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
	"github.com/floegence/redevplugin/v2/pkg/releasetrust"
)

const (
	defaultSourceID  = "fixture_source"
	defaultChannel   = "stable"
	defaultSigningID = "fixture_signing_key"
	defaultRootID    = "fixture_root_key"
)

type Options struct {
	SourceID             string
	Channel              string
	SourceType           string
	SourceClass          string
	InstallPolicy        string
	DowngradePolicy      string
	AllowedArtifactHosts []string
	HostRequirements     []releasecontract.ReleaseHostRequirement
	GeneratedAt          time.Time
	ExpiresAt            time.Time
}

type Fixture struct {
	Service               *releasetrust.ReleaseTrustService
	ServiceSet            *releasetrust.ServiceSet
	Identity              releasetrust.ReleaseIdentity
	SourcePolicy          releasecontract.SourcePolicyV2
	Package               pluginpkg.Package
	PackageBytes          []byte
	Metadata              releasecontract.ReleaseMetadataV8
	MetadataBytes         []byte
	MetadataSignature     []byte
	PackageSignature      releasecontract.PackageSignatureV1
	SigningPrivateKey     ed25519.PrivateKey
	DocumentTransport     *DocumentTransport
	ReleaseArtifactSHA256 string
	GeneratedAt           time.Time
	ExpiresAt             time.Time
}

func New(packageBytes []byte, options Options) (*Fixture, error) {
	if len(packageBytes) == 0 {
		return nil, errors.New("release trust fixture package is required")
	}
	sourceID := valueOrDefault(options.SourceID, defaultSourceID)
	channel := valueOrDefault(options.Channel, defaultChannel)
	generatedAt := options.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC().Truncate(time.Second)
	}
	expiresAt := options.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = generatedAt.Add(24 * time.Hour)
	}
	if !expiresAt.After(generatedAt) {
		return nil, errors.New("release trust fixture expiry must follow generation time")
	}

	configuration, err := releasetrust.NewSourceConfiguration(sourceID, []string{channel})
	if err != nil {
		return nil, err
	}
	rootPrivate := deterministicPrivateKey(11)
	signingPrivate := deterministicPrivateKey(12)
	rootAnchor, err := releasetrust.NewEd25519TrustAnchor(defaultRootID, rootPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	trustOptions, err := releasetrust.NewReleaseTrustOptions(
		configuration,
		rootAnchor,
		releasetrust.SourceRelativeLocatorPolicyV1,
	)
	if err != nil {
		return nil, err
	}

	unsignedPackage, err := pluginpkg.Read(context.Background(), bytes.NewReader(packageBytes), int64(len(packageBytes)), pluginpkg.DefaultReadLimits())
	if err != nil {
		return nil, err
	}
	packageInput := releasecontract.PackageSigningInput{
		SourceID: sourceID, Channel: channel, Version: unsignedPackage.Manifest.Version(),
		Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: defaultSigningID,
		PublisherID: unsignedPackage.Manifest.Publisher.PublisherID, PluginID: unsignedPackage.Manifest.PluginID(),
		PackageHash: prefixedSHA256(unsignedPackage.PackageHash), ManifestHash: prefixedSHA256(unsignedPackage.ManifestHash),
		EntriesHash: prefixedSHA256(unsignedPackage.EntriesHash), SignedAt: generatedAt.Format(time.RFC3339Nano),
	}
	packagePreimage, err := releasecontract.PackageSigningPreimage(packageInput)
	if err != nil {
		return nil, err
	}
	packageSignature, err := releasecontract.BuildPackageSignature(packageInput, signDigest(signingPrivate, packagePreimage))
	if err != nil {
		return nil, err
	}
	unsignedPackage.PackageSignature = &pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion, Algorithm: packageSignature.Algorithm,
		KeyID: packageSignature.KeyID, PublisherID: packageSignature.PublisherID, PluginID: packageSignature.PluginID,
		PackageHash: unsignedPackage.PackageHash, ManifestHash: unsignedPackage.ManifestHash, EntriesHash: unsignedPackage.EntriesHash,
		Signature: packageSignature.Signature, SignedAt: packageSignature.SignedAt,
	}
	var signedPackageBuffer bytes.Buffer
	if err := pluginpkg.WritePackage(context.Background(), &signedPackageBuffer, unsignedPackage); err != nil {
		return nil, err
	}
	signedPackageBytes := signedPackageBuffer.Bytes()
	signedPackage, err := pluginpkg.Read(context.Background(), bytes.NewReader(signedPackageBytes), int64(len(signedPackageBytes)), pluginpkg.DefaultReadLimits())
	if err != nil {
		return nil, err
	}

	generatedAtValue := generatedAt.Format(time.RFC3339Nano)
	expiresAtValue := expiresAt.Format(time.RFC3339Nano)
	rootInput := releasecontract.RootDelegationInput{
		SourceID: sourceID, RootEpoch: "1",
		GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue,
		DelegatedKeys: []releasecontract.RootDelegatedKey{{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: defaultSigningID,
			PublicKey: base64.StdEncoding.EncodeToString(signingPrivate.Public().(ed25519.PublicKey)),
			Usages: []releasecontract.DelegatedKeyUsage{
				releasecontract.DelegatedKeyUsagePackage,
				releasecontract.DelegatedKeyUsageReleaseMetadata,
				releasecontract.DelegatedKeyUsageRevocation,
				releasecontract.DelegatedKeyUsageRevocationPointer,
				releasecontract.DelegatedKeyUsageSourcePolicy,
				releasecontract.DelegatedKeyUsageSourcePolicyPointer,
			},
			Channels: []string{channel}, ValidFrom: generatedAt.Add(-time.Hour).Format(time.RFC3339Nano), ValidUntil: expiresAtValue,
		}},
		KeyID: defaultRootID,
	}
	rootPreimage, err := releasecontract.RootDelegationSigningPreimage(rootInput)
	if err != nil {
		return nil, err
	}
	root, err := releasecontract.BuildRootDelegation(rootInput, signDigest(rootPrivate, rootPreimage))
	if err != nil {
		return nil, err
	}
	rootBytes, err := releasecontract.CanonicalRootDelegation(root)
	if err != nil {
		return nil, err
	}

	sourceType := valueOrDefault(options.SourceType, "registry")
	allowedArtifactHosts := slices.Clone(options.AllowedArtifactHosts)
	if sourceType == "registry" && len(allowedArtifactHosts) == 0 {
		allowedArtifactHosts = []string{"artifacts.example.com"}
	}
	policyInput := releasecontract.SourcePolicyInput{
		SourceID: sourceID, Channel: channel, Epoch: "1", RootEpoch: "1",
		SourceType: sourceType, SourceClass: valueOrDefault(options.SourceClass, "official"),
		AllowedPublishers: []string{signedPackage.Manifest.Publisher.PublisherID}, AllowedArtifactHosts: allowedArtifactHosts,
		ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			Package: []string{defaultSigningID}, ReleaseMetadata: []string{defaultSigningID},
			SourcePolicyPointer: []string{defaultSigningID}, Revocation: []string{defaultSigningID}, RevocationPointer: []string{defaultSigningID},
		},
		RequireSignature: true, InstallPolicy: valueOrDefault(options.InstallPolicy, "allow"), UnsignedPolicy: "block",
		DowngradePolicy: valueOrDefault(options.DowngradePolicy, "block"), MinimumRevocationEpoch: "1",
		Limits: releasecontract.PersonalMaintainerSourcePolicyLimits(), GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue, KeyID: defaultSigningID,
	}
	policyPreimage, err := releasecontract.SourcePolicySigningPreimage(policyInput)
	if err != nil {
		return nil, err
	}
	policy, err := releasecontract.BuildSourcePolicy(policyInput, signDigest(signingPrivate, policyPreimage))
	if err != nil {
		return nil, err
	}
	policyBytes, err := releasecontract.CanonicalSourcePolicy(policy)
	if err != nil {
		return nil, err
	}
	policyRef := fmt.Sprintf("sources/%s/%s/policy/1.json", sourceID, channel)
	policyPointerInput := releasecontract.ReleasePointerInput{
		SourceID: sourceID, Channel: channel, Epoch: "1", Ref: policyRef, DocumentSHA256: digestHex(policyBytes),
		GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue, KeyID: defaultSigningID,
	}
	policyPointerPreimage, err := releasecontract.SourcePolicyPointerSigningPreimage(policyPointerInput)
	if err != nil {
		return nil, err
	}
	policyPointer, err := releasecontract.BuildSourcePolicyPointer(policyPointerInput, signDigest(signingPrivate, policyPointerPreimage))
	if err != nil {
		return nil, err
	}
	policyPointerBytes, err := releasecontract.CanonicalSourcePolicyPointer(policyPointer)
	if err != nil {
		return nil, err
	}

	revocationInput := releasecontract.RevocationInput{
		SourceID: sourceID, Channel: channel, Epoch: "1", RootEpoch: "1",
		GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue, RevokedKeyIDs: []string{},
		RevokedReleases: []releasecontract.RevokedRelease{}, KeyID: defaultSigningID,
	}
	revocationPreimage, err := releasecontract.RevocationSigningPreimage(revocationInput)
	if err != nil {
		return nil, err
	}
	revocation, err := releasecontract.BuildRevocation(revocationInput, signDigest(signingPrivate, revocationPreimage))
	if err != nil {
		return nil, err
	}
	revocationBytes, err := releasecontract.CanonicalRevocation(revocation)
	if err != nil {
		return nil, err
	}
	revocationRef := fmt.Sprintf("sources/%s/%s/revocation/1.json", sourceID, channel)
	revocationPointerInput := releasecontract.ReleasePointerInput{
		SourceID: sourceID, Channel: channel, Epoch: "1", Ref: revocationRef, DocumentSHA256: digestHex(revocationBytes),
		GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue, KeyID: defaultSigningID,
	}
	revocationPointerPreimage, err := releasecontract.RevocationPointerSigningPreimage(revocationPointerInput)
	if err != nil {
		return nil, err
	}
	revocationPointer, err := releasecontract.BuildRevocationPointer(revocationPointerInput, signDigest(signingPrivate, revocationPointerPreimage))
	if err != nil {
		return nil, err
	}
	revocationPointerBytes, err := releasecontract.CanonicalRevocationPointer(revocationPointer)
	if err != nil {
		return nil, err
	}

	releaseMetadataRef := fmt.Sprintf(
		"plugins/%s/%s/%s/release.json",
		signedPackage.Manifest.Publisher.PublisherID,
		signedPackage.Manifest.PluginID(),
		signedPackage.Manifest.Version(),
	)
	releaseMetadata := releasecontract.ReleaseMetadataV8{
		SchemaVersion: releaseMetadataSchemaVersion(signedPackage.Manifest.Plugin.UIProtocolVersion), SourceID: sourceID, ReleaseMetadataRef: releaseMetadataRef,
		PublisherID: signedPackage.Manifest.Publisher.PublisherID, PluginID: signedPackage.Manifest.PluginID(), Version: signedPackage.Manifest.Version(),
		DistributionRef: releasecontract.ReleaseDistributionRef{
			Distribution: "registry_ref",
			ArtifactRef:  fmt.Sprintf("plugins/%s/%s/%s/package.redevplugin", signedPackage.Manifest.Publisher.PublisherID, signedPackage.Manifest.PluginID(), signedPackage.Manifest.Version()),
		},
		Hashes: releasecontract.ReleasePackageHashSet{
			PackageSHA256: signedPackage.PackageHash, ManifestSHA256: signedPackage.ManifestHash, EntriesSHA256: signedPackage.EntriesHash,
		},
		ReleaseMetadataSignature: releasecontract.ReleaseMetadataSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: defaultSigningID,
			SignatureRef: releaseMetadataRef + ".sig", SourcePolicyEpoch: "1", RevocationEpoch: "1",
		},
		PackageSignature: releasecontract.PackageReleaseSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: defaultSigningID,
			SignatureBundleRef: fmt.Sprintf("plugins/%s/%s/%s/package.sig", signedPackage.Manifest.Publisher.PublisherID, signedPackage.Manifest.PluginID(), signedPackage.Manifest.Version()),
			SourcePolicyEpoch:  "1", RevocationEpoch: "1",
		},
		Compatibility: releasecontract.ReleaseCompatibility{
			MinReDevPluginVersion: "0.1.0", MinRuntimeVersion: signedPackage.Manifest.Plugin.MinRuntimeVersion,
			UIProtocolVersion: signedPackage.Manifest.Plugin.UIProtocolVersion,
		},
		HostRequirements: cloneHostRequirements(options.HostRequirements),
	}
	releaseMetadata, err = releasecontract.BuildReleaseMetadata(releaseMetadata)
	if err != nil {
		return nil, err
	}
	metadataBytes, err := releasecontract.CanonicalReleaseMetadata(releaseMetadata)
	if err != nil {
		return nil, err
	}
	metadataPreimage, err := releasecontract.ReleaseMetadataSigningPreimage(channel, releaseMetadata)
	if err != nil {
		return nil, err
	}
	metadataSignature := signDigest(signingPrivate, metadataPreimage)
	metadataSHA256 := digestHex(metadataBytes)
	identity := releasetrust.ReleaseIdentity{
		SourceID: sourceID, Channel: channel, ReleaseMetadataRef: releaseMetadataRef, ReleaseMetadataSHA256: metadataSHA256,
		PublisherID: signedPackage.Manifest.Publisher.PublisherID, PluginID: signedPackage.Manifest.PluginID(), Version: signedPackage.Manifest.Version(),
	}

	documents := &DocumentTransport{values: map[string][]byte{}, tokens: map[string]string{}}
	for locator, value := range map[string][]byte{
		fmt.Sprintf("sources/%s/root/current.json", sourceID):               rootBytes,
		fmt.Sprintf("sources/%s/%s/policy/current.json", sourceID, channel): policyPointerBytes,
		policyRef: policyBytes,
		fmt.Sprintf("sources/%s/%s/revocation/current.json", sourceID, channel): revocationPointerBytes,
		revocationRef: revocationBytes,
	} {
		documents.values[locator] = slices.Clone(value)
		documents.tokens[locator] = "fixture-token-" + digestHex([]byte(locator))[:16]
	}
	service, err := releasetrust.NewReleaseTrustService(trustOptions, releasetrust.ReleaseTrustAdapters{Documents: documents})
	if err != nil {
		return nil, err
	}
	serviceSet, err := releasetrust.NewServiceSet(service)
	if err != nil {
		return nil, err
	}
	artifactDigest := digestHex(signedPackageBytes)
	return &Fixture{
		Service: service, ServiceSet: serviceSet, Identity: identity, SourcePolicy: policy, Package: signedPackage,
		PackageBytes: slices.Clone(signedPackageBytes), Metadata: releaseMetadata, MetadataBytes: slices.Clone(metadataBytes),
		MetadataSignature: slices.Clone(metadataSignature), PackageSignature: packageSignature,
		SigningPrivateKey:     slices.Clone(signingPrivate),
		DocumentTransport:     documents,
		ReleaseArtifactSHA256: artifactDigest, GeneratedAt: generatedAt, ExpiresAt: expiresAt,
	}, nil
}

func (fixture *Fixture) RevokeRelease(now time.Time) error {
	return fixture.publishRevocation(now, []string{}, []releasecontract.RevokedRelease{{
		PublisherID: fixture.Identity.PublisherID, PluginID: fixture.Identity.PluginID, Version: fixture.Identity.Version,
		ReleaseMetadataSHA256: fixture.Identity.ReleaseMetadataSHA256, RevokedAt: normalizedRevocationTime(now).Format(time.RFC3339Nano),
	}})
}

func (fixture *Fixture) RevokeSigningKey(now time.Time) error {
	return fixture.publishRevocation(now, []string{defaultSigningID}, []releasecontract.RevokedRelease{})
}

func normalizedRevocationTime(now time.Time) time.Time {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}
	return now
}

func (fixture *Fixture) publishRevocation(now time.Time, revokedKeyIDs []string, revokedReleases []releasecontract.RevokedRelease) error {
	if fixture == nil || fixture.DocumentTransport == nil {
		return errors.New("release trust fixture is required")
	}
	now = normalizedRevocationTime(now)
	currentRef := fmt.Sprintf("sources/%s/%s/revocation/current.json", fixture.Identity.SourceID, fixture.Identity.Channel)
	fixture.DocumentTransport.mu.Lock()
	previousPointerBytes := slices.Clone(fixture.DocumentTransport.values[currentRef])
	fixture.DocumentTransport.mu.Unlock()
	if _, err := releasecontract.DecodeRevocationPointer(previousPointerBytes); err != nil {
		return err
	}
	revocationRef := fmt.Sprintf("sources/%s/%s/revocation/2.json", fixture.Identity.SourceID, fixture.Identity.Channel)
	revocationInput := releasecontract.RevocationInput{
		SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel, Epoch: "2",
		RootEpoch:   fixture.SourcePolicy.RootEpoch,
		GeneratedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		RevokedKeyIDs: slices.Clone(revokedKeyIDs), RevokedReleases: slices.Clone(revokedReleases),
		KeyID: defaultSigningID,
	}
	preimage, err := releasecontract.RevocationSigningPreimage(revocationInput)
	if err != nil {
		return err
	}
	revocation, err := releasecontract.BuildRevocation(revocationInput, signDigest(fixture.SigningPrivateKey, preimage))
	if err != nil {
		return err
	}
	revocationBytes, err := releasecontract.CanonicalRevocation(revocation)
	if err != nil {
		return err
	}
	pointerInput := releasecontract.ReleasePointerInput{
		SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel, Epoch: "2",
		Ref: revocationRef, DocumentSHA256: digestHex(revocationBytes), GeneratedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339Nano), KeyID: defaultSigningID,
	}
	pointerPreimage, err := releasecontract.RevocationPointerSigningPreimage(pointerInput)
	if err != nil {
		return err
	}
	pointer, err := releasecontract.BuildRevocationPointer(pointerInput, signDigest(fixture.SigningPrivateKey, pointerPreimage))
	if err != nil {
		return err
	}
	pointerBytes, err := releasecontract.CanonicalRevocationPointer(pointer)
	if err != nil {
		return err
	}
	fixture.DocumentTransport.mu.Lock()
	fixture.DocumentTransport.values[revocationRef] = slices.Clone(revocationBytes)
	fixture.DocumentTransport.tokens[revocationRef] = "fixture-token-" + digestHex([]byte(revocationRef))[:16]
	fixture.DocumentTransport.values[currentRef] = slices.Clone(pointerBytes)
	fixture.DocumentTransport.tokens[currentRef] = "fixture-token-" + digestHex(pointerBytes)[:16]
	fixture.DocumentTransport.mu.Unlock()
	return nil
}

type DocumentTransport struct {
	mu                     sync.Mutex
	values                 map[string][]byte
	tokens                 map[string]string
	calls                  int
	blocked                bool
	firstDeadlineRemaining time.Duration
	hasDeadline            bool
}

func (transport *DocumentTransport) FetchReleaseDocument(ctx context.Context, request releasetrust.ReleaseDocumentRequest) (releasetrust.ReleaseDocumentResult, error) {
	transport.mu.Lock()
	transport.calls++
	if transport.calls == 1 {
		if deadline, ok := ctx.Deadline(); ok {
			transport.firstDeadlineRemaining = time.Until(deadline)
			transport.hasDeadline = true
		}
	}
	blocked := transport.blocked
	locator := request.Locator().String()
	value := slices.Clone(transport.values[locator])
	token := transport.tokens[locator]
	transport.mu.Unlock()
	if blocked {
		<-ctx.Done()
		return releasetrust.ReleaseDocumentResult{}, ctx.Err()
	}
	if value == nil {
		return releasetrust.ReleaseDocumentResult{}, fmt.Errorf("missing release document fixture %s", locator)
	}
	return releasetrust.NewReleaseDocumentResult(request, token, value)
}

func (transport *DocumentTransport) Calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

func (transport *DocumentTransport) SetBlocked(blocked bool) {
	transport.mu.Lock()
	transport.blocked = blocked
	transport.mu.Unlock()
}

func (transport *DocumentTransport) FirstDeadlineRemaining() (time.Duration, bool) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.firstDeadlineRemaining, transport.hasDeadline
}

func cloneHostRequirements(values []releasecontract.ReleaseHostRequirement) []releasecontract.ReleaseHostRequirement {
	cloned := make([]releasecontract.ReleaseHostRequirement, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].RequiredCapabilityContracts = slices.Clone(value.RequiredCapabilityContracts)
	}
	return cloned
}

func deterministicPrivateKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func signDigest(privateKey ed25519.PrivateKey, preimage []byte) []byte {
	digest := sha256.Sum256(preimage)
	return ed25519.Sign(privateKey, digest[:])
}

func prefixedSHA256(value string) string {
	return "sha256:" + strings.TrimPrefix(value, "sha256:")
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func releaseMetadataSchemaVersion(uiProtocolVersion string) string {
	if uiProtocolVersion == "plugin-ui-v7" {
		return releasecontract.ReleaseMetadataSchemaVersionV8
	}
	return ""
}
