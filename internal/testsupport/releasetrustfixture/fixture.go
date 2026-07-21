package releasetrustfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasetrust"
)

const (
	defaultSourceID  = "fixture_source"
	defaultChannel   = "stable"
	defaultSigningID = "fixture_signing_key"
	defaultRootID    = "fixture_root_key"
	defaultTimeID    = "fixture_time_key"
	defaultTimeLogID = "fixture_time_log"
	defaultLedgerID  = "fixture_ledger_key"
	defaultLedgerLog = "fixture_signing_log"
	zeroSHA256       = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Options struct {
	SourceID             string
	Channel              string
	SourceClass          string
	InstallPolicy        string
	DowngradePolicy      string
	AllowedArtifactHosts []string
	HostRequirements     []releasecontract.ReleaseHostRequirement
	GeneratedAt          time.Time
	ExpiresAt            time.Time
}

type Fixture struct {
	ServiceSet            *releasetrust.ServiceSet
	Identity              releasetrust.ReleaseIdentity
	SourcePolicy          releasecontract.SourcePolicyV2
	Package               pluginpkg.Package
	PackageBytes          []byte
	Metadata              releasecontract.ReleaseMetadataV5
	MetadataBytes         []byte
	MetadataSignature     []byte
	PackageSignature      releasecontract.PackageSignatureV1
	SigningPrivateKey     ed25519.PrivateKey
	CapabilityBundle      *capabilitycontract.Bundle
	DocumentTransport     *DocumentTransport
	LedgerTransport       *LedgerTransport
	StateStore            *StateStore
	TrustedTime           *TrustedTimeAdapter
	ReleaseArtifactSHA256 string
}

func New(packageBytes []byte, options Options) (*Fixture, error) {
	if len(packageBytes) == 0 {
		return nil, errors.New("release trust fixture package is required")
	}
	sourceID := valueOrDefault(options.SourceID, defaultSourceID)
	channel := valueOrDefault(options.Channel, defaultChannel)
	generatedAt := options.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC)
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
	timePrivate := deterministicPrivateKey(13)
	ledgerPrivate := deterministicPrivateKey(14)
	rootAnchor, err := releasetrust.NewEd25519TrustAnchor(defaultRootID, rootPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	timeAnchor, err := releasetrust.NewEd25519TrustAnchor(defaultTimeID, timePrivate.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	timeRoot, err := releasetrust.NewTransparencyRoot(defaultTimeLogID, timeAnchor)
	if err != nil {
		return nil, err
	}
	ledgerAnchor, err := releasetrust.NewEd25519TrustAnchor(defaultLedgerID, ledgerPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	ledgerRoot, err := releasetrust.NewPinnedSigningLedgerRoot(defaultLedgerLog, ledgerAnchor)
	if err != nil {
		return nil, err
	}
	trustOptions, err := releasetrust.NewReleaseTrustOptions(
		configuration,
		rootAnchor,
		[]releasetrust.TransparencyRoot{timeRoot},
		ledgerRoot,
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
		SourceID: sourceID, RootEpoch: "1", PreviousRootEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDelegationSHA256: releasecontract.GenesisPreviousDocumentSHA256,
		GeneratedAt:              generatedAtValue, ExpiresAt: expiresAtValue,
		DelegatedKeys: []releasecontract.RootDelegatedKey{{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: defaultSigningID,
			PublicKey: base64.StdEncoding.EncodeToString(signingPrivate.Public().(ed25519.PublicKey)),
			Usages: []releasecontract.DelegatedKeyUsage{
				releasecontract.DelegatedKeyUsagePackage,
				releasecontract.DelegatedKeyUsageReleaseMetadata,
				releasecontract.DelegatedKeyUsageHostCapabilityContract,
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

	allowedArtifactHosts := slices.Clone(options.AllowedArtifactHosts)
	if len(allowedArtifactHosts) == 0 {
		allowedArtifactHosts = []string{"artifacts.example.com"}
	}
	policyInput := releasecontract.SourcePolicyInput{
		SourceID: sourceID, Channel: channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
		SourceType: "registry", SourceClass: valueOrDefault(options.SourceClass, "official"),
		AllowedPublishers: []string{signedPackage.Manifest.Publisher.PublisherID}, AllowedArtifactHosts: allowedArtifactHosts,
		ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			Package: []string{defaultSigningID}, ReleaseMetadata: []string{defaultSigningID}, HostCapabilityContract: []string{defaultSigningID},
			SourcePolicyPointer: []string{defaultSigningID}, Revocation: []string{defaultSigningID}, RevocationPointer: []string{defaultSigningID},
		},
		RequireSignature: true, InstallPolicy: valueOrDefault(options.InstallPolicy, "allow"), UnsignedPolicy: "block",
		DowngradePolicy: valueOrDefault(options.DowngradePolicy, "block"), MinimumRevocationEpoch: "1",
		Limits: releasecontract.DefaultSourcePolicyLimits(), GeneratedAt: generatedAtValue, ExpiresAt: expiresAtValue, KeyID: defaultSigningID,
	}
	policyInput.CapabilityPublisherScopes = []releasecontract.SourcePolicyCapabilityPublisherScope{{
		KeyID: defaultSigningID, AllowedPublishers: []string{"fixture.capability"},
	}}
	for _, requirement := range options.HostRequirements {
		for _, capability := range requirement.RequiredCapabilityContracts {
			policyInput.CapabilityPublisherScopes = append(policyInput.CapabilityPublisherScopes, releasecontract.SourcePolicyCapabilityPublisherScope{
				KeyID: defaultSigningID, AllowedPublishers: []string{capability.Contract.PublisherID},
			})
		}
	}
	policyInput.CapabilityPublisherScopes = canonicalCapabilityScopes(policyInput.CapabilityPublisherScopes)
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
		SourceID: sourceID, Channel: channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, Ref: policyRef, DocumentSHA256: digestHex(policyBytes),
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
		SourceID: sourceID, Channel: channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
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
		SourceID: sourceID, Channel: channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, Ref: revocationRef, DocumentSHA256: digestHex(revocationBytes),
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
	releaseMetadata := releasecontract.ReleaseMetadataV5{
		SchemaVersion: releasecontract.ReleaseMetadataSchemaVersion, SourceID: sourceID, ReleaseMetadataRef: releaseMetadataRef,
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
	signedDocuments := []signedDocument{
		{subject: rootSigningSubject(root), preimage: rootPreimage, keyID: root.KeyID, signature: root.Signature},
		{subject: epochSigningSubject(sourceID, channel, releasecontract.SigningSubjectUsageSourcePolicyPointer, "1"), preimage: policyPointerPreimage, keyID: policyPointer.KeyID, signature: policyPointer.Signature},
		{subject: epochSigningSubject(sourceID, channel, releasecontract.SigningSubjectUsageSourcePolicy, "1"), preimage: policyPreimage, keyID: policy.KeyID, signature: policy.Signature},
		{subject: epochSigningSubject(sourceID, channel, releasecontract.SigningSubjectUsageRevocationPointer, "1"), preimage: revocationPointerPreimage, keyID: revocationPointer.KeyID, signature: revocationPointer.Signature},
		{subject: epochSigningSubject(sourceID, channel, releasecontract.SigningSubjectUsageRevocation, "1"), preimage: revocationPreimage, keyID: revocation.KeyID, signature: revocation.Signature},
		{subject: releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageReleaseMetadata,
			SourceID: sourceID, Channel: channel, PublisherID: identity.PublisherID, PluginID: identity.PluginID,
			Version: identity.Version, ArtifactIdentitySHA256: metadataSHA256,
		}, preimage: metadataPreimage, keyID: defaultSigningID, signature: base64.StdEncoding.EncodeToString(metadataSignature)},
		{subject: releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsagePackage,
			SourceID: sourceID, Channel: channel, PublisherID: identity.PublisherID, PluginID: identity.PluginID,
			Version: identity.Version, ArtifactIdentitySHA256: strings.TrimPrefix(signedPackage.PackageHash, "sha256:"),
		}, preimage: packagePreimage, keyID: defaultSigningID, signature: packageSignature.Signature},
	}
	ledger, err := buildLedger(configuration, signedDocuments, ledgerPrivate, generatedAt.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	state := &StateStore{}
	trustedTime := &TrustedTimeAdapter{privateKey: timePrivate, start: generatedAt.Add(time.Hour)}
	service, err := releasetrust.NewReleaseTrustService(trustOptions, releasetrust.ReleaseTrustAdapters{
		Documents: documents, Ledger: ledger, State: state, TrustedTime: trustedTime,
	})
	if err != nil {
		return nil, err
	}
	serviceSet, err := releasetrust.NewServiceSet(service)
	if err != nil {
		return nil, err
	}
	artifactDigest := digestHex(signedPackageBytes)
	return &Fixture{
		ServiceSet: serviceSet, Identity: identity, SourcePolicy: policy, Package: signedPackage,
		PackageBytes: slices.Clone(signedPackageBytes), Metadata: releaseMetadata, MetadataBytes: slices.Clone(metadataBytes),
		MetadataSignature: slices.Clone(metadataSignature), PackageSignature: packageSignature,
		SigningPrivateKey: slices.Clone(signingPrivate),
		DocumentTransport: documents, LedgerTransport: ledger, StateStore: state, TrustedTime: trustedTime,
		ReleaseArtifactSHA256: artifactDigest,
	}, nil
}

func (fixture *Fixture) SetCapabilityBundle(bundle capabilitycontract.Bundle) {
	if fixture == nil {
		return
	}
	cloned := capabilitycontract.Bundle{Pin: bundle.Pin, Files: make(map[string][]byte, len(bundle.Files))}
	for name, value := range bundle.Files {
		cloned.Files[name] = slices.Clone(value)
	}
	fixture.CapabilityBundle = &cloned
}

type DocumentTransport struct {
	mu     sync.Mutex
	values map[string][]byte
	tokens map[string]string
	calls  int
}

func (transport *DocumentTransport) FetchReleaseDocument(_ context.Context, request releasetrust.ReleaseDocumentRequest) (releasetrust.ReleaseDocumentResult, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls++
	locator := request.Locator().String()
	value := transport.values[locator]
	if value == nil {
		return releasetrust.ReleaseDocumentResult{}, fmt.Errorf("missing release document fixture %s", locator)
	}
	return releasetrust.NewReleaseDocumentResult(request, transport.tokens[locator], value)
}

func (transport *DocumentTransport) Calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

type LedgerTransport struct {
	mu     sync.Mutex
	values map[string][]byte
	calls  int
}

func (transport *LedgerTransport) FetchSigningLedgerArtifact(_ context.Context, request releasetrust.SigningLedgerRequest) (releasetrust.SigningLedgerResult, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.calls++
	locator := request.Locator().String()
	value := transport.values[locator]
	if value == nil {
		return releasetrust.SigningLedgerResult{}, fmt.Errorf("missing signing ledger fixture %s", locator)
	}
	return releasetrust.NewSigningLedgerResult(request, value)
}

func (transport *LedgerTransport) Calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls
}

type StateStore struct {
	mu        sync.Mutex
	committed []byte
	pending   []byte
}

func (store *StateStore) LoadSourceTrustState(_ context.Context, request releasetrust.SourceTrustStateLoadRequest) (releasetrust.SourceTrustStateLoadResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return releasetrust.NewSourceTrustStateLoadResult(request, store.committed, store.pending)
}

func (store *StateStore) PrepareSourceTrustState(_ context.Context, request releasetrust.SourceTrustStatePrepareRequest) (releasetrust.StateMutationOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if digestOrEmpty(store.committed) != request.ExpectedCommittedSHA256() {
		return releasetrust.StateMutationConflict, nil
	}
	if len(store.pending) != 0 && digestHex(store.pending) != request.PendingSHA256() {
		return releasetrust.StateMutationConflict, nil
	}
	store.pending = request.PendingBytes()
	return releasetrust.StateMutationApplied, nil
}

func (store *StateStore) CommitSourceTrustState(_ context.Context, request releasetrust.SourceTrustStateCommitRequest) (releasetrust.StateMutationOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) == 0 || digestHex(store.pending) != request.PendingSHA256() || digestHex(request.NextStateBytes()) != request.NextStateSHA256() {
		return releasetrust.StateMutationConflict, nil
	}
	store.committed = request.NextStateBytes()
	store.pending = nil
	return releasetrust.StateMutationApplied, nil
}

type TrustedTimeAdapter struct {
	mu         sync.Mutex
	privateKey ed25519.PrivateKey
	start      time.Time
	calls      int
	leaves     [][]byte
}

func (adapter *TrustedTimeAdapter) Observe(_ context.Context, request releasetrust.TrustedTimeRequest) (releasetrust.TrustedTimeObservation, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	integrated := adapter.start.Add(time.Duration(adapter.calls) * time.Minute)
	leaf := releasetrust.TrustedTimeLeafV1{
		SchemaVersion: releasetrust.TrustedTimeLeafSchemaVersion, SourceID: request.SourceTrustKey().SourceID(), Channel: request.SourceTrustKey().Channel(),
		Nonce: request.Nonce(), MinimumTime: request.MinimumTime(), ClaimedTime: integrated.Add(time.Hour).Format(time.RFC3339Nano),
		RequestSHA256: request.RequestSHA256(), LogID: request.LogID(),
	}
	leafBytes, err := json.Marshal(leaf)
	if err != nil {
		return releasetrust.TrustedTimeObservation{}, err
	}
	leafHashes := make([][]byte, 0, len(adapter.leaves)+1)
	for _, previous := range adapter.leaves {
		leafHashes = append(leafHashes, merkleLeafHash(previous))
	}
	leafHashes = append(leafHashes, merkleLeafHash(leafBytes))
	treeSize := uint64(len(leafHashes))
	rootHash := merkleRoot(leafHashes)
	checkpoint := releasetrust.TrustedTimeCheckpointV1{
		SchemaVersion: releasetrust.TrustedTimeCheckpointSchemaVersion, LogID: request.LogID(), TreeSize: treeSize,
		RootHash: hex.EncodeToString(rootHash), CheckpointTime: integrated.Format(time.RFC3339Nano), KeyID: defaultTimeID,
	}
	checkpointPreimage, err := json.Marshal(struct {
		Domain         string `json:"domain"`
		SchemaVersion  string `json:"schema_version"`
		LogID          string `json:"log_id"`
		TreeSize       uint64 `json:"tree_size"`
		RootHash       string `json:"root_hash"`
		CheckpointTime string `json:"checkpoint_time"`
		KeyID          string `json:"key_id"`
	}{
		Domain: "redevplugin.trusted-time.checkpoint.v1", SchemaVersion: checkpoint.SchemaVersion, LogID: checkpoint.LogID,
		TreeSize: checkpoint.TreeSize, RootHash: checkpoint.RootHash, CheckpointTime: checkpoint.CheckpointTime, KeyID: checkpoint.KeyID,
	})
	if err != nil {
		return releasetrust.TrustedTimeObservation{}, err
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(adapter.privateKey, checkpointPreimage))
	leafSHA256 := digestHex(leafBytes)
	setPreimage, err := json.Marshal(struct {
		Domain         string `json:"domain"`
		LeafSHA256     string `json:"leaf_sha256"`
		IntegratedTime string `json:"integrated_time"`
		LogID          string `json:"log_id"`
	}{
		Domain: "redevplugin.trusted-time.set.v1", LeafSHA256: leafSHA256,
		IntegratedTime: integrated.Format(time.RFC3339Nano), LogID: request.LogID(),
	})
	if err != nil {
		return releasetrust.TrustedTimeObservation{}, err
	}
	var consistency []string
	if len(adapter.leaves) != 0 {
		consistency = encodeProof(merkleConsistencyProof(leafHashes, len(adapter.leaves)))
	}
	evidence := releasetrust.TrustedTimeEvidenceV1{
		SchemaVersion: releasetrust.TrustedTimeEvidenceSchemaVersion, Kind: releasetrust.TrustedTimeEvidenceTransparency,
		Leaf: leaf, LeafSHA256: leafSHA256, IntegratedTime: integrated.Format(time.RFC3339Nano),
		SignedEntryTimestamp: base64.StdEncoding.EncodeToString(ed25519.Sign(adapter.privateKey, setPreimage)),
		Checkpoint:           checkpoint, LeafIndex: treeSize - 1, InclusionProof: encodeProof(merkleInclusionProof(leafHashes, len(leafHashes)-1)),
		ConsistencyProof: consistency,
	}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		return releasetrust.TrustedTimeObservation{}, err
	}
	adapter.leaves = append(adapter.leaves, slices.Clone(leafBytes))
	adapter.calls++
	return releasetrust.NewTransparencyTimeObservation(request, evidenceBytes)
}

type signedDocument struct {
	subject   releasecontract.SigningSubjectV1
	preimage  []byte
	keyID     string
	signature string
}

type ledgerValue struct {
	subject       releasecontract.SigningSubjectV1
	subjectDigest string
	preimageHash  string
	envelopeHash  string
	sequence      uint64
}

func buildLedger(configuration releasetrust.SourceConfiguration, documents []signedDocument, privateKey ed25519.PrivateKey, checkpointTime time.Time) (*LedgerTransport, error) {
	values := make([]ledgerValue, len(documents))
	logLeaves := make([][]byte, len(documents))
	for index, document := range documents {
		subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(document.subject)
		if err != nil {
			return nil, fmt.Errorf("build signing ledger subject %q: %w", document.subject.Usage, err)
		}
		preimageDigest := sha256.Sum256(document.preimage)
		envelope := releasecontract.SignatureEnvelopeV1{
			SchemaVersion: releasecontract.SigningEnvelopeSchemaVersion, SubjectIdentitySHA256: subjectDigest,
			SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]), Algorithm: releasecontract.SignatureAlgorithmEd25519,
			KeyID: document.keyID, Signature: document.signature,
		}
		envelopeBytes, err := releasecontract.CanonicalSignatureEnvelope(envelope)
		if err != nil {
			return nil, err
		}
		sequence := uint64(index + 1)
		leaf := releasecontract.SigningLedgerLogLeafV1{
			SchemaVersion: releasecontract.SigningLedgerLogLeafSchemaVersion, SourceID: document.subject.SourceID,
			Channel: document.subject.Channel, SubjectIdentitySHA256: subjectDigest,
			SigningPreimageSHA256: envelope.SigningPreimageSHA256, SignatureEnvelopeSHA256: digestHex(envelopeBytes), Sequence: sequence,
		}
		leafBytes, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
		if err != nil {
			return nil, err
		}
		logLeaves[index] = merkleLeafHash(leafBytes)
		values[index] = ledgerValue{
			subject: document.subject, subjectDigest: subjectDigest, preimageHash: envelope.SigningPreimageSHA256,
			envelopeHash: digestHex(envelopeBytes), sequence: sequence,
		}
	}
	logRoot := merkleRoot(logLeaves)
	latestRoot, latestProofs := latestMap(values)
	checkpoint := releasecontract.SigningLedgerCheckpointV1{
		SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactCheckpoint,
		LogID: defaultLedgerLog, TreeSize: uint64(len(values)), LogRootHash: hex.EncodeToString(logRoot),
		LatestMapRootHash: hex.EncodeToString(latestRoot), CheckpointTime: checkpointTime.Format(time.RFC3339Nano), KeyID: defaultLedgerID,
	}
	checkpointPreimage, err := releasecontract.SigningLedgerCheckpointSigningPreimage(checkpoint)
	if err != nil {
		return nil, err
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(signDigest(privateKey, checkpointPreimage))
	checkpointBytes, err := releasecontract.CanonicalSigningLedgerCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	checkpointSHA256 := digestHex(checkpointBytes)
	base := fmt.Sprintf("sources/%s/signing-ledger", configuration.SourceID())
	transport := &LedgerTransport{values: map[string][]byte{
		fmt.Sprintf("%s/checkpoints/%s.json", base, checkpointSHA256): checkpointBytes,
	}}
	for index, value := range values {
		receipt := releasecontract.SigningLedgerReceiptV1{
			SchemaVersion: releasecontract.SigningLedgerReceiptSchemaVersion, LogID: defaultLedgerLog,
			SourceID: value.subject.SourceID, Channel: value.subject.Channel, SubjectIdentitySHA256: value.subjectDigest,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash,
			Sequence: value.sequence, LeafIndex: uint64(index), TreeSize: uint64(len(values)), LogRootHash: checkpoint.LogRootHash,
			LatestMapRootHash: checkpoint.LatestMapRootHash, CheckpointSHA256: checkpointSHA256,
			CheckpointTime: checkpoint.CheckpointTime, KeyID: defaultLedgerID,
		}
		receiptPreimage, err := releasecontract.SigningLedgerReceiptSigningPreimage(receipt)
		if err != nil {
			return nil, err
		}
		receipt.Signature = base64.StdEncoding.EncodeToString(signDigest(privateKey, receiptPreimage))
		receiptBytes, err := releasecontract.CanonicalSigningLedgerReceipt(receipt)
		if err != nil {
			return nil, err
		}
		inclusion := releasecontract.SigningLedgerInclusionProofV1{
			SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactInclusionProof,
			LogID: defaultLedgerLog, LeafIndex: uint64(index), TreeSize: uint64(len(values)), Nodes: encodeProof(merkleInclusionProof(logLeaves, index)),
		}
		inclusionBytes, err := releasecontract.CanonicalSigningLedgerInclusionProof(inclusion)
		if err != nil {
			return nil, err
		}
		latest := releasecontract.SigningLedgerLatestProofV1{
			SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactLatestProof,
			LogID: defaultLedgerLog, SubjectIdentitySHA256: value.subjectDigest, Present: true, Sequence: value.sequence,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash, Siblings: latestProofs[value.subjectDigest],
		}
		latestBytes, err := releasecontract.CanonicalSigningLedgerLatestProof(latest)
		if err != nil {
			return nil, err
		}
		receiptRef := fmt.Sprintf("%s/receipts/%s.json", base, value.subjectDigest)
		checkpointRef := fmt.Sprintf("%s/checkpoints/%s.json", base, checkpointSHA256)
		inclusionRef := fmt.Sprintf("%s/proofs/inclusion/%s.json", base, value.subjectDigest)
		latestRef := fmt.Sprintf("%s/proofs/latest/%s.json", base, value.subjectDigest)
		evidence := releasecontract.SigningLedgerEvidenceV1{
			SchemaVersion: releasecontract.SigningLedgerEvidenceSchemaVersion, SourceID: value.subject.SourceID,
			Channel: value.subject.Channel, SubjectIdentitySHA256: value.subjectDigest,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash,
			ReceiptRef: receiptRef, ReceiptSHA256: digestHex(receiptBytes), CheckpointRef: checkpointRef,
			CheckpointSHA256: checkpointSHA256, InclusionProofRef: inclusionRef, InclusionProofSHA256: digestHex(inclusionBytes),
			LatestProofRef: latestRef, LatestProofSHA256: digestHex(latestBytes),
		}
		evidenceBytes, err := releasecontract.CanonicalSigningLedgerEvidence(evidence)
		if err != nil {
			return nil, err
		}
		transport.values[fmt.Sprintf("%s/evidence/%s.json", base, value.subjectDigest)] = evidenceBytes
		transport.values[receiptRef] = receiptBytes
		transport.values[inclusionRef] = inclusionBytes
		transport.values[latestRef] = latestBytes
	}
	return transport, nil
}

func rootSigningSubject(root releasecontract.RootDelegationV1) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{
		SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRootDelegation,
		SourceID: root.SourceID, RootEpoch: root.RootEpoch,
	}
}

func epochSigningSubject(sourceID, channel string, usage releasecontract.SigningSubjectUsage, epoch string) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{
		SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: usage, SourceID: sourceID, Channel: channel, Epoch: epoch,
	}
}

func canonicalCapabilityScopes(values []releasecontract.SourcePolicyCapabilityPublisherScope) []releasecontract.SourcePolicyCapabilityPublisherScope {
	byKey := make(map[string][]string, len(values))
	for _, value := range values {
		byKey[value.KeyID] = append(byKey[value.KeyID], value.AllowedPublishers...)
	}
	result := make([]releasecontract.SourcePolicyCapabilityPublisherScope, 0, len(byKey))
	for keyID, publishers := range byKey {
		slices.Sort(publishers)
		publishers = slices.Compact(publishers)
		result = append(result, releasecontract.SourcePolicyCapabilityPublisherScope{KeyID: keyID, AllowedPublishers: publishers})
	}
	slices.SortFunc(result, func(left, right releasecontract.SourcePolicyCapabilityPublisherScope) int {
		return strings.Compare(left.KeyID, right.KeyID)
	})
	return result
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

func digestOrEmpty(value []byte) string {
	if len(value) == 0 {
		return zeroSHA256
	}
	return digestHex(value)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func merkleLeafHash(value []byte) []byte {
	digest := sha256.Sum256(append([]byte{0}, value...))
	return digest[:]
}

func merkleNodeHash(left, right []byte) []byte {
	value := make([]byte, 1, 1+len(left)+len(right))
	value[0] = 1
	value = append(value, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return slices.Clone(leaves[0])
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	return merkleNodeHash(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

func merkleInclusionProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(merkleInclusionProof(leaves[:k], index), merkleRoot(leaves[k:]))
	}
	return append(merkleInclusionProof(leaves[k:], index-k), merkleRoot(leaves[:k]))
}

func merkleConsistencyProof(leaves [][]byte, oldSize int) [][]byte {
	if oldSize <= 0 || oldSize >= len(leaves) {
		return nil
	}
	return merkleConsistencySubproof(leaves, oldSize, true)
}

func merkleConsistencySubproof(leaves [][]byte, oldSize int, complete bool) [][]byte {
	if oldSize == len(leaves) {
		if complete {
			return nil
		}
		return [][]byte{merkleRoot(leaves)}
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if oldSize <= k {
		return append(merkleConsistencySubproof(leaves[:k], oldSize, complete), merkleRoot(leaves[k:]))
	}
	return append(merkleConsistencySubproof(leaves[k:], oldSize-k, false), merkleRoot(leaves[:k]))
}

func largestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}

func encodeProof(values [][]byte) []string {
	encoded := make([]string, len(values))
	for index, value := range values {
		encoded[index] = hex.EncodeToString(value)
	}
	return encoded
}

type latestLeaf struct {
	key   [sha256.Size]byte
	value []byte
}

func latestMap(values []ledgerValue) ([]byte, map[string][]string) {
	leaves := make([]latestLeaf, len(values))
	for index, value := range values {
		keyBytes, _ := hex.DecodeString(value.subjectDigest)
		copy(leaves[index].key[:], keyBytes)
		sequence := make([]byte, 8)
		binary.BigEndian.PutUint64(sequence, value.sequence)
		preimage, _ := hex.DecodeString(value.preimageHash)
		envelope, _ := hex.DecodeString(value.envelopeHash)
		encoded := append([]byte{3}, keyBytes...)
		encoded = append(encoded, sequence...)
		encoded = append(encoded, preimage...)
		encoded = append(encoded, envelope...)
		digest := sha256.Sum256(encoded)
		leaves[index].value = digest[:]
	}
	root := latestSubtree(leaves, 0)
	proofs := make(map[string][]string, len(leaves))
	for _, leaf := range leaves {
		nodes := latestProof(leaves, leaf.key, 0)
		slices.Reverse(nodes)
		proofs[hex.EncodeToString(leaf.key[:])] = encodeProof(nodes)
	}
	return root, proofs
}

func latestSubtree(leaves []latestLeaf, depth int) []byte {
	if len(leaves) == 0 {
		return make([]byte, sha256.Size)
	}
	if depth == sha256.Size*8 {
		return slices.Clone(leaves[0].value)
	}
	left, right := splitLatestLeaves(leaves, depth)
	return latestNode(latestSubtree(left, depth+1), latestSubtree(right, depth+1))
}

func latestProof(leaves []latestLeaf, key [sha256.Size]byte, depth int) [][]byte {
	if depth == sha256.Size*8 {
		return nil
	}
	left, right := splitLatestLeaves(leaves, depth)
	if latestKeyBit(key, depth) == 0 {
		return append([][]byte{latestSubtree(right, depth+1)}, latestProof(left, key, depth+1)...)
	}
	return append([][]byte{latestSubtree(left, depth+1)}, latestProof(right, key, depth+1)...)
}

func splitLatestLeaves(leaves []latestLeaf, depth int) ([]latestLeaf, []latestLeaf) {
	left := make([]latestLeaf, 0, len(leaves))
	right := make([]latestLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		if latestKeyBit(leaf.key, depth) == 0 {
			left = append(left, leaf)
		} else {
			right = append(right, leaf)
		}
	}
	return left, right
}

func latestKeyBit(key [sha256.Size]byte, depth int) byte {
	return (key[depth/8] >> uint(7-depth%8)) & 1
}

func latestNode(left, right []byte) []byte {
	value := append([]byte{4}, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}
