package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

type assemblyResult struct {
	Phase      string
	Pending    []ExternalSignerRequestV1
	Complete   bool
	Files      map[string][]byte
	ReleaseRef PublisherReleaseRefV1
}

type preparedRelease struct {
	pkg                         pluginpkg.Package
	packageInput                releasecontract.PackageSigningInput
	packagePreimage             []byte
	rootInput                   releasecontract.RootDelegationInput
	rootPreimage                []byte
	policyInput                 releasecontract.SourcePolicyInput
	policyPreimage              []byte
	revocationInput             releasecontract.RevocationInput
	revocationPreimage          []byte
	metadata                    releasecontract.ReleaseMetadata
	metadataBytes               []byte
	metadataPreimage            []byte
	releaseMetadataRef          string
	packageArtifactRef          string
	packageSignatureRef         string
	releaseMetadataSignatureRef string
}

type signedPrimary struct {
	prepared                  preparedRelease
	signedPackage             []byte
	root                      releasecontract.RootDelegationV1
	rootBytes                 []byte
	policy                    releasecontract.SourcePolicyV3
	policyBytes               []byte
	revocation                releasecontract.RevocationV3
	revocationBytes           []byte
	metadataSignature         []byte
	policyPointerInput        releasecontract.ReleasePointerInput
	policyPointerPreimage     []byte
	revocationPointerInput    releasecontract.ReleasePointerInput
	revocationPointerPreimage []byte
}

type signedPointers struct {
	primary                signedPrimary
	policyPointer          releasecontract.SourcePolicyPointerV2
	policyPointerBytes     []byte
	revocationPointer      releasecontract.RevocationPointerV2
	revocationPointerBytes []byte
}

func assemble(ctx context.Context, config ConfigV1, packageBytes []byte, responses map[string]string) (assemblyResult, error) {
	prepared, err := prepareRelease(ctx, config, packageBytes)
	if err != nil {
		return assemblyResult{}, err
	}
	primaryRequests, err := requestsForPrimary(config, prepared)
	if err != nil {
		return assemblyResult{}, err
	}
	if pending := pendingRequests(primaryRequests, responses); len(pending) != 0 {
		return assemblyResult{Phase: "primary_signatures", Pending: pending}, nil
	}
	primary, err := buildSignedPrimary(config, prepared, primaryRequests, responses)
	if err != nil {
		return assemblyResult{}, err
	}
	pointerRequests, err := requestsForPointers(config, primary)
	if err != nil {
		return assemblyResult{}, err
	}
	if pending := pendingRequests(pointerRequests, responses); len(pending) != 0 {
		return assemblyResult{Phase: "pointer_signatures", Pending: pending}, nil
	}
	pointers, err := buildSignedPointers(config, primary, pointerRequests, responses)
	if err != nil {
		return assemblyResult{}, err
	}
	return buildCompleteAssembly(config, pointers, primaryRequests, responses)
}

func prepareRelease(ctx context.Context, config ConfigV1, packageBytes []byte) (preparedRelease, error) {
	pkg, err := readUnsignedPackage(ctx, packageBytes)
	if err != nil {
		return preparedRelease{}, err
	}
	publisherID := pkg.Manifest.Publisher.PublisherID
	pluginID := pkg.Manifest.PluginID()
	version := pkg.Manifest.Version()
	base := fmt.Sprintf("plugins/%s/%s/%s", publisherID, pluginID, version)
	packageArtifactRef := base + "/package.redevplugin"
	metadataRef := base + "/release.json"
	metadataSignatureRef := metadataRef + ".sig"
	packageSignatureRef := base + "/package.sig"
	packageInput := releasecontract.PackageSigningInput{
		SourceID: config.SourceID, Channel: config.Channel, Version: version,
		Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: config.Signing.KeyID,
		PublisherID: publisherID, PluginID: pluginID,
		PackageHash: prefixedSHA256(pkg.PackageHash), ManifestHash: prefixedSHA256(pkg.ManifestHash),
		EntriesHash: prefixedSHA256(pkg.EntriesHash), SignedAt: config.GeneratedAt,
	}
	packagePreimage, err := releasecontract.PackageSigningPreimage(packageInput)
	if err != nil {
		return preparedRelease{}, err
	}
	generatedAt, err := parseCanonicalTime(config.GeneratedAt)
	if err != nil {
		return preparedRelease{}, ErrInvalidPublisherConfig
	}
	rootInput := releasecontract.RootDelegationInput{
		SourceID:    config.SourceID,
		RootEpoch:   "1",
		GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt,
		DelegatedKeys: []releasecontract.RootDelegatedKey{{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: config.Signing.KeyID, PublicKey: config.Signing.PublicKey,
			Usages: []releasecontract.DelegatedKeyUsage{
				releasecontract.DelegatedKeyUsagePackage, releasecontract.DelegatedKeyUsageReleaseMetadata,
				releasecontract.DelegatedKeyUsageRevocation,
				releasecontract.DelegatedKeyUsageRevocationPointer, releasecontract.DelegatedKeyUsageSourcePolicy,
				releasecontract.DelegatedKeyUsageSourcePolicyPointer,
			},
			Channels: []string{config.Channel}, ValidFrom: generatedAt.Add(-time.Hour).Format(time.RFC3339Nano), ValidUntil: config.ExpiresAt,
		}},
		KeyID: config.Root.KeyID,
	}
	rootPreimage, err := releasecontract.RootDelegationSigningPreimage(rootInput)
	if err != nil {
		return preparedRelease{}, err
	}
	policyInput := releasecontract.SourcePolicyInput{
		SourceID: config.SourceID, Channel: config.Channel, Epoch: "1", RootEpoch: "1",
		SourceType: config.SourceType, SourceClass: config.SourceClass, AllowedPublishers: []string{publisherID},
		AllowedArtifactHosts: slices.Clone(config.AllowedArtifactHosts),
		ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			Package: []string{config.Signing.KeyID}, ReleaseMetadata: []string{config.Signing.KeyID},
			SourcePolicyPointer: []string{config.Signing.KeyID},
			Revocation:          []string{config.Signing.KeyID}, RevocationPointer: []string{config.Signing.KeyID},
		},
		RequireSignature: true, InstallPolicy: "allow", UnsignedPolicy: "block", DowngradePolicy: "block",
		MinimumRevocationEpoch: "1", Limits: releasecontract.PersonalMaintainerSourcePolicyLimits(),
		GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
	}
	policyPreimage, err := releasecontract.SourcePolicySigningPreimage(policyInput)
	if err != nil {
		return preparedRelease{}, err
	}
	revocationInput := releasecontract.RevocationInput{
		SourceID: config.SourceID, Channel: config.Channel, Epoch: "1", RootEpoch: "1",
		GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, RevokedKeyIDs: []string{},
		RevokedReleases: []releasecontract.RevokedRelease{}, KeyID: config.Signing.KeyID,
	}
	revocationPreimage, err := releasecontract.RevocationSigningPreimage(revocationInput)
	if err != nil {
		return preparedRelease{}, err
	}
	metadata := releasecontract.ReleaseMetadata{
		SchemaVersion: releasecontract.ReleaseMetadataSchemaVersion, SourceID: config.SourceID,
		ReleaseMetadataRef: metadataRef, PublisherID: publisherID, PluginID: pluginID, Version: version,
		DistributionRef: releasecontract.ReleaseDistributionRef{Distribution: config.Distribution, ArtifactRef: packageArtifactRef},
		Hashes:          releasecontract.ReleasePackageHashSet{PackageSHA256: pkg.PackageHash, ManifestSHA256: pkg.ManifestHash, EntriesSHA256: pkg.EntriesHash},
		ReleaseMetadataSignature: releasecontract.ReleaseMetadataSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: config.Signing.KeyID, SignatureRef: metadataSignatureRef,
			SourcePolicyEpoch: "1", RevocationEpoch: "1",
		},
		PackageSignature: releasecontract.PackageReleaseSignatureRef{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: config.Signing.KeyID, SignatureBundleRef: packageSignatureRef,
			SourcePolicyEpoch: "1", RevocationEpoch: "1",
		},
		ReleaseEvidence: &releasecontract.ReleaseEvidence{GeneratedAt: config.GeneratedAt},
	}
	metadata, err = releasecontract.BuildReleaseMetadata(metadata)
	if err != nil {
		return preparedRelease{}, err
	}
	metadataBytes, err := releasecontract.CanonicalReleaseMetadata(metadata)
	if err != nil {
		return preparedRelease{}, err
	}
	metadataPreimage, err := releasecontract.ReleaseMetadataSigningPreimage(config.Channel, metadata)
	if err != nil {
		return preparedRelease{}, err
	}
	return preparedRelease{
		pkg: pkg, packageInput: packageInput, packagePreimage: packagePreimage,
		rootInput: rootInput, rootPreimage: rootPreimage,
		policyInput: policyInput, policyPreimage: policyPreimage,
		revocationInput: revocationInput, revocationPreimage: revocationPreimage,
		metadata: metadata, metadataBytes: metadataBytes, metadataPreimage: metadataPreimage,
		releaseMetadataRef: metadataRef, packageArtifactRef: packageArtifactRef,
		packageSignatureRef: packageSignatureRef, releaseMetadataSignatureRef: metadataSignatureRef,
	}, nil
}

func requestsForPrimary(config ConfigV1, prepared preparedRelease) ([]ExternalSignerRequestV1, error) {
	inputs := []struct {
		usage    releasecontract.SigningUsage
		key      string
		preimage []byte
	}{
		{releasecontract.SigningUsageRootDelegation, config.Root.KeyID, prepared.rootPreimage},
		{releasecontract.SigningUsagePackage, config.Signing.KeyID, prepared.packagePreimage},
		{releasecontract.SigningUsageReleaseMetadata, config.Signing.KeyID, prepared.metadataPreimage},
		{releasecontract.SigningUsageSourcePolicy, config.Signing.KeyID, prepared.policyPreimage},
		{releasecontract.SigningUsageRevocation, config.Signing.KeyID, prepared.revocationPreimage},
	}
	requests := make([]ExternalSignerRequestV1, 0, len(inputs))
	for _, input := range inputs {
		request, err := NewExternalSignerRequest(input.usage, input.key, input.preimage)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, nil
}

func buildSignedPrimary(config ConfigV1, prepared preparedRelease, requests []ExternalSignerRequestV1, responses map[string]string) (signedPrimary, error) {
	rootSignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageRootDelegation)
	packageSignatureBytes, _ := signatureForUsage(requests, responses, releasecontract.SigningUsagePackage)
	metadataSignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageReleaseMetadata)
	policySignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageSourcePolicy)
	revocationSignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageRevocation)
	root, err := releasecontract.BuildRootDelegation(prepared.rootInput, rootSignature)
	if err != nil {
		return signedPrimary{}, err
	}
	policy, err := releasecontract.BuildSourcePolicy(prepared.policyInput, policySignature)
	if err != nil {
		return signedPrimary{}, err
	}
	revocation, err := releasecontract.BuildRevocation(prepared.revocationInput, revocationSignature)
	if err != nil {
		return signedPrimary{}, err
	}
	rootBytes, _ := releasecontract.CanonicalRootDelegation(root)
	policyBytes, _ := releasecontract.CanonicalSourcePolicy(policy)
	revocationBytes, _ := releasecontract.CanonicalRevocation(revocation)
	packageSignature, err := releasecontract.BuildPackageSignature(prepared.packageInput, packageSignatureBytes)
	if err != nil {
		return signedPrimary{}, err
	}
	prepared.pkg.PackageSignature = &pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion, Algorithm: packageSignature.Algorithm, KeyID: packageSignature.KeyID,
		PublisherID: packageSignature.PublisherID, PluginID: packageSignature.PluginID, PackageHash: prepared.pkg.PackageHash,
		ManifestHash: prepared.pkg.ManifestHash, EntriesHash: prepared.pkg.EntriesHash, Signature: packageSignature.Signature, SignedAt: packageSignature.SignedAt,
	}
	var packageBuffer bytes.Buffer
	if err := pluginpkg.WritePackage(context.Background(), &packageBuffer, prepared.pkg); err != nil {
		return signedPrimary{}, err
	}
	verifiers, _ := validateConfig(config)
	verifier := releasecontract.Ed25519PublicKeyVerifier(verifiers)
	if err := releasecontract.VerifyRootDelegation(root, verifier); err != nil {
		return signedPrimary{}, err
	}
	if err := releasecontract.VerifySourcePolicy(policy, verifier); err != nil {
		return signedPrimary{}, err
	}
	if err := releasecontract.VerifyRevocation(revocation, verifier); err != nil {
		return signedPrimary{}, err
	}
	if err := releasecontract.VerifyReleaseMetadata(config.Channel, prepared.metadata, metadataSignature, verifier); err != nil {
		return signedPrimary{}, err
	}
	if err := releasecontract.VerifyPackageSignature(releasecontract.PackageVerificationContext{SourceID: config.SourceID, Channel: config.Channel, Version: prepared.pkg.Manifest.Version()}, packageSignature, verifier); err != nil {
		return signedPrimary{}, err
	}
	policyRef := fmt.Sprintf("sources/%s/%s/policy/1.json", config.SourceID, config.Channel)
	revocationRef := fmt.Sprintf("sources/%s/%s/revocation/1.json", config.SourceID, config.Channel)
	policyPointerInput := releasecontract.ReleasePointerInput{
		SourceID: config.SourceID, Channel: config.Channel,
		Epoch: "1",
		Ref:   policyRef, DocumentSHA256: sha256Hex(policyBytes), GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
	}
	revocationPointerInput := releasecontract.ReleasePointerInput{
		SourceID: config.SourceID, Channel: config.Channel,
		Epoch: "1",
		Ref:   revocationRef, DocumentSHA256: sha256Hex(revocationBytes), GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
	}
	policyPointerPreimage, err := releasecontract.SourcePolicyPointerSigningPreimage(policyPointerInput)
	if err != nil {
		return signedPrimary{}, err
	}
	revocationPointerPreimage, err := releasecontract.RevocationPointerSigningPreimage(revocationPointerInput)
	if err != nil {
		return signedPrimary{}, err
	}
	return signedPrimary{
		prepared: prepared, signedPackage: packageBuffer.Bytes(), root: root, rootBytes: rootBytes,
		policy: policy, policyBytes: policyBytes, revocation: revocation, revocationBytes: revocationBytes,
		metadataSignature:  metadataSignature,
		policyPointerInput: policyPointerInput, policyPointerPreimage: policyPointerPreimage,
		revocationPointerInput: revocationPointerInput, revocationPointerPreimage: revocationPointerPreimage,
	}, nil
}

func requestsForPointers(config ConfigV1, primary signedPrimary) ([]ExternalSignerRequestV1, error) {
	policy, err := NewExternalSignerRequest(releasecontract.SigningUsageSourcePolicyPointer, config.Signing.KeyID, primary.policyPointerPreimage)
	if err != nil {
		return nil, err
	}
	revocation, err := NewExternalSignerRequest(releasecontract.SigningUsageRevocationPointer, config.Signing.KeyID, primary.revocationPointerPreimage)
	if err != nil {
		return nil, err
	}
	return []ExternalSignerRequestV1{policy, revocation}, nil
}

func buildSignedPointers(config ConfigV1, primary signedPrimary, requests []ExternalSignerRequestV1, responses map[string]string) (signedPointers, error) {
	policySignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageSourcePolicyPointer)
	revocationSignature, _ := signatureForUsage(requests, responses, releasecontract.SigningUsageRevocationPointer)
	policyPointer, err := releasecontract.BuildSourcePolicyPointer(primary.policyPointerInput, policySignature)
	if err != nil {
		return signedPointers{}, err
	}
	revocationPointer, err := releasecontract.BuildRevocationPointer(primary.revocationPointerInput, revocationSignature)
	if err != nil {
		return signedPointers{}, err
	}
	policyPointerBytes, _ := releasecontract.CanonicalSourcePolicyPointer(policyPointer)
	revocationPointerBytes, _ := releasecontract.CanonicalRevocationPointer(revocationPointer)
	keys, _ := validateConfig(config)
	verifier := releasecontract.Ed25519PublicKeyVerifier(keys)
	if err := releasecontract.VerifySourcePolicyPointer(policyPointer, verifier); err != nil {
		return signedPointers{}, err
	}
	if err := releasecontract.VerifyRevocationPointer(revocationPointer, verifier); err != nil {
		return signedPointers{}, err
	}
	return signedPointers{primary: primary, policyPointer: policyPointer, policyPointerBytes: policyPointerBytes, revocationPointer: revocationPointer, revocationPointerBytes: revocationPointerBytes}, nil
}

func pendingRequests(requests []ExternalSignerRequestV1, responses map[string]string) []ExternalSignerRequestV1 {
	pending := make([]ExternalSignerRequestV1, 0, len(requests))
	for _, request := range requests {
		if _, ok := responses[request.RequestID]; !ok {
			pending = append(pending, request)
		}
	}
	return pending
}

func signatureFor(request ExternalSignerRequestV1, responses map[string]string) ([]byte, error) {
	value, ok := responses[request.RequestID]
	if !ok {
		return nil, ErrWorkspaceIncomplete
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, ErrInvalidWorkspace
	}
	return decoded, nil
}

func signatureForUsage(requests []ExternalSignerRequestV1, responses map[string]string, usage releasecontract.SigningUsage) ([]byte, error) {
	for _, request := range requests {
		if request.Usage == usage {
			return signatureFor(request, responses)
		}
	}
	return nil, ErrWorkspaceIncomplete
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("time is not canonical UTC RFC3339")
	}
	return parsed, nil
}

func prefixedSHA256(value string) string { return "sha256:" + strings.TrimPrefix(value, "sha256:") }
