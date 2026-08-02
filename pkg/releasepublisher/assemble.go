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

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
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
	packageSubject              releasecontract.SigningSubjectV1
	rootInput                   releasecontract.RootDelegationInput
	rootPreimage                []byte
	rootSubject                 releasecontract.SigningSubjectV1
	policyInput                 releasecontract.SourcePolicyInput
	policyPreimage              []byte
	policySubject               releasecontract.SigningSubjectV1
	revocationInput             releasecontract.RevocationInput
	revocationPreimage          []byte
	revocationSubject           releasecontract.SigningSubjectV1
	metadata                    releasecontract.ReleaseMetadataV8
	metadataBytes               []byte
	metadataPreimage            []byte
	metadataSubject             releasecontract.SigningSubjectV1
	releaseMetadataRef          string
	packageArtifactRef          string
	packageSignatureRef         string
	releaseMetadataSignatureRef string
}

type signedDocument struct {
	subject   releasecontract.SigningSubjectV1
	preimage  []byte
	keyID     string
	signature string
}

type signedPrimary struct {
	prepared                  preparedRelease
	signedPackage             []byte
	root                      releasecontract.RootDelegationV1
	rootBytes                 []byte
	policy                    releasecontract.SourcePolicyV2
	policyBytes               []byte
	revocation                releasecontract.RevocationV2
	revocationBytes           []byte
	metadataSignature         []byte
	policyPointerInput        releasecontract.ReleasePointerInput
	policyPointerPreimage     []byte
	policyPointerSubject      releasecontract.SigningSubjectV1
	revocationPointerInput    releasecontract.ReleasePointerInput
	revocationPointerPreimage []byte
	revocationPointerSubject  releasecontract.SigningSubjectV1
}

type signedPointers struct {
	primary                signedPrimary
	policyPointer          releasecontract.SourcePolicyPointerV1
	policyPointerBytes     []byte
	revocationPointer      releasecontract.RevocationPointerV1
	revocationPointerBytes []byte
	documents              []signedDocument
	ledger                 ledgerDraft
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
	checkpointRequest, err := NewExternalSignerRequest(
		releasecontract.SigningUsageLedgerCheckpoint,
		config.SigningLedger.KeyID,
		prepared.rootSubject,
		pointers.ledger.checkpointPreimage,
	)
	if err != nil {
		return assemblyResult{}, err
	}
	if pending := pendingRequests([]ExternalSignerRequestV1{checkpointRequest}, responses); len(pending) != 0 {
		return assemblyResult{Phase: "ledger_checkpoint_signature", Pending: pending}, nil
	}
	checkpointSignature, err := signatureFor(checkpointRequest, responses)
	if err != nil {
		return assemblyResult{}, err
	}
	checkpoint, checkpointBytes, err := finalizeLedgerCheckpoint(config, pointers.ledger, checkpointSignature)
	if err != nil {
		return assemblyResult{}, err
	}
	receiptDrafts, receiptRequests, err := prepareLedgerReceipts(config, pointers.ledger, checkpoint, checkpointBytes)
	if err != nil {
		return assemblyResult{}, err
	}
	if pending := pendingRequests(receiptRequests, responses); len(pending) != 0 {
		return assemblyResult{Phase: "ledger_receipt_signatures", Pending: pending}, nil
	}
	return buildCompleteAssembly(config, pointers, checkpoint, checkpointBytes, receiptDrafts, receiptRequests, responses)
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
		SourceID: config.SourceID, RootEpoch: "1", PreviousRootEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDelegationSHA256: releasecontract.GenesisPreviousDocumentSHA256,
		GeneratedAt:              config.GeneratedAt, ExpiresAt: config.ExpiresAt,
		DelegatedKeys: []releasecontract.RootDelegatedKey{{
			Algorithm: releasecontract.SignatureAlgorithmEd25519, KeyID: config.Signing.KeyID, PublicKey: config.Signing.PublicKey,
			Usages: []releasecontract.DelegatedKeyUsage{
				releasecontract.DelegatedKeyUsagePackage, releasecontract.DelegatedKeyUsageReleaseMetadata,
				releasecontract.DelegatedKeyUsageHostCapabilityContract, releasecontract.DelegatedKeyUsageRevocation,
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
		SchemaVersion: releasecontract.SourcePolicySchemaVersion,
		SourceID:      config.SourceID, Channel: config.Channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
		SourceType: config.SourceType, SourceClass: config.SourceClass, AllowedPublishers: []string{publisherID},
		AllowedArtifactHosts: slices.Clone(config.AllowedArtifactHosts),
		ActiveKeys: releasecontract.SourcePolicyActiveKeys{
			Package: []string{config.Signing.KeyID}, ReleaseMetadata: []string{config.Signing.KeyID},
			HostCapabilityContract: []string{config.Signing.KeyID}, SourcePolicyPointer: []string{config.Signing.KeyID},
			Revocation: []string{config.Signing.KeyID}, RevocationPointer: []string{config.Signing.KeyID},
		},
		CapabilityPublisherScopes: capabilityScopes(config.Signing.KeyID, publisherID, config.HostRequirements),
		RequireSignature:          true, InstallPolicy: "allow", UnsignedPolicy: "block", DowngradePolicy: "block",
		MinimumRevocationEpoch: "1", Limits: releasecontract.PersonalMaintainerSourcePolicyLimits(),
		GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
	}
	policyPreimage, err := releasecontract.SourcePolicySigningPreimage(policyInput)
	if err != nil {
		return preparedRelease{}, err
	}
	revocationInput := releasecontract.RevocationInput{
		SchemaVersion: releasecontract.RevocationSchemaVersion,
		SourceID:      config.SourceID, Channel: config.Channel, Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch,
		PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256, RootEpoch: "1",
		GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, RevokedKeyIDs: []string{},
		RevokedReleases: []releasecontract.RevokedRelease{}, KeyID: config.Signing.KeyID,
	}
	revocationPreimage, err := releasecontract.RevocationSigningPreimage(revocationInput)
	if err != nil {
		return preparedRelease{}, err
	}
	metadata := releasecontract.ReleaseMetadataV8{
		SchemaVersion: metadataSchemaVersion(pkg.Manifest.Plugin.UIProtocolVersion), SourceID: config.SourceID,
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
		Compatibility: releasecontract.ReleaseCompatibility{
			MinReDevPluginVersion: config.MinReDevPluginVersion, MinRuntimeVersion: pkg.Manifest.Plugin.MinRuntimeVersion,
			UIProtocolVersion: pkg.Manifest.Plugin.UIProtocolVersion,
		},
		HostRequirements: cloneHostRequirements(config.HostRequirements),
		ReleaseEvidence:  &releasecontract.ReleaseEvidence{GeneratedAt: config.GeneratedAt},
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
	metadataDigest := sha256Hex(metadataBytes)
	return preparedRelease{
		pkg: pkg, packageInput: packageInput, packagePreimage: packagePreimage,
		packageSubject: releaseSubject(config, pkg, releasecontract.SigningSubjectUsagePackage, strings.TrimPrefix(pkg.PackageHash, "sha256:")),
		rootInput:      rootInput, rootPreimage: rootPreimage,
		rootSubject: releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRootDelegation, SourceID: config.SourceID, RootEpoch: "1"},
		policyInput: policyInput, policyPreimage: policyPreimage,
		policySubject:   epochSubject(config, releasecontract.SigningSubjectUsageSourcePolicy),
		revocationInput: revocationInput, revocationPreimage: revocationPreimage,
		revocationSubject: epochSubject(config, releasecontract.SigningSubjectUsageRevocation),
		metadata:          metadata, metadataBytes: metadataBytes, metadataPreimage: metadataPreimage,
		metadataSubject:    releaseSubject(config, pkg, releasecontract.SigningSubjectUsageReleaseMetadata, metadataDigest),
		releaseMetadataRef: metadataRef, packageArtifactRef: packageArtifactRef,
		packageSignatureRef: packageSignatureRef, releaseMetadataSignatureRef: metadataSignatureRef,
	}, nil
}

func requestsForPrimary(config ConfigV1, prepared preparedRelease) ([]ExternalSignerRequestV1, error) {
	inputs := []struct {
		usage    releasecontract.SigningUsage
		key      string
		subject  releasecontract.SigningSubjectV1
		preimage []byte
	}{
		{releasecontract.SigningUsageRootDelegation, config.Root.KeyID, prepared.rootSubject, prepared.rootPreimage},
		{releasecontract.SigningUsagePackage, config.Signing.KeyID, prepared.packageSubject, prepared.packagePreimage},
		{releasecontract.SigningUsageReleaseMetadata, config.Signing.KeyID, prepared.metadataSubject, prepared.metadataPreimage},
		{releasecontract.SigningUsageSourcePolicy, config.Signing.KeyID, prepared.policySubject, prepared.policyPreimage},
		{releasecontract.SigningUsageRevocation, config.Signing.KeyID, prepared.revocationSubject, prepared.revocationPreimage},
	}
	requests := make([]ExternalSignerRequestV1, 0, len(inputs))
	for _, input := range inputs {
		request, err := NewExternalSignerRequest(input.usage, input.key, input.subject, input.preimage)
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
		SchemaVersion: releasecontract.SourcePolicyPointerSchemaVersion, SourceID: config.SourceID, Channel: config.Channel,
		Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch, PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256,
		Ref: policyRef, DocumentSHA256: sha256Hex(policyBytes), GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
	}
	revocationPointerInput := releasecontract.ReleasePointerInput{
		SchemaVersion: releasecontract.RevocationPointerSchemaVersion, SourceID: config.SourceID, Channel: config.Channel,
		Epoch: "1", PreviousEpoch: releasecontract.GenesisPreviousEpoch, PreviousDocumentSHA256: releasecontract.GenesisPreviousDocumentSHA256,
		Ref: revocationRef, DocumentSHA256: sha256Hex(revocationBytes), GeneratedAt: config.GeneratedAt, ExpiresAt: config.ExpiresAt, KeyID: config.Signing.KeyID,
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
		policyPointerSubject:   epochSubject(config, releasecontract.SigningSubjectUsageSourcePolicyPointer),
		revocationPointerInput: revocationPointerInput, revocationPointerPreimage: revocationPointerPreimage,
		revocationPointerSubject: epochSubject(config, releasecontract.SigningSubjectUsageRevocationPointer),
	}, nil
}

func requestsForPointers(config ConfigV1, primary signedPrimary) ([]ExternalSignerRequestV1, error) {
	policy, err := NewExternalSignerRequest(releasecontract.SigningUsageSourcePolicyPointer, config.Signing.KeyID, primary.policyPointerSubject, primary.policyPointerPreimage)
	if err != nil {
		return nil, err
	}
	revocation, err := NewExternalSignerRequest(releasecontract.SigningUsageRevocationPointer, config.Signing.KeyID, primary.revocationPointerSubject, primary.revocationPointerPreimage)
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
	primaryRequests, err := requestsForPrimary(config, primary.prepared)
	if err != nil {
		return signedPointers{}, err
	}
	primarySignatures := map[releasecontract.SigningUsage]string{}
	for _, request := range primaryRequests {
		primarySignatures[request.Usage] = responses[request.RequestID]
	}
	documents := []signedDocument{
		{primary.prepared.rootSubject, primary.prepared.rootPreimage, config.Root.KeyID, primarySignatures[releasecontract.SigningUsageRootDelegation]},
		{primary.policyPointerSubject, primary.policyPointerPreimage, config.Signing.KeyID, base64.StdEncoding.EncodeToString(policySignature)},
		{primary.prepared.policySubject, primary.prepared.policyPreimage, config.Signing.KeyID, primarySignatures[releasecontract.SigningUsageSourcePolicy]},
		{primary.revocationPointerSubject, primary.revocationPointerPreimage, config.Signing.KeyID, base64.StdEncoding.EncodeToString(revocationSignature)},
		{primary.prepared.revocationSubject, primary.prepared.revocationPreimage, config.Signing.KeyID, primarySignatures[releasecontract.SigningUsageRevocation]},
		{primary.prepared.metadataSubject, primary.prepared.metadataPreimage, config.Signing.KeyID, primarySignatures[releasecontract.SigningUsageReleaseMetadata]},
		{primary.prepared.packageSubject, primary.prepared.packagePreimage, config.Signing.KeyID, primarySignatures[releasecontract.SigningUsagePackage]},
	}
	ledger, err := prepareLedger(config, documents)
	if err != nil {
		return signedPointers{}, err
	}
	return signedPointers{primary: primary, policyPointer: policyPointer, policyPointerBytes: policyPointerBytes, revocationPointer: revocationPointer, revocationPointerBytes: revocationPointerBytes, documents: documents, ledger: ledger}, nil
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

func releaseSubject(config ConfigV1, pkg pluginpkg.Package, usage releasecontract.SigningSubjectUsage, identity string) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{
		SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: usage, SourceID: config.SourceID, Channel: config.Channel,
		PublisherID: pkg.Manifest.Publisher.PublisherID, PluginID: pkg.Manifest.PluginID(), Version: pkg.Manifest.Version(), ArtifactIdentitySHA256: identity,
	}
}

func epochSubject(config ConfigV1, usage releasecontract.SigningSubjectUsage) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: usage, SourceID: config.SourceID, Channel: config.Channel, Epoch: "1"}
}

func capabilityScopes(keyID, publisherID string, requirements []releasecontract.ReleaseHostRequirement) []releasecontract.SourcePolicyCapabilityPublisherScope {
	publishers := []string{publisherID}
	for _, requirement := range requirements {
		for _, capability := range requirement.RequiredCapabilityContracts {
			publishers = append(publishers, capability.Contract.PublisherID)
		}
	}
	slices.Sort(publishers)
	publishers = slices.Compact(publishers)
	return []releasecontract.SourcePolicyCapabilityPublisherScope{{KeyID: keyID, AllowedPublishers: publishers}}
}

func cloneHostRequirements(values []releasecontract.ReleaseHostRequirement) []releasecontract.ReleaseHostRequirement {
	result := make([]releasecontract.ReleaseHostRequirement, len(values))
	for index, value := range values {
		result[index] = value
		result[index].RequiredCapabilityContracts = slices.Clone(value.RequiredCapabilityContracts)
	}
	return result
}

func metadataSchemaVersion(protocol string) string {
	if protocol == "plugin-ui-v7" {
		return releasecontract.ReleaseMetadataSchemaVersionV8
	}
	return ""
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("time is not canonical UTC RFC3339")
	}
	return parsed, nil
}

func prefixedSHA256(value string) string { return "sha256:" + strings.TrimPrefix(value, "sha256:") }
