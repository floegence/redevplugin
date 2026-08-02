package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func writeAssembly(output string, assembly assemblyResult) error {
	if !assembly.Complete || len(assembly.Files) == 0 {
		return ErrWorkspaceIncomplete
	}
	files := make(map[string][]byte, len(assembly.Files)+2)
	for locator, value := range assembly.Files {
		files[locator] = slices.Clone(value)
	}
	rootRaw, _ := json.Marshal(assembly.ReleaseRef.Root)
	ledgerRaw, _ := json.Marshal(assembly.ReleaseRef.SigningLedger)
	const rootLocator = "anchors/root.public.json"
	const ledgerLocator = "anchors/signing-ledger.public.json"
	files[rootLocator] = rootRaw
	files[ledgerLocator] = ledgerRaw
	locators := make([]string, 0, len(files))
	for locator := range files {
		locators = append(locators, locator)
	}
	sort.Strings(locators)
	published := make([]PublishedFileV1, 0, len(locators))
	usedNames := map[string]bool{}
	for _, locator := range locators {
		name := outputAssetName(assembly.ReleaseRef, locator)
		if usedNames[name] {
			return ErrInvalidWorkspace
		}
		usedNames[name] = true
		value := files[locator]
		published = append(published, PublishedFileV1{Locator: locator, AssetName: name, SHA256: sha256Hex(value), Size: int64(len(value))})
		if err := writeImmutableFile(filepath.Join(output, name), value, 0o644); err != nil {
			return err
		}
	}
	assembly.ReleaseRef.Files = published
	referenceRaw, err := json.MarshalIndent(assembly.ReleaseRef, "", "  ")
	if err != nil {
		return err
	}
	referenceName := releaseRefAssetName(assembly.ReleaseRef.ReleaseRef.PluginID, assembly.ReleaseRef.ReleaseRef.Version)
	return writeImmutableFile(filepath.Join(output, referenceName), append(referenceRaw, '\n'), 0o644)
}

func VerifyOutput(ctx context.Context, output string) error {
	_, err := VerifyAndInspectOutput(ctx, output)
	return err
}

func VerifyAndInspectOutput(ctx context.Context, output string) (VerifiedOutputV1, error) {
	var verified VerifiedOutputV1
	if err := verifyOutputSnapshot(ctx, output, &verified); err != nil {
		return VerifiedOutputV1{}, err
	}
	return verified, nil
}

func verifyOutputSnapshot(ctx context.Context, output string, verified *VerifiedOutputV1) error {
	matches, err := filepath.Glob(filepath.Join(output, "*.release-ref.json"))
	if err != nil || len(matches) != 1 {
		return ErrInvalidWorkspace
	}
	var reference PublisherReleaseRefV1
	if err := readClosedJSONFile(matches[0], &reference, 1<<20); err != nil {
		return err
	}
	if reference.SchemaVersion != ReleaseRefSchemaVersion || len(reference.Files) == 0 {
		return ErrInvalidWorkspace
	}
	byLocator := make(map[string][]byte, len(reference.Files))
	for _, file := range reference.Files {
		if file.Locator == "" || file.AssetName == "" || file.Size <= 0 || !isSHA256(file.SHA256) || byLocator[file.Locator] != nil ||
			filepath.Base(file.AssetName) != file.AssetName {
			return ErrInvalidWorkspace
		}
		raw, err := os.ReadFile(filepath.Join(output, file.AssetName))
		if err != nil || int64(len(raw)) != file.Size || sha256Hex(raw) != file.SHA256 {
			return ErrInvalidWorkspace
		}
		byLocator[file.Locator] = raw
	}
	rootKey, err := decodePublicKey(reference.Root)
	if err != nil {
		return err
	}
	ledgerKey, err := decodePublicKey(reference.SigningLedger.PublicKeyV1)
	if err != nil {
		return err
	}
	rootBytes := byLocator[fmt.Sprintf("sources/%s/root/current.json", reference.ReleaseRef.SourceID)]
	root, err := releasecontract.DecodeRootDelegation(rootBytes)
	if err != nil {
		return err
	}
	verifier := releasecontract.Ed25519PublicKeyVerifier{reference.Root.KeyID: rootKey, reference.SigningLedger.KeyID: ledgerKey}
	if err := releasecontract.VerifyRootDelegation(root, verifier); err != nil {
		return err
	}
	for _, delegated := range root.DelegatedKeys {
		key, decodeErr := base64.StdEncoding.DecodeString(delegated.PublicKey)
		if decodeErr != nil || len(key) != ed25519.PublicKeySize {
			return ErrInvalidWorkspace
		}
		verifier[delegated.KeyID] = ed25519.PublicKey(key)
	}
	policyPointerBytes := byLocator[fmt.Sprintf("sources/%s/%s/policy/current.json", reference.ReleaseRef.SourceID, reference.ReleaseRef.Channel)]
	policyPointer, err := releasecontract.DecodeSourcePolicyPointer(policyPointerBytes)
	if err != nil || sha256Hex(byLocator[policyPointer.Ref]) != policyPointer.DocumentSHA256 {
		return ErrInvalidWorkspace
	}
	if err := releasecontract.VerifySourcePolicyPointer(policyPointer, verifier); err != nil {
		return err
	}
	policy, err := releasecontract.DecodeSourcePolicy(byLocator[policyPointer.Ref])
	if err != nil {
		return err
	}
	if err := releasecontract.VerifySourcePolicy(policy, verifier); err != nil {
		return err
	}
	revocationPointerBytes := byLocator[fmt.Sprintf("sources/%s/%s/revocation/current.json", reference.ReleaseRef.SourceID, reference.ReleaseRef.Channel)]
	revocationPointer, err := releasecontract.DecodeRevocationPointer(revocationPointerBytes)
	if err != nil || sha256Hex(byLocator[revocationPointer.Ref]) != revocationPointer.DocumentSHA256 {
		return ErrInvalidWorkspace
	}
	if err := releasecontract.VerifyRevocationPointer(revocationPointer, verifier); err != nil {
		return err
	}
	revocation, err := releasecontract.DecodeRevocation(byLocator[revocationPointer.Ref])
	if err != nil {
		return err
	}
	if err := releasecontract.VerifyRevocation(revocation, verifier); err != nil {
		return err
	}
	metadataBytes := byLocator[reference.ReleaseRef.ReleaseMetadataRef]
	if sha256Hex(metadataBytes) != reference.ReleaseRef.ReleaseMetadataSHA256 {
		return ErrInvalidWorkspace
	}
	metadata, err := releasecontract.DecodeReleaseMetadata(metadataBytes)
	if err != nil {
		return err
	}
	metadataSignature := byLocator[metadata.ReleaseMetadataSignature.SignatureRef]
	if err := releasecontract.VerifyReleaseMetadata(reference.ReleaseRef.Channel, metadata, metadataSignature, verifier); err != nil {
		return err
	}
	packageSignature, err := releasecontract.DecodePackageSignature(
		byLocator[metadata.PackageSignature.SignatureBundleRef],
		releasecontract.PackageVerificationContext{SourceID: reference.ReleaseRef.SourceID, Channel: reference.ReleaseRef.Channel, Version: reference.ReleaseRef.Version},
	)
	if err != nil {
		return err
	}
	if err := releasecontract.VerifyPackageSignature(releasecontract.PackageVerificationContext{SourceID: reference.ReleaseRef.SourceID, Channel: reference.ReleaseRef.Channel, Version: reference.ReleaseRef.Version}, packageSignature, verifier); err != nil {
		return err
	}
	packageBytes := byLocator[metadata.DistributionRef.ArtifactRef]
	pkg, err := pluginpkg.Read(ctx, bytes.NewReader(packageBytes), int64(len(packageBytes)), pluginpkg.DefaultReadLimits())
	if err != nil || pkg.PackageSignature == nil {
		return ErrInvalidWorkspace
	}
	if pkg.Manifest.Publisher.PublisherID != reference.ReleaseRef.PublisherID || pkg.Manifest.PluginID() != reference.ReleaseRef.PluginID || pkg.Manifest.Version() != reference.ReleaseRef.Version ||
		pkg.PackageHash != reference.ReleaseRef.ExpectedHashes.PackageSHA256 || pkg.ManifestHash != reference.ReleaseRef.ExpectedHashes.ManifestSHA256 ||
		pkg.EntriesHash != reference.ReleaseRef.ExpectedHashes.EntriesSHA256 || pkg.PackageSignature.Signature != packageSignature.Signature {
		return ErrInvalidWorkspace
	}
	expectedSubjects := []releasecontract.SigningSubjectV1{
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRootDelegation, SourceID: root.SourceID, RootEpoch: root.RootEpoch},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageSourcePolicyPointer, SourceID: policy.SourceID, Channel: policy.Channel, Epoch: policy.Epoch},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageSourcePolicy, SourceID: policy.SourceID, Channel: policy.Channel, Epoch: policy.Epoch},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRevocationPointer, SourceID: revocation.SourceID, Channel: revocation.Channel, Epoch: revocation.Epoch},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRevocation, SourceID: revocation.SourceID, Channel: revocation.Channel, Epoch: revocation.Epoch},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageReleaseMetadata, SourceID: metadata.SourceID, Channel: reference.ReleaseRef.Channel, PublisherID: metadata.PublisherID, PluginID: metadata.PluginID, Version: metadata.Version, ArtifactIdentitySHA256: reference.ReleaseRef.ReleaseMetadataSHA256},
		{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsagePackage, SourceID: metadata.SourceID, Channel: reference.ReleaseRef.Channel, PublisherID: metadata.PublisherID, PluginID: metadata.PluginID, Version: metadata.Version, ArtifactIdentitySHA256: strings.TrimPrefix(pkg.PackageHash, "sha256:")},
	}
	for _, subject := range expectedSubjects {
		digest, err := releasecontract.SigningSubjectIdentitySHA256(subject)
		if err != nil {
			return err
		}
		evidenceRef := fmt.Sprintf("sources/%s/signing-ledger/evidence/%s.json", reference.ReleaseRef.SourceID, digest)
		evidence, err := releasecontract.DecodeSigningLedgerEvidence(byLocator[evidenceRef])
		if err != nil {
			return err
		}
		receipt, err := releasecontract.DecodeSigningLedgerReceipt(byLocator[evidence.ReceiptRef])
		if err != nil || sha256Hex(byLocator[evidence.ReceiptRef]) != evidence.ReceiptSHA256 {
			return ErrInvalidWorkspace
		}
		checkpoint, err := releasecontract.DecodeSigningLedgerCheckpoint(byLocator[evidence.CheckpointRef])
		if err != nil || sha256Hex(byLocator[evidence.CheckpointRef]) != evidence.CheckpointSHA256 {
			return ErrInvalidWorkspace
		}
		inclusion, err := releasecontract.DecodeSigningLedgerInclusionProof(byLocator[evidence.InclusionProofRef])
		if err != nil || sha256Hex(byLocator[evidence.InclusionProofRef]) != evidence.InclusionProofSHA256 {
			return ErrInvalidWorkspace
		}
		latest, err := releasecontract.DecodeSigningLedgerLatestProof(byLocator[evidence.LatestProofRef])
		if err != nil || sha256Hex(byLocator[evidence.LatestProofRef]) != evidence.LatestProofSHA256 {
			return ErrInvalidWorkspace
		}
		if err := releasecontract.VerifySigningLedgerInclusion(receipt, inclusion, checkpoint, verifier); err != nil {
			return err
		}
		if err := releasecontract.VerifySigningLedgerLatest(receipt, latest, checkpoint, verifier); err != nil {
			return err
		}
	}
	presentation := pkg.Manifest.PresentationCatalog()
	presentationSHA256, err := manifest.PresentationCatalogSHA256(presentation)
	if err != nil {
		return err
	}
	*verified = VerifiedOutputV1{
		Presentation: presentation, ManifestSHA256: pkg.ManifestHash, PresentationSHA256: presentationSHA256,
	}
	return nil
}

func outputAssetName(reference PublisherReleaseRefV1, locator string) string {
	switch locator {
	case "anchors/root.public.json":
		return "root.public.json"
	case "anchors/signing-ledger.public.json":
		return "signing-ledger.public.json"
	case reference.ReleaseRef.ReleaseMetadataRef:
		return pluginSlug(reference.ReleaseRef.PluginID) + "-" + reference.ReleaseRef.Version + ".release.json"
	}
	if strings.HasSuffix(locator, "/package.redevplugin") {
		return pluginSlug(reference.ReleaseRef.PluginID) + "-" + reference.ReleaseRef.Version + ".redevplugin"
	}
	extension := ".json"
	if strings.HasSuffix(locator, ".sig") {
		extension = ".sig"
	}
	return "trust-" + sha256Hex([]byte(locator))[:20] + extension
}

func releaseRefAssetName(pluginID, version string) string {
	return pluginSlug(pluginID) + "-" + version + ".release-ref.json"
}

func pluginSlug(pluginID string) string {
	parts := strings.Split(pluginID, ".")
	return parts[len(parts)-1]
}

func writeImmutableFile(path string, value []byte, mode os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, value) {
			return nil
		}
		return ErrWorkspaceConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomic(path, value, mode)
}

func decodePublicKey(document PublicKeyV1) (ed25519.PublicKey, error) {
	if document.Algorithm != releasecontract.SignatureAlgorithmEd25519 || document.KeyID == "" {
		return nil, ErrInvalidWorkspace
	}
	key, err := base64.StdEncoding.DecodeString(document.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != document.PublicKey {
		return nil, ErrInvalidWorkspace
	}
	return ed25519.PublicKey(key), nil
}
