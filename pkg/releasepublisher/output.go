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
	files := make(map[string][]byte)
	for locator, value := range assembly.Files {
		files[locator] = slices.Clone(value)
	}
	rootRaw, _ := json.Marshal(assembly.ReleaseRef.Root)
	const rootLocator = "anchors/root.public.json"
	files[rootLocator] = rootRaw
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
	verified, _, err := inspectVerifiedOutput(ctx, output)
	return verified, err
}

// ExtractPresentationIcon writes the exact package-local image only after the
// complete release output has been re-verified. Existing targets are never
// replaced so a caller cannot mistake stale bytes for current evidence.
func ExtractPresentationIcon(ctx context.Context, output, destination string) (PresentationIconEvidenceV1, error) {
	verified, content, err := inspectVerifiedOutput(ctx, output)
	if err != nil {
		return PresentationIconEvidenceV1{}, err
	}
	if verified.PresentationIcon == nil {
		return PresentationIconEvidenceV1{}, ErrPresentationIconUnavailable
	}
	if err := writePresentationIconNoOverwrite(destination, content); err != nil {
		return PresentationIconEvidenceV1{}, err
	}
	return *verified.PresentationIcon, nil
}

func inspectVerifiedOutput(ctx context.Context, output string) (VerifiedOutputV1, []byte, error) {
	var verified VerifiedOutputV1
	var iconContent []byte
	if err := verifyOutputSnapshot(ctx, output, &verified, &iconContent); err != nil {
		return VerifiedOutputV1{}, nil, err
	}
	return verified, iconContent, nil
}

func verifyOutputSnapshot(ctx context.Context, output string, verified *VerifiedOutputV1, iconContent *[]byte) error {
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
	rootBytes := byLocator[fmt.Sprintf("sources/%s/root/current.json", reference.ReleaseRef.SourceID)]
	root, err := releasecontract.DecodeRootDelegation(rootBytes)
	if err != nil {
		return err
	}
	verifier := releasecontract.Ed25519PublicKeyVerifier{reference.Root.KeyID: rootKey}
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
	presentation := pkg.Manifest.PresentationCatalog()
	presentationSHA256, err := manifest.PresentationCatalogSHA256(presentation)
	if err != nil {
		return err
	}
	var presentationIcon *PresentationIconEvidenceV1
	icon, content, iconErr := pluginpkg.ReadPresentationIcon(pkg)
	if iconErr == nil {
		presentationIcon = &PresentationIconEvidenceV1{
			SchemaVersion: PresentationIconEvidenceSchemaVersion,
			Path:          icon.Path, MediaType: icon.MediaType, Width: icon.Width, Height: icon.Height,
			SHA256: icon.SHA256, Size: icon.Size,
		}
	} else if !errors.Is(iconErr, pluginpkg.ErrPresentationIconUnavailable) {
		return ErrInvalidWorkspace
	}
	*verified = VerifiedOutputV1{
		Presentation: presentation, PresentationIcon: presentationIcon,
		ManifestSHA256: pkg.ManifestHash, PresentationSHA256: presentationSHA256,
	}
	if iconContent != nil && presentationIcon != nil {
		*iconContent = content
	}
	return nil
}

func outputAssetName(reference PublisherReleaseRefV1, locator string) string {
	switch locator {
	case "anchors/root.public.json":
		return "root.public.json"
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

func writePresentationIconNoOverwrite(path string, content []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return ErrPresentationIconOutputExists
	}
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	completed = true
	return nil
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
