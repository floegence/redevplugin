package releasepublisher

import (
	"fmt"
	"slices"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

func buildCompleteAssembly(
	config ConfigV1,
	pointers signedPointers,
	primaryRequests []ExternalSignerRequestV1,
	responses map[string]string,
) (assemblyResult, error) {
	prepared := pointers.primary.prepared
	packageSignatureBytes, err := signatureForUsage(primaryRequests, responses, releasecontract.SigningUsagePackage)
	if err != nil {
		return assemblyResult{}, err
	}
	packageSignature, err := releasecontract.BuildPackageSignature(prepared.packageInput, packageSignatureBytes)
	if err != nil {
		return assemblyResult{}, err
	}
	packageSignatureDocument, err := releasecontract.CanonicalPackageSignature(
		releasecontract.PackageVerificationContext{
			SourceID: config.SourceID,
			Channel:  config.Channel,
			Version:  prepared.pkg.Manifest.Version(),
		},
		packageSignature,
	)
	if err != nil {
		return assemblyResult{}, err
	}
	files := map[string][]byte{
		fmt.Sprintf("sources/%s/root/current.json", config.SourceID):                          pointers.primary.rootBytes,
		fmt.Sprintf("sources/%s/%s/policy/current.json", config.SourceID, config.Channel):     pointers.policyPointerBytes,
		pointers.primary.policyPointerInput.Ref:                                               pointers.primary.policyBytes,
		fmt.Sprintf("sources/%s/%s/revocation/current.json", config.SourceID, config.Channel): pointers.revocationPointerBytes,
		pointers.primary.revocationPointerInput.Ref:                                           pointers.primary.revocationBytes,
		prepared.releaseMetadataRef:                                                           prepared.metadataBytes,
		prepared.releaseMetadataSignatureRef:                                                  slices.Clone(pointers.primary.metadataSignature),
		prepared.packageArtifactRef:                                                           slices.Clone(pointers.primary.signedPackage),
		prepared.packageSignatureRef:                                                          packageSignatureDocument,
	}
	reference := PublisherReleaseRefV1{
		SchemaVersion: ReleaseRefSchemaVersion,
		ReleaseRef: PluginReleaseRefV1{
			SourceID:              config.SourceID,
			Channel:               config.Channel,
			ReleaseMetadataRef:    prepared.releaseMetadataRef,
			ReleaseMetadataSHA256: sha256Hex(prepared.metadataBytes),
			PublisherID:           prepared.pkg.Manifest.Publisher.PublisherID,
			PluginID:              prepared.pkg.Manifest.PluginID(),
			Version:               prepared.pkg.Manifest.Version(),
			ExpectedHashes: PackageHashSetV1{
				PackageSHA256:  prepared.pkg.PackageHash,
				ManifestSHA256: prepared.pkg.ManifestHash,
				EntriesSHA256:  prepared.pkg.EntriesHash,
			},
		},
		Root: config.Root,
	}
	return assemblyResult{Phase: "complete", Complete: true, Files: files, ReleaseRef: reference}, nil
}
