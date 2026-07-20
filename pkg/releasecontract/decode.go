package releasecontract

func DecodeRootDelegation(raw []byte) (RootDelegationV1, error) {
	var document RootDelegationV1
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateRootDelegation(document, true)
	}); err != nil {
		return RootDelegationV1{}, err
	}
	return document, nil
}

func DecodePackageSignature(raw []byte, context PackageVerificationContext) (PackageSignatureV1, error) {
	var document PackageSignatureV1
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validatePackageSignature(packageInputFromDocument(context, document), document, true)
	}); err != nil {
		return PackageSignatureV1{}, err
	}
	return document, nil
}

func DecodeReleaseMetadata(raw []byte) (ReleaseMetadataV5, error) {
	var document ReleaseMetadataV5
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateReleaseMetadata(document)
	}); err != nil {
		return ReleaseMetadataV5{}, err
	}
	return cloneReleaseMetadata(document), nil
}

func DecodeSourcePolicy(raw []byte) (SourcePolicyV2, error) {
	var document SourcePolicyV2
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateSourcePolicy(document, true)
	}); err != nil {
		return SourcePolicyV2{}, err
	}
	return sourcePolicyFromInput(SourcePolicyInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		RootEpoch:              document.RootEpoch,
		SourceType:             document.SourceType,
		SourceClass:            document.SourceClass,
		AllowedPublishers:      document.AllowedPublishers,
		AllowedArtifactHosts:   document.AllowedArtifactHosts,
		ActiveKeys:             document.ActiveKeys,
		RequireSignature:       document.RequireSignature,
		InstallPolicy:          document.InstallPolicy,
		UnsignedPolicy:         document.UnsignedPolicy,
		DowngradePolicy:        document.DowngradePolicy,
		MinimumRevocationEpoch: document.MinimumRevocationEpoch,
		Limits:                 document.Limits,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		KeyID:                  document.KeyID,
	}, document.Signature), nil
}

func DecodeSourcePolicyPointer(raw []byte) (SourcePolicyPointerV1, error) {
	var document SourcePolicyPointerV1
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateSourcePolicyPointer(document, true)
	}); err != nil {
		return SourcePolicyPointerV1{}, err
	}
	return document, nil
}

func DecodeRevocation(raw []byte) (RevocationV2, error) {
	var document RevocationV2
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateRevocation(document, true)
	}); err != nil {
		return RevocationV2{}, err
	}
	return revocationFromInput(RevocationInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		RootEpoch:              document.RootEpoch,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		RevokedKeyIDs:          document.RevokedKeyIDs,
		RevokedReleases:        document.RevokedReleases,
		KeyID:                  document.KeyID,
	}, document.Signature), nil
}

func DecodeRevocationPointer(raw []byte) (RevocationPointerV1, error) {
	var document RevocationPointerV1
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateRevocationPointer(document, true)
	}); err != nil {
		return RevocationPointerV1{}, err
	}
	return document, nil
}
