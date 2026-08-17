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

func DecodeReleaseMetadata(raw []byte) (ReleaseMetadata, error) {
	var document ReleaseMetadata
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateReleaseMetadata(document)
	}); err != nil {
		return ReleaseMetadata{}, err
	}
	return cloneReleaseMetadata(document), nil
}

func DecodeSourcePolicy(raw []byte) (SourcePolicyV3, error) {
	var document SourcePolicyV3
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateSourcePolicy(document, true)
	}); err != nil {
		return SourcePolicyV3{}, err
	}
	return sourcePolicyFromInput(SourcePolicyInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
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

func DecodeSourcePolicyPointer(raw []byte) (SourcePolicyPointerV2, error) {
	var document SourcePolicyPointerV2
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateSourcePolicyPointer(document, true)
	}); err != nil {
		return SourcePolicyPointerV2{}, err
	}
	return document, nil
}

func DecodeRevocation(raw []byte) (RevocationV3, error) {
	var document RevocationV3
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateRevocation(document, true)
	}); err != nil {
		return RevocationV3{}, err
	}
	return revocationFromInput(RevocationInput{
		SourceID:        document.SourceID,
		Channel:         document.Channel,
		Epoch:           document.Epoch,
		RootEpoch:       document.RootEpoch,
		GeneratedAt:     document.GeneratedAt,
		ExpiresAt:       document.ExpiresAt,
		RevokedKeyIDs:   document.RevokedKeyIDs,
		RevokedReleases: document.RevokedReleases,
		KeyID:           document.KeyID,
	}, document.Signature), nil
}

func DecodeRevocationPointer(raw []byte) (RevocationPointerV2, error) {
	var document RevocationPointerV2
	if err := decodeCanonicalDocument(raw, &document, func() error {
		return validateRevocationPointer(document, true)
	}); err != nil {
		return RevocationPointerV2{}, err
	}
	return document, nil
}
