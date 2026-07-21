package releasecontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
)

type SignatureVerificationRequest struct {
	Usage                 SigningUsage
	KeyID                 string
	SigningPreimageSHA256 [sha256.Size]byte
	Signature             []byte
}

type SignatureVerifier interface {
	VerifySignature(SignatureVerificationRequest) error
}

type SignatureVerifierFunc func(SignatureVerificationRequest) error

func (verify SignatureVerifierFunc) VerifySignature(request SignatureVerificationRequest) error {
	if verify == nil {
		return ErrVerifierRequired
	}
	return verify(request)
}

type Ed25519PublicKeyVerifier map[string]ed25519.PublicKey

func (keys Ed25519PublicKeyVerifier) VerifySignature(request SignatureVerificationRequest) error {
	key := keys[request.KeyID]
	if len(key) != ed25519.PublicKeySize || len(request.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, request.SigningPreimageSHA256[:], request.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func BuildRootDelegation(input RootDelegationInput, signature []byte) (RootDelegationV1, error) {
	document := rootDelegationFromInput(input, encodeSignature(signature))
	if err := validateRootDelegation(document, true); err != nil {
		return RootDelegationV1{}, err
	}
	return document, nil
}

func RootDelegationSigningPreimage(input RootDelegationInput) ([]byte, error) {
	document := rootDelegationFromInput(input, "")
	if err := validateRootDelegation(document, false); err != nil {
		return nil, err
	}
	return signingPreimageWithoutTopLevelSignature(SigningUsageRootDelegation, document)
}

func CanonicalRootDelegation(document RootDelegationV1) ([]byte, error) {
	if err := validateRootDelegation(document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifyRootDelegation(document RootDelegationV1, verifier SignatureVerifier) error {
	input := RootDelegationInput{
		SourceID:                 document.SourceID,
		RootEpoch:                document.RootEpoch,
		PreviousRootEpoch:        document.PreviousRootEpoch,
		PreviousDelegationSHA256: document.PreviousDelegationSHA256,
		GeneratedAt:              document.GeneratedAt,
		ExpiresAt:                document.ExpiresAt,
		DelegatedKeys:            cloneDelegatedKeys(document.DelegatedKeys),
		KeyID:                    document.KeyID,
	}
	preimage, err := RootDelegationSigningPreimage(input)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageRootDelegation, document.KeyID, preimage, document.Signature, verifier)
}

func BuildPackageSignature(input PackageSigningInput, signature []byte) (PackageSignatureV1, error) {
	document := PackageSignatureV1{
		SchemaVersion: PackageSignatureSchemaVersion,
		Algorithm:     input.Algorithm,
		KeyID:         input.KeyID,
		PublisherID:   input.PublisherID,
		PluginID:      input.PluginID,
		PackageHash:   input.PackageHash,
		ManifestHash:  input.ManifestHash,
		EntriesHash:   input.EntriesHash,
		Signature:     encodeSignature(signature),
		SignedAt:      input.SignedAt,
	}
	if err := validatePackageSignature(input, document, true); err != nil {
		return PackageSignatureV1{}, err
	}
	return document, nil
}

func PackageSigningPreimage(input PackageSigningInput) ([]byte, error) {
	if err := validatePackageInput(input); err != nil {
		return nil, err
	}
	payload := struct {
		Channel          string `json:"channel"`
		PackageSignature struct {
			Algorithm     string `json:"algorithm"`
			EntriesHash   string `json:"entries_hash"`
			KeyID         string `json:"key_id"`
			ManifestHash  string `json:"manifest_hash"`
			PackageHash   string `json:"package_hash"`
			PluginID      string `json:"plugin_id"`
			PublisherID   string `json:"publisher_id"`
			SchemaVersion string `json:"schema_version"`
			SignedAt      string `json:"signed_at"`
		} `json:"package_signature"`
		SourceID string `json:"source_id"`
		Version  string `json:"version"`
	}{
		Channel:  input.Channel,
		SourceID: input.SourceID,
		Version:  input.Version,
	}
	payload.PackageSignature.Algorithm = input.Algorithm
	payload.PackageSignature.EntriesHash = input.EntriesHash
	payload.PackageSignature.KeyID = input.KeyID
	payload.PackageSignature.ManifestHash = input.ManifestHash
	payload.PackageSignature.PackageHash = input.PackageHash
	payload.PackageSignature.PluginID = input.PluginID
	payload.PackageSignature.PublisherID = input.PublisherID
	payload.PackageSignature.SchemaVersion = PackageSignatureSchemaVersion
	payload.PackageSignature.SignedAt = input.SignedAt
	return signingPreimage(SigningUsagePackage, payload)
}

func CanonicalPackageSignature(context PackageVerificationContext, document PackageSignatureV1) ([]byte, error) {
	input := packageInputFromDocument(context, document)
	if err := validatePackageSignature(input, document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifyPackageSignature(context PackageVerificationContext, document PackageSignatureV1, verifier SignatureVerifier) error {
	input := packageInputFromDocument(context, document)
	preimage, err := PackageSigningPreimage(input)
	if err != nil {
		return err
	}
	if err := validatePackageSignature(input, document, true); err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsagePackage, document.KeyID, preimage, document.Signature, verifier)
}

func BuildReleaseMetadata(document ReleaseMetadataV5) (ReleaseMetadataV5, error) {
	document = cloneReleaseMetadata(document)
	if err := validateReleaseMetadata(document); err != nil {
		return ReleaseMetadataV5{}, err
	}
	return document, nil
}

func ReleaseMetadataSigningPreimage(channel string, document ReleaseMetadataV5) ([]byte, error) {
	if !newContractIDPattern.MatchString(channel) {
		return nil, invalid("release metadata channel")
	}
	built, err := BuildReleaseMetadata(document)
	if err != nil {
		return nil, err
	}
	payload := struct {
		Channel         string            `json:"channel"`
		ReleaseMetadata ReleaseMetadataV5 `json:"release_metadata"`
	}{Channel: channel, ReleaseMetadata: built}
	return signingPreimage(SigningUsageReleaseMetadata, payload)
}

func CanonicalReleaseMetadata(document ReleaseMetadataV5) ([]byte, error) {
	built, err := BuildReleaseMetadata(document)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(built)
}

func VerifyReleaseMetadata(channel string, document ReleaseMetadataV5, signature []byte, verifier SignatureVerifier) error {
	preimage, err := ReleaseMetadataSigningPreimage(channel, document)
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	return verifySignature(SigningUsageReleaseMetadata, document.ReleaseMetadataSignature.KeyID, preimage, signature, verifier)
}

func BuildSourcePolicy(input SourcePolicyInput, signature []byte) (SourcePolicyV2, error) {
	document := sourcePolicyFromInput(input, encodeSignature(signature))
	if err := validateSourcePolicy(document, true); err != nil {
		return SourcePolicyV2{}, err
	}
	return document, nil
}

func SourcePolicySigningPreimage(input SourcePolicyInput) ([]byte, error) {
	document := sourcePolicyFromInput(input, "")
	if err := validateSourcePolicy(document, false); err != nil {
		return nil, err
	}
	return signingPreimageWithoutTopLevelSignature(SigningUsageSourcePolicy, document)
}

func CanonicalSourcePolicy(document SourcePolicyV2) ([]byte, error) {
	if err := validateSourcePolicy(document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifySourcePolicy(document SourcePolicyV2, verifier SignatureVerifier) error {
	input := SourcePolicyInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		RootEpoch:              document.RootEpoch,
		SourceType:             document.SourceType,
		SourceClass:            document.SourceClass,
		AllowedPublishers:      slices.Clone(document.AllowedPublishers),
		AllowedArtifactHosts:   slices.Clone(document.AllowedArtifactHosts),
		ActiveKeys:             cloneActiveKeys(document.ActiveKeys),
		RequireSignature:       document.RequireSignature,
		InstallPolicy:          document.InstallPolicy,
		UnsignedPolicy:         document.UnsignedPolicy,
		DowngradePolicy:        document.DowngradePolicy,
		MinimumRevocationEpoch: document.MinimumRevocationEpoch,
		Limits:                 document.Limits,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		KeyID:                  document.KeyID,
	}
	preimage, err := SourcePolicySigningPreimage(input)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageSourcePolicy, document.KeyID, preimage, document.Signature, verifier)
}

func BuildSourcePolicyPointer(input ReleasePointerInput, signature []byte) (SourcePolicyPointerV1, error) {
	document := SourcePolicyPointerV1{
		SchemaVersion:          SourcePolicyPointerSchemaVersion,
		SourceID:               input.SourceID,
		Channel:                input.Channel,
		Epoch:                  input.Epoch,
		PreviousEpoch:          input.PreviousEpoch,
		PreviousDocumentSHA256: input.PreviousDocumentSHA256,
		Ref:                    input.Ref,
		DocumentSHA256:         input.DocumentSHA256,
		GeneratedAt:            input.GeneratedAt,
		ExpiresAt:              input.ExpiresAt,
		KeyID:                  input.KeyID,
		Signature:              encodeSignature(signature),
	}
	if err := validateSourcePolicyPointer(document, true); err != nil {
		return SourcePolicyPointerV1{}, err
	}
	return document, nil
}

func SourcePolicyPointerSigningPreimage(input ReleasePointerInput) ([]byte, error) {
	document, err := BuildSourcePolicyPointer(input, make([]byte, ed25519.SignatureSize))
	if err != nil {
		return nil, err
	}
	document.Signature = ""
	return signingPreimageWithoutTopLevelSignature(SigningUsageSourcePolicyPointer, document)
}

func CanonicalSourcePolicyPointer(document SourcePolicyPointerV1) ([]byte, error) {
	if err := validateSourcePolicyPointer(document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifySourcePolicyPointer(document SourcePolicyPointerV1, verifier SignatureVerifier) error {
	preimage, err := SourcePolicyPointerSigningPreimage(pointerInputFromSourcePolicy(document))
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageSourcePolicyPointer, document.KeyID, preimage, document.Signature, verifier)
}

func BuildRevocation(input RevocationInput, signature []byte) (RevocationV2, error) {
	document := revocationFromInput(input, encodeSignature(signature))
	if err := validateRevocation(document, true); err != nil {
		return RevocationV2{}, err
	}
	return document, nil
}

func RevocationSigningPreimage(input RevocationInput) ([]byte, error) {
	document := revocationFromInput(input, "")
	if err := validateRevocation(document, false); err != nil {
		return nil, err
	}
	return signingPreimageWithoutTopLevelSignature(SigningUsageRevocation, document)
}

func CanonicalRevocation(document RevocationV2) ([]byte, error) {
	if err := validateRevocation(document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifyRevocation(document RevocationV2, verifier SignatureVerifier) error {
	input := RevocationInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		RootEpoch:              document.RootEpoch,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		RevokedKeyIDs:          slices.Clone(document.RevokedKeyIDs),
		RevokedReleases:        slices.Clone(document.RevokedReleases),
		KeyID:                  document.KeyID,
	}
	preimage, err := RevocationSigningPreimage(input)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageRevocation, document.KeyID, preimage, document.Signature, verifier)
}

func BuildRevocationPointer(input ReleasePointerInput, signature []byte) (RevocationPointerV1, error) {
	document := RevocationPointerV1{
		SchemaVersion:          RevocationPointerSchemaVersion,
		SourceID:               input.SourceID,
		Channel:                input.Channel,
		Epoch:                  input.Epoch,
		PreviousEpoch:          input.PreviousEpoch,
		PreviousDocumentSHA256: input.PreviousDocumentSHA256,
		Ref:                    input.Ref,
		DocumentSHA256:         input.DocumentSHA256,
		GeneratedAt:            input.GeneratedAt,
		ExpiresAt:              input.ExpiresAt,
		KeyID:                  input.KeyID,
		Signature:              encodeSignature(signature),
	}
	if err := validateRevocationPointer(document, true); err != nil {
		return RevocationPointerV1{}, err
	}
	return document, nil
}

func RevocationPointerSigningPreimage(input ReleasePointerInput) ([]byte, error) {
	document, err := BuildRevocationPointer(input, make([]byte, ed25519.SignatureSize))
	if err != nil {
		return nil, err
	}
	document.Signature = ""
	return signingPreimageWithoutTopLevelSignature(SigningUsageRevocationPointer, document)
}

func CanonicalRevocationPointer(document RevocationPointerV1) ([]byte, error) {
	if err := validateRevocationPointer(document, true); err != nil {
		return nil, err
	}
	return canonicalJSON(document)
}

func VerifyRevocationPointer(document RevocationPointerV1, verifier SignatureVerifier) error {
	preimage, err := RevocationPointerSigningPreimage(pointerInputFromRevocation(document))
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageRevocationPointer, document.KeyID, preimage, document.Signature, verifier)
}

func rootDelegationFromInput(input RootDelegationInput, signature string) RootDelegationV1 {
	return RootDelegationV1{
		SchemaVersion:            RootDelegationSchemaVersion,
		SourceID:                 input.SourceID,
		RootEpoch:                input.RootEpoch,
		PreviousRootEpoch:        input.PreviousRootEpoch,
		PreviousDelegationSHA256: input.PreviousDelegationSHA256,
		GeneratedAt:              input.GeneratedAt,
		ExpiresAt:                input.ExpiresAt,
		DelegatedKeys:            cloneDelegatedKeys(input.DelegatedKeys),
		KeyID:                    input.KeyID,
		Signature:                signature,
	}
}

func sourcePolicyFromInput(input SourcePolicyInput, signature string) SourcePolicyV2 {
	return SourcePolicyV2{
		SchemaVersion:          SourcePolicySchemaVersion,
		SourceID:               input.SourceID,
		Channel:                input.Channel,
		Epoch:                  input.Epoch,
		PreviousEpoch:          input.PreviousEpoch,
		PreviousDocumentSHA256: input.PreviousDocumentSHA256,
		RootEpoch:              input.RootEpoch,
		SourceType:             input.SourceType,
		SourceClass:            input.SourceClass,
		AllowedPublishers:      slices.Clone(input.AllowedPublishers),
		AllowedArtifactHosts:   slices.Clone(input.AllowedArtifactHosts),
		ActiveKeys:             cloneActiveKeys(input.ActiveKeys),
		RequireSignature:       input.RequireSignature,
		InstallPolicy:          input.InstallPolicy,
		UnsignedPolicy:         input.UnsignedPolicy,
		DowngradePolicy:        input.DowngradePolicy,
		MinimumRevocationEpoch: input.MinimumRevocationEpoch,
		Limits:                 input.Limits,
		GeneratedAt:            input.GeneratedAt,
		ExpiresAt:              input.ExpiresAt,
		KeyID:                  input.KeyID,
		Signature:              signature,
	}
}

func revocationFromInput(input RevocationInput, signature string) RevocationV2 {
	return RevocationV2{
		SchemaVersion:          RevocationSchemaVersion,
		SourceID:               input.SourceID,
		Channel:                input.Channel,
		Epoch:                  input.Epoch,
		PreviousEpoch:          input.PreviousEpoch,
		PreviousDocumentSHA256: input.PreviousDocumentSHA256,
		RootEpoch:              input.RootEpoch,
		GeneratedAt:            input.GeneratedAt,
		ExpiresAt:              input.ExpiresAt,
		RevokedKeyIDs:          slices.Clone(input.RevokedKeyIDs),
		RevokedReleases:        slices.Clone(input.RevokedReleases),
		KeyID:                  input.KeyID,
		Signature:              signature,
	}
}

func packageInputFromDocument(context PackageVerificationContext, document PackageSignatureV1) PackageSigningInput {
	return PackageSigningInput{
		SourceID:     context.SourceID,
		Channel:      context.Channel,
		Version:      context.Version,
		Algorithm:    document.Algorithm,
		KeyID:        document.KeyID,
		PublisherID:  document.PublisherID,
		PluginID:     document.PluginID,
		PackageHash:  document.PackageHash,
		ManifestHash: document.ManifestHash,
		EntriesHash:  document.EntriesHash,
		SignedAt:     document.SignedAt,
	}
}

func pointerInputFromSourcePolicy(document SourcePolicyPointerV1) ReleasePointerInput {
	return ReleasePointerInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		Ref:                    document.Ref,
		DocumentSHA256:         document.DocumentSHA256,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		KeyID:                  document.KeyID,
	}
}

func pointerInputFromRevocation(document RevocationPointerV1) ReleasePointerInput {
	return ReleasePointerInput{
		SourceID:               document.SourceID,
		Channel:                document.Channel,
		Epoch:                  document.Epoch,
		PreviousEpoch:          document.PreviousEpoch,
		PreviousDocumentSHA256: document.PreviousDocumentSHA256,
		Ref:                    document.Ref,
		DocumentSHA256:         document.DocumentSHA256,
		GeneratedAt:            document.GeneratedAt,
		ExpiresAt:              document.ExpiresAt,
		KeyID:                  document.KeyID,
	}
}

func validateSourcePolicyPointer(document SourcePolicyPointerV1, requireSignature bool) error {
	return validatePointer(document.SchemaVersion, SourcePolicyPointerSchemaVersion, document.SourceID, document.Channel,
		document.Epoch, document.PreviousEpoch, document.PreviousDocumentSHA256, document.Ref, document.DocumentSHA256,
		document.GeneratedAt, document.ExpiresAt, document.KeyID, document.Signature, requireSignature)
}

func validateRevocationPointer(document RevocationPointerV1, requireSignature bool) error {
	return validatePointer(document.SchemaVersion, RevocationPointerSchemaVersion, document.SourceID, document.Channel,
		document.Epoch, document.PreviousEpoch, document.PreviousDocumentSHA256, document.Ref, document.DocumentSHA256,
		document.GeneratedAt, document.ExpiresAt, document.KeyID, document.Signature, requireSignature)
}

func signingPreimageWithoutTopLevelSignature(usage SigningUsage, document any) ([]byte, error) {
	raw, err := canonicalJSON(document)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := decodeCanonicalValue(raw, &value); err != nil {
		return nil, err
	}
	delete(value, "signature")
	return signingPreimage(usage, value)
}

func decodeCanonicalValue(raw []byte, value any) error {
	if err := json.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("%w: canonical payload", ErrInvalidDocument)
	}
	return nil
}

func verifyEncodedSignature(usage SigningUsage, keyID string, preimage []byte, encoded string, verifier SignatureVerifier) error {
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	return verifySignature(usage, keyID, preimage, signature, verifier)
}

func verifySignature(usage SigningUsage, keyID string, preimage []byte, signature []byte, verifier SignatureVerifier) error {
	if verifier == nil {
		return ErrVerifierRequired
	}
	digest := sha256.Sum256(preimage)
	request := SignatureVerificationRequest{
		Usage:                 usage,
		KeyID:                 keyID,
		SigningPreimageSHA256: digest,
		Signature:             slices.Clone(signature),
	}
	if err := verifier.VerifySignature(request); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func encodeSignature(signature []byte) string {
	if len(signature) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func cloneDelegatedKeys(values []RootDelegatedKey) []RootDelegatedKey {
	if values == nil {
		return nil
	}
	cloned := make([]RootDelegatedKey, len(values))
	for index, value := range values {
		value.Usages = slices.Clone(value.Usages)
		value.Channels = slices.Clone(value.Channels)
		cloned[index] = value
	}
	return cloned
}

func cloneActiveKeys(value SourcePolicyActiveKeys) SourcePolicyActiveKeys {
	return SourcePolicyActiveKeys{
		Package:             slices.Clone(value.Package),
		ReleaseMetadata:     slices.Clone(value.ReleaseMetadata),
		SourcePolicyPointer: slices.Clone(value.SourcePolicyPointer),
		Revocation:          slices.Clone(value.Revocation),
		RevocationPointer:   slices.Clone(value.RevocationPointer),
	}
}

func cloneReleaseMetadata(value ReleaseMetadataV5) ReleaseMetadataV5 {
	value.Compatibility.SupportedTargets = slices.Clone(value.Compatibility.SupportedTargets)
	if value.HostRequirements != nil {
		value.HostRequirements = slices.Clone(value.HostRequirements)
		for index := range value.HostRequirements {
			value.HostRequirements[index].RequiredCapabilityContracts = slices.Clone(value.HostRequirements[index].RequiredCapabilityContracts)
		}
	}
	if value.ReleaseEvidence != nil {
		cloned := *value.ReleaseEvidence
		value.ReleaseEvidence = &cloned
	}
	value.Metadata = cloneSortedStringMap(value.Metadata)
	return value
}
