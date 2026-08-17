package releasecontract

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	canonicalUnsignedDecimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	positiveEpochPattern            = regexp.MustCompile(`^[1-9][0-9]*$`)
	newContractIDPattern            = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	releaseIDPattern                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hostnamePattern                 = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	sha256Pattern                   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	prefixedSHA256Pattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	packageSHA256Pattern            = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{64}$`)
	artifactRefPattern              = regexp.MustCompile(`^[A-Za-z0-9._/@+-]+$`)
	semverPattern                   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	canonicalTimePattern            = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

func invalid(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDocument, field)
}

func validateRootDelegation(value RootDelegationV1, requireSignature bool) error {
	if value.SchemaVersion != RootDelegationSchemaVersion {
		return invalid("root delegation schema_version")
	}
	if !newContractIDPattern.MatchString(value.SourceID) || !newContractIDPattern.MatchString(value.KeyID) {
		return invalid("root delegation identity")
	}
	if !positiveEpochPattern.MatchString(value.RootEpoch) {
		return invalid("root delegation epoch")
	}
	generatedAt, expiresAt, err := validateTimeRange(value.GeneratedAt, value.ExpiresAt, 0)
	if err != nil {
		return err
	}
	if len(value.DelegatedKeys) < 1 || len(value.DelegatedKeys) > 32 {
		return invalid("root delegation delegated_keys")
	}
	previousKeyID := ""
	for _, key := range value.DelegatedKeys {
		if key.Algorithm != SignatureAlgorithmEd25519 || !newContractIDPattern.MatchString(key.KeyID) || key.KeyID <= previousKeyID {
			return invalid("root delegation delegated key identity or order")
		}
		publicKey, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
		if err != nil || len(publicKey) != 32 {
			return invalid("root delegation delegated public key")
		}
		if err := validateUsageList(key.Usages); err != nil {
			return err
		}
		if err := validateSortedIDs(key.Channels, 1, 16, true); err != nil {
			return invalid("root delegation delegated key channels")
		}
		validFrom, validUntil, err := validateTimeRange(key.ValidFrom, key.ValidUntil, 0)
		if err != nil || validUntil.After(expiresAt) || validFrom.After(expiresAt) || validUntil.Before(generatedAt) {
			return invalid("root delegation delegated key validity")
		}
		previousKeyID = key.KeyID
	}
	return validateSignatureString(value.Signature, requireSignature)
}

func validateUsageList(usages []DelegatedKeyUsage) error {
	if len(usages) < 1 || len(usages) > 6 {
		return invalid("root delegation delegated key usages")
	}
	previous := -1
	for _, usage := range usages {
		rank := delegatedUsageRank(usage)
		if rank < 0 || rank <= previous {
			return invalid("root delegation delegated key usage order")
		}
		previous = rank
	}
	return nil
}

func delegatedUsageRank(usage DelegatedKeyUsage) int {
	switch usage {
	case DelegatedKeyUsagePackage:
		return 0
	case DelegatedKeyUsageReleaseMetadata:
		return 1
	case DelegatedKeyUsageRevocation:
		return 2
	case DelegatedKeyUsageRevocationPointer:
		return 3
	case DelegatedKeyUsageSourcePolicy:
		return 4
	case DelegatedKeyUsageSourcePolicyPointer:
		return 5
	default:
		return -1
	}
}

func validatePackageInput(value PackageSigningInput) error {
	if !newContractIDPattern.MatchString(value.SourceID) || !newContractIDPattern.MatchString(value.Channel) {
		return invalid("package signing source or channel")
	}
	if value.Algorithm != SignatureAlgorithmEd25519 || !newContractIDPattern.MatchString(value.KeyID) {
		return invalid("package signing key")
	}
	if !releaseIDPattern.MatchString(value.PublisherID) || !releaseIDPattern.MatchString(value.PluginID) || !semverPattern.MatchString(value.Version) {
		return invalid("package signing subject")
	}
	if !prefixedSHA256Pattern.MatchString(value.PackageHash) || !prefixedSHA256Pattern.MatchString(value.ManifestHash) || !prefixedSHA256Pattern.MatchString(value.EntriesHash) {
		return invalid("package signing hashes")
	}
	if _, err := parseCanonicalTime(value.SignedAt); err != nil {
		return invalid("package signed_at")
	}
	return nil
}

func validatePackageSignature(context PackageSigningInput, value PackageSignatureV1, requireSignature bool) error {
	if value.SchemaVersion != PackageSignatureSchemaVersion ||
		value.Algorithm != context.Algorithm || value.KeyID != context.KeyID ||
		value.PublisherID != context.PublisherID || value.PluginID != context.PluginID ||
		value.PackageHash != context.PackageHash || value.ManifestHash != context.ManifestHash ||
		value.EntriesHash != context.EntriesHash || value.SignedAt != context.SignedAt {
		return invalid("package signature does not match signing context")
	}
	if err := validatePackageInput(context); err != nil {
		return err
	}
	return validateSignatureString(value.Signature, requireSignature)
}

func validateReleaseMetadata(value ReleaseMetadata) error {
	if value.SchemaVersion != ReleaseMetadataSchemaVersion || !newContractIDPattern.MatchString(value.SourceID) {
		return invalid("release metadata schema or source")
	}
	if !releaseIDPattern.MatchString(value.PublisherID) || !releaseIDPattern.MatchString(value.PluginID) || !semverPattern.MatchString(value.Version) {
		return invalid("release metadata subject")
	}
	if !validArtifactRef(value.ReleaseMetadataRef) || !validArtifactRef(value.DistributionRef.ArtifactRef) {
		return invalid("release metadata artifact ref")
	}
	if value.DistributionRef.Distribution != "registry_ref" && value.DistributionRef.Distribution != "host_artifact_ref" {
		return invalid("release metadata distribution")
	}
	if !packageSHA256Pattern.MatchString(value.Hashes.PackageSHA256) ||
		!packageSHA256Pattern.MatchString(value.Hashes.ManifestSHA256) ||
		!packageSHA256Pattern.MatchString(value.Hashes.EntriesSHA256) {
		return invalid("release metadata hashes")
	}
	if err := validateReleaseMetadataSignatureRef(value.ReleaseMetadataSignature); err != nil {
		return err
	}
	if err := validatePackageReleaseSignatureRef(value.PackageSignature); err != nil {
		return err
	}
	if value.ReleaseEvidence != nil {
		if value.ReleaseEvidence.NoticesSHA256 != "" && !packageSHA256Pattern.MatchString(value.ReleaseEvidence.NoticesSHA256) {
			return invalid("release metadata notices digest")
		}
		if value.ReleaseEvidence.ProvenanceSHA256 != "" && !packageSHA256Pattern.MatchString(value.ReleaseEvidence.ProvenanceSHA256) {
			return invalid("release metadata provenance digest")
		}
		if value.ReleaseEvidence.GeneratedAt != "" {
			if _, err := parseCanonicalTime(value.ReleaseEvidence.GeneratedAt); err != nil {
				return invalid("release metadata evidence generated_at")
			}
		}
	}
	if len(value.Metadata) > 128 {
		return invalid("release metadata metadata limit")
	}
	for key, item := range value.Metadata {
		if len(key) == 0 || len(key) > 128 || len(item) > 4096 || !utf8.ValidString(key) || !utf8.ValidString(item) {
			return invalid("release metadata metadata entry")
		}
	}
	return nil
}

func validateReleaseMetadataSignatureRef(value ReleaseMetadataSignatureRef) error {
	if value.Algorithm != SignatureAlgorithmEd25519 || !newContractIDPattern.MatchString(value.KeyID) || !validArtifactRef(value.SignatureRef) ||
		!canonicalUnsignedDecimalPattern.MatchString(value.SourcePolicyEpoch) || !canonicalUnsignedDecimalPattern.MatchString(value.RevocationEpoch) {
		return invalid("release metadata signature reference")
	}
	return nil
}

func validatePackageReleaseSignatureRef(value PackageReleaseSignatureRef) error {
	if value.Algorithm != SignatureAlgorithmEd25519 || !newContractIDPattern.MatchString(value.KeyID) || !validArtifactRef(value.SignatureBundleRef) ||
		!canonicalUnsignedDecimalPattern.MatchString(value.SourcePolicyEpoch) || !canonicalUnsignedDecimalPattern.MatchString(value.RevocationEpoch) {
		return invalid("release metadata package signature reference")
	}
	return nil
}

func validateSourcePolicy(value SourcePolicyV3, requireSignature bool) error {
	if value.SchemaVersion != SourcePolicySchemaVersion || !newContractIDPattern.MatchString(value.SourceID) ||
		!newContractIDPattern.MatchString(value.Channel) || !newContractIDPattern.MatchString(value.KeyID) {
		return invalid("source policy schema or identity")
	}
	if !positiveEpochPattern.MatchString(value.Epoch) || !positiveEpochPattern.MatchString(value.RootEpoch) || !canonicalUnsignedDecimalPattern.MatchString(value.MinimumRevocationEpoch) {
		return invalid("source policy epoch")
	}
	if value.SourceType != "registry" && value.SourceType != "host_artifact" {
		return invalid("source policy source_type")
	}
	if value.SourceClass != "official" && value.SourceClass != "curated" && value.SourceClass != "community" && value.SourceClass != "private" {
		return invalid("source policy source_class")
	}
	if err := validateSortedIDs(value.AllowedPublishers, 1, 1024, true); err != nil {
		return invalid("source policy allowed_publishers")
	}
	if len(value.AllowedArtifactHosts) > 1024 {
		return invalid("source policy allowed_artifact_hosts")
	}
	previousHost := ""
	for _, host := range value.AllowedArtifactHosts {
		if len(host) > 253 || !hostnamePattern.MatchString(host) || strings.ToLower(host) != host || host <= previousHost {
			return invalid("source policy allowed_artifact_hosts")
		}
		previousHost = host
	}
	for _, keys := range [][]string{
		value.ActiveKeys.Package,
		value.ActiveKeys.ReleaseMetadata,
		value.ActiveKeys.SourcePolicyPointer,
		value.ActiveKeys.Revocation,
		value.ActiveKeys.RevocationPointer,
	} {
		if err := validateSortedIDs(keys, 1, 16, true); err != nil {
			return invalid("source policy active_keys")
		}
	}
	if value.InstallPolicy != "allow" && value.InstallPolicy != "review_required" && value.InstallPolicy != "block" {
		return invalid("source policy install_policy")
	}
	if value.UnsignedPolicy != "dev_only" && value.UnsignedPolicy != "review_required" && value.UnsignedPolicy != "block" {
		return invalid("source policy unsigned_policy")
	}
	if value.DowngradePolicy != "review_required" && value.DowngradePolicy != "block" {
		return invalid("source policy downgrade_policy")
	}
	if value.Limits != PersonalMaintainerSourcePolicyLimits() {
		return invalid("source policy limits")
	}
	if _, _, err := validateTimeRange(value.GeneratedAt, value.ExpiresAt, 90*24*time.Hour); err != nil {
		return err
	}
	return validateSignatureString(value.Signature, requireSignature)
}

func validatePointer(schemaVersion string, expectedSchemaVersion string, sourceID string, channel string, epoch string, ref string, documentDigest string, generatedAt string, expiresAt string, keyID string, signature string, requireSignature bool) error {
	if schemaVersion != expectedSchemaVersion || !newContractIDPattern.MatchString(sourceID) ||
		!newContractIDPattern.MatchString(channel) || !newContractIDPattern.MatchString(keyID) {
		return invalid("release pointer schema or identity")
	}
	if !positiveEpochPattern.MatchString(epoch) || !validArtifactRef(ref) || !sha256Pattern.MatchString(documentDigest) || documentDigest == strings.Repeat("0", 64) {
		return invalid("release pointer document ref or digest")
	}
	if _, _, err := validateTimeRange(generatedAt, expiresAt, 90*24*time.Hour); err != nil {
		return err
	}
	return validateSignatureString(signature, requireSignature)
}

func validateRevocation(value RevocationV3, requireSignature bool) error {
	if value.SchemaVersion != RevocationSchemaVersion || !newContractIDPattern.MatchString(value.SourceID) ||
		!newContractIDPattern.MatchString(value.Channel) || !newContractIDPattern.MatchString(value.KeyID) {
		return invalid("revocation schema or identity")
	}
	if !positiveEpochPattern.MatchString(value.Epoch) || !positiveEpochPattern.MatchString(value.RootEpoch) {
		return invalid("revocation root_epoch")
	}
	generatedAt, expiresAt, err := validateTimeRange(value.GeneratedAt, value.ExpiresAt, 90*24*time.Hour)
	if err != nil {
		return err
	}
	_ = generatedAt
	if err := validateSortedIDs(value.RevokedKeyIDs, 0, 4096, true); err != nil {
		return invalid("revocation revoked_key_ids")
	}
	if value.RevokedKeyIDs == nil || value.RevokedReleases == nil || len(value.RevokedReleases) > 16_384 {
		return invalid("revocation arrays")
	}
	previous := ""
	for _, revoked := range value.RevokedReleases {
		key := revoked.PublisherID + "\x00" + revoked.PluginID + "\x00" + revoked.Version + "\x00" + revoked.ReleaseMetadataSHA256
		if !releaseIDPattern.MatchString(revoked.PublisherID) || !releaseIDPattern.MatchString(revoked.PluginID) ||
			!semverPattern.MatchString(revoked.Version) || !sha256Pattern.MatchString(revoked.ReleaseMetadataSHA256) || key <= previous {
			return invalid("revocation revoked release identity or order")
		}
		revokedAt, err := parseCanonicalTime(revoked.RevokedAt)
		if err != nil || revokedAt.After(expiresAt) {
			return invalid("revocation revoked_at")
		}
		previous = key
	}
	return validateSignatureString(value.Signature, requireSignature)
}

func validateTimeRange(generated string, expires string, maxLifetime time.Duration) (time.Time, time.Time, error) {
	generatedAt, err := parseCanonicalTime(generated)
	if err != nil {
		return time.Time{}, time.Time{}, invalid("release generated_at")
	}
	expiresAt, err := parseCanonicalTime(expires)
	if err != nil || !expiresAt.After(generatedAt) {
		return time.Time{}, time.Time{}, invalid("release expires_at")
	}
	if maxLifetime > 0 && expiresAt.Sub(generatedAt) > maxLifetime {
		return time.Time{}, time.Time{}, invalid("release document lifetime")
	}
	return generatedAt, expiresAt, nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	if !canonicalTimePattern.MatchString(value) {
		return time.Time{}, invalid("canonical timestamp")
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, invalid("canonical timestamp")
	}
	return parsed, nil
}

func validateSignatureString(value string, required bool) error {
	if !required && value == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 64 {
		return invalid("release signature encoding")
	}
	return nil
}

func validateSortedIDs(values []string, minimum int, maximum int, lower bool) error {
	if values == nil || len(values) < minimum || len(values) > maximum {
		return invalid("identifier list size")
	}
	previous := ""
	for _, value := range values {
		pattern := releaseIDPattern
		if lower {
			pattern = newContractIDPattern
		}
		if !pattern.MatchString(value) || value <= previous {
			return invalid("identifier list value or order")
		}
		previous = value
	}
	return nil
}

func validArtifactRef(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && artifactRefPattern.MatchString(value) &&
		!strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && !strings.ContainsAny(value, "?#") &&
		!containsDotSegment(value)
}

func containsDotSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || segment == "" {
			return true
		}
	}
	return false
}

func cloneSortedStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	cloned := make(map[string]string, len(value))
	for _, key := range keys {
		cloned[key] = value[key]
	}
	return cloned
}
