package releasecontract

const (
	RootDelegationSchemaVersion      = "redevplugin.release_root_delegation.v1"
	PackageSignatureSchemaVersion    = "redevplugin.package_signature.v1"
	ReleaseMetadataSchemaVersion     = "redevplugin.release_metadata.v5"
	SourcePolicySchemaVersion        = "redevplugin.release_source_policy.v2"
	SourcePolicyPointerSchemaVersion = "redevplugin.release_source_policy_pointer.v1"
	RevocationSchemaVersion          = "redevplugin.release_revocation.v2"
	RevocationPointerSchemaVersion   = "redevplugin.release_revocation_pointer.v1"

	SignatureAlgorithmEd25519 = "ed25519"

	GenesisPreviousEpoch          = "0"
	GenesisPreviousDocumentSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
)

type SigningUsage string

const (
	SigningUsageRootDelegation      SigningUsage = "redevplugin.release-signing.root-delegation.v1"
	SigningUsagePackage             SigningUsage = "redevplugin.release-signing.package.v1"
	SigningUsageReleaseMetadata     SigningUsage = "redevplugin.release-signing.release-metadata.v1"
	SigningUsageSourcePolicy        SigningUsage = "redevplugin.release-signing.source-policy-document.v1"
	SigningUsageSourcePolicyPointer SigningUsage = "redevplugin.release-signing.source-policy-pointer.v1"
	SigningUsageRevocation          SigningUsage = "redevplugin.release-signing.revocation-document.v1"
	SigningUsageRevocationPointer   SigningUsage = "redevplugin.release-signing.revocation-pointer.v1"
)

type DelegatedKeyUsage string

const (
	DelegatedKeyUsagePackage             DelegatedKeyUsage = "package"
	DelegatedKeyUsageReleaseMetadata     DelegatedKeyUsage = "release_metadata"
	DelegatedKeyUsageSourcePolicy        DelegatedKeyUsage = "source_policy_document"
	DelegatedKeyUsageSourcePolicyPointer DelegatedKeyUsage = "source_policy_pointer"
	DelegatedKeyUsageRevocation          DelegatedKeyUsage = "revocation_document"
	DelegatedKeyUsageRevocationPointer   DelegatedKeyUsage = "revocation_pointer"
)

type RootDelegatedKey struct {
	Algorithm  string              `json:"algorithm"`
	KeyID      string              `json:"key_id"`
	PublicKey  string              `json:"public_key"`
	Usages     []DelegatedKeyUsage `json:"usages"`
	Channels   []string            `json:"channels"`
	ValidFrom  string              `json:"valid_from"`
	ValidUntil string              `json:"valid_until"`
}

type RootDelegationInput struct {
	SourceID                 string
	RootEpoch                string
	PreviousRootEpoch        string
	PreviousDelegationSHA256 string
	GeneratedAt              string
	ExpiresAt                string
	DelegatedKeys            []RootDelegatedKey
	KeyID                    string
}

type RootDelegationV1 struct {
	SchemaVersion            string             `json:"schema_version"`
	SourceID                 string             `json:"source_id"`
	RootEpoch                string             `json:"root_epoch"`
	PreviousRootEpoch        string             `json:"previous_root_epoch"`
	PreviousDelegationSHA256 string             `json:"previous_delegation_sha256"`
	GeneratedAt              string             `json:"generated_at"`
	ExpiresAt                string             `json:"expires_at"`
	DelegatedKeys            []RootDelegatedKey `json:"delegated_keys"`
	KeyID                    string             `json:"key_id"`
	Signature                string             `json:"signature"`
}

type PackageSigningInput struct {
	SourceID     string
	Channel      string
	Version      string
	Algorithm    string
	KeyID        string
	PublisherID  string
	PluginID     string
	PackageHash  string
	ManifestHash string
	EntriesHash  string
	SignedAt     string
}

type PackageVerificationContext struct {
	SourceID string
	Channel  string
	Version  string
}

type PackageSignatureV1 struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id,omitempty"`
	PluginID      string `json:"plugin_id,omitempty"`
	PackageHash   string `json:"package_hash"`
	ManifestHash  string `json:"manifest_hash"`
	EntriesHash   string `json:"entries_hash"`
	Signature     string `json:"signature"`
	SignedAt      string `json:"signed_at,omitempty"`
}

type ReleaseMetadataV5 struct {
	SchemaVersion            string                      `json:"schema_version"`
	SourceID                 string                      `json:"source_id"`
	ReleaseMetadataRef       string                      `json:"release_metadata_ref"`
	PublisherID              string                      `json:"publisher_id"`
	PluginID                 string                      `json:"plugin_id"`
	Version                  string                      `json:"version"`
	DistributionRef          ReleaseDistributionRef      `json:"distribution_ref"`
	Hashes                   ReleasePackageHashSet       `json:"hashes"`
	ReleaseMetadataSignature ReleaseMetadataSignatureRef `json:"release_metadata_signature"`
	PackageSignature         PackageReleaseSignatureRef  `json:"package_signature"`
	Compatibility            ReleaseCompatibility        `json:"compatibility"`
	HostRequirements         []ReleaseHostRequirement    `json:"host_requirements,omitempty"`
	ReleaseEvidence          *ReleaseEvidence            `json:"release_evidence,omitempty"`
	Metadata                 map[string]string           `json:"metadata,omitempty"`
}

type ReleaseDistributionRef struct {
	Distribution string `json:"distribution"`
	ArtifactRef  string `json:"artifact_ref"`
}

type ReleasePackageHashSet struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type ReleaseMetadataSignatureRef struct {
	Algorithm         string `json:"algorithm"`
	KeyID             string `json:"key_id"`
	SignatureRef      string `json:"signature_ref"`
	SourcePolicyEpoch string `json:"source_policy_epoch"`
	RevocationEpoch   string `json:"revocation_epoch"`
}

type PackageReleaseSignatureRef struct {
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	SignatureBundleRef string `json:"signature_bundle_ref"`
	SourcePolicyEpoch  string `json:"source_policy_epoch"`
	RevocationEpoch    string `json:"revocation_epoch"`
}

type ReleaseCompatibility struct {
	MinReDevPluginVersion string   `json:"min_redevplugin_version"`
	MinRuntimeVersion     string   `json:"min_runtime_version"`
	UIProtocolVersion     string   `json:"ui_protocol_version"`
	SupportedTargets      []string `json:"supported_targets,omitempty"`
}

type ReleaseHostRequirement struct {
	HostID                      string                         `json:"host_id"`
	MinHostVersion              string                         `json:"min_host_version,omitempty"`
	RequiredCapabilityContracts []HostCapabilityRequirementRef `json:"required_capability_contracts,omitempty"`
}

type HostCapabilityRequirementRef struct {
	CapabilityID      string                    `json:"capability_id"`
	CapabilityVersion string                    `json:"capability_version"`
	Contract          HostCapabilityContractRef `json:"contract"`
}

type HostCapabilityContractRef struct {
	PublisherID              string `json:"publisher_id"`
	ContractID               string `json:"contract_id"`
	ContractVersion          string `json:"contract_version"`
	ArtifactRef              string `json:"artifact_ref"`
	ArtifactSHA256           string `json:"artifact_sha256"`
	ManifestRef              string `json:"manifest_ref"`
	ManifestSHA256           string `json:"manifest_sha256"`
	SignatureRef             string `json:"signature_ref"`
	SignatureSHA256          string `json:"signature_sha256"`
	SignatureKeyID           string `json:"signature_key_id"`
	SignaturePolicyEpoch     string `json:"signature_policy_epoch"`
	SignatureRevocationEpoch string `json:"signature_revocation_epoch"`
	CompatibilityRef         string `json:"compatibility_ref"`
	CompatibilitySHA256      string `json:"compatibility_sha256"`
	GeneratedClientRef       string `json:"generated_client_ref"`
	GeneratedClientSHA256    string `json:"generated_client_sha256"`
	NoticesRef               string `json:"notices_ref"`
	NoticesSHA256            string `json:"notices_sha256"`
}

type ReleaseEvidence struct {
	NoticesSHA256    string `json:"notices_sha256,omitempty"`
	ProvenanceSHA256 string `json:"provenance_sha256,omitempty"`
	GeneratedAt      string `json:"generated_at,omitempty"`
}

type SourcePolicyLimits struct {
	DocumentMaxLifetimeSeconds     int `json:"document_max_lifetime_seconds"`
	FutureSkewSeconds              int `json:"future_skew_seconds"`
	ActivationLeaseMaxSeconds      int `json:"activation_lease_max_seconds"`
	RefreshIntervalMaxSeconds      int `json:"refresh_interval_max_seconds"`
	FailureTeardownDeadlineSeconds int `json:"failure_teardown_deadline_seconds"`
}

func DefaultSourcePolicyLimits() SourcePolicyLimits {
	return SourcePolicyLimits{
		DocumentMaxLifetimeSeconds:     86_400,
		FutureSkewSeconds:              300,
		ActivationLeaseMaxSeconds:      300,
		RefreshIntervalMaxSeconds:      60,
		FailureTeardownDeadlineSeconds: 30,
	}
}

type SourcePolicyActiveKeys struct {
	Package             []string `json:"package"`
	ReleaseMetadata     []string `json:"release_metadata"`
	SourcePolicyPointer []string `json:"source_policy_pointer"`
	Revocation          []string `json:"revocation_document"`
	RevocationPointer   []string `json:"revocation_pointer"`
}

type SourcePolicyInput struct {
	SourceID               string
	Channel                string
	Epoch                  string
	PreviousEpoch          string
	PreviousDocumentSHA256 string
	RootEpoch              string
	SourceType             string
	SourceClass            string
	AllowedPublishers      []string
	AllowedArtifactHosts   []string
	ActiveKeys             SourcePolicyActiveKeys
	RequireSignature       bool
	InstallPolicy          string
	UnsignedPolicy         string
	DowngradePolicy        string
	MinimumRevocationEpoch string
	Limits                 SourcePolicyLimits
	GeneratedAt            string
	ExpiresAt              string
	KeyID                  string
}

type SourcePolicyV2 struct {
	SchemaVersion          string                 `json:"schema_version"`
	SourceID               string                 `json:"source_id"`
	Channel                string                 `json:"channel"`
	Epoch                  string                 `json:"epoch"`
	PreviousEpoch          string                 `json:"previous_epoch"`
	PreviousDocumentSHA256 string                 `json:"previous_document_sha256"`
	RootEpoch              string                 `json:"root_epoch"`
	SourceType             string                 `json:"source_type"`
	SourceClass            string                 `json:"source_class"`
	AllowedPublishers      []string               `json:"allowed_publishers"`
	AllowedArtifactHosts   []string               `json:"allowed_artifact_hosts"`
	ActiveKeys             SourcePolicyActiveKeys `json:"active_keys"`
	RequireSignature       bool                   `json:"require_signature"`
	InstallPolicy          string                 `json:"install_policy"`
	UnsignedPolicy         string                 `json:"unsigned_policy"`
	DowngradePolicy        string                 `json:"downgrade_policy"`
	MinimumRevocationEpoch string                 `json:"minimum_revocation_epoch"`
	Limits                 SourcePolicyLimits     `json:"limits"`
	GeneratedAt            string                 `json:"generated_at"`
	ExpiresAt              string                 `json:"expires_at"`
	KeyID                  string                 `json:"key_id"`
	Signature              string                 `json:"signature"`
}

type ReleasePointerInput struct {
	SourceID               string
	Channel                string
	Epoch                  string
	PreviousEpoch          string
	PreviousDocumentSHA256 string
	Ref                    string
	DocumentSHA256         string
	GeneratedAt            string
	ExpiresAt              string
	KeyID                  string
}

type SourcePolicyPointerV1 struct {
	SchemaVersion          string `json:"schema_version"`
	SourceID               string `json:"source_id"`
	Channel                string `json:"channel"`
	Epoch                  string `json:"epoch"`
	PreviousEpoch          string `json:"previous_epoch"`
	PreviousDocumentSHA256 string `json:"previous_document_sha256"`
	Ref                    string `json:"ref"`
	DocumentSHA256         string `json:"document_sha256"`
	GeneratedAt            string `json:"generated_at"`
	ExpiresAt              string `json:"expires_at"`
	KeyID                  string `json:"key_id"`
	Signature              string `json:"signature"`
}

type RevokedRelease struct {
	PublisherID           string `json:"publisher_id"`
	PluginID              string `json:"plugin_id"`
	Version               string `json:"version"`
	ReleaseMetadataSHA256 string `json:"release_metadata_sha256"`
	RevokedAt             string `json:"revoked_at"`
}

type RevocationInput struct {
	SourceID               string
	Channel                string
	Epoch                  string
	PreviousEpoch          string
	PreviousDocumentSHA256 string
	RootEpoch              string
	GeneratedAt            string
	ExpiresAt              string
	RevokedKeyIDs          []string
	RevokedReleases        []RevokedRelease
	KeyID                  string
}

type RevocationV2 struct {
	SchemaVersion          string           `json:"schema_version"`
	SourceID               string           `json:"source_id"`
	Channel                string           `json:"channel"`
	Epoch                  string           `json:"epoch"`
	PreviousEpoch          string           `json:"previous_epoch"`
	PreviousDocumentSHA256 string           `json:"previous_document_sha256"`
	RootEpoch              string           `json:"root_epoch"`
	GeneratedAt            string           `json:"generated_at"`
	ExpiresAt              string           `json:"expires_at"`
	RevokedKeyIDs          []string         `json:"revoked_key_ids"`
	RevokedReleases        []RevokedRelease `json:"revoked_releases"`
	KeyID                  string           `json:"key_id"`
	Signature              string           `json:"signature"`
}

type RevocationPointerV1 struct {
	SchemaVersion          string `json:"schema_version"`
	SourceID               string `json:"source_id"`
	Channel                string `json:"channel"`
	Epoch                  string `json:"epoch"`
	PreviousEpoch          string `json:"previous_epoch"`
	PreviousDocumentSHA256 string `json:"previous_document_sha256"`
	Ref                    string `json:"ref"`
	DocumentSHA256         string `json:"document_sha256"`
	GeneratedAt            string `json:"generated_at"`
	ExpiresAt              string `json:"expires_at"`
	KeyID                  string `json:"key_id"`
	Signature              string `json:"signature"`
}
