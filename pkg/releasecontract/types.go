package releasecontract

const (
	RootDelegationSchemaVersion        = "redevplugin.release_root_delegation.v1"
	PackageSignatureSchemaVersion      = "redevplugin.package_signature.v1"
	ReleaseMetadataSchemaVersion       = "redevplugin.release_metadata.v5"
	SourcePolicySchemaVersion          = "redevplugin.release_source_policy.v2"
	SourcePolicyPointerSchemaVersion   = "redevplugin.release_source_policy_pointer.v1"
	RevocationSchemaVersion            = "redevplugin.release_revocation.v2"
	RevocationPointerSchemaVersion     = "redevplugin.release_revocation_pointer.v1"
	SigningLedgerEvidenceSchemaVersion = "redevplugin.release_signing_ledger_evidence.v1"
	SigningLedgerSchemaVersion         = "redevplugin.release_signing_ledger.v1"
	SigningLedgerEntrySchemaVersion    = "redevplugin.release_signing_ledger_entry.v1"
	SigningLedgerLogLeafSchemaVersion  = "redevplugin.release_signing_ledger_log_leaf.v1"
	SigningSubjectSchemaVersion        = "redevplugin.release_signing_subject.v1"
	SigningEnvelopeSchemaVersion       = "redevplugin.release_signature_envelope.v1"
	SigningLedgerReceiptSchemaVersion  = "redevplugin.release_signing_ledger_receipt.v1"

	SignatureAlgorithmEd25519 = "ed25519"

	GenesisPreviousEpoch          = "0"
	GenesisPreviousDocumentSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
)

type SigningLedgerEvidenceV1 struct {
	SchemaVersion           string `json:"schema_version"`
	SourceID                string `json:"source_id"`
	Channel                 string `json:"channel,omitempty"`
	SubjectIdentitySHA256   string `json:"subject_identity_sha256"`
	SigningPreimageSHA256   string `json:"signing_preimage_sha256"`
	SignatureEnvelopeSHA256 string `json:"signature_envelope_sha256"`
	ReceiptRef              string `json:"receipt_ref"`
	ReceiptSHA256           string `json:"receipt_sha256"`
	CheckpointRef           string `json:"checkpoint_ref"`
	CheckpointSHA256        string `json:"checkpoint_sha256"`
	InclusionProofRef       string `json:"inclusion_proof_ref"`
	InclusionProofSHA256    string `json:"inclusion_proof_sha256"`
	LatestProofRef          string `json:"latest_proof_ref"`
	LatestProofSHA256       string `json:"latest_proof_sha256"`
	ConsistencyProofRef     string `json:"consistency_proof_ref,omitempty"`
	ConsistencyProofSHA256  string `json:"consistency_proof_sha256,omitempty"`
}

type SigningUsage string

const (
	SigningUsageRootDelegation      SigningUsage = "redevplugin.release-signing.root-delegation.v1"
	SigningUsagePackage             SigningUsage = "redevplugin.release-signing.package.v1"
	SigningUsageReleaseMetadata     SigningUsage = "redevplugin.release-signing.release-metadata.v1"
	SigningUsageSourcePolicy        SigningUsage = "redevplugin.release-signing.source-policy-document.v1"
	SigningUsageSourcePolicyPointer SigningUsage = "redevplugin.release-signing.source-policy-pointer.v1"
	SigningUsageRevocation          SigningUsage = "redevplugin.release-signing.revocation-document.v1"
	SigningUsageRevocationPointer   SigningUsage = "redevplugin.release-signing.revocation-pointer.v1"
	SigningUsageLedgerCheckpoint    SigningUsage = "redevplugin.release-signing.ledger-checkpoint.v1"
	SigningUsageLedgerReceipt       SigningUsage = "redevplugin.release-signing.ledger-receipt.v1"
)

type SigningSubjectUsage string

const (
	SigningSubjectUsageRootDelegation      SigningSubjectUsage = "root_delegation"
	SigningSubjectUsagePackage             SigningSubjectUsage = "package"
	SigningSubjectUsageReleaseMetadata     SigningSubjectUsage = "release_metadata"
	SigningSubjectUsageSourcePolicy        SigningSubjectUsage = "source_policy_document"
	SigningSubjectUsageSourcePolicyPointer SigningSubjectUsage = "source_policy_pointer"
	SigningSubjectUsageRevocation          SigningSubjectUsage = "revocation_document"
	SigningSubjectUsageRevocationPointer   SigningSubjectUsage = "revocation_pointer"
)

type SigningSubjectV1 struct {
	SchemaVersion          string              `json:"schema_version"`
	Usage                  SigningSubjectUsage `json:"usage"`
	SourceID               string              `json:"source_id"`
	Channel                string              `json:"channel,omitempty"`
	RootEpoch              string              `json:"root_epoch,omitempty"`
	PublisherID            string              `json:"publisher_id,omitempty"`
	PluginID               string              `json:"plugin_id,omitempty"`
	Version                string              `json:"version,omitempty"`
	ArtifactIdentitySHA256 string              `json:"artifact_or_metadata_identity_sha256,omitempty"`
	Epoch                  string              `json:"epoch,omitempty"`
}

type SignatureEnvelopeV1 struct {
	SchemaVersion         string `json:"schema_version"`
	SubjectIdentitySHA256 string `json:"subject_identity_sha256"`
	SigningPreimageSHA256 string `json:"signing_preimage_sha256"`
	Algorithm             string `json:"algorithm"`
	KeyID                 string `json:"key_id"`
	Signature             string `json:"signature"`
}

type SigningLedgerEntryState string

const (
	SigningLedgerEntryReserved       SigningLedgerEntryState = "reserved"
	SigningLedgerEntryFinalized      SigningLedgerEntryState = "finalized"
	SigningLedgerEntryTerminalFailed SigningLedgerEntryState = "terminal_failed"
)

type SigningLedgerFailureCode string

const (
	SigningLedgerFailureSignerRejected  SigningLedgerFailureCode = "signer_rejected"
	SigningLedgerFailureSubjectConflict SigningLedgerFailureCode = "subject_conflict"
	SigningLedgerFailureLedgerRejected  SigningLedgerFailureCode = "ledger_rejected"
)

type SigningLedgerEntryV1 struct {
	SchemaVersion           string                   `json:"schema_version"`
	State                   SigningLedgerEntryState  `json:"state"`
	Subject                 SigningSubjectV1         `json:"subject"`
	SubjectIdentitySHA256   string                   `json:"subject_identity_sha256"`
	SigningPreimageSHA256   string                   `json:"signing_preimage_sha256"`
	Algorithm               string                   `json:"algorithm"`
	KeyID                   string                   `json:"key_id"`
	Revision                uint64                   `json:"revision"`
	ReservedAt              string                   `json:"reserved_at"`
	SignatureEnvelope       *SignatureEnvelopeV1     `json:"signature_envelope,omitempty"`
	SignatureEnvelopeSHA256 string                   `json:"signature_envelope_sha256,omitempty"`
	FinalizedAt             string                   `json:"finalized_at,omitempty"`
	FailureCode             SigningLedgerFailureCode `json:"failure_code,omitempty"`
	FailedAt                string                   `json:"failed_at,omitempty"`
}

type SigningLedgerArtifactKind string

const (
	SigningLedgerArtifactCheckpoint       SigningLedgerArtifactKind = "checkpoint"
	SigningLedgerArtifactInclusionProof   SigningLedgerArtifactKind = "inclusion_proof"
	SigningLedgerArtifactLatestProof      SigningLedgerArtifactKind = "latest_proof"
	SigningLedgerArtifactConsistencyProof SigningLedgerArtifactKind = "consistency_proof"
)

const SigningLedgerLatestProofDepth = 256

type SigningLedgerCheckpointV1 struct {
	SchemaVersion     string                    `json:"schema_version"`
	Kind              SigningLedgerArtifactKind `json:"kind"`
	LogID             string                    `json:"log_id"`
	TreeSize          uint64                    `json:"tree_size"`
	LogRootHash       string                    `json:"log_root_hash"`
	LatestMapRootHash string                    `json:"latest_map_root_hash"`
	CheckpointTime    string                    `json:"checkpoint_time"`
	KeyID             string                    `json:"key_id"`
	Signature         string                    `json:"signature"`
}

type SigningLedgerReceiptV1 struct {
	SchemaVersion           string `json:"schema_version"`
	LogID                   string `json:"log_id"`
	SourceID                string `json:"source_id"`
	Channel                 string `json:"channel,omitempty"`
	SubjectIdentitySHA256   string `json:"subject_identity_sha256"`
	SigningPreimageSHA256   string `json:"signing_preimage_sha256"`
	SignatureEnvelopeSHA256 string `json:"signature_envelope_sha256"`
	Sequence                uint64 `json:"sequence"`
	LeafIndex               uint64 `json:"leaf_index"`
	TreeSize                uint64 `json:"tree_size"`
	LogRootHash             string `json:"log_root_hash"`
	LatestMapRootHash       string `json:"latest_map_root_hash"`
	CheckpointSHA256        string `json:"checkpoint_sha256"`
	CheckpointTime          string `json:"checkpoint_time"`
	KeyID                   string `json:"key_id"`
	Signature               string `json:"signature"`
}

type SigningLedgerLogLeafV1 struct {
	SchemaVersion           string `json:"schema_version"`
	SourceID                string `json:"source_id"`
	Channel                 string `json:"channel,omitempty"`
	SubjectIdentitySHA256   string `json:"subject_identity_sha256"`
	SigningPreimageSHA256   string `json:"signing_preimage_sha256"`
	SignatureEnvelopeSHA256 string `json:"signature_envelope_sha256"`
	Sequence                uint64 `json:"sequence"`
}

type SigningLedgerInclusionProofV1 struct {
	SchemaVersion string                    `json:"schema_version"`
	Kind          SigningLedgerArtifactKind `json:"kind"`
	LogID         string                    `json:"log_id"`
	LeafIndex     uint64                    `json:"leaf_index"`
	TreeSize      uint64                    `json:"tree_size"`
	Nodes         []string                  `json:"nodes"`
}

type SigningLedgerLatestProofV1 struct {
	SchemaVersion           string                    `json:"schema_version"`
	Kind                    SigningLedgerArtifactKind `json:"kind"`
	LogID                   string                    `json:"log_id"`
	SubjectIdentitySHA256   string                    `json:"subject_identity_sha256"`
	Present                 bool                      `json:"present"`
	Sequence                uint64                    `json:"sequence,omitempty"`
	SigningPreimageSHA256   string                    `json:"signing_preimage_sha256,omitempty"`
	SignatureEnvelopeSHA256 string                    `json:"signature_envelope_sha256,omitempty"`
	Siblings                []string                  `json:"siblings"`
}

type SigningLedgerConsistencyProofV1 struct {
	SchemaVersion string                    `json:"schema_version"`
	Kind          SigningLedgerArtifactKind `json:"kind"`
	LogID         string                    `json:"log_id"`
	OldTreeSize   uint64                    `json:"old_tree_size"`
	NewTreeSize   uint64                    `json:"new_tree_size"`
	Nodes         []string                  `json:"nodes"`
}

type DelegatedKeyUsage string

const (
	DelegatedKeyUsagePackage                DelegatedKeyUsage = "package"
	DelegatedKeyUsageReleaseMetadata        DelegatedKeyUsage = "release_metadata"
	DelegatedKeyUsageHostCapabilityContract DelegatedKeyUsage = "host_capability_contract"
	DelegatedKeyUsageSourcePolicy           DelegatedKeyUsage = "source_policy_document"
	DelegatedKeyUsageSourcePolicyPointer    DelegatedKeyUsage = "source_policy_pointer"
	DelegatedKeyUsageRevocation             DelegatedKeyUsage = "revocation_document"
	DelegatedKeyUsageRevocationPointer      DelegatedKeyUsage = "revocation_pointer"
	DelegatedKeyUsageSigningLedger          DelegatedKeyUsage = "signing_ledger"
	DelegatedKeyUsageTrustedTime            DelegatedKeyUsage = "trusted_time"
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
	Package                []string `json:"package"`
	ReleaseMetadata        []string `json:"release_metadata"`
	HostCapabilityContract []string `json:"host_capability_contract"`
	SourcePolicyPointer    []string `json:"source_policy_pointer"`
	Revocation             []string `json:"revocation_document"`
	RevocationPointer      []string `json:"revocation_pointer"`
}

type SourcePolicyCapabilityPublisherScope struct {
	KeyID             string   `json:"key_id"`
	AllowedPublishers []string `json:"allowed_publishers"`
}

type SourcePolicyInput struct {
	SourceID                  string
	Channel                   string
	Epoch                     string
	PreviousEpoch             string
	PreviousDocumentSHA256    string
	RootEpoch                 string
	SourceType                string
	SourceClass               string
	AllowedPublishers         []string
	AllowedArtifactHosts      []string
	ActiveKeys                SourcePolicyActiveKeys
	CapabilityPublisherScopes []SourcePolicyCapabilityPublisherScope
	RequireSignature          bool
	InstallPolicy             string
	UnsignedPolicy            string
	DowngradePolicy           string
	MinimumRevocationEpoch    string
	Limits                    SourcePolicyLimits
	GeneratedAt               string
	ExpiresAt                 string
	KeyID                     string
}

type SourcePolicyV2 struct {
	SchemaVersion             string                                 `json:"schema_version"`
	SourceID                  string                                 `json:"source_id"`
	Channel                   string                                 `json:"channel"`
	Epoch                     string                                 `json:"epoch"`
	PreviousEpoch             string                                 `json:"previous_epoch"`
	PreviousDocumentSHA256    string                                 `json:"previous_document_sha256"`
	RootEpoch                 string                                 `json:"root_epoch"`
	SourceType                string                                 `json:"source_type"`
	SourceClass               string                                 `json:"source_class"`
	AllowedPublishers         []string                               `json:"allowed_publishers"`
	AllowedArtifactHosts      []string                               `json:"allowed_artifact_hosts"`
	ActiveKeys                SourcePolicyActiveKeys                 `json:"active_keys"`
	CapabilityPublisherScopes []SourcePolicyCapabilityPublisherScope `json:"capability_publisher_scopes"`
	RequireSignature          bool                                   `json:"require_signature"`
	InstallPolicy             string                                 `json:"install_policy"`
	UnsignedPolicy            string                                 `json:"unsigned_policy"`
	DowngradePolicy           string                                 `json:"downgrade_policy"`
	MinimumRevocationEpoch    string                                 `json:"minimum_revocation_epoch"`
	Limits                    SourcePolicyLimits                     `json:"limits"`
	GeneratedAt               string                                 `json:"generated_at"`
	ExpiresAt                 string                                 `json:"expires_at"`
	KeyID                     string                                 `json:"key_id"`
	Signature                 string                                 `json:"signature"`
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
