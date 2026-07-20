use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub const ROOT_DELEGATION_SCHEMA_VERSION: &str = "redevplugin.release_root_delegation.v1";
pub const PACKAGE_SIGNATURE_SCHEMA_VERSION: &str = "redevplugin.package_signature.v1";
pub const RELEASE_METADATA_SCHEMA_VERSION: &str = "redevplugin.release_metadata.v5";
pub const SOURCE_POLICY_SCHEMA_VERSION: &str = "redevplugin.release_source_policy.v2";
pub const SOURCE_POLICY_POINTER_SCHEMA_VERSION: &str =
    "redevplugin.release_source_policy_pointer.v1";
pub const REVOCATION_SCHEMA_VERSION: &str = "redevplugin.release_revocation.v2";
pub const REVOCATION_POINTER_SCHEMA_VERSION: &str = "redevplugin.release_revocation_pointer.v1";
pub const SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
pub const GENESIS_PREVIOUS_EPOCH: &str = "0";
pub const GENESIS_PREVIOUS_DOCUMENT_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const SIGNING_PREFIX: &[u8] = b"REDEVPLUGIN-SIGNING-V1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SigningUsage {
    RootDelegation,
    Package,
    ReleaseMetadata,
    SourcePolicy,
    SourcePolicyPointer,
    Revocation,
    RevocationPointer,
}

impl SigningUsage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootDelegation => "redevplugin.release-signing.root-delegation.v1",
            Self::Package => "redevplugin.release-signing.package.v1",
            Self::ReleaseMetadata => "redevplugin.release-signing.release-metadata.v1",
            Self::SourcePolicy => "redevplugin.release-signing.source-policy-document.v1",
            Self::SourcePolicyPointer => "redevplugin.release-signing.source-policy-pointer.v1",
            Self::Revocation => "redevplugin.release-signing.revocation-document.v1",
            Self::RevocationPointer => "redevplugin.release-signing.revocation-pointer.v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum DelegatedKeyUsage {
    #[serde(rename = "package")]
    Package,
    #[serde(rename = "release_metadata")]
    ReleaseMetadata,
    #[serde(rename = "source_policy_document")]
    SourcePolicy,
    #[serde(rename = "source_policy_pointer")]
    SourcePolicyPointer,
    #[serde(rename = "revocation_document")]
    Revocation,
    #[serde(rename = "revocation_pointer")]
    RevocationPointer,
}

impl DelegatedKeyUsage {
    const fn rank(self) -> u8 {
        match self {
            Self::Package => 0,
            Self::ReleaseMetadata => 1,
            Self::Revocation => 2,
            Self::RevocationPointer => 3,
            Self::SourcePolicy => 4,
            Self::SourcePolicyPointer => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootDelegatedKey {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub usages: Vec<DelegatedKeyUsage>,
    pub channels: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootDelegationInput {
    pub source_id: String,
    pub root_epoch: String,
    pub previous_root_epoch: String,
    pub previous_delegation_sha256: String,
    pub generated_at: String,
    pub expires_at: String,
    pub delegated_keys: Vec<RootDelegatedKey>,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootDelegationV1 {
    pub schema_version: String,
    pub source_id: String,
    pub root_epoch: String,
    pub previous_root_epoch: String,
    pub previous_delegation_sha256: String,
    pub generated_at: String,
    pub expires_at: String,
    pub delegated_keys: Vec<RootDelegatedKey>,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSigningInput {
    pub source_id: String,
    pub channel: String,
    pub version: String,
    pub algorithm: String,
    pub key_id: String,
    pub publisher_id: String,
    pub plugin_id: String,
    pub package_hash: String,
    pub manifest_hash: String,
    pub entries_hash: String,
    pub signed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageVerificationContext {
    pub source_id: String,
    pub channel: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSignatureV1 {
    pub schema_version: String,
    pub algorithm: String,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    pub package_hash: String,
    pub manifest_hash: String,
    pub entries_hash: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseDistributionRef {
    pub distribution: String,
    pub artifact_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePackageHashSet {
    pub package_sha256: String,
    pub manifest_sha256: String,
    pub entries_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadataSignatureRef {
    pub algorithm: String,
    pub key_id: String,
    pub signature_ref: String,
    pub source_policy_epoch: String,
    pub revocation_epoch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageReleaseSignatureRef {
    pub algorithm: String,
    pub key_id: String,
    pub signature_bundle_ref: String,
    pub source_policy_epoch: String,
    pub revocation_epoch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibility {
    pub min_redevplugin_version: String,
    pub min_runtime_version: String,
    pub ui_protocol_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_targets: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapabilityContractRef {
    pub publisher_id: String,
    pub contract_id: String,
    pub contract_version: String,
    pub artifact_ref: String,
    pub artifact_sha256: String,
    pub manifest_ref: String,
    pub manifest_sha256: String,
    pub signature_ref: String,
    pub signature_sha256: String,
    pub signature_key_id: String,
    pub signature_policy_epoch: String,
    pub signature_revocation_epoch: String,
    pub compatibility_ref: String,
    pub compatibility_sha256: String,
    pub generated_client_ref: String,
    pub generated_client_sha256: String,
    pub notices_ref: String,
    pub notices_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapabilityRequirementRef {
    pub capability_id: String,
    pub capability_version: String,
    pub contract: HostCapabilityContractRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseHostRequirement {
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_host_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_capability_contracts: Option<Vec<HostCapabilityRequirementRef>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notices_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadataV5 {
    pub schema_version: String,
    pub source_id: String,
    pub release_metadata_ref: String,
    pub publisher_id: String,
    pub plugin_id: String,
    pub version: String,
    pub distribution_ref: ReleaseDistributionRef,
    pub hashes: ReleasePackageHashSet,
    pub release_metadata_signature: ReleaseMetadataSignatureRef,
    pub package_signature: PackageReleaseSignatureRef,
    pub compatibility: ReleaseCompatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_requirements: Option<Vec<ReleaseHostRequirement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_evidence: Option<ReleaseEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicyLimits {
    pub document_max_lifetime_seconds: u32,
    pub future_skew_seconds: u32,
    pub activation_lease_max_seconds: u32,
    pub refresh_interval_max_seconds: u32,
    pub failure_teardown_deadline_seconds: u32,
}

impl Default for SourcePolicyLimits {
    fn default() -> Self {
        Self {
            document_max_lifetime_seconds: 86_400,
            future_skew_seconds: 300,
            activation_lease_max_seconds: 300,
            refresh_interval_max_seconds: 60,
            failure_teardown_deadline_seconds: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicyActiveKeys {
    pub package: Vec<String>,
    pub release_metadata: Vec<String>,
    pub source_policy_pointer: Vec<String>,
    pub revocation_document: Vec<String>,
    pub revocation_pointer: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePolicyInput {
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    pub root_epoch: String,
    pub source_type: String,
    pub source_class: String,
    pub allowed_publishers: Vec<String>,
    pub allowed_artifact_hosts: Vec<String>,
    pub active_keys: SourcePolicyActiveKeys,
    pub require_signature: bool,
    pub install_policy: String,
    pub unsigned_policy: String,
    pub downgrade_policy: String,
    pub minimum_revocation_epoch: String,
    pub limits: SourcePolicyLimits,
    pub generated_at: String,
    pub expires_at: String,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicyV2 {
    pub schema_version: String,
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    pub root_epoch: String,
    pub source_type: String,
    pub source_class: String,
    pub allowed_publishers: Vec<String>,
    pub allowed_artifact_hosts: Vec<String>,
    pub active_keys: SourcePolicyActiveKeys,
    pub require_signature: bool,
    pub install_policy: String,
    pub unsigned_policy: String,
    pub downgrade_policy: String,
    pub minimum_revocation_epoch: String,
    pub limits: SourcePolicyLimits,
    pub generated_at: String,
    pub expires_at: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePointerInput {
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    pub r#ref: String,
    pub document_sha256: String,
    pub generated_at: String,
    pub expires_at: String,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicyPointerV1 {
    pub schema_version: String,
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    #[serde(rename = "ref")]
    pub r#ref: String,
    pub document_sha256: String,
    pub generated_at: String,
    pub expires_at: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedRelease {
    pub publisher_id: String,
    pub plugin_id: String,
    pub version: String,
    pub release_metadata_sha256: String,
    pub revoked_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationInput {
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    pub root_epoch: String,
    pub generated_at: String,
    pub expires_at: String,
    pub revoked_key_ids: Vec<String>,
    pub revoked_releases: Vec<RevokedRelease>,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationV2 {
    pub schema_version: String,
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    pub root_epoch: String,
    pub generated_at: String,
    pub expires_at: String,
    pub revoked_key_ids: Vec<String>,
    pub revoked_releases: Vec<RevokedRelease>,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPointerV1 {
    pub schema_version: String,
    pub source_id: String,
    pub channel: String,
    pub epoch: String,
    pub previous_epoch: String,
    pub previous_document_sha256: String,
    #[serde(rename = "ref")]
    pub r#ref: String,
    pub document_sha256: String,
    pub generated_at: String,
    pub expires_at: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseContractError {
    InvalidDocument,
    InvalidSignature,
}

impl fmt::Display for ReleaseContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDocument => formatter.write_str("release contract document is invalid"),
            Self::InvalidSignature => formatter.write_str("release contract signature is invalid"),
        }
    }
}

impl Error for ReleaseContractError {}

#[derive(Clone, Copy, Debug)]
pub struct SignatureVerificationRequest<'a> {
    pub usage: SigningUsage,
    pub key_id: &'a str,
    pub preimage: &'a [u8],
    pub signature: &'a [u8],
}

pub trait SignatureVerifier {
    fn verify_signature(&self, request: SignatureVerificationRequest<'_>) -> bool;
}

impl<F> SignatureVerifier for F
where
    F: for<'a> Fn(SignatureVerificationRequest<'a>) -> bool,
{
    fn verify_signature(&self, request: SignatureVerificationRequest<'_>) -> bool {
        self(request)
    }
}

pub fn build_root_delegation(
    input: &RootDelegationInput,
    signature: &[u8],
) -> Result<RootDelegationV1, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = root_delegation_from_input(input, encode_signature(signature));
    validate_root_delegation(&document, true)?;
    Ok(document)
}

pub fn root_delegation_signing_preimage(
    input: &RootDelegationInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    let document = root_delegation_from_input(input, String::new());
    validate_root_delegation(&document, false)?;
    preimage_without_top_level_signature(SigningUsage::RootDelegation, &document)
}

pub fn canonical_root_delegation(
    document: &RootDelegationV1,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_root_delegation(document, true)?;
    canonical_json(document)
}

pub fn verify_root_delegation(
    document: &RootDelegationV1,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let input = RootDelegationInput {
        source_id: document.source_id.clone(),
        root_epoch: document.root_epoch.clone(),
        previous_root_epoch: document.previous_root_epoch.clone(),
        previous_delegation_sha256: document.previous_delegation_sha256.clone(),
        generated_at: document.generated_at.clone(),
        expires_at: document.expires_at.clone(),
        delegated_keys: document.delegated_keys.clone(),
        key_id: document.key_id.clone(),
    };
    verify_encoded_signature(
        SigningUsage::RootDelegation,
        &document.key_id,
        &root_delegation_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn build_package_signature(
    input: &PackageSigningInput,
    signature: &[u8],
) -> Result<PackageSignatureV1, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = PackageSignatureV1 {
        schema_version: PACKAGE_SIGNATURE_SCHEMA_VERSION.to_owned(),
        algorithm: input.algorithm.clone(),
        key_id: input.key_id.clone(),
        publisher_id: Some(input.publisher_id.clone()),
        plugin_id: Some(input.plugin_id.clone()),
        package_hash: input.package_hash.clone(),
        manifest_hash: input.manifest_hash.clone(),
        entries_hash: input.entries_hash.clone(),
        signature: encode_signature(signature),
        signed_at: Some(input.signed_at.clone()),
    };
    validate_package_signature(
        &PackageVerificationContext {
            source_id: input.source_id.clone(),
            channel: input.channel.clone(),
            version: input.version.clone(),
        },
        &document,
        true,
    )?;
    Ok(document)
}

pub fn package_signing_preimage(
    input: &PackageSigningInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_package_input(input)?;
    let payload = serde_json::json!({
        "channel": input.channel,
        "package_signature": {
            "algorithm": input.algorithm,
            "entries_hash": input.entries_hash,
            "key_id": input.key_id,
            "manifest_hash": input.manifest_hash,
            "package_hash": input.package_hash,
            "plugin_id": input.plugin_id,
            "publisher_id": input.publisher_id,
            "schema_version": PACKAGE_SIGNATURE_SCHEMA_VERSION,
            "signed_at": input.signed_at,
        },
        "source_id": input.source_id,
        "version": input.version,
    });
    signing_preimage(SigningUsage::Package, &payload)
}

pub fn canonical_package_signature(
    context: &PackageVerificationContext,
    document: &PackageSignatureV1,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_package_signature(context, document, true)?;
    canonical_json(document)
}

pub fn verify_package_signature(
    context: &PackageVerificationContext,
    document: &PackageSignatureV1,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    validate_package_signature(context, document, true)?;
    let input = package_input_from_document(context, document)?;
    verify_encoded_signature(
        SigningUsage::Package,
        &document.key_id,
        &package_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn build_release_metadata(
    document: &ReleaseMetadataV5,
) -> Result<ReleaseMetadataV5, ReleaseContractError> {
    validate_release_metadata(document)?;
    Ok(document.clone())
}

pub fn release_metadata_signing_preimage(
    channel: &str,
    document: &ReleaseMetadataV5,
) -> Result<Vec<u8>, ReleaseContractError> {
    if !valid_new_id(channel) {
        return Err(ReleaseContractError::InvalidDocument);
    }
    let built = build_release_metadata(document)?;
    let payload = serde_json::json!({"channel": channel, "release_metadata": built});
    signing_preimage(SigningUsage::ReleaseMetadata, &payload)
}

pub fn canonical_release_metadata(
    document: &ReleaseMetadataV5,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_release_metadata(document)?;
    canonical_json(document)
}

pub fn verify_release_metadata(
    channel: &str,
    document: &ReleaseMetadataV5,
    signature: &[u8],
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    require_signature_bytes(signature).map_err(|_| ReleaseContractError::InvalidSignature)?;
    verify_raw_signature(
        SigningUsage::ReleaseMetadata,
        &document.release_metadata_signature.key_id,
        &release_metadata_signing_preimage(channel, document)?,
        signature,
        verifier,
    )
}

pub fn build_source_policy(
    input: &SourcePolicyInput,
    signature: &[u8],
) -> Result<SourcePolicyV2, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = source_policy_from_input(input, encode_signature(signature));
    validate_source_policy(&document, true)?;
    Ok(document)
}

pub fn source_policy_signing_preimage(
    input: &SourcePolicyInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    let document = source_policy_from_input(input, String::new());
    validate_source_policy(&document, false)?;
    preimage_without_top_level_signature(SigningUsage::SourcePolicy, &document)
}

pub fn canonical_source_policy(document: &SourcePolicyV2) -> Result<Vec<u8>, ReleaseContractError> {
    validate_source_policy(document, true)?;
    canonical_json(document)
}

pub fn verify_source_policy(
    document: &SourcePolicyV2,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let input = source_policy_input_from_document(document);
    verify_encoded_signature(
        SigningUsage::SourcePolicy,
        &document.key_id,
        &source_policy_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn build_source_policy_pointer(
    input: &ReleasePointerInput,
    signature: &[u8],
) -> Result<SourcePolicyPointerV1, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = SourcePolicyPointerV1 {
        schema_version: SOURCE_POLICY_POINTER_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        r#ref: input.r#ref.clone(),
        document_sha256: input.document_sha256.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        key_id: input.key_id.clone(),
        signature: encode_signature(signature),
    };
    validate_source_policy_pointer(&document, true)?;
    Ok(document)
}

pub fn source_policy_pointer_signing_preimage(
    input: &ReleasePointerInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    let document = SourcePolicyPointerV1 {
        schema_version: SOURCE_POLICY_POINTER_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        r#ref: input.r#ref.clone(),
        document_sha256: input.document_sha256.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        key_id: input.key_id.clone(),
        signature: String::new(),
    };
    validate_source_policy_pointer(&document, false)?;
    preimage_without_top_level_signature(SigningUsage::SourcePolicyPointer, &document)
}

pub fn canonical_source_policy_pointer(
    document: &SourcePolicyPointerV1,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_source_policy_pointer(document, true)?;
    canonical_json(document)
}

pub fn verify_source_policy_pointer(
    document: &SourcePolicyPointerV1,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let input = pointer_input_from_source_policy(document);
    verify_encoded_signature(
        SigningUsage::SourcePolicyPointer,
        &document.key_id,
        &source_policy_pointer_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn build_revocation(
    input: &RevocationInput,
    signature: &[u8],
) -> Result<RevocationV2, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = revocation_from_input(input, encode_signature(signature));
    validate_revocation(&document, true)?;
    Ok(document)
}

pub fn revocation_signing_preimage(
    input: &RevocationInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    let document = revocation_from_input(input, String::new());
    validate_revocation(&document, false)?;
    preimage_without_top_level_signature(SigningUsage::Revocation, &document)
}

pub fn canonical_revocation(document: &RevocationV2) -> Result<Vec<u8>, ReleaseContractError> {
    validate_revocation(document, true)?;
    canonical_json(document)
}

pub fn verify_revocation(
    document: &RevocationV2,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let input = revocation_input_from_document(document);
    verify_encoded_signature(
        SigningUsage::Revocation,
        &document.key_id,
        &revocation_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn build_revocation_pointer(
    input: &ReleasePointerInput,
    signature: &[u8],
) -> Result<RevocationPointerV1, ReleaseContractError> {
    require_signature_bytes(signature)?;
    let document = RevocationPointerV1 {
        schema_version: REVOCATION_POINTER_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        r#ref: input.r#ref.clone(),
        document_sha256: input.document_sha256.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        key_id: input.key_id.clone(),
        signature: encode_signature(signature),
    };
    validate_revocation_pointer(&document, true)?;
    Ok(document)
}

pub fn revocation_pointer_signing_preimage(
    input: &ReleasePointerInput,
) -> Result<Vec<u8>, ReleaseContractError> {
    let document = RevocationPointerV1 {
        schema_version: REVOCATION_POINTER_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        r#ref: input.r#ref.clone(),
        document_sha256: input.document_sha256.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        key_id: input.key_id.clone(),
        signature: String::new(),
    };
    validate_revocation_pointer(&document, false)?;
    preimage_without_top_level_signature(SigningUsage::RevocationPointer, &document)
}

pub fn canonical_revocation_pointer(
    document: &RevocationPointerV1,
) -> Result<Vec<u8>, ReleaseContractError> {
    validate_revocation_pointer(document, true)?;
    canonical_json(document)
}

pub fn verify_revocation_pointer(
    document: &RevocationPointerV1,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let input = pointer_input_from_revocation(document);
    verify_encoded_signature(
        SigningUsage::RevocationPointer,
        &document.key_id,
        &revocation_pointer_signing_preimage(&input)?,
        &document.signature,
        verifier,
    )
}

pub fn decode_root_delegation(raw: &[u8]) -> Result<RootDelegationV1, ReleaseContractError> {
    decode_canonical_document(raw, |value| validate_root_delegation(value, true))
}

pub fn decode_package_signature(
    raw: &[u8],
    context: &PackageVerificationContext,
) -> Result<PackageSignatureV1, ReleaseContractError> {
    decode_canonical_document(raw, |value| {
        validate_package_signature(context, value, true)
    })
}

pub fn decode_release_metadata(raw: &[u8]) -> Result<ReleaseMetadataV5, ReleaseContractError> {
    decode_canonical_document(raw, validate_release_metadata)
}

pub fn decode_source_policy(raw: &[u8]) -> Result<SourcePolicyV2, ReleaseContractError> {
    decode_canonical_document(raw, |value| validate_source_policy(value, true))
}

pub fn decode_source_policy_pointer(
    raw: &[u8],
) -> Result<SourcePolicyPointerV1, ReleaseContractError> {
    decode_canonical_document(raw, |value| validate_source_policy_pointer(value, true))
}

pub fn decode_revocation(raw: &[u8]) -> Result<RevocationV2, ReleaseContractError> {
    decode_canonical_document(raw, |value| validate_revocation(value, true))
}

pub fn decode_revocation_pointer(raw: &[u8]) -> Result<RevocationPointerV1, ReleaseContractError> {
    decode_canonical_document(raw, |value| validate_revocation_pointer(value, true))
}

fn root_delegation_from_input(input: &RootDelegationInput, signature: String) -> RootDelegationV1 {
    RootDelegationV1 {
        schema_version: ROOT_DELEGATION_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        root_epoch: input.root_epoch.clone(),
        previous_root_epoch: input.previous_root_epoch.clone(),
        previous_delegation_sha256: input.previous_delegation_sha256.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        delegated_keys: input.delegated_keys.clone(),
        key_id: input.key_id.clone(),
        signature,
    }
}

fn source_policy_from_input(input: &SourcePolicyInput, signature: String) -> SourcePolicyV2 {
    SourcePolicyV2 {
        schema_version: SOURCE_POLICY_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        root_epoch: input.root_epoch.clone(),
        source_type: input.source_type.clone(),
        source_class: input.source_class.clone(),
        allowed_publishers: input.allowed_publishers.clone(),
        allowed_artifact_hosts: input.allowed_artifact_hosts.clone(),
        active_keys: input.active_keys.clone(),
        require_signature: input.require_signature,
        install_policy: input.install_policy.clone(),
        unsigned_policy: input.unsigned_policy.clone(),
        downgrade_policy: input.downgrade_policy.clone(),
        minimum_revocation_epoch: input.minimum_revocation_epoch.clone(),
        limits: input.limits,
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        key_id: input.key_id.clone(),
        signature,
    }
}

fn revocation_from_input(input: &RevocationInput, signature: String) -> RevocationV2 {
    RevocationV2 {
        schema_version: REVOCATION_SCHEMA_VERSION.to_owned(),
        source_id: input.source_id.clone(),
        channel: input.channel.clone(),
        epoch: input.epoch.clone(),
        previous_epoch: input.previous_epoch.clone(),
        previous_document_sha256: input.previous_document_sha256.clone(),
        root_epoch: input.root_epoch.clone(),
        generated_at: input.generated_at.clone(),
        expires_at: input.expires_at.clone(),
        revoked_key_ids: input.revoked_key_ids.clone(),
        revoked_releases: input.revoked_releases.clone(),
        key_id: input.key_id.clone(),
        signature,
    }
}

fn package_input_from_document(
    context: &PackageVerificationContext,
    document: &PackageSignatureV1,
) -> Result<PackageSigningInput, ReleaseContractError> {
    Ok(PackageSigningInput {
        source_id: context.source_id.clone(),
        channel: context.channel.clone(),
        version: context.version.clone(),
        algorithm: document.algorithm.clone(),
        key_id: document.key_id.clone(),
        publisher_id: document
            .publisher_id
            .clone()
            .ok_or(ReleaseContractError::InvalidDocument)?,
        plugin_id: document
            .plugin_id
            .clone()
            .ok_or(ReleaseContractError::InvalidDocument)?,
        package_hash: document.package_hash.clone(),
        manifest_hash: document.manifest_hash.clone(),
        entries_hash: document.entries_hash.clone(),
        signed_at: document
            .signed_at
            .clone()
            .ok_or(ReleaseContractError::InvalidDocument)?,
    })
}

fn source_policy_input_from_document(document: &SourcePolicyV2) -> SourcePolicyInput {
    SourcePolicyInput {
        source_id: document.source_id.clone(),
        channel: document.channel.clone(),
        epoch: document.epoch.clone(),
        previous_epoch: document.previous_epoch.clone(),
        previous_document_sha256: document.previous_document_sha256.clone(),
        root_epoch: document.root_epoch.clone(),
        source_type: document.source_type.clone(),
        source_class: document.source_class.clone(),
        allowed_publishers: document.allowed_publishers.clone(),
        allowed_artifact_hosts: document.allowed_artifact_hosts.clone(),
        active_keys: document.active_keys.clone(),
        require_signature: document.require_signature,
        install_policy: document.install_policy.clone(),
        unsigned_policy: document.unsigned_policy.clone(),
        downgrade_policy: document.downgrade_policy.clone(),
        minimum_revocation_epoch: document.minimum_revocation_epoch.clone(),
        limits: document.limits,
        generated_at: document.generated_at.clone(),
        expires_at: document.expires_at.clone(),
        key_id: document.key_id.clone(),
    }
}

fn revocation_input_from_document(document: &RevocationV2) -> RevocationInput {
    RevocationInput {
        source_id: document.source_id.clone(),
        channel: document.channel.clone(),
        epoch: document.epoch.clone(),
        previous_epoch: document.previous_epoch.clone(),
        previous_document_sha256: document.previous_document_sha256.clone(),
        root_epoch: document.root_epoch.clone(),
        generated_at: document.generated_at.clone(),
        expires_at: document.expires_at.clone(),
        revoked_key_ids: document.revoked_key_ids.clone(),
        revoked_releases: document.revoked_releases.clone(),
        key_id: document.key_id.clone(),
    }
}

fn pointer_input_from_source_policy(document: &SourcePolicyPointerV1) -> ReleasePointerInput {
    ReleasePointerInput {
        source_id: document.source_id.clone(),
        channel: document.channel.clone(),
        epoch: document.epoch.clone(),
        previous_epoch: document.previous_epoch.clone(),
        previous_document_sha256: document.previous_document_sha256.clone(),
        r#ref: document.r#ref.clone(),
        document_sha256: document.document_sha256.clone(),
        generated_at: document.generated_at.clone(),
        expires_at: document.expires_at.clone(),
        key_id: document.key_id.clone(),
    }
}

fn pointer_input_from_revocation(document: &RevocationPointerV1) -> ReleasePointerInput {
    ReleasePointerInput {
        source_id: document.source_id.clone(),
        channel: document.channel.clone(),
        epoch: document.epoch.clone(),
        previous_epoch: document.previous_epoch.clone(),
        previous_document_sha256: document.previous_document_sha256.clone(),
        r#ref: document.r#ref.clone(),
        document_sha256: document.document_sha256.clone(),
        generated_at: document.generated_at.clone(),
        expires_at: document.expires_at.clone(),
        key_id: document.key_id.clone(),
    }
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ReleaseContractError> {
    let value = serde_json::to_value(value).map_err(|_| ReleaseContractError::InvalidDocument)?;
    validate_canonical_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| ReleaseContractError::InvalidDocument)
}

fn validate_canonical_value(value: &Value) -> Result<(), ReleaseContractError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) if number.as_u64().is_some() => Ok(()),
        Value::Array(values) => values.iter().try_for_each(validate_canonical_value),
        Value::Object(values) => values.values().try_for_each(validate_canonical_value),
        _ => Err(ReleaseContractError::InvalidDocument),
    }
}

fn signing_preimage(
    usage: SigningUsage,
    value: &impl Serialize,
) -> Result<Vec<u8>, ReleaseContractError> {
    let payload = canonical_json(value)?;
    let mut preimage =
        Vec::with_capacity(SIGNING_PREFIX.len() + usage.as_str().len() + 1 + payload.len());
    preimage.extend_from_slice(SIGNING_PREFIX);
    preimage.extend_from_slice(usage.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&payload);
    Ok(preimage)
}

fn preimage_without_top_level_signature(
    usage: SigningUsage,
    document: &impl Serialize,
) -> Result<Vec<u8>, ReleaseContractError> {
    let mut value =
        serde_json::to_value(document).map_err(|_| ReleaseContractError::InvalidDocument)?;
    let object = value
        .as_object_mut()
        .ok_or(ReleaseContractError::InvalidDocument)?;
    object.remove("signature");
    signing_preimage(usage, &value)
}

fn decode_canonical_document<T>(
    raw: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ReleaseContractError>,
) -> Result<T, ReleaseContractError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if raw.is_empty() || raw.len() > MAX_DOCUMENT_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(ReleaseContractError::InvalidDocument);
    }
    let document: T =
        serde_json::from_slice(raw).map_err(|_| ReleaseContractError::InvalidDocument)?;
    validate(&document)?;
    if canonical_json(&document)? != raw {
        return Err(ReleaseContractError::InvalidDocument);
    }
    Ok(document)
}

fn verify_encoded_signature(
    usage: SigningUsage,
    key_id: &str,
    preimage: &[u8],
    encoded_signature: &str,
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    let signature =
        decode_signature(encoded_signature).map_err(|_| ReleaseContractError::InvalidSignature)?;
    verify_raw_signature(usage, key_id, preimage, &signature, verifier)
}

fn verify_raw_signature(
    usage: SigningUsage,
    key_id: &str,
    preimage: &[u8],
    signature: &[u8],
    verifier: &impl SignatureVerifier,
) -> Result<(), ReleaseContractError> {
    if signature.len() != 64
        || !verifier.verify_signature(SignatureVerificationRequest {
            usage,
            key_id,
            preimage,
            signature,
        })
    {
        return Err(ReleaseContractError::InvalidSignature);
    }
    Ok(())
}

fn require_signature_bytes(signature: &[u8]) -> Result<(), ReleaseContractError> {
    if signature.len() != 64 {
        return Err(ReleaseContractError::InvalidDocument);
    }
    Ok(())
}

fn encode_signature(signature: &[u8]) -> String {
    BASE64_STANDARD.encode(signature)
}

fn decode_signature(value: &str) -> Result<Vec<u8>, ReleaseContractError> {
    if value.len() != 88 || !value.ends_with("==") {
        return Err(ReleaseContractError::InvalidDocument);
    }
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| ReleaseContractError::InvalidDocument)?;
    if decoded.len() != 64 || BASE64_STANDARD.encode(&decoded) != value {
        return Err(ReleaseContractError::InvalidDocument);
    }
    Ok(decoded)
}

fn validate_root_delegation(
    value: &RootDelegationV1,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    if value.schema_version != ROOT_DELEGATION_SCHEMA_VERSION
        || !valid_new_id(&value.source_id)
        || !valid_new_id(&value.key_id)
    {
        return invalid_document();
    }
    validate_epoch_chain(
        &value.root_epoch,
        &value.previous_root_epoch,
        &value.previous_delegation_sha256,
    )?;
    let (_, expires_at) = validate_time_range(&value.generated_at, &value.expires_at, None)?;
    if value.delegated_keys.is_empty() || value.delegated_keys.len() > 32 {
        return invalid_document();
    }
    let mut previous_key_id = "";
    for key in &value.delegated_keys {
        if key.algorithm != SIGNATURE_ALGORITHM_ED25519
            || !valid_new_id(&key.key_id)
            || key.key_id.as_str() <= previous_key_id
        {
            return invalid_document();
        }
        let public_key = BASE64_STANDARD
            .decode(&key.public_key)
            .map_err(|_| ReleaseContractError::InvalidDocument)?;
        if public_key.len() != 32 || BASE64_STANDARD.encode(&public_key) != key.public_key {
            return invalid_document();
        }
        if key.usages.is_empty() || key.usages.len() > 6 {
            return invalid_document();
        }
        let mut previous_usage = None;
        for usage in &key.usages {
            let rank = usage.rank();
            if previous_usage.is_some_and(|previous| rank <= previous) {
                return invalid_document();
            }
            previous_usage = Some(rank);
        }
        validate_sorted_ids(&key.channels, 1, 16, true)?;
        let (_, valid_until) = validate_time_range(&key.valid_from, &key.valid_until, None)?;
        if valid_until > expires_at {
            return invalid_document();
        }
        previous_key_id = &key.key_id;
    }
    validate_signature_field(&value.signature, require_signature)
}

fn validate_package_input(value: &PackageSigningInput) -> Result<(), ReleaseContractError> {
    if !valid_new_id(&value.source_id)
        || !valid_new_id(&value.channel)
        || value.algorithm != SIGNATURE_ALGORITHM_ED25519
        || !valid_new_id(&value.key_id)
        || !valid_legacy_id(&value.publisher_id)
        || !valid_legacy_id(&value.plugin_id)
        || !valid_semver(&value.version)
        || !valid_prefixed_sha256(&value.package_hash)
        || !valid_prefixed_sha256(&value.manifest_hash)
        || !valid_prefixed_sha256(&value.entries_hash)
        || canonical_timestamp_seconds(&value.signed_at).is_none()
    {
        return invalid_document();
    }
    Ok(())
}

fn validate_package_signature(
    context: &PackageVerificationContext,
    value: &PackageSignatureV1,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    if value.schema_version != PACKAGE_SIGNATURE_SCHEMA_VERSION {
        return invalid_document();
    }
    let input = package_input_from_document(context, value)?;
    validate_package_input(&input)?;
    validate_signature_field(&value.signature, require_signature)
}

fn validate_release_metadata(value: &ReleaseMetadataV5) -> Result<(), ReleaseContractError> {
    if value.schema_version != RELEASE_METADATA_SCHEMA_VERSION
        || !valid_new_id(&value.source_id)
        || !valid_legacy_id(&value.publisher_id)
        || !valid_legacy_id(&value.plugin_id)
        || !valid_semver(&value.version)
        || !valid_artifact_ref(&value.release_metadata_ref)
    {
        return invalid_document();
    }
    if !matches!(
        value.distribution_ref.distribution.as_str(),
        "registry_ref" | "host_artifact_ref"
    ) || !valid_artifact_ref(&value.distribution_ref.artifact_ref)
    {
        return invalid_document();
    }
    if !valid_legacy_sha256(&value.hashes.package_sha256)
        || !valid_legacy_sha256(&value.hashes.manifest_sha256)
        || !valid_legacy_sha256(&value.hashes.entries_sha256)
    {
        return invalid_document();
    }
    let metadata_signature = &value.release_metadata_signature;
    if metadata_signature.algorithm != SIGNATURE_ALGORITHM_ED25519
        || !valid_new_id(&metadata_signature.key_id)
        || !valid_artifact_ref(&metadata_signature.signature_ref)
        || !valid_epoch(&metadata_signature.source_policy_epoch)
        || !valid_epoch(&metadata_signature.revocation_epoch)
    {
        return invalid_document();
    }
    let package_signature = &value.package_signature;
    if package_signature.algorithm != SIGNATURE_ALGORITHM_ED25519
        || !valid_new_id(&package_signature.key_id)
        || !valid_artifact_ref(&package_signature.signature_bundle_ref)
        || !valid_epoch(&package_signature.source_policy_epoch)
        || !valid_epoch(&package_signature.revocation_epoch)
    {
        return invalid_document();
    }
    if !valid_semver(&value.compatibility.min_redevplugin_version)
        || !valid_semver(&value.compatibility.min_runtime_version)
        || value.compatibility.ui_protocol_version != "plugin-ui-v5"
    {
        return invalid_document();
    }
    if let Some(targets) = &value.compatibility.supported_targets {
        let mut previous = "";
        for target in targets {
            if !matches!(
                target.as_str(),
                "darwin/amd64" | "darwin/arm64" | "linux/amd64" | "linux/arm64"
            ) || target.as_str() <= previous
            {
                return invalid_document();
            }
            previous = target;
        }
    }
    validate_host_requirements(value.host_requirements.as_deref().unwrap_or(&[]))?;
    if let Some(evidence) = &value.release_evidence {
        if evidence
            .notices_sha256
            .as_deref()
            .is_some_and(|digest| !valid_legacy_sha256(digest))
            || evidence
                .provenance_sha256
                .as_deref()
                .is_some_and(|digest| !valid_legacy_sha256(digest))
            || evidence
                .generated_at
                .as_deref()
                .is_some_and(|generated| canonical_timestamp_seconds(generated).is_none())
        {
            return invalid_document();
        }
    }
    if let Some(metadata) = &value.metadata {
        if metadata.len() > 128
            || metadata
                .iter()
                .any(|(key, item)| key.is_empty() || key.len() > 128 || item.len() > 4096)
        {
            return invalid_document();
        }
    }
    Ok(())
}

fn validate_host_requirements(
    values: &[ReleaseHostRequirement],
) -> Result<(), ReleaseContractError> {
    let mut previous_host = "";
    for value in values {
        if !valid_legacy_id(&value.host_id) || value.host_id.as_str() <= previous_host {
            return invalid_document();
        }
        if value
            .min_host_version
            .as_deref()
            .is_some_and(|version| !valid_semver(version))
        {
            return invalid_document();
        }
        let mut previous_capability = String::new();
        for capability in value
            .required_capability_contracts
            .as_deref()
            .unwrap_or(&[])
        {
            let identity = format!(
                "{}\0{}",
                capability.capability_id, capability.capability_version
            );
            if !valid_legacy_id(&capability.capability_id)
                || !valid_semver(&capability.capability_version)
                || identity <= previous_capability
            {
                return invalid_document();
            }
            validate_capability_contract_ref(&capability.contract)?;
            previous_capability = identity;
        }
        previous_host = &value.host_id;
    }
    Ok(())
}

fn validate_capability_contract_ref(
    value: &HostCapabilityContractRef,
) -> Result<(), ReleaseContractError> {
    if !valid_legacy_id(&value.publisher_id)
        || !valid_legacy_id(&value.contract_id)
        || !valid_legacy_id(&value.signature_key_id)
        || !valid_semver(&value.contract_version)
        || !valid_epoch(&value.signature_policy_epoch)
        || !valid_epoch(&value.signature_revocation_epoch)
    {
        return invalid_document();
    }
    for reference in [
        &value.artifact_ref,
        &value.manifest_ref,
        &value.signature_ref,
        &value.compatibility_ref,
        &value.generated_client_ref,
        &value.notices_ref,
    ] {
        if !valid_artifact_ref(reference) {
            return invalid_document();
        }
    }
    for digest in [
        &value.artifact_sha256,
        &value.manifest_sha256,
        &value.signature_sha256,
        &value.compatibility_sha256,
        &value.generated_client_sha256,
        &value.notices_sha256,
    ] {
        if !valid_sha256(digest) {
            return invalid_document();
        }
    }
    Ok(())
}

fn validate_source_policy(
    value: &SourcePolicyV2,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    if value.schema_version != SOURCE_POLICY_SCHEMA_VERSION
        || !valid_new_id(&value.source_id)
        || !valid_new_id(&value.channel)
        || !valid_new_id(&value.key_id)
    {
        return invalid_document();
    }
    validate_epoch_chain(
        &value.epoch,
        &value.previous_epoch,
        &value.previous_document_sha256,
    )?;
    if !valid_positive_epoch(&value.root_epoch)
        || !valid_epoch(&value.minimum_revocation_epoch)
        || !matches!(value.source_type.as_str(), "registry" | "host_artifact")
        || !matches!(
            value.source_class.as_str(),
            "official" | "curated" | "community" | "private"
        )
    {
        return invalid_document();
    }
    validate_sorted_ids(&value.allowed_publishers, 1, 1024, true)?;
    if value.allowed_artifact_hosts.len() > 1024 {
        return invalid_document();
    }
    let mut previous_host = "";
    for host in &value.allowed_artifact_hosts {
        if host.len() > 253
            || !valid_hostname(host)
            || host.to_ascii_lowercase() != *host
            || host.as_str() <= previous_host
        {
            return invalid_document();
        }
        previous_host = host;
    }
    for keys in [
        &value.active_keys.package,
        &value.active_keys.release_metadata,
        &value.active_keys.source_policy_pointer,
        &value.active_keys.revocation_document,
        &value.active_keys.revocation_pointer,
    ] {
        validate_sorted_ids(keys, 1, 16, true)?;
    }
    if !matches!(
        value.install_policy.as_str(),
        "allow" | "review_required" | "block"
    ) || !matches!(
        value.unsigned_policy.as_str(),
        "dev_only" | "review_required" | "block"
    ) || !matches!(value.downgrade_policy.as_str(), "review_required" | "block")
        || value.limits != SourcePolicyLimits::default()
    {
        return invalid_document();
    }
    validate_time_range(&value.generated_at, &value.expires_at, Some(24 * 60 * 60))?;
    validate_signature_field(&value.signature, require_signature)
}

fn validate_source_policy_pointer(
    value: &SourcePolicyPointerV1,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    validate_pointer(
        &value.schema_version,
        SOURCE_POLICY_POINTER_SCHEMA_VERSION,
        &value.source_id,
        &value.channel,
        &value.epoch,
        &value.previous_epoch,
        &value.previous_document_sha256,
        &value.r#ref,
        &value.document_sha256,
        &value.generated_at,
        &value.expires_at,
        &value.key_id,
        &value.signature,
        require_signature,
    )
}

fn validate_revocation_pointer(
    value: &RevocationPointerV1,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    validate_pointer(
        &value.schema_version,
        REVOCATION_POINTER_SCHEMA_VERSION,
        &value.source_id,
        &value.channel,
        &value.epoch,
        &value.previous_epoch,
        &value.previous_document_sha256,
        &value.r#ref,
        &value.document_sha256,
        &value.generated_at,
        &value.expires_at,
        &value.key_id,
        &value.signature,
        require_signature,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_pointer(
    schema_version: &str,
    expected_schema_version: &str,
    source_id: &str,
    channel: &str,
    epoch: &str,
    previous_epoch: &str,
    previous_digest: &str,
    reference: &str,
    document_digest: &str,
    generated_at: &str,
    expires_at: &str,
    key_id: &str,
    signature: &str,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    if schema_version != expected_schema_version
        || !valid_new_id(source_id)
        || !valid_new_id(channel)
        || !valid_new_id(key_id)
    {
        return invalid_document();
    }
    validate_epoch_chain(epoch, previous_epoch, previous_digest)?;
    if !valid_artifact_ref(reference)
        || !valid_sha256(document_digest)
        || document_digest == GENESIS_PREVIOUS_DOCUMENT_SHA256
    {
        return invalid_document();
    }
    validate_time_range(generated_at, expires_at, Some(24 * 60 * 60))?;
    validate_signature_field(signature, require_signature)
}

fn validate_revocation(
    value: &RevocationV2,
    require_signature: bool,
) -> Result<(), ReleaseContractError> {
    if value.schema_version != REVOCATION_SCHEMA_VERSION
        || !valid_new_id(&value.source_id)
        || !valid_new_id(&value.channel)
        || !valid_new_id(&value.key_id)
    {
        return invalid_document();
    }
    validate_epoch_chain(
        &value.epoch,
        &value.previous_epoch,
        &value.previous_document_sha256,
    )?;
    if !valid_positive_epoch(&value.root_epoch) {
        return invalid_document();
    }
    let (_, expires_at) =
        validate_time_range(&value.generated_at, &value.expires_at, Some(24 * 60 * 60))?;
    validate_sorted_ids(&value.revoked_key_ids, 0, 4096, true)?;
    if value.revoked_releases.len() > 16_384 {
        return invalid_document();
    }
    let mut previous = String::new();
    for revoked in &value.revoked_releases {
        let identity = format!(
            "{}\0{}\0{}\0{}",
            revoked.publisher_id,
            revoked.plugin_id,
            revoked.version,
            revoked.release_metadata_sha256
        );
        let revoked_at = canonical_timestamp_seconds(&revoked.revoked_at)
            .ok_or(ReleaseContractError::InvalidDocument)?;
        if !valid_legacy_id(&revoked.publisher_id)
            || !valid_legacy_id(&revoked.plugin_id)
            || !valid_semver(&revoked.version)
            || !valid_sha256(&revoked.release_metadata_sha256)
            || identity <= previous
            || revoked_at > expires_at
        {
            return invalid_document();
        }
        previous = identity;
    }
    validate_signature_field(&value.signature, require_signature)
}

fn invalid_document<T>() -> Result<T, ReleaseContractError> {
    Err(ReleaseContractError::InvalidDocument)
}

fn validate_signature_field(value: &str, required: bool) -> Result<(), ReleaseContractError> {
    if !required && value.is_empty() {
        return Ok(());
    }
    decode_signature(value).map(|_| ())
}

fn validate_epoch_chain(
    epoch: &str,
    previous_epoch: &str,
    previous_digest: &str,
) -> Result<(), ReleaseContractError> {
    if !valid_positive_epoch(epoch)
        || !valid_epoch(previous_epoch)
        || !valid_sha256(previous_digest)
        || increment_decimal(previous_epoch).as_deref() != Some(epoch)
    {
        return invalid_document();
    }
    if previous_epoch == GENESIS_PREVIOUS_EPOCH {
        if previous_digest != GENESIS_PREVIOUS_DOCUMENT_SHA256 {
            return invalid_document();
        }
    } else if previous_digest == GENESIS_PREVIOUS_DOCUMENT_SHA256 {
        return invalid_document();
    }
    Ok(())
}

fn increment_decimal(value: &str) -> Option<String> {
    if !valid_epoch(value) {
        return None;
    }
    let mut bytes = value.as_bytes().to_vec();
    let mut index = bytes.len();
    while index > 0 {
        index -= 1;
        if bytes[index] < b'9' {
            bytes[index] += 1;
            return String::from_utf8(bytes).ok();
        }
        bytes[index] = b'0';
    }
    bytes.insert(0, b'1');
    String::from_utf8(bytes).ok()
}

fn validate_time_range(
    generated_at: &str,
    expires_at: &str,
    maximum_seconds: Option<i64>,
) -> Result<(i64, i64), ReleaseContractError> {
    let generated =
        canonical_timestamp_seconds(generated_at).ok_or(ReleaseContractError::InvalidDocument)?;
    let expires =
        canonical_timestamp_seconds(expires_at).ok_or(ReleaseContractError::InvalidDocument)?;
    if expires <= generated || maximum_seconds.is_some_and(|maximum| expires - generated > maximum)
    {
        return invalid_document();
    }
    Ok((generated, expires))
}

fn canonical_timestamp_seconds(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let year = parse_digits(&bytes[0..4])? as i32;
    let month = parse_digits(&bytes[5..7])? as u32;
    let day = parse_digits(&bytes[8..10])? as u32;
    let hour = parse_digits(&bytes[11..13])? as i64;
    let minute = parse_digits(&bytes[14..16])? as i64;
    let second = parse_digits(&bytes[17..19])? as i64;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    bytes.iter().try_fold(0_u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = i64::from(year) - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn validate_sorted_ids(
    values: &[String],
    minimum: usize,
    maximum: usize,
    lower: bool,
) -> Result<(), ReleaseContractError> {
    if values.len() < minimum || values.len() > maximum {
        return invalid_document();
    }
    let mut previous = "";
    for value in values {
        let valid = if lower {
            valid_new_id(value)
        } else {
            valid_legacy_id(value)
        };
        if !valid || value.as_str() <= previous {
            return invalid_document();
        }
        previous = value;
    }
    Ok(())
}

fn valid_new_id(value: &str) -> bool {
    value.len() <= 128
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_legacy_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_epoch(value: &str) -> bool {
    value == "0" || valid_positive_epoch(value)
}

fn valid_positive_epoch(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_digit()
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256)
}

fn valid_legacy_sha256(value: &str) -> bool {
    valid_sha256(value) || valid_prefixed_sha256(value)
}

fn valid_artifact_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains(['?', '#'])
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'/' | b'@' | b'+' | b'~' | b'-')
        })
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_semver(value: &str) -> bool {
    semver::Version::parse(value)
        .map(|version| version.to_string() == value)
        .unwrap_or(false)
}
