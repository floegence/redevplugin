use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use redevplugin_contracts::*;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Fixture {
    public_key_base64: String,
    release_metadata_channel: String,
    package_context: FixturePackageContext,
    documents: FixtureDocuments,
    detached_signatures: FixtureDetachedSignatures,
    preimages: BTreeMap<String, String>,
    signatures: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct FixturePackageContext {
    source_id: String,
    channel: String,
    version: String,
}

#[derive(Deserialize)]
struct FixtureDocuments {
    root_delegation: RootDelegationV1,
    package_signature: PackageSignatureV1,
    release_metadata: ReleaseMetadataV5,
    source_policy: SourcePolicyV2,
    source_policy_pointer: SourcePolicyPointerV1,
    revocation: RevocationV2,
    revocation_pointer: RevocationPointerV1,
}

#[derive(Deserialize)]
struct FixtureDetachedSignatures {
    release_metadata: String,
}

struct TestVerifier(VerifyingKey);

type DocumentDecoder = Box<dyn Fn(&[u8]) -> Result<(), ReleaseContractError>>;
type CanonicalCase = (Vec<u8>, DocumentDecoder);

impl SignatureVerifier for TestVerifier {
    fn verify_signature(&self, request: SignatureVerificationRequest<'_>) -> bool {
        let Ok(signature) = Signature::try_from(request.signature) else {
            return false;
        };
        self.0.verify(request.preimage, &signature).is_ok()
    }
}

#[test]
fn release_signing_projection_matches_every_shared_preimage() {
    let fixture = fixture();
    let preimages = fixture_preimages(&fixture);
    for (usage, preimage) in preimages {
        assert_eq!(
            BASE64_STANDARD.encode(preimage),
            fixture.preimages[usage.as_str()],
            "{}",
            usage.as_str()
        );
    }
}

#[test]
fn release_signing_projection_verifies_all_domains_and_rejects_the_7x6_matrix() {
    let fixture = fixture();
    let verifier = fixture_verifier(&fixture);
    let documents = &fixture.documents;
    let context = package_context(&fixture);
    verify_root_delegation(&documents.root_delegation, &verifier).unwrap();
    verify_package_signature(&context, &documents.package_signature, &verifier).unwrap();
    verify_release_metadata(
        &fixture.release_metadata_channel,
        &documents.release_metadata,
        &decode_base64(&fixture.detached_signatures.release_metadata),
        &verifier,
    )
    .unwrap();
    verify_source_policy(&documents.source_policy, &verifier).unwrap();
    verify_source_policy_pointer(&documents.source_policy_pointer, &verifier).unwrap();
    verify_revocation(&documents.revocation, &verifier).unwrap();
    verify_revocation_pointer(&documents.revocation_pointer, &verifier).unwrap();

    let preimages = fixture_preimages(&fixture);
    for signed_usage in usage_order() {
        for verified_usage in usage_order() {
            let valid = verifier.verify_signature(SignatureVerificationRequest {
                usage: verified_usage,
                key_id: "test_signing_key",
                preimage: &preimages[&verified_usage],
                signature: &decode_base64(&fixture.signatures[signed_usage.as_str()]),
            });
            assert_eq!(
                valid,
                signed_usage == verified_usage,
                "{} as {}",
                signed_usage.as_str(),
                verified_usage.as_str()
            );
        }
    }
}

#[test]
fn release_signing_builders_and_closed_decoders_preserve_canonical_documents() {
    let fixture = fixture();
    let documents = &fixture.documents;
    let context = package_context(&fixture);

    assert_eq!(
        build_root_delegation(
            &root_input(&documents.root_delegation),
            &decode_signature_field(&documents.root_delegation.signature)
        )
        .unwrap(),
        documents.root_delegation
    );
    assert_eq!(
        build_package_signature(
            &package_input(&fixture),
            &decode_signature_field(&documents.package_signature.signature)
        )
        .unwrap(),
        documents.package_signature
    );
    assert_eq!(
        build_release_metadata(&documents.release_metadata).unwrap(),
        documents.release_metadata
    );
    assert_eq!(
        build_source_policy(
            &source_policy_input(&documents.source_policy),
            &decode_signature_field(&documents.source_policy.signature)
        )
        .unwrap(),
        documents.source_policy
    );
    assert_eq!(
        build_source_policy_pointer(
            &source_pointer_input(&documents.source_policy_pointer),
            &decode_signature_field(&documents.source_policy_pointer.signature)
        )
        .unwrap(),
        documents.source_policy_pointer
    );
    assert_eq!(
        build_revocation(
            &revocation_input(&documents.revocation),
            &decode_signature_field(&documents.revocation.signature)
        )
        .unwrap(),
        documents.revocation
    );
    assert_eq!(
        build_revocation_pointer(
            &revocation_pointer_input(&documents.revocation_pointer),
            &decode_signature_field(&documents.revocation_pointer.signature)
        )
        .unwrap(),
        documents.revocation_pointer
    );

    let cases: Vec<CanonicalCase> = vec![
        (
            canonical_root_delegation(&documents.root_delegation).unwrap(),
            Box::new(|raw| decode_root_delegation(raw).map(|_| ())),
        ),
        (
            canonical_package_signature(&context, &documents.package_signature).unwrap(),
            Box::new(move |raw| decode_package_signature(raw, &context).map(|_| ())),
        ),
        (
            canonical_release_metadata(&documents.release_metadata).unwrap(),
            Box::new(|raw| decode_release_metadata(raw).map(|_| ())),
        ),
        (
            canonical_source_policy(&documents.source_policy).unwrap(),
            Box::new(|raw| decode_source_policy(raw).map(|_| ())),
        ),
        (
            canonical_source_policy_pointer(&documents.source_policy_pointer).unwrap(),
            Box::new(|raw| decode_source_policy_pointer(raw).map(|_| ())),
        ),
        (
            canonical_revocation(&documents.revocation).unwrap(),
            Box::new(|raw| decode_revocation(raw).map(|_| ())),
        ),
        (
            canonical_revocation_pointer(&documents.revocation_pointer).unwrap(),
            Box::new(|raw| decode_revocation_pointer(raw).map(|_| ())),
        ),
    ];
    for (raw, decode) in cases {
        decode(&raw).unwrap();
        let source = String::from_utf8(raw).unwrap();
        for invalid in [
            format!(" {source}"),
            format!("{source} true"),
            insert_before_object_end(&source, ",\"unknown\":true"),
            insert_before_object_end(&source, ",\"schema_version\":\"duplicate\""),
        ] {
            assert_eq!(
                decode(invalid.as_bytes()),
                Err(ReleaseContractError::InvalidDocument)
            );
        }
    }
}

#[test]
fn release_signing_rejects_source_policy_schema_limit_drift() {
    let fixture = fixture();
    let mut input = source_policy_input(&fixture.documents.source_policy);
    input.allowed_artifact_hosts = (0..1025)
        .map(|index| format!("host-{index:04}.example"))
        .collect();
    assert_eq!(
        source_policy_signing_preimage(&input),
        Err(ReleaseContractError::InvalidDocument)
    );
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/release-signing-v1.json")).unwrap()
}

fn fixture_verifier(fixture: &Fixture) -> TestVerifier {
    let key: [u8; 32] = decode_base64(&fixture.public_key_base64)
        .try_into()
        .unwrap();
    TestVerifier(VerifyingKey::from_bytes(&key).unwrap())
}

fn fixture_preimages(fixture: &Fixture) -> BTreeMap<SigningUsage, Vec<u8>> {
    let documents = &fixture.documents;
    BTreeMap::from([
        (
            SigningUsage::RootDelegation,
            root_delegation_signing_preimage(&root_input(&documents.root_delegation)).unwrap(),
        ),
        (
            SigningUsage::Package,
            package_signing_preimage(&package_input(fixture)).unwrap(),
        ),
        (
            SigningUsage::ReleaseMetadata,
            release_metadata_signing_preimage(
                &fixture.release_metadata_channel,
                &documents.release_metadata,
            )
            .unwrap(),
        ),
        (
            SigningUsage::SourcePolicy,
            source_policy_signing_preimage(&source_policy_input(&documents.source_policy)).unwrap(),
        ),
        (
            SigningUsage::SourcePolicyPointer,
            source_policy_pointer_signing_preimage(&source_pointer_input(
                &documents.source_policy_pointer,
            ))
            .unwrap(),
        ),
        (
            SigningUsage::Revocation,
            revocation_signing_preimage(&revocation_input(&documents.revocation)).unwrap(),
        ),
        (
            SigningUsage::RevocationPointer,
            revocation_pointer_signing_preimage(&revocation_pointer_input(
                &documents.revocation_pointer,
            ))
            .unwrap(),
        ),
    ])
}

fn usage_order() -> [SigningUsage; 7] {
    [
        SigningUsage::RootDelegation,
        SigningUsage::Package,
        SigningUsage::ReleaseMetadata,
        SigningUsage::SourcePolicy,
        SigningUsage::SourcePolicyPointer,
        SigningUsage::Revocation,
        SigningUsage::RevocationPointer,
    ]
}

fn package_context(fixture: &Fixture) -> PackageVerificationContext {
    PackageVerificationContext {
        source_id: fixture.package_context.source_id.clone(),
        channel: fixture.package_context.channel.clone(),
        version: fixture.package_context.version.clone(),
    }
}

fn root_input(value: &RootDelegationV1) -> RootDelegationInput {
    RootDelegationInput {
        source_id: value.source_id.clone(),
        root_epoch: value.root_epoch.clone(),
        previous_root_epoch: value.previous_root_epoch.clone(),
        previous_delegation_sha256: value.previous_delegation_sha256.clone(),
        generated_at: value.generated_at.clone(),
        expires_at: value.expires_at.clone(),
        delegated_keys: value.delegated_keys.clone(),
        key_id: value.key_id.clone(),
    }
}

fn package_input(fixture: &Fixture) -> PackageSigningInput {
    let value = &fixture.documents.package_signature;
    PackageSigningInput {
        source_id: fixture.package_context.source_id.clone(),
        channel: fixture.package_context.channel.clone(),
        version: fixture.package_context.version.clone(),
        algorithm: value.algorithm.clone(),
        key_id: value.key_id.clone(),
        publisher_id: value.publisher_id.clone().unwrap(),
        plugin_id: value.plugin_id.clone().unwrap(),
        package_hash: value.package_hash.clone(),
        manifest_hash: value.manifest_hash.clone(),
        entries_hash: value.entries_hash.clone(),
        signed_at: value.signed_at.clone().unwrap(),
    }
}

fn source_policy_input(value: &SourcePolicyV2) -> SourcePolicyInput {
    SourcePolicyInput {
        source_id: value.source_id.clone(),
        channel: value.channel.clone(),
        epoch: value.epoch.clone(),
        previous_epoch: value.previous_epoch.clone(),
        previous_document_sha256: value.previous_document_sha256.clone(),
        root_epoch: value.root_epoch.clone(),
        source_type: value.source_type.clone(),
        source_class: value.source_class.clone(),
        allowed_publishers: value.allowed_publishers.clone(),
        allowed_artifact_hosts: value.allowed_artifact_hosts.clone(),
        active_keys: value.active_keys.clone(),
        require_signature: value.require_signature,
        install_policy: value.install_policy.clone(),
        unsigned_policy: value.unsigned_policy.clone(),
        downgrade_policy: value.downgrade_policy.clone(),
        minimum_revocation_epoch: value.minimum_revocation_epoch.clone(),
        limits: value.limits,
        generated_at: value.generated_at.clone(),
        expires_at: value.expires_at.clone(),
        key_id: value.key_id.clone(),
    }
}

fn source_pointer_input(value: &SourcePolicyPointerV1) -> ReleasePointerInput {
    ReleasePointerInput {
        source_id: value.source_id.clone(),
        channel: value.channel.clone(),
        epoch: value.epoch.clone(),
        previous_epoch: value.previous_epoch.clone(),
        previous_document_sha256: value.previous_document_sha256.clone(),
        r#ref: value.r#ref.clone(),
        document_sha256: value.document_sha256.clone(),
        generated_at: value.generated_at.clone(),
        expires_at: value.expires_at.clone(),
        key_id: value.key_id.clone(),
    }
}

fn revocation_input(value: &RevocationV2) -> RevocationInput {
    RevocationInput {
        source_id: value.source_id.clone(),
        channel: value.channel.clone(),
        epoch: value.epoch.clone(),
        previous_epoch: value.previous_epoch.clone(),
        previous_document_sha256: value.previous_document_sha256.clone(),
        root_epoch: value.root_epoch.clone(),
        generated_at: value.generated_at.clone(),
        expires_at: value.expires_at.clone(),
        revoked_key_ids: value.revoked_key_ids.clone(),
        revoked_releases: value.revoked_releases.clone(),
        key_id: value.key_id.clone(),
    }
}

fn revocation_pointer_input(value: &RevocationPointerV1) -> ReleasePointerInput {
    ReleasePointerInput {
        source_id: value.source_id.clone(),
        channel: value.channel.clone(),
        epoch: value.epoch.clone(),
        previous_epoch: value.previous_epoch.clone(),
        previous_document_sha256: value.previous_document_sha256.clone(),
        r#ref: value.r#ref.clone(),
        document_sha256: value.document_sha256.clone(),
        generated_at: value.generated_at.clone(),
        expires_at: value.expires_at.clone(),
        key_id: value.key_id.clone(),
    }
}

fn decode_signature_field(value: &str) -> Vec<u8> {
    decode_base64(value)
}

fn decode_base64(value: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(value).unwrap()
}

fn insert_before_object_end(source: &str, suffix: &str) -> String {
    format!("{}{suffix}}}", &source[..source.len() - 1])
}
