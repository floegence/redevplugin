use redevplugin_contracts::{
    ReleaseContractError, SignatureEnvelopeV1, SigningLedgerEntryV1, SigningLedgerEvidenceV1,
    SigningSubjectV1, canonical_signature_envelope, canonical_signing_ledger_entry,
    canonical_signing_subject, decode_signature_envelope, decode_signing_ledger_entry,
    decode_signing_ledger_evidence, decode_signing_subject,
};
use serde_json::Value;

#[test]
fn signing_ledger_evidence_projection_is_closed_and_canonical() {
    let value: Value = serde_json::from_str(include_str!(
        "fixtures/release-signing-ledger-evidence-v1.json"
    ))
    .unwrap();
    let canonical = serde_json::to_vec(&value).unwrap();
    let evidence = decode_signing_ledger_evidence(&canonical).unwrap();
    assert_eq!(evidence.source_id, "redeven-official-github");
    assert_eq!(evidence.channel.as_deref(), Some("stable"));

    let mut unknown = value.clone();
    unknown["unknown"] = Value::Bool(true);
    assert_eq!(
        decode_signing_ledger_evidence(&serde_json::to_vec(&unknown).unwrap()),
        Err(ReleaseContractError::InvalidDocument)
    );

    let mut partial: SigningLedgerEvidenceV1 = serde_json::from_value(value).unwrap();
    partial.consistency_proof_sha256 = None;
    assert_eq!(
        decode_signing_ledger_evidence(&serde_json::to_vec(&partial).unwrap()),
        Err(ReleaseContractError::InvalidDocument)
    );
}

#[test]
fn signing_ledger_subject_envelope_and_entry_are_closed_and_canonical() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/release-signing-ledger-wire-v1.json")).unwrap();
    let subject: SigningSubjectV1 = serde_json::from_value(fixture["subject"].clone()).unwrap();
    let envelope: SignatureEnvelopeV1 =
        serde_json::from_value(fixture["envelope"].clone()).unwrap();
    let entry: SigningLedgerEntryV1 =
        serde_json::from_value(fixture["reserved_entry"].clone()).unwrap();

    assert_eq!(
        decode_signing_subject(&canonical_signing_subject(&subject).unwrap()).unwrap(),
        subject
    );
    assert_eq!(
        decode_signature_envelope(&canonical_signature_envelope(&envelope).unwrap()).unwrap(),
        envelope
    );
    assert_eq!(
        decode_signing_ledger_entry(&canonical_signing_ledger_entry(&entry).unwrap()).unwrap(),
        entry
    );

    let mut unknown = fixture["reserved_entry"].clone();
    unknown["unknown"] = Value::Bool(true);
    assert_eq!(
        decode_signing_ledger_entry(&serde_json::to_vec(&unknown).unwrap()),
        Err(ReleaseContractError::InvalidDocument)
    );
}
