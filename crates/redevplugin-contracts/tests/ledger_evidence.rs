use redevplugin_contracts::{
    ReleaseContractError, SigningLedgerEvidenceV1, decode_signing_ledger_evidence,
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
