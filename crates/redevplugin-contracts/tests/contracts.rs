use redevplugin_contracts::{
    ContractError, ContractId, all, artifacts, get, package_set, registry_contract,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[test]
fn inventory_includes_one_separate_synthetic_registry_contract() {
    assert_eq!(artifacts().len(), 49);
    assert_eq!(all().len(), 50);
    assert!(
        artifacts()
            .iter()
            .all(|contract| contract.id() != ContractId::CONTRACT_REGISTRY)
    );
    assert_eq!(registry_contract().id(), ContractId::CONTRACT_REGISTRY);
    assert_eq!(get(ContractId::CONTRACT_REGISTRY), registry_contract());
    assert!(std::ptr::eq(
        get(ContractId::CONTRACT_REGISTRY),
        registry_contract()
    ));
    assert!(
        all()
            .windows(2)
            .all(|pair| pair[0].id().as_str() < pair[1].id().as_str())
    );
}

#[test]
fn package_set_and_contract_metadata_are_static_and_complete() {
    let package_set = package_set();
    assert_eq!(package_set.platform_version, "0.6.10");
    assert_eq!(
        package_set.go_module.module,
        "github.com/floegence/redevplugin"
    );
    assert_eq!(package_set.npm_packages.len(), 2);
    assert_eq!(package_set.rust_crates.len(), 6);
    assert_eq!(package_set.contract_set_sha256.len(), 64);
    for contract in all() {
        assert!(!contract.id().as_str().is_empty());
        assert!(!contract.version().is_empty());
        assert_eq!(contract.sha256().len(), 64);
        assert!(!contract.bytes().is_empty());
        assert_eq!(
            format!("{:x}", Sha256::digest(contract.bytes())),
            contract.sha256()
        );
    }
}

#[test]
fn contract_id_parse_is_validated_for_every_known_id() {
    for contract in all() {
        assert_eq!(
            ContractId::parse(contract.id().as_str()).unwrap(),
            contract.id()
        );
        assert_eq!(
            ContractId::try_from(contract.id().as_str()).unwrap(),
            contract.id()
        );
        assert!(std::ptr::eq(get(contract.id()), contract));
    }
    assert_eq!(
        ContractId::parse("contract-registry").unwrap(),
        ContractId::CONTRACT_REGISTRY
    );
    assert!(matches!(
        ContractId::parse("unknown-contract"),
        Err(ContractError::UnknownId)
    ));
    assert!(matches!(
        ContractId::try_from("unknown-contract"),
        Err(ContractError::UnknownId)
    ));

    let oversized = "x".repeat(1024 * 1024);
    assert!(matches!(
        ContractId::parse(&oversized),
        Err(ContractError::UnknownId)
    ));
}

#[derive(Serialize)]
struct Coordinate<'a> {
    id: &'a str,
    version: &'a str,
    sha256: &'a str,
}

#[test]
fn contract_set_digest_includes_the_synthetic_registry_coordinate() {
    let mut coordinates = all()
        .iter()
        .map(|contract| Coordinate {
            id: contract.id().as_str(),
            version: contract.version(),
            sha256: contract.sha256(),
        })
        .collect::<Vec<_>>();
    coordinates.sort_by(|left, right| left.id.cmp(right.id));
    let canonical = serde_json::to_vec(&coordinates).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&canonical)),
        package_set().contract_set_sha256
    );

    let mut tampered = canonical;
    tampered[0] ^= 1;
    assert_ne!(
        format!("{:x}", Sha256::digest(&tampered)),
        package_set().contract_set_sha256
    );
}
