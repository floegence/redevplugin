#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

mod contracts_gen;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContractId(&'static str);

impl ContractId {
    const fn from_static(value: &'static str) -> Self {
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub fn parse(value: &str) -> Result<Self, ContractError> {
        contracts_gen::parse_contract_id(value).ok_or(ContractError::UnknownId)
    }
}

impl TryFrom<&str> for ContractId {
    type Error = ContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    UnknownId,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownId => formatter.write_str("contract id is unknown"),
        }
    }
}

impl Error for ContractError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contract {
    id: ContractId,
    version: &'static str,
    sha256: &'static str,
    bytes: &'static [u8],
}

impl Contract {
    const fn new(
        id: ContractId,
        version: &'static str,
        sha256: &'static str,
        bytes: &'static [u8],
    ) -> Self {
        Self {
            id,
            version,
            sha256,
            bytes,
        }
    }

    pub const fn id(&self) -> ContractId {
        self.id
    }
    pub const fn version(&self) -> &'static str {
        self.version
    }
    pub const fn sha256(&self) -> &'static str {
        self.sha256
    }
    pub const fn bytes(&self) -> &'static [u8] {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoModuleCoordinate {
    pub module: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPackageCoordinate {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustCrateCoordinate {
    pub name: &'static str,
    pub version: &'static str,
    pub role: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageSet {
    pub schema_version: &'static str,
    pub platform_version: &'static str,
    pub go_module: GoModuleCoordinate,
    pub npm_packages: &'static [NpmPackageCoordinate],
    pub rust_crates: &'static [RustCrateCoordinate],
    pub contract_registry_version: &'static str,
    pub contract_set_sha256: &'static str,
}

pub fn package_set() -> &'static PackageSet {
    &contracts_gen::PACKAGE_SET
}
pub fn artifacts() -> &'static [Contract] {
    &contracts_gen::ARTIFACTS
}
pub fn registry_contract() -> &'static Contract {
    &contracts_gen::ALL[contracts_gen::REGISTRY_CONTRACT_INDEX]
}
pub fn all() -> &'static [Contract] {
    &contracts_gen::ALL
}
pub fn get(id: ContractId) -> &'static Contract {
    contracts_gen::get(id)
}
