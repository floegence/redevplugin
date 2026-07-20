import {
  generatedContractArtifacts,
  generatedContractRegistry,
  generatedContractSetSHA256,
  generatedPackageSet,
  generatedRegistryContract,
} from "./contracts.gen.js";

export type ContractID =
  | (typeof generatedContractArtifacts)[number]["id"]
  | typeof generatedRegistryContract.id;

export type Contract = Readonly<{
  id: ContractID;
  path: string;
  version: string;
  sha256: string;
  body: string;
}>;

export class UnknownContractError extends RangeError {
  readonly id: string;

  constructor(id: string) {
    super(`contract id ${JSON.stringify(id)} is unknown`);
    this.name = "UnknownContractError";
    this.id = id;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export const contractArtifacts = deepFreeze(generatedContractArtifacts) as readonly Contract[];
export const registryContract = deepFreeze(generatedRegistryContract) as Contract;
export const contractRegistry = deepFreeze(generatedContractRegistry);
export const packageSet = deepFreeze(generatedPackageSet);
export const contractSetSHA256 = generatedContractSetSHA256;

const contractsByID = new Map<ContractID, Contract>();
for (const contract of contractArtifacts) contractsByID.set(contract.id, contract);
contractsByID.set(registryContract.id, registryContract);

export function getContract(id: ContractID): Contract {
  const contract = contractsByID.get(id);
  if (contract === undefined) throw new UnknownContractError(id);
  return contract;
}
