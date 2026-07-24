import assert from "node:assert/strict";
import { test } from "node:test";

import {
  UnknownContractError,
  contractArtifacts,
  contractRegistry,
  contractSetSHA256,
  getContract,
  packageSet,
  registryContract,
  type ContractID,
} from "../src/index.js";

test("contracts package exposes the complete immutable lookup inventory", () => {
  assert.equal(contractArtifacts.length, 49);
  assert.equal(contractArtifacts.some(({ id }) => id === "contract-registry"), false);
  assert.equal(registryContract.id, "contract-registry");
  assert.equal(getContract("contract-registry"), registryContract);
  assert.equal(contractRegistry.artifacts.length, contractArtifacts.length);
  assert.equal(packageSet.contract_set_sha256, contractSetSHA256);
  assert.match(contractSetSHA256, /^[0-9a-f]{64}$/);
  for (const contract of [...contractArtifacts, registryContract]) {
    assert.equal(getContract(contract.id), contract);
    assert.match(contract.sha256, /^[0-9a-f]{64}$/);
    assert.ok(contract.body.length > 0);
  }
});

test("contracts package recursively freezes every exported snapshot", () => {
  assert.ok(Object.isFrozen(packageSet));
  assert.ok(Object.isFrozen(packageSet.npm_packages));
  assert.ok(Object.isFrozen(packageSet.npm_packages[0]));
  assert.ok(Object.isFrozen(packageSet.rust_crates));
  assert.ok(Object.isFrozen(contractRegistry));
  assert.ok(Object.isFrozen(contractRegistry.artifacts));
  assert.ok(Object.isFrozen(contractArtifacts));
  assert.ok(Object.isFrozen(contractArtifacts[0]));
  assert.ok(Object.isFrozen(registryContract));
  assert.throws(() => {
    (packageSet.npm_packages as unknown as Array<unknown>).push({});
  }, TypeError);
});

test("unknown runtime IDs fail with a stable typed error", () => {
  assert.throws(
    () => getContract("unknown-contract" as ContractID),
    (error: unknown) => error instanceof UnknownContractError && error.id === "unknown-contract",
  );
});

const knownID: ContractID = "contract-registry";
const arbitraryString: string = "contract-registry";
// @ts-expect-error ContractID is a generated closed union.
const unknownID: ContractID = "unknown-contract";
function assertCompileTimeBoundaries(): void {
  // @ts-expect-error getContract does not accept an unconstrained string.
  getContract(arbitraryString);
  // @ts-expect-error package-set fields are deeply readonly.
  packageSet.platform_version = "0.6.15";
  // @ts-expect-error artifact metadata is deeply readonly.
  contractArtifacts[0].sha256 = "0";
}
void knownID;
void unknownID;
void assertCompileTimeBoundaries;
