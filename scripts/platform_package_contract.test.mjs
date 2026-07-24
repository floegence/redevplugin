#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  computeContractSetSHA256,
  decodeContractRegistry,
  decodePlatformPackagePublication,
  decodePlatformPackageSet,
} from "./generate_platform_package_contracts.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rootRealPath = realpathSync(root);

function read(relativePath) {
  return readFileSync(join(root, relativePath));
}

function readJSON(relativePath) {
  return JSON.parse(read(relativePath).toString("utf8"));
}

function workflowJob(relativePath, name) {
  const source = read(relativePath).toString("utf8");
  const marker = `  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `${relativePath} must define ${name}`);
  const remainder = source.slice(start + marker.length);
  const next = remainder.search(/^  [a-z0-9_-]+:\n/m);
  return next === -1 ? remainder : remainder.slice(0, next);
}

function encode(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function clone(value) {
  return structuredClone(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareASCII(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function independentContractSetSHA256(registryBytes, artifacts) {
  const coordinates = artifacts.map(({ id, version, sha256: digest }) => ({
    id,
    version,
    sha256: digest,
  }));
  coordinates.push({
    id: "contract-registry",
    version: "contract-registry-v2",
    sha256: sha256(registryBytes),
  });
  coordinates.sort((left, right) => compareASCII(left.id, right.id));
  return sha256(Buffer.from(JSON.stringify(coordinates), "utf8"));
}

function base64Digest(size, byte, prefix) {
  return `${prefix}${Buffer.alloc(size, byte).toString("base64")}`;
}

function validPublication(packageSet) {
  const sourceCommit = "1".repeat(40);
  const integrityBytes = [0x11, 0x22];
  return {
    schema_version: "redevplugin.platform_package_publication.v1",
    platform_version: packageSet.platform_version,
    source_commit: sourceCommit,
    workflow: {
      repository: "floegence/redevplugin",
      path: ".github/workflows/release.yml",
      ref: `refs/tags/v${packageSet.platform_version}`,
      sha: sourceCommit,
    },
    go_module: {
      module: packageSet.go_module.module,
      version: packageSet.go_module.version,
      h1: base64Digest(32, 0x33, "h1:"),
      go_mod_h1: base64Digest(32, 0x44, "h1:"),
    },
    npm_packages: packageSet.npm_packages.map((coordinate, index) => ({
      ...coordinate,
      integrity: base64Digest(64, integrityBytes[index], "sha512-"),
      provenance_subject_sha512: Buffer.alloc(64, integrityBytes[index]).toString("hex"),
    })),
    rust_crates: packageSet.rust_crates.map(({ name, version }, index) => ({
      name,
      version,
      registry_checksum_sha256: (index + 2).toString(16).repeat(64),
    })),
    contract_set_sha256: packageSet.contract_set_sha256,
  };
}

test("the active compatibility surface is the atomic v8 contract set", () => {
  const activeRegistry = readJSON("spec/plugin/contract-registry-v2.json");
  const compatibilitySchema = readJSON("spec/plugin/compatibility-manifest-v8.schema.json");
  const generatedGo = read("pkg/version/contracts_gen.go").toString("utf8");
  const generatedTypeScript = read("packages/redevplugin-ui/src/contracts.gen.ts").toString("utf8");

  assert.equal(activeRegistry.schema_version, "redevplugin.contract_registry.v2");
  assert.equal(activeRegistry.registry_version, "contract-registry-v2");
  assert.equal(compatibilitySchema.properties.schema_version.const, "redevplugin.compatibility.v8");
  assert.match(generatedGo, /ContractRegistryVersion\s+= "contract-registry-v2"/);
  assert.match(generatedTypeScript, /"contract_registry_version": "contract-registry-v2"/);
  assert.equal(activeRegistry.artifacts.some(({ id }) => id === "release-manifest-schema"), false);
  assert.equal(existsSync(join(root, "spec/plugin/contract-registry-v1.json")), false);
  assert.equal(existsSync(join(root, "spec/plugin/release-manifest-v4.schema.json")), false);
});

test("contract registry v2 is closed, sorted, cycle-free, and content addressed", () => {
  const registryBytes = read("spec/plugin/contract-registry-v2.json");
  const registry = decodeContractRegistry(registryBytes);
  const source = readJSON("internal/contracts/active-contracts.json");
  const expectedIDs = source.artifacts.map(({ id }) => id).sort(compareASCII);

  assert.equal(registryBytes.toString("utf8"), `${JSON.stringify(registry, null, 2)}\n`);
  assert.deepEqual(registry.artifacts.map(({ id }) => id), expectedIDs);
  assert.equal(registry.artifacts.length, 49);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-manifest-schema"), false);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-metadata-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "source-policy-schema"), false);
  assert.equal(registry.artifacts.some(({ id }) => id === "source-revocations-schema"), false);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-root-delegation-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-signing-ledger-evidence-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-source-policy-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-source-policy-pointer-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-revocation-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "release-revocation-pointer-schema"), true);
  assert.equal(registry.artifacts.some(({ id }) => id === "contract-registry"), false);
  assert.equal(registry.artifacts.some(({ path }) => path === "spec/plugin/contract-registry-v2.json"), false);
  assert.equal(registry.artifacts.some(({ path }) => path === "spec/plugin/platform-package-set-v1.json"), false);
  assert.match(read("pkg/host/host.go").toString("utf8"), /type ReleaseArtifactResolver interface/);

  const paths = new Set();
  const versions = new Set();
  for (const artifact of registry.artifacts) {
    assert.equal(paths.has(artifact.path), false, `duplicate path ${artifact.path}`);
    assert.equal(versions.has(artifact.version), false, `duplicate version ${artifact.version}`);
    paths.add(artifact.path);
    versions.add(artifact.version);

    const absolutePath = resolve(root, artifact.path);
    const rel = relative(rootRealPath, realpathSync(absolutePath));
    assert.ok(rel !== "" && rel !== ".." && !rel.startsWith("../"), `${artifact.path} escapes the repository`);
    const info = lstatSync(absolutePath);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${artifact.path} must be a regular file`);
    assert.equal(sha256(read(artifact.path)), artifact.sha256);
  }

  const packageSet = decodePlatformPackageSet(read("spec/plugin/platform-package-set-v1.json"));
  const independentDigest = independentContractSetSHA256(registryBytes, registry.artifacts);
  assert.equal(packageSet.contract_set_sha256, independentDigest);
  assert.equal(computeContractSetSHA256(registryBytes, registry.artifacts), independentDigest);
});

test("contract registry v2 rejects malformed, ambiguous, and cyclic inputs", () => {
  const raw = read("spec/plugin/contract-registry-v2.json");
  const registry = decodeContractRegistry(raw);
  const malformed = [];

  const unknown = clone(registry);
  unknown.unexpected = true;
  malformed.push(encode(unknown));

  const unsorted = clone(registry);
  [unsorted.artifacts[0], unsorted.artifacts[1]] = [unsorted.artifacts[1], unsorted.artifacts[0]];
  malformed.push(encode(unsorted));

  const duplicateID = clone(registry);
  duplicateID.artifacts[1].id = duplicateID.artifacts[0].id;
  malformed.push(encode(duplicateID));

  const duplicatePath = clone(registry);
  duplicatePath.artifacts[1].path = duplicatePath.artifacts[0].path;
  malformed.push(encode(duplicatePath));

  const duplicateVersion = clone(registry);
  duplicateVersion.artifacts[1].version = duplicateVersion.artifacts[0].version;
  malformed.push(encode(duplicateVersion));

  for (const forbiddenPath of [
    "spec/plugin/../../../../etc/passwd",
    "spec/plugin/contract-registry-v2.json",
    "spec/plugin/platform-package-set-v1.json",
  ]) {
    const invalidPath = clone(registry);
    invalidPath.artifacts[0].path = forbiddenPath;
    malformed.push(encode(invalidPath));
  }

  const selfID = clone(registry);
  selfID.artifacts[0].id = "contract-registry";
  malformed.push(encode(selfID));

  const nestedUnknown = clone(registry);
  nestedUnknown.artifacts[0].runtime_binary = "forbidden";
  malformed.push(encode(nestedUnknown));

  malformed.push(Buffer.from(`${raw.toString("utf8")} true`, "utf8"));
  malformed.push(Buffer.from(raw.toString("utf8").replace(
    '"registry_version": "contract-registry-v2",',
    '"registry_version": "contract-registry-v2",\n  "registry_version": "contract-registry-v2",',
  ), "utf8"));
  malformed.push(Buffer.from(raw.toString("utf8").replace(
    '"id": "contract-registry-schema",',
    '"id": "contract-registry-schema",\n      "id": "contract-registry-schema",',
  ), "utf8"));
  malformed.push(Buffer.from([0xff]));
  malformed.push(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), raw]));
  malformed.push(Buffer.alloc(64 * 1024 + 1, 0x20));

  for (const [index, candidate] of malformed.entries()) {
    assert.throws(() => decodeContractRegistry(candidate), `malformed registry case ${index}`);
  }
});

test("platform package set binds the exact Go, npm, Rust, role, and contract coordinates", () => {
  const registryBytes = read("spec/plugin/contract-registry-v2.json");
  const registry = decodeContractRegistry(registryBytes);
  const digest = independentContractSetSHA256(registryBytes, registry.artifacts);
  const packageSet = decodePlatformPackageSet(read("spec/plugin/platform-package-set-v1.json"), digest);
  const platformVersion = readJSON("spec/plugin/platform-version.json");

  assert.deepEqual(platformVersion, {
    schema_version: "redevplugin.platform_version.v1",
    platform_version: "0.6.13",
  });
  assert.equal(packageSet.platform_version, platformVersion.platform_version);
  assert.deepEqual(packageSet.go_module, {
    module: "github.com/floegence/redevplugin",
    version: "v0.6.13",
  });
  assert.deepEqual(packageSet.npm_packages, [
    { name: "@floegence/redevplugin-contracts", version: "0.6.13" },
    { name: "@floegence/redevplugin-ui", version: "0.6.13" },
  ]);
  assert.deepEqual(packageSet.rust_crates, [
    { name: "redevplugin-contracts", version: "0.6.13", role: "contracts" },
    { name: "redevplugin-ipc", version: "0.6.13", role: "ipc" },
    { name: "redevplugin-wasm-abi", version: "0.6.13", role: "wasm_abi" },
    { name: "redevplugin-target-classifier", version: "0.6.13", role: "target_classifier" },
    { name: "redevplugin-worker-sdk", version: "0.6.13", role: "worker_sdk" },
    { name: "redevplugin-runtime", version: "0.6.13", role: "runtime" },
  ]);
  assert.equal(packageSet.contract_registry_version, "contract-registry-v2");
  assert.equal(packageSet.contract_set_sha256, digest);
  assert.doesNotMatch(JSON.stringify(packageSet), /runtime_binary|runtime_archive|installer|product_signature|product_checksum/i);
});

test("Rust source packages remain wired into dedicated Rust and release gates", () => {
  const packageJSON = readJSON("package.json");
  assert.equal(
    packageJSON.scripts["rust-source-packages:test"],
    "node --test scripts/rust_source_packages.test.mjs",
  );
  assert.match(
    read("scripts/check_redevplugin_pre_push.sh").toString("utf8"),
    /cargo deny check\nnpm run rust-source-packages:test\n/,
  );

  const rustJob = workflowJob(".github/workflows/ci.yml", "rust");
  assert.match(rustJob, /actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020/);
  assert.match(rustJob, /node-version: 24/);
  assert.match(rustJob, /npm run rust-source-packages:test/);

  const releaseQuality = workflowJob(".github/workflows/release.yml", "quality");
  assert.match(releaseQuality, /\.\/scripts\/check_redevplugin_pre_push\.sh --ci/);
  const packageBuild = workflowJob(".github/workflows/release.yml", "package-build");
  assert.match(packageBuild, /rustup target add wasm32-unknown-unknown/);
  assert.match(packageBuild, /scripts\/platform_package_build\.mjs build/);
  assert.match(packageBuild, /scripts\/platform_package_build\.mjs verify/);
  assert.doesNotMatch(read(".github/workflows/release.yml").toString("utf8"), /build_redevplugin_release|runtime-target|\.tar\.gz/);
  assert.doesNotMatch(packageJSON.scripts.check, /rust-source-packages/);
});

test("platform package set rejects duplicate, mismatched, unknown, and OS artifact fields", () => {
  const registryBytes = read("spec/plugin/contract-registry-v2.json");
  const registry = decodeContractRegistry(registryBytes);
  const digest = independentContractSetSHA256(registryBytes, registry.artifacts);
  const raw = read("spec/plugin/platform-package-set-v1.json");
  const packageSet = decodePlatformPackageSet(raw, digest);
  const invalid = [];

  const duplicateNPM = clone(packageSet);
  duplicateNPM.npm_packages[1] = clone(duplicateNPM.npm_packages[0]);
  invalid.push(duplicateNPM);

  const wrongRole = clone(packageSet);
  wrongRole.rust_crates[0].role = "runtime";
  invalid.push(wrongRole);

  const wrongVersion = clone(packageSet);
  wrongVersion.rust_crates[5].version = "0.6.0";
  invalid.push(wrongVersion);

  const wrongDigest = clone(packageSet);
  wrongDigest.contract_set_sha256 = "0".repeat(64);
  invalid.push(wrongDigest);

  for (const mutate of [
    (value) => { value.runtime_binary = "forbidden"; },
    (value) => { value.go_module.installer = "forbidden"; },
    (value) => { value.npm_packages[0].product_signature = "forbidden"; },
    (value) => { value.rust_crates[0].runtime_archive = "forbidden"; },
  ]) {
    const candidate = clone(packageSet);
    mutate(candidate);
    invalid.push(candidate);
  }

  for (const candidate of invalid) {
    assert.throws(() => decodePlatformPackageSet(encode(candidate), digest));
  }
  assert.throws(() => decodePlatformPackageSet(Buffer.from(`${raw.toString("utf8")} null`, "utf8"), digest));
  assert.throws(() => decodePlatformPackageSet(Buffer.from(raw.toString("utf8").replace(
    '"platform_version": "0.6.13",',
    '"platform_version": "0.6.13",\n  "platform_version": "0.6.13",',
  ), "utf8"), digest));
  assert.throws(() => decodePlatformPackageSet(Buffer.from(raw.toString("utf8").replace(
    '"name": "@floegence/redevplugin-contracts",',
    '"name": "@floegence/redevplugin-contracts",\n      "name": "@floegence/redevplugin-contracts",',
  ), "utf8"), digest));
});

test("platform publication schema and decoder cannot describe product artifacts", () => {
  const schema = readJSON("spec/plugin/platform-package-publication-v1.schema.json");
  const registryBytes = read("spec/plugin/contract-registry-v2.json");
  const registry = decodeContractRegistry(registryBytes);
  const digest = independentContractSetSHA256(registryBytes, registry.artifacts);
  const packageSet = decodePlatformPackageSet(read("spec/plugin/platform-package-set-v1.json"), digest);
  const publication = validPublication(packageSet);

  assert.deepEqual(Object.keys(schema.properties).sort(compareASCII), [
    "contract_set_sha256",
    "go_module",
    "npm_packages",
    "platform_version",
    "rust_crates",
    "schema_version",
    "source_commit",
    "workflow",
  ]);
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.schema_version.const, "redevplugin.platform_package_publication.v1");
  assert.equal(schema.properties.npm_packages.prefixItems.length, 2);
  assert.equal(schema.properties.rust_crates.prefixItems.length, 6);
  assert.equal(schema.properties.npm_packages.items, false);
  assert.equal(schema.properties.rust_crates.items, false);
  assert.deepEqual(decodePlatformPackagePublication(encode(publication), digest), publication);

  const invalid = [];
  const wrongRepository = clone(publication);
  wrongRepository.workflow.repository = "attacker/redevplugin";
  invalid.push(wrongRepository);
  const wrongWorkflow = clone(publication);
  wrongWorkflow.workflow.path = ".github/workflows/other.yml";
  invalid.push(wrongWorkflow);
  const wrongRef = clone(publication);
  wrongRef.workflow.ref = "refs/tags/v9.9.9";
  invalid.push(wrongRef);
  const wrongCommit = clone(publication);
  wrongCommit.workflow.sha = "2".repeat(40);
  invalid.push(wrongCommit);
  const wrongVersion = clone(publication);
  wrongVersion.npm_packages[0].version = "0.6.0";
  invalid.push(wrongVersion);
  const duplicateCrate = clone(publication);
  duplicateCrate.rust_crates[1] = clone(duplicateCrate.rust_crates[0]);
  invalid.push(duplicateCrate);
  const shortIntegrity = clone(publication);
  shortIntegrity.npm_packages[0].integrity = "sha512-AA==";
  invalid.push(shortIntegrity);
  const wrongProvenance = clone(publication);
  wrongProvenance.npm_packages[0].provenance_subject_sha512 = "0".repeat(128);
  invalid.push(wrongProvenance);
  const wrongDigest = clone(publication);
  wrongDigest.contract_set_sha256 = "0".repeat(64);
  invalid.push(wrongDigest);

  for (const mutate of [
    (value) => { value.runtime_binary = "forbidden"; },
    (value) => { value.workflow.installer = "forbidden"; },
    (value) => { value.go_module.product_checksum = "forbidden"; },
    (value) => { value.npm_packages[0].product_signature = "forbidden"; },
    (value) => { value.rust_crates[0].runtime_archive = "forbidden"; },
  ]) {
    const candidate = clone(publication);
    mutate(candidate);
    invalid.push(candidate);
  }

  for (const candidate of invalid) {
    assert.throws(() => decodePlatformPackagePublication(encode(candidate), digest));
  }
  const raw = JSON.stringify(publication);
  assert.throws(() => decodePlatformPackagePublication(Buffer.from(`${raw} true`, "utf8"), digest));
  assert.throws(() => decodePlatformPackagePublication(Buffer.from(raw.replace(
    '"repository":"floegence/redevplugin",',
    '"repository":"floegence/redevplugin","repository":"floegence/redevplugin",',
  ), "utf8"), digest));
});
