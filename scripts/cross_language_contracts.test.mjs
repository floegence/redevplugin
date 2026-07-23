#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { build } from "esbuild";

import { decodeUTF8 } from "./generate_platform_package_contracts.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return readFileSync(join(root, relativePath));
}

function readText(relativePath) {
  return read(relativePath).toString("utf8");
}

function readJSON(relativePath) {
  return JSON.parse(readText(relativePath));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

const contractsModuleURL = pathToFileURL(join(root, "packages/redevplugin-contracts/dist/index.js"));
contractsModuleURL.searchParams.set("test", sha256(read("spec/plugin/contract-registry-v2.json")));
const contracts = await import(contractsModuleURL.href);

test("Go, npm, and Rust projections share one contract inventory and digest", () => {
  const registryBytes = read("spec/plugin/contract-registry-v2.json");
  const registry = JSON.parse(registryBytes.toString("utf8"));
  const packageSet = readJSON("spec/plugin/platform-package-set-v1.json");

  assert.deepEqual(Object.keys(contracts).sort(), [
    "InvalidReleaseDocumentError",
    "InvalidReleaseSignatureError",
    "UnknownContractError",
    "buildPackageSignature",
    "buildReleaseMetadata",
    "buildRevocation",
    "buildRevocationPointer",
    "buildRootDelegation",
    "buildSourcePolicy",
    "buildSourcePolicyPointer",
    "canonicalPackageSignature",
    "canonicalReleaseMetadata",
    "canonicalRevocation",
    "canonicalRevocationPointer",
    "canonicalRootDelegation",
	"canonicalSignatureEnvelope",
	"canonicalSigningLedgerEntry",
	"canonicalSigningSubject",
    "canonicalSourcePolicy",
    "canonicalSourcePolicyPointer",
    "contractArtifacts",
    "contractRegistry",
    "contractSetSHA256",
    "createEd25519Verifier",
    "decodePackageSignature",
    "decodeReleaseMetadata",
    "decodeRevocation",
    "decodeRevocationPointer",
    "decodeRootDelegation",
	"decodeSignatureEnvelope",
	"decodeSigningLedgerCheckpoint",
	"decodeSigningLedgerConsistencyProof",
	"decodeSigningLedgerEntry",
    "decodeSigningLedgerEvidence",
	"decodeSigningLedgerInclusionProof",
	"decodeSigningLedgerLatestProof",
	"decodeSigningLedgerLogLeaf",
	"decodeSigningLedgerReceipt",
	"decodeSigningSubject",
    "decodeSourcePolicy",
    "decodeSourcePolicyPointer",
    "defaultSourcePolicyLimits",
    "genesisPreviousDocumentSHA256",
    "genesisPreviousEpoch",
    "getContract",
    "packageSet",
    "packageSignatureSchemaVersion",
    "packageSigningPreimage",
    "registryContract",
    "releaseMetadataSchemaVersion",
    "releaseMetadataSigningPreimage",
    "releaseSigningLedgerEvidenceSchemaVersion",
    "revocationPointerSchemaVersion",
    "revocationPointerSigningPreimage",
    "revocationSchemaVersion",
    "revocationSigningPreimage",
    "rootDelegationSchemaVersion",
    "rootDelegationSigningPreimage",
    "signatureAlgorithmEd25519",
    "signatureEnvelopeSchemaVersion",
    "signingLedgerEntrySchemaVersion",
    "signingLedgerLogLeafSchemaVersion",
    "signingLedgerReceiptSchemaVersion",
    "signingLedgerSchemaVersion",
    "signingSubjectSchemaVersion",
    "signingUsages",
    "sourcePolicyPointerSchemaVersion",
    "sourcePolicyPointerSigningPreimage",
    "sourcePolicySchemaVersion",
    "sourcePolicySigningPreimage",
    "verifyPackageSignature",
    "verifyReleaseMetadata",
    "verifyRevocation",
    "verifyRevocationPointer",
    "verifyRootDelegation",
    "verifySigningLedgerEntryBindings",
    "verifySourcePolicy",
    "verifySourcePolicyPointer",
  ]);
  assert.deepEqual(contracts.contractRegistry, registry);
  assert.deepEqual(contracts.packageSet, packageSet);
  assert.equal(contracts.contractArtifacts.length, registry.artifacts.length);
  for (const [index, artifact] of registry.artifacts.entries()) {
    const projected = contracts.contractArtifacts[index];
    assert.deepEqual(
      { id: projected.id, path: projected.path, version: projected.version, sha256: projected.sha256 },
      artifact,
    );
    assert.equal(Buffer.from(projected.body, "utf8").compare(read(artifact.path)), 0, artifact.id);
    assert.equal(sha256(Buffer.from(projected.body, "utf8")), artifact.sha256, artifact.id);
    assert.equal(contracts.getContract(artifact.id), projected);
  }

  assert.equal(contracts.registryContract.id, "contract-registry");
  assert.equal(contracts.registryContract.version, "contract-registry-v2");
  assert.equal(contracts.registryContract.sha256, sha256(registryBytes));
  assert.equal(Buffer.from(contracts.registryContract.body, "utf8").compare(registryBytes), 0);
  assert.equal(contracts.getContract("contract-registry"), contracts.registryContract);
  assert.equal(contracts.contractSetSHA256, packageSet.contract_set_sha256);

  for (const [path, pattern] of [
    ["pkg/version/contract_set_gen.go", /ContractSetSHA256 = "([0-9a-f]{64})"/],
    ["crates/redevplugin-ipc/src/contract_set_gen.rs", /CONTRACT_SET_SHA256: &str =\s*"([0-9a-f]{64})"/],
    ["crates/redevplugin-contracts/src/contracts_gen.rs", /contract_set_sha256: "([0-9a-f]{64})"/],
  ]) {
    const match = readText(path).match(pattern);
    assert.equal(match?.[1], packageSet.contract_set_sha256, path);
  }
});

test("npm contract exports are recursively immutable and reject unknown IDs", () => {
  const visit = (value) => {
    if (value === null || typeof value !== "object") return;
    assert.ok(Object.isFrozen(value));
    for (const nested of Object.values(value)) visit(nested);
  };
  visit(contracts.packageSet);
  visit(contracts.contractRegistry);
  visit(contracts.contractArtifacts);
  visit(contracts.registryContract);
  assert.throws(() => {
    contracts.packageSet.npm_packages.push({});
  }, TypeError);
  assert.throws(
    () => contracts.getContract("unknown-contract"),
    (error) => error instanceof contracts.UnknownContractError && error.id === "unknown-contract",
  );
});

test("contracts package tarball has one closed browser-neutral payload", () => {
  const outputDirectory = mkdtempSync(join(tmpdir(), "redevplugin-contracts-package-"));
  try {
    const tarball = run("node", [
      "scripts/build_redevplugin_contracts_package.mjs",
      "0.6.8",
      outputDirectory,
    ]).split("\n").at(-1);
    assert.ok(tarball);
    const files = run("tar", ["-tzf", tarball]).split("\n").filter(Boolean).sort();
    assert.deepEqual(files, [
      "package/LICENSE",
      "package/README.md",
      "package/dist/contracts.gen.d.ts",
      "package/dist/contracts.gen.js",
      "package/dist/index.d.ts",
      "package/dist/index.js",
      "package/dist/release-signing.d.ts",
      "package/dist/release-signing.js",
      "package/package.json",
    ]);
    const manifest = JSON.parse(run("tar", ["-xOf", tarball, "package/package.json"]));
    assert.deepEqual(Object.keys(manifest).sort(), [
      "description",
      "exports",
      "files",
      "license",
      "main",
      "name",
      "publishConfig",
      "repository",
      "scripts",
      "sideEffects",
      "type",
      "types",
      "version",
    ]);
    assert.equal(manifest.name, "@floegence/redevplugin-contracts");
    assert.equal(manifest.version, "0.6.8");
    assert.deepEqual(manifest.files, ["dist"]);
    assert.equal(manifest.sideEffects, false);
    assert.deepEqual(Object.keys(manifest.exports), ["."]);
    for (const forbidden of [
      "dependencies",
      "optionalDependencies",
      "peerDependencies",
      "bundledDependencies",
    ]) {
      assert.equal(forbidden in manifest, false, forbidden);
    }
  } finally {
    rmSync(outputDirectory, { recursive: true, force: true });
  }
});

test("contract UTF-8 decoding preserves a leading byte-order mark exactly", () => {
  const source = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("contract\n", "utf8")]);
  assert.equal(Buffer.from(decodeUTF8(source, "BOM fixture"), "utf8").compare(source), 0);
});

test("packed npm packages install together offline and remain browser-neutral", async () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "redevplugin-platform-packages-"));
  const packageDirectory = join(temporaryRoot, "packages");
  const consumerDirectory = join(temporaryRoot, "consumer");
  const version = "0.6.0-ci.local";
  try {
    mkdirSync(packageDirectory, { recursive: true });
    mkdirSync(consumerDirectory, { recursive: true });
    run(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "packages/redevplugin-ui/tsconfig.json"]);
    const contractsTarball = run(process.execPath, [
      "scripts/build_redevplugin_contracts_package.mjs",
      version,
      packageDirectory,
    ]).split("\n").at(-1);
    const uiTarball = run(process.execPath, [
      "scripts/build_redevplugin_ui_package.mjs",
      version,
      packageDirectory,
    ]).split("\n").at(-1);
    assert.ok(contractsTarball);
    assert.ok(uiTarball);
    writeFileSync(join(consumerDirectory, "package.json"), JSON.stringify({
      name: "redevplugin-platform-package-consumer",
      private: true,
      type: "module",
    }, null, 2) + "\n");
    run("npm", [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      contractsTarball,
      uiTarball,
    ], { cwd: consumerDirectory });

    const lock = JSON.parse(readFileSync(join(consumerDirectory, "package-lock.json"), "utf8"));
    const installedContracts = lock.packages["node_modules/@floegence/redevplugin-contracts"];
    const installedUI = lock.packages["node_modules/@floegence/redevplugin-ui"];
    assert.equal(installedContracts.version, version);
    assert.equal(installedUI.version, version);
    assert.match(installedContracts.resolved, /floegence-redevplugin-contracts-0\.6\.0-ci\.local\.tgz$/);
    assert.match(installedUI.resolved, /floegence-redevplugin-ui-0\.6\.0-ci\.local\.tgz$/);
    const installedUIManifest = JSON.parse(readFileSync(
      join(consumerDirectory, "node_modules/@floegence/redevplugin-ui/package.json"),
      "utf8",
    ));
    assert.deepEqual(installedUIManifest.dependencies, {
      "@floegence/redevplugin-contracts": version,
    });
    run(process.execPath, ["--input-type=module", "--eval", `
      await import("@floegence/redevplugin-ui");
      const contracts = await import("@floegence/redevplugin-contracts");
      if (contracts.contractArtifacts.length !== 49) throw new Error("contracts package is incomplete");
    `], { cwd: consumerDirectory });

    const browserBundle = await build({
      bundle: true,
      format: "esm",
      platform: "browser",
      stdin: {
        contents: 'import { contractRegistry } from "@floegence/redevplugin-contracts"; globalThis.registry = contractRegistry;',
        resolveDir: consumerDirectory,
        sourcefile: "contracts-browser-consumer.ts",
      },
      write: false,
    });
    assert.match(browserBundle.outputFiles.map(({ text }) => text).join("\n"), /redevplugin\.contract_registry\.v2/);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("UI entrypoints declare an exact dependency without loading raw contract bodies", async () => {
  const uiPackage = readJSON("packages/redevplugin-ui/package.json");
  const packageSet = readJSON("spec/plugin/platform-package-set-v1.json");
  assert.deepEqual(uiPackage.dependencies, {
    "@floegence/redevplugin-contracts": packageSet.platform_version,
  });
  assert.doesNotMatch(uiPackage.dependencies["@floegence/redevplugin-contracts"], /[~^*]|workspace:|file:|link:/);

  for (const entrypoint of ["index.ts", "trusted-parent.ts", "plugin.ts"]) {
    const result = await build({
      absWorkingDir: root,
      bundle: true,
      entryPoints: [`packages/redevplugin-ui/src/${entrypoint}`],
      format: "esm",
      metafile: true,
      platform: "browser",
      write: false,
    });
    assert.equal(
      Object.keys(result.metafile.inputs).some((path) => path.includes("redevplugin-contracts")),
      false,
      entrypoint,
    );
    const output = result.outputFiles.map(({ text }) => text).join("\n");
    assert.doesNotMatch(output, /redevplugin\.contract_registry\.v2|ReDevPlugin Contract Registry V2/);
  }
});

test("runtime normal dependencies do not link the raw contracts crate", () => {
  const tree = run("cargo", ["tree", "-p", "redevplugin-runtime", "-e", "normal", "--prefix", "none"]);
  assert.equal(tree.split("\n").some((line) => line.startsWith("redevplugin-contracts ")), false);
});
