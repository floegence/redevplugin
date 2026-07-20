#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const registrySeedPath = join(root, "spec/plugin/contract-registry-v1.json");
const platformVersionPath = join(root, "spec/plugin/platform-version.json");
const registryOutputPath = join(root, "spec/plugin/contract-registry-v2.json");
const packageSetOutputPath = join(root, "spec/plugin/platform-package-set-v1.json");
const checkOnly = process.argv.slice(2).includes("--check");

const MAX_JSON_BYTES = 64 * 1024;
const MAX_CONTRACT_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_CONTRACT_BYTES = 32 * 1024 * 1024;
const RETIRED_SEED_IDS = new Set(["contract-registry", "release-manifest-schema"]);
const FORBIDDEN_ARTIFACT_PATHS = new Set([
  "spec/plugin/contract-registry-v2.json",
  "spec/plugin/platform-package-set-v1.json",
]);

const npmPackages = [
  "@floegence/redevplugin-contracts",
  "@floegence/redevplugin-ui",
];

const rustCrates = [
  ["redevplugin-contracts", "contracts"],
  ["redevplugin-ipc", "ipc"],
  ["redevplugin-wasm-abi", "wasm_abi"],
  ["redevplugin-target-classifier", "target_classifier"],
  ["redevplugin-worker-sdk", "worker_sdk"],
  ["redevplugin-runtime", "runtime"],
];

const stagedSchemaArtifacts = [
  {
    id: "contract-registry-schema",
    path: "spec/plugin/contract-registry-v2.schema.json",
    version: "contract-registry-v2",
  },
  {
    id: "platform-package-publication-schema",
    path: "spec/plugin/platform-package-publication-v1.schema.json",
    version: "platform-package-publication-v1",
  },
  {
    id: "platform-package-set-schema",
    path: "spec/plugin/platform-package-set-v1.schema.json",
    version: "platform-package-set-v1",
  },
];

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}

async function main() {
  const outputs = await generatePlatformPackageContracts();
  for (const [filename, content] of outputs) {
    if (checkOnly) {
      const current = await readFile(filename, "utf8").catch(() => "");
      if (current !== content) {
        throw new Error(`${relative(root, filename)} is stale; run npm run platform-package-contracts:generate`);
      }
      continue;
    }
    await writeFile(filename, content);
  }
}

export async function generatePlatformPackageContracts() {
  const platformVersionSource = parseStrictJSON(
    await readFile(platformVersionPath),
    "platform version source",
  );
  exactKeys(platformVersionSource, ["schema_version", "platform_version"], "platform version source");
  if (platformVersionSource.schema_version !== "redevplugin.platform_version.v1") {
    throw new Error("unsupported platform version source schema");
  }
  assertStableVersion(platformVersionSource.platform_version, "platform version");

  const seed = parseStrictJSON(await readFile(registrySeedPath), "active contract registry seed");
  validateRegistrySeed(seed);
  const declarations = seed.contracts
    .filter(({ id }) => !RETIRED_SEED_IDS.has(id))
    .map((contract) => ({
      id: contract.id,
      path: contract.path,
      version: seed.matrix[contract.version_key],
    }))
    .concat(stagedSchemaArtifacts)
    .sort(compareArtifactIDs);

  validateArtifactDeclarations(declarations);
  const artifacts = [];
  let totalBytes = 0;
  for (const declaration of declarations) {
    const content = await readContractFile(declaration.path);
    totalBytes += content.length;
    if (totalBytes > MAX_TOTAL_CONTRACT_BYTES) {
      throw new Error("staged contract set exceeds the total byte limit");
    }
    artifacts.push({
      id: declaration.id,
      path: declaration.path,
      version: declaration.version,
      sha256: sha256(content),
    });
  }

  const registry = {
    schema_version: "redevplugin.contract_registry.v2",
    registry_version: "contract-registry-v2",
    artifacts,
  };
  validateContractRegistry(registry);
  const registryBytes = canonicalDocument(registry);
  const contractSetSHA256 = computeContractSetSHA256(registryBytes, artifacts);
  const version = platformVersionSource.platform_version;
  const packageSet = {
    schema_version: "redevplugin.platform_package_set.v1",
    platform_version: version,
    go_module: {
      module: "github.com/floegence/redevplugin",
      version: `v${version}`,
    },
    npm_packages: npmPackages.map((name) => ({ name, version })),
    rust_crates: rustCrates.map(([name, role]) => ({ name, version, role })),
    contract_registry_version: "contract-registry-v2",
    contract_set_sha256: contractSetSHA256,
  };
  validatePlatformPackageSet(packageSet, contractSetSHA256);

  return new Map([
    [registryOutputPath, registryBytes.toString("utf8")],
    [packageSetOutputPath, canonicalDocument(packageSet).toString("utf8")],
  ]);
}

export function decodeContractRegistry(raw) {
  const value = parseStrictJSON(raw, "contract registry");
  validateContractRegistry(value);
  return value;
}

export function decodePlatformPackageSet(raw, expectedContractSetSHA256) {
  const value = parseStrictJSON(raw, "platform package set");
  validatePlatformPackageSet(value, expectedContractSetSHA256);
  return value;
}

export function decodePlatformPackagePublication(raw, expectedContractSetSHA256) {
  const value = parseStrictJSON(raw, "platform package publication");
  validatePlatformPackagePublication(value, expectedContractSetSHA256);
  return value;
}

export function computeContractSetSHA256(registryBytes, artifacts) {
  const body = toBuffer(registryBytes, "contract registry bytes");
  const coordinates = artifacts.map(({ id, version, sha256: digest }) => ({
    id,
    version,
    sha256: digest,
  }));
  coordinates.push({
    id: "contract-registry",
    version: "contract-registry-v2",
    sha256: sha256(body),
  });
  coordinates.sort(compareArtifactIDs);
  return sha256(Buffer.from(JSON.stringify(coordinates), "utf8"));
}

function validateRegistrySeed(value) {
  exactKeys(value, ["schema_version", "matrix", "contracts"], "active contract registry seed");
  if (value.schema_version !== "redevplugin.contract_registry.v1") {
    throw new Error("R1b must derive from the still-active contract-registry-v1 seed");
  }
  if (!isRecord(value.matrix) || Object.keys(value.matrix).length === 0) {
    throw new Error("active contract registry matrix is required");
  }
  if (!Array.isArray(value.contracts) || value.contracts.length === 0) {
    throw new Error("active contract registry contracts are required");
  }
  const ids = new Set();
  const paths = new Set();
  for (const contract of value.contracts) {
    exactKeys(contract, ["id", "path", "version_key"], "active contract registry entry");
    assertID(contract.id, "active contract id");
    assertSafeContractPath(contract.path);
    if (ids.has(contract.id) || paths.has(contract.path)) {
      throw new Error(`duplicate active contract declaration: ${contract.id}`);
    }
    if (typeof contract.version_key !== "string" || !(contract.version_key in value.matrix)) {
      throw new Error(`unknown active contract version key: ${contract.version_key}`);
    }
    assertVersionLabel(value.matrix[contract.version_key], `active contract ${contract.id} version`);
    ids.add(contract.id);
    paths.add(contract.path);
  }
}

function validateArtifactDeclarations(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length === 0 || artifacts.length > 256) {
    throw new Error("staged artifact declarations must contain 1..256 entries");
  }
  const ids = new Set();
  const paths = new Set();
  const versions = new Set();
  let previousID = "";
  for (const artifact of artifacts) {
    exactKeys(artifact, ["id", "path", "version"], "staged artifact declaration");
    assertID(artifact.id, "staged artifact id");
    assertSafeContractPath(artifact.path);
    assertVersionLabel(artifact.version, `staged artifact ${artifact.id} version`);
    if (previousID && compareASCII(previousID, artifact.id) >= 0) {
      throw new Error("staged artifact declarations must be strictly sorted by id");
    }
    if (ids.has(artifact.id) || paths.has(artifact.path) || versions.has(artifact.version)) {
      throw new Error(`duplicate staged artifact coordinate: ${artifact.id}`);
    }
    if (artifact.id === "contract-registry" || FORBIDDEN_ARTIFACT_PATHS.has(artifact.path)) {
      throw new Error(`staged artifact creates a registry hash cycle: ${artifact.id}`);
    }
    previousID = artifact.id;
    ids.add(artifact.id);
    paths.add(artifact.path);
    versions.add(artifact.version);
  }
}

function validateContractRegistry(value) {
  if (!isRecord(value)) throw new Error("contract registry must be an object");
  exactKeys(value, ["schema_version", "registry_version", "artifacts"], "contract registry");
  if (value.schema_version !== "redevplugin.contract_registry.v2") {
    throw new Error("unsupported contract registry schema version");
  }
  if (value.registry_version !== "contract-registry-v2") {
    throw new Error("unsupported contract registry version");
  }
  if (!Array.isArray(value.artifacts)) throw new Error("contract registry artifacts must be an array");
  const declarations = value.artifacts.map((artifact) => {
    if (!isRecord(artifact)) throw new Error("contract registry artifact must be an object");
    exactKeys(artifact, ["id", "path", "version", "sha256"], "contract registry artifact");
    assertSHA256(artifact.sha256, `contract registry ${artifact.id} sha256`);
    return { id: artifact.id, path: artifact.path, version: artifact.version };
  });
  validateArtifactDeclarations(declarations);
}

function validatePlatformPackageSet(value, expectedContractSetSHA256) {
  if (!isRecord(value)) throw new Error("platform package set must be an object");
  exactKeys(value, [
    "schema_version",
    "platform_version",
    "go_module",
    "npm_packages",
    "rust_crates",
    "contract_registry_version",
    "contract_set_sha256",
  ], "platform package set");
  if (value.schema_version !== "redevplugin.platform_package_set.v1") {
    throw new Error("unsupported platform package set schema version");
  }
  assertStableVersion(value.platform_version, "platform package set version");
  validateGoModuleCoordinate(value.go_module, value.platform_version, false);
  validateNPMPackageCoordinates(value.npm_packages, value.platform_version, false);
  validateRustCrateCoordinates(value.rust_crates, value.platform_version, false);
  if (value.contract_registry_version !== "contract-registry-v2") {
    throw new Error("platform package set registry version mismatch");
  }
  assertSHA256(value.contract_set_sha256, "platform package set contract digest");
  if (expectedContractSetSHA256 !== undefined && value.contract_set_sha256 !== expectedContractSetSHA256) {
    throw new Error("platform package set contract digest mismatch");
  }
}

function validatePlatformPackagePublication(value, expectedContractSetSHA256) {
  if (!isRecord(value)) throw new Error("platform package publication must be an object");
  exactKeys(value, [
    "schema_version",
    "platform_version",
    "source_commit",
    "workflow",
    "go_module",
    "npm_packages",
    "rust_crates",
    "contract_set_sha256",
  ], "platform package publication");
  if (value.schema_version !== "redevplugin.platform_package_publication.v1") {
    throw new Error("unsupported platform package publication schema version");
  }
  assertStableVersion(value.platform_version, "platform package publication version");
  assertCommit(value.source_commit, "platform package publication source commit");
  validatePublicationWorkflow(value.workflow, value.platform_version, value.source_commit);
  validateGoModuleCoordinate(value.go_module, value.platform_version, true);
  validateNPMPackageCoordinates(value.npm_packages, value.platform_version, true);
  validateRustCrateCoordinates(value.rust_crates, value.platform_version, true);
  assertSHA256(value.contract_set_sha256, "platform package publication contract digest");
  if (expectedContractSetSHA256 !== undefined && value.contract_set_sha256 !== expectedContractSetSHA256) {
    throw new Error("platform package publication contract digest mismatch");
  }
}

function validatePublicationWorkflow(value, version, sourceCommit) {
  if (!isRecord(value)) throw new Error("publication workflow must be an object");
  exactKeys(value, ["repository", "path", "ref", "sha"], "publication workflow");
  if (value.repository !== "floegence/redevplugin" || value.path !== ".github/workflows/release.yml") {
    throw new Error("publication workflow identity mismatch");
  }
  if (value.ref !== `refs/tags/v${version}`) throw new Error("publication workflow ref mismatch");
  assertCommit(value.sha, "publication workflow sha");
  if (value.sha !== sourceCommit) throw new Error("publication workflow source commit mismatch");
}

function validateGoModuleCoordinate(value, version, published) {
  if (!isRecord(value)) throw new Error("Go module coordinate must be an object");
  const keys = published ? ["module", "version", "h1", "go_mod_h1"] : ["module", "version"];
  exactKeys(value, keys, "Go module coordinate");
  if (value.module !== "github.com/floegence/redevplugin" || value.version !== `v${version}`) {
    throw new Error("Go module coordinate mismatch");
  }
  if (published) {
    assertBase64Digest(value.h1, "h1:", 32, "Go module h1");
    assertBase64Digest(value.go_mod_h1, "h1:", 32, "Go module go.mod h1");
  }
}

function validateNPMPackageCoordinates(values, version, published) {
  if (!Array.isArray(values) || values.length !== npmPackages.length) {
    throw new Error("npm package coordinates must contain the exact package set");
  }
  for (let index = 0; index < npmPackages.length; index += 1) {
    const value = values[index];
    if (!isRecord(value)) throw new Error("npm package coordinate must be an object");
    const keys = published
      ? ["name", "version", "integrity", "provenance_subject_sha512"]
      : ["name", "version"];
    exactKeys(value, keys, `npm package ${index}`);
    if (value.name !== npmPackages[index] || value.version !== version) {
      throw new Error(`npm package coordinate mismatch at index ${index}`);
    }
    if (published) {
      const bytes = assertBase64Digest(value.integrity, "sha512-", 64, `npm package ${index} integrity`);
      if (!/^[0-9a-f]{128}$/.test(value.provenance_subject_sha512)
          || bytes.toString("hex") !== value.provenance_subject_sha512) {
        throw new Error(`npm package ${index} provenance digest mismatch`);
      }
    }
  }
}

function validateRustCrateCoordinates(values, version, published) {
  if (!Array.isArray(values) || values.length !== rustCrates.length) {
    throw new Error("Rust crate coordinates must contain the exact crate set");
  }
  for (let index = 0; index < rustCrates.length; index += 1) {
    const value = values[index];
    if (!isRecord(value)) throw new Error("Rust crate coordinate must be an object");
    const [name, role] = rustCrates[index];
    const keys = published ? ["name", "version", "registry_checksum_sha256"] : ["name", "version", "role"];
    exactKeys(value, keys, `Rust crate ${index}`);
    if (value.name !== name || value.version !== version || (!published && value.role !== role)) {
      throw new Error(`Rust crate coordinate mismatch at index ${index}`);
    }
    if (published) assertSHA256(value.registry_checksum_sha256, `Rust crate ${index} checksum`);
  }
}

async function readContractFile(path) {
  assertSafeContractPath(path);
  const absolutePath = resolve(root, path);
  const rootRealPath = await realpath(root);
  const info = await lstat(absolutePath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`contract artifact must be a regular non-symlink file: ${path}`);
  }
  const resolvedPath = await realpath(absolutePath);
  if (!isWithin(rootRealPath, resolvedPath)) {
    throw new Error(`contract artifact escapes the repository root: ${path}`);
  }
  if (info.size <= 0 || info.size > MAX_CONTRACT_BYTES) {
    throw new Error(`contract artifact has an invalid size: ${path}`);
  }
  return readFile(absolutePath);
}

function parseStrictJSON(raw, label) {
  const bytes = toBuffer(raw, label);
  if (bytes.length === 0 || bytes.length > MAX_JSON_BYTES) {
    throw new Error(`${label} must contain 1..${MAX_JSON_BYTES} bytes`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error(`${label} must not contain a UTF-8 byte-order mark`);
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const document = parseDocument(text, {
    schema: "json",
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    throw new Error(`${label} contains duplicate or invalid JSON keys: ${document.errors[0].message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not one strict JSON document: ${error.message}`);
  }
}

function canonicalDocument(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function exactKeys(value, expected, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort(compareASCII);
  const wanted = [...expected].sort(compareASCII);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} must contain exactly: ${wanted.join(", ")}`);
  }
}

function assertSafeContractPath(path) {
  if (typeof path !== "string" || path.length === 0 || path.length > 1024
      || !/^spec\/(openapi|plugin)\/[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(path)
      || path.includes("..") || path.includes("\\")) {
    throw new Error(`unsafe contract path: ${path}`);
  }
}

function assertID(value, label) {
  if (typeof value !== "string" || value.length > 128 || !/^[a-z][a-z0-9-]+$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function assertVersionLabel(value, label) {
  if (typeof value !== "string" || value.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function assertStableVersion(value, label) {
  if (typeof value !== "string" || value.length > 64
      || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a stable semantic version`);
  }
}

function assertSHA256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertCommit(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error(`${label} must be a lowercase Git commit OID`);
  }
}

function assertBase64Digest(value, prefix, size, label) {
  if (typeof value !== "string" || !value.startsWith(prefix)) throw new Error(`${label} is invalid`);
  const encoded = value.slice(prefix.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error(`${label} is invalid`);
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== size || bytes.toString("base64") !== encoded) throw new Error(`${label} is invalid`);
  return bytes;
}

function isWithin(parent, filename) {
  const rel = relative(parent, filename);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !resolve(filename).startsWith(`${parent}${sep}..${sep}`);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareArtifactIDs(left, right) {
  return compareASCII(left.id, right.id);
}

function compareASCII(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toBuffer(raw, label) {
  if (Buffer.isBuffer(raw)) return raw;
  if (typeof raw === "string") return Buffer.from(raw, "utf8");
  if (raw instanceof Uint8Array) return Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  throw new TypeError(`${label} must be bytes or a string`);
}
