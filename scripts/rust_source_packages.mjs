#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { validateTarGzipArchive } from "./archive_contract.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const platformVersion = JSON.parse(
  readFileSync(join(root, "spec/plugin/platform-version.json"), "utf8"),
).platform_version;
const rustToolchainSource = readFileSync(join(root, "rust-toolchain.toml"), "utf8");
const rustToolchainMatch = rustToolchainSource.match(/^channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$/m);
if (!rustToolchainMatch) throw new Error("rust-toolchain.toml must pin an exact stable Rust version");
const rustToolchain = rustToolchainMatch[1];
const OFFICIAL_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index";

export const rustSourcePackages = Object.freeze([
  Object.freeze({ name: "redevplugin-contracts", role: "contracts" }),
  Object.freeze({ name: "redevplugin-ipc", role: "ipc" }),
  Object.freeze({ name: "redevplugin-wasm-abi", role: "wasm_abi" }),
  Object.freeze({ name: "redevplugin-target-classifier", role: "target_classifier" }),
  Object.freeze({ name: "redevplugin-worker-sdk", role: "worker_sdk" }),
  Object.freeze({ name: "redevplugin-runtime", role: "runtime" }),
]);

const MAX_INDEX_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 16 * 1024 * 1024;
const MAX_PACKAGE_ENTRIES = 4_096;
const MAX_PACKAGE_MEMBER_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGE_UNCOMPRESSED_BYTES = 32 * 1024 * 1024;
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/;
const TOKEN_PATTERNS = [
  /gh[pousr]_[A-Za-z0-9]{30,}/,
  /npm_[A-Za-z0-9]{30,}/,
  /AKIA[0-9A-Z]{16}/,
];
const FORBIDDEN_FILENAMES = [
  /(^|\/)build\.rs$/i,
  /(^|\/)(?:id_rsa|id_ed25519|credentials|\.npmrc|\.env)$/i,
  /\.(?:a|bc|dll|dylib|exe|key|lib|o|obj|pem|rlib|so)$/i,
];

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const requireClean = process.argv.includes("--require-clean");
  const result = await buildRustSourcePackages({ allowDirty: !requireClean });
  result.cleanup();
}

export async function buildRustSourcePackages({ allowDirty = true, keepTemporary = false } = {}) {
  validateSourcePackageMetadata();
  const temporaryRoot = mkdtempSync(join(tmpdir(), "redevplugin-rust-packages-"));
  const cargoHome = join(temporaryRoot, "cargo-home");
  const registryRoot = join(temporaryRoot, "registry");
  const packageTarget = join(temporaryRoot, "package-target");
  const unpackedRoot = join(temporaryRoot, "unpacked");
  mkdirSync(cargoHome, { recursive: true });
  mkdirSync(join(registryRoot, "index"), { recursive: true });
  mkdirSync(packageTarget, { recursive: true });
  mkdirSync(unpackedRoot, { recursive: true });

  try {
    const seedEnvironment = cargoEnvironment(cargoHome);
    run("cargo", ["fetch", "--locked"], { cwd: root, env: seedEnvironment });
    const workspaceMetadata = JSON.parse(run("cargo", [
      "metadata",
      "--locked",
      "--format-version",
      "1",
    ], { cwd: root, env: seedEnvironment }));
    await seedExternalRegistry({ cargoHome, registryRoot, workspaceMetadata });
    writeCargoSourceReplacement(cargoHome, registryRoot);

    const packageEnvironment = cargoEnvironment(cargoHome, {
      CARGO_NET_OFFLINE: "true",
      CARGO_TARGET_DIR: join(temporaryRoot, "build-target"),
    });
    const artifacts = [];
    for (const coordinate of rustSourcePackages) {
      const packageMetadata = workspaceMetadata.packages.find(({ name }) => name === coordinate.name);
      if (!packageMetadata) throw new Error(`cargo metadata omitted ${coordinate.name}`);
      const packageArguments = [
        "package",
        "--locked",
        "--package",
        coordinate.name,
        "--target-dir",
        packageTarget,
      ];
      if (allowDirty) packageArguments.push("--allow-dirty");
      run("cargo", packageArguments, { cwd: root, env: packageEnvironment });
      const archivePath = join(packageTarget, "package", `${coordinate.name}-${platformVersion}.crate`);
      if (!existsSync(archivePath)) throw new Error(`cargo package omitted ${archivePath}`);
      assertPackageArchiveSize(archivePath, coordinate.name);
      const firstBytes = readFileSync(archivePath);
      const firstDigest = sha256(firstBytes);
      run("cargo", packageArguments, { cwd: root, env: packageEnvironment });
      assertPackageArchiveSize(archivePath, coordinate.name);
      const secondBytes = readFileSync(archivePath);
      if (!firstBytes.equals(secondBytes)) {
        throw new Error(`${coordinate.name} package bytes are not deterministic`);
      }

      const extractionRoot = join(unpackedRoot, coordinate.name);
      const packageRoot = inspectAndExtractPackage({
        archivePath,
        extractionRoot,
        packageName: coordinate.name,
      });
      registerPackage({
        registryRoot,
        archivePath,
        packageMetadata,
        checksum: firstDigest,
      });
      verifyUnpackedPackage({
        cargoHome,
        packageName: coordinate.name,
        packageRoot,
        registryRoot,
        repositoryRoot: root,
      });
      artifacts.push(Object.freeze({
        ...coordinate,
        version: platformVersion,
        archivePath,
        sha256: firstDigest,
        size: firstBytes.length,
      }));
    }
    return Object.freeze({
      temporaryRoot,
      cargoHome,
      registryRoot,
      artifacts: Object.freeze(artifacts),
      cleanup() {
        if (!keepTemporary) rmSync(temporaryRoot, { recursive: true, force: true });
      },
    });
  } catch (error) {
    if (!keepTemporary) rmSync(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}

export function validateSourcePackageMetadata() {
  const metadata = JSON.parse(run("cargo", [
    "metadata",
    "--locked",
    "--format-version",
    "1",
    "--no-deps",
  ], { cwd: root, env: cargoEnvironment(process.env.CARGO_HOME) }));
  const packageSet = JSON.parse(
    readFileSync(join(root, "spec/plugin/platform-package-set-v1.json"), "utf8"),
  );
  const expected = packageSet.rust_crates.map(({ name, version, role }) => ({ name, version, role }));
  if (JSON.stringify(expected) !== JSON.stringify(rustSourcePackages.map(({ name, role }) => ({
    name,
    version: platformVersion,
    role,
  })))) {
    throw new Error("Rust source package topology differs from the platform package set");
  }

  for (const coordinate of rustSourcePackages) {
    const pkg = metadata.packages.find(({ name }) => name === coordinate.name);
    if (!pkg) throw new Error(`cargo metadata omitted ${coordinate.name}`);
    for (const [field, expectedValue] of [
      ["version", platformVersion],
      ["edition", "2024"],
      ["license", "MIT"],
      ["repository", "https://github.com/floegence/redevplugin"],
      ["rust_version", rustToolchain],
    ]) {
      if (pkg[field] !== expectedValue) {
        throw new Error(`${coordinate.name} ${field} = ${JSON.stringify(pkg[field])}, want ${expectedValue}`);
      }
    }
    if (typeof pkg.description !== "string" || pkg.description.length === 0) {
      throw new Error(`${coordinate.name} description is required`);
    }
    if (typeof pkg.manifest_path !== "string" || !isWithin(root, pkg.manifest_path)) {
      throw new Error(`${coordinate.name} manifest path escapes the repository`);
    }
    const packageRoot = dirname(pkg.manifest_path);
    const manifest = readFileSync(pkg.manifest_path, "utf8");
    if (!manifest.includes('readme = "README.md"')
        || !manifest.includes("include = [")
        || !manifest.includes('"LICENSE"')) {
      throw new Error(`${coordinate.name} must declare README, LICENSE, and a closed include set`);
    }
    for (const required of ["LICENSE", "README.md"]) {
      if (!existsSync(join(packageRoot, required))) {
        throw new Error(`${coordinate.name} ${required} is missing`);
      }
    }
    if (/^publish\s*=\s*false\s*$/m.test(manifest)) {
      throw new Error(`${coordinate.name} is not publishable`);
    }
    assertNoFirstPartyBuildHooks(pkg, coordinate.name);
  }

  const expectedInternalDependencies = new Map([
    ["redevplugin-ipc", new Set(["redevplugin-contracts"])],
    ["redevplugin-target-classifier", new Set(["redevplugin-contracts"])],
    ["redevplugin-runtime", new Set(["redevplugin-ipc", "redevplugin-wasm-abi"])],
  ]);
  for (const coordinate of rustSourcePackages) {
    const pkg = metadata.packages.find(({ name }) => name === coordinate.name);
    const expected = expectedInternalDependencies.get(coordinate.name) ?? new Set();
    const actual = new Set();
    for (const dependency of pkg.dependencies) {
      if (dependency.source !== null) {
        if (dependency.source !== OFFICIAL_REGISTRY_SOURCE) {
          throw new Error(`${coordinate.name} dependency ${dependency.name} uses a forbidden source`);
        }
        continue;
      }
      if (!expected.has(dependency.name)) {
        throw new Error(`${coordinate.name} has unexpected path dependency ${dependency.name}`);
      }
      const expectedPath = join(root, "crates", dependency.name);
      if (dependency.req !== `=${platformVersion}`
          || typeof dependency.path !== "string"
          || realpathSync(dependency.path) !== realpathSync(expectedPath)) {
        throw new Error(`${coordinate.name} must use canonical path + exact ${dependency.name} ${platformVersion}`);
      }
      actual.add(dependency.name);
    }
    if (actual.size !== expected.size || [...expected].some((name) => !actual.has(name))) {
      throw new Error(`${coordinate.name} internal dependency topology is incomplete`);
    }
  }

  const runtime = metadata.packages.find(({ name }) => name === "redevplugin-runtime");
  if (runtime.dependencies.some(({ name, kind }) => name === "redevplugin-contracts" && kind === null)) {
    throw new Error("runtime normal dependencies must not link raw contracts");
  }
}

export function assertSafePackagedFile(relativePath, bytes) {
  const portablePath = relativePath.replaceAll("\\", "/");
  for (const pattern of FORBIDDEN_FILENAMES) {
    if (pattern.test(portablePath)) throw new Error(`forbidden package file ${portablePath}`);
  }
  if (hasNativeMagic(bytes)) throw new Error(`native executable or library bytes in ${portablePath}`);
  const ascii = bytes.toString("latin1");
  if (PRIVATE_KEY_PATTERN.test(ascii) || TOKEN_PATTERNS.some((pattern) => pattern.test(ascii))) {
    throw new Error(`credential material in ${portablePath}`);
  }
}

export function writeRegistryEntry(registryRoot, entry) {
  const path = join(registryRoot, "index", registryIndexPath(entry.name));
  mkdirSync(dirname(path), { recursive: true });
  const current = existsSync(path)
    ? readFileSync(path, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line))
    : [];
  const existing = current.find(({ vers }) => vers === entry.vers);
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(entry)) {
      throw new Error(`registry coordinate ${entry.name}@${entry.vers} already has different bytes`);
    }
    return;
  }
  current.push(entry);
  current.sort((left, right) => left.vers.localeCompare(right.vers));
  writeFileSync(path, `${current.map((value) => JSON.stringify(value)).join("\n")}\n`);
}

async function seedExternalRegistry({ cargoHome, registryRoot, workspaceMetadata }) {
  const packages = workspaceMetadata.packages
    .filter(({ source }) => source === "registry+https://github.com/rust-lang/crates.io-index")
    .sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));
  const cacheDirectories = readdirSync(join(cargoHome, "registry", "cache"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(cargoHome, "registry", "cache", entry.name));

  for (let offset = 0; offset < packages.length; offset += 8) {
    const batch = packages.slice(offset, offset + 8);
    const entries = await Promise.all(batch.map(async (pkg) => {
      const filename = `${pkg.name}-${pkg.version}.crate`;
      const matches = cacheDirectories
        .map((directory) => join(directory, filename))
        .filter((path) => existsSync(path));
      if (matches.length !== 1) throw new Error(`Cargo cache must contain exactly one ${filename}`);
      const archiveBytes = readFileSync(matches[0]);
      const indexEntry = await readOfficialIndexEntry(pkg.name, pkg.version);
      if (indexEntry.cksum !== sha256(archiveBytes)) {
        throw new Error(`official checksum mismatch for ${pkg.name}@${pkg.version}`);
      }
      return { pkg, archivePath: matches[0], indexEntry };
    }));
    for (const { pkg, archivePath, indexEntry } of entries) {
      cpSync(archivePath, join(registryRoot, `${pkg.name}-${pkg.version}.crate`));
      writeRegistryEntry(registryRoot, indexEntry);
    }
  }
}

async function readOfficialIndexEntry(name, version) {
  const url = `https://index.crates.io/${registryIndexPath(name)}`;
  const response = await fetchOfficialRegistryIndex(url);
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > MAX_INDEX_BYTES) throw new Error(`registry index entry for ${name} is oversized`);
  const text = await response.text();
  if (Buffer.byteLength(text) > MAX_INDEX_BYTES) {
    throw new Error(`registry index entry for ${name} is oversized`);
  }
  const matches = text
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((entry) => entry.name === name && entry.vers === version);
  if (matches.length !== 1) throw new Error(`official registry omitted exact ${name}@${version}`);
  return matches[0];
}

export async function fetchOfficialRegistryIndex(url, {
  fetchImpl = fetch,
  retryDelaysMs = [0, 250, 1_000, 2_000],
  timeoutMs = 10_000,
} = {}) {
  let lastFailure;
  for (let attempt = 0; attempt < retryDelaysMs.length; attempt += 1) {
    const delay = retryDelaysMs[attempt];
    if (delay > 0) await new Promise((resolveDelay) => setTimeout(resolveDelay, delay));
    let response;
    try {
      response = await fetchImpl(url, {
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      lastFailure = error;
      continue;
    }
    if (response.ok) return response;
    const retryable = response.status === 429 || (response.status >= 500 && response.status <= 599);
    if (!retryable) throw new Error(`official registry index returned ${response.status}`);
    lastFailure = new Error(`official registry index returned ${response.status}`);
  }
  throw new Error("official registry index remained unavailable after bounded retries", {
    cause: lastFailure,
  });
}

function registerPackage({ registryRoot, archivePath, packageMetadata, checksum }) {
  const destination = join(registryRoot, basename(archivePath));
  if (existsSync(destination) && !readFileSync(destination).equals(readFileSync(archivePath))) {
    throw new Error(`${packageMetadata.name}@${packageMetadata.version} registry bytes conflict`);
  }
  cpSync(archivePath, destination);
  writeRegistryEntry(registryRoot, metadataIndexEntry(packageMetadata, checksum));
}

function metadataIndexEntry(pkg, checksum) {
  const dependencies = pkg.dependencies.map((dependency) => ({
    name: dependency.rename ?? dependency.name,
    req: dependency.req,
    features: [...dependency.features].sort(),
    optional: dependency.optional,
    default_features: dependency.uses_default_features,
    target: dependency.target,
    kind: dependency.kind,
    package: dependency.rename === null ? null : dependency.name,
  })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  const features = Object.fromEntries(
    Object.entries(pkg.features)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, values]) => [name, [...values].sort()]),
  );
  return {
    name: pkg.name,
    vers: pkg.version,
    deps: dependencies,
    cksum: checksum,
    features,
    yanked: false,
  };
}

function inspectAndExtractPackage({ archivePath, extractionRoot, packageName }) {
  const expectedRoot = `${packageName}-${platformVersion}`;
  assertPackageArchiveSize(archivePath, packageName);
  const entries = validateTarGzipArchive(archivePath, {
    expectedRoot,
    label: `${packageName} source crate`,
  });
  assertSafePackageEntryPaths(entries);
  const packagedFiles = new Map();
  const memberSizes = new Map();
  for (const entry of entries) {
    if (entry.endsWith("/")) continue;
    const relativePath = entry.slice(expectedRoot.length + 1);
    if (!isAllowedPackagePath(relativePath)) {
      throw new Error(`${packageName} contains unexpected package file ${relativePath}`);
    }
    const bytes = readTarMember(archivePath, entry, packageName);
    memberSizes.set(entry, bytes.length);
    assertSafePackageMemberSizes(memberSizes);
    packagedFiles.set(entry, bytes);
  }
  for (const [entry, bytes] of packagedFiles) {
    assertSafePackagedFile(entry.slice(expectedRoot.length + 1), bytes);
  }
  mkdirSync(extractionRoot, { recursive: true });
  run("tar", ["-xzf", archivePath, "-C", extractionRoot]);
  const packageRoot = join(extractionRoot, expectedRoot);
  for (const entry of entries) {
    if (entry.endsWith("/")) continue;
    const relativePath = entry.slice(expectedRoot.length + 1);
    const absolutePath = join(packageRoot, relativePath);
    const info = lstatSync(absolutePath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`${packageName} package member is not a regular file: ${relativePath}`);
    }
    if (!readFileSync(absolutePath).equals(packagedFiles.get(entry))) {
      throw new Error(`${packageName} package member changed during extraction: ${relativePath}`);
    }
  }
  for (const required of ["Cargo.lock", "Cargo.toml", "Cargo.toml.orig", "LICENSE", "README.md"]) {
    if (!existsSync(join(packageRoot, required))) {
      throw new Error(`${packageName} package omitted ${required}`);
    }
  }
  const normalized = readFileSync(join(packageRoot, "Cargo.toml"), "utf8");
  if (/^\s*path\s*=\s*"\.\./m.test(normalized)
      || /^\s*git\s*=/m.test(normalized)
      || /^\s*\[(?:patch|replace)(?:\.|\])/m.test(normalized)) {
    throw new Error(`${packageName} normalized manifest retained a local override`);
  }
  return packageRoot;
}

function assertPackageArchiveSize(archivePath, packageName) {
  const size = statSync(archivePath).size;
  if (size <= 0 || size > MAX_PACKAGE_BYTES) {
    throw new Error(`${packageName} source crate size is outside the package limit`);
  }
}

function verifyUnpackedPackage({ cargoHome, packageName, packageRoot, repositoryRoot }) {
  const environment = cargoEnvironment(cargoHome, {
    CARGO_NET_OFFLINE: "true",
    CARGO_TARGET_DIR: join(dirname(packageRoot), `${packageName}-target`),
  });
  const manifestPath = join(packageRoot, "Cargo.toml");
  const metadata = JSON.parse(run("cargo", [
    "metadata",
    "--locked",
    "--offline",
    "--format-version",
    "1",
    "--manifest-path",
    manifestPath,
  ], { cwd: packageRoot, env: environment }));
  for (const pkg of metadata.packages) {
    if (isWithin(repositoryRoot, pkg.manifest_path)) {
      throw new Error(`${packageName} unpacked metadata resolved a sibling worktree package`);
    }
  }
  const selected = metadata.packages.find((pkg) => (
    pkg.name === packageName
      && pkg.version === platformVersion
      && realpathSync(pkg.manifest_path) === realpathSync(manifestPath)
  ));
  if (!selected) throw new Error(`${packageName} unpacked metadata omitted its package root`);
  for (const pkg of metadata.packages) {
    if (pkg === selected) {
      if (pkg.source !== null) throw new Error(`${packageName} unpacked root must be the sole path package`);
    } else if (pkg.source !== OFFICIAL_REGISTRY_SOURCE) {
      throw new Error(`${packageName} unpacked dependency ${pkg.name} is not crates.io registry source`);
    }
  }
  assertNoFirstPartyBuildHooks(selected, `${packageName} unpacked package`);
  for (const dependency of selected.dependencies) {
    if (dependency.source !== OFFICIAL_REGISTRY_SOURCE) {
      throw new Error(`${packageName} unpacked dependency ${dependency.name} is not registry source`);
    }
    if (dependency.name.startsWith("redevplugin-") && dependency.req !== `=${platformVersion}`) {
      throw new Error(`${packageName} unpacked internal dependency ${dependency.name} is not exact registry source`);
    }
  }
  run("cargo", ["check", "--locked", "--offline", "--manifest-path", manifestPath], {
    cwd: packageRoot,
    env: environment,
  });
  run("cargo", ["test", "--locked", "--offline", "--manifest-path", manifestPath], {
    cwd: packageRoot,
    env: environment,
  });
}

function writeCargoSourceReplacement(cargoHome, registryRoot) {
  writeFileSync(join(cargoHome, "config.toml"), `[source.crates-io]
replace-with = "redevplugin-local"

[source.redevplugin-local]
local-registry = ${JSON.stringify(registryRoot)}

[net]
offline = true
`);
}

export function assertNoFirstPartyBuildHooks(pkg, label) {
  const hasBuildTarget = pkg.targets?.some(({ kind }) => (
    kind.includes("custom-build") || kind.includes("proc-macro")
  ));
  const hasBuildDependency = pkg.dependencies?.some(({ kind }) => kind === "build");
  if (pkg.links !== null || hasBuildTarget || hasBuildDependency) {
    throw new Error(`${label} declares forbidden build code`);
  }
}

function isAllowedPackagePath(path) {
  if (["Cargo.lock", "Cargo.toml", "Cargo.toml.orig", "LICENSE", "README.md", ".cargo_vcs_info.json"].includes(path)) {
    return true;
  }
  return /^(?:src|tests|testdata)\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(path)
    && !path.split("/").some((segment) => segment === "." || segment === "..");
}

function hasNativeMagic(bytes) {
  if (bytes.length >= 8 && bytes.subarray(0, 8).toString("ascii") === "!<arch>\n") return true;
  if (bytes.length < 2) return false;
  const first2 = bytes.subarray(0, 2).toString("hex");
  if ([
    "4c01",
    "6601",
    "6901",
    "8401",
    "a201",
    "a301",
    "a601",
    "a801",
    "c001",
    "c201",
    "c401",
    "d301",
    "f001",
    "f101",
    "0002",
    "6602",
    "8402",
    "6603",
    "6604",
    "bc0e",
    "3250",
    "6450",
    "2851",
    "3262",
    "6462",
    "4190",
    "6486",
    "41a6",
    "4ea6",
    "64aa",
  ].includes(first2)) return true;
  if (bytes.length < 4) return false;
  const first4 = bytes.subarray(0, 4).toString("hex");
  if ([
    "7f454c46",
    "feedface",
    "feedfacf",
    "cefaedfe",
    "cffaedfe",
    "cafebabe",
    "cafebabf",
    "bebafeca",
    "bfbafeca",
    "4243c0de",
    "dec0170b",
  ].includes(first4)) {
    return true;
  }
  return bytes[0] === 0x4d && bytes[1] === 0x5a;
}

export function assertSafePackageEntryPaths(entries) {
  if (entries.length > MAX_PACKAGE_ENTRIES) throw new Error("source crate has too many archive members");
  const folded = new Map();
  for (const entry of entries) {
    const path = entry.endsWith("/") ? entry.slice(0, -1) : entry;
    const segments = path.split("/");
    for (let length = 1; length <= segments.length; length += 1) {
      const prefix = segments.slice(0, length).join("/");
      const kind = length === segments.length && !entry.endsWith("/") ? "file" : "directory";
      const key = prefix.toLowerCase();
      const previous = folded.get(key);
      if (previous !== undefined && previous.path !== prefix) {
        throw new Error(`source crate has case-colliding archive paths ${previous.path} and ${prefix}`);
      }
      if (previous !== undefined && previous.kind !== kind) {
        throw new Error(`source crate has conflicting file and directory path ${prefix}`);
      }
      folded.set(key, { path: prefix, kind });
    }
  }
}

export function assertSafePackageMemberSizes(memberSizes) {
  let total = 0;
  for (const [path, size] of memberSizes) {
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_PACKAGE_MEMBER_BYTES) {
      throw new Error(`source crate member ${path} exceeds the size limit`);
    }
    total += size;
    if (total > MAX_PACKAGE_UNCOMPRESSED_BYTES) {
      throw new Error("source crate exceeds the uncompressed size limit");
    }
  }
}

function readTarMember(archivePath, entry, packageName) {
  const result = spawnSync("tar", ["-xOzf", archivePath, entry], {
    encoding: null,
    maxBuffer: MAX_PACKAGE_MEMBER_BYTES + 1,
  });
  if (result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    throw new Error(`${packageName} source crate member ${entry} exceeds limits or cannot be inspected`);
  }
  return result.stdout;
}

function registryIndexPath(name) {
  const normalized = name.toLowerCase();
  if (normalized.length === 1) return `1/${normalized}`;
  if (normalized.length === 2) return `2/${normalized}`;
  if (normalized.length === 3) return `3/${normalized[0]}/${normalized}`;
  return `${normalized.slice(0, 2)}/${normalized.slice(2, 4)}/${normalized}`;
}

function cargoEnvironment(cargoHome, extra = {}) {
  const environment = {};
  for (const key of [
    "HOME",
    "PATH",
    "RUSTUP_HOME",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
  ]) {
    if (process.env[key] !== undefined) environment[key] = process.env[key];
  }
  if (cargoHome) environment.CARGO_HOME = cargoHome;
  environment.CARGO_TERM_COLOR = "never";
  environment.RUSTUP_TOOLCHAIN = rustToolchain;
  return { ...environment, ...extra };
}

function run(command, args, { cwd = root, env = process.env } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const stdout = result.stdout ? `\nstdout:\n${result.stdout}` : "";
    const stderr = result.stderr ? `\nstderr:\n${result.stderr}` : "";
    const spawnError = result.error ? `\nspawn error:\n${result.error}` : "";
    throw new Error(`${command} ${args.join(" ")} failed:${stdout}${stderr}${spawnError}`);
  }
  return result.stdout.trim();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isWithin(parent, child) {
  const rel = relative(realpathSync(parent), realpathSync(child));
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== "..");
}
