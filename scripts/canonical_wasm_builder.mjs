import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, lstat, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

const pinnedRustImages = Object.freeze({
  "1.88.0": "docker.io/library/rust:1.88.0-bookworm@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0",
});

const inheritedEnvironmentKeys = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "RUSTUP_HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];

export function isCanonicalBuildHost() {
  return process.platform === "linux" && process.arch === "x64";
}

export function selectCanonicalWasmBuildMode({ forceDocker = false, platform = process.platform, arch = process.arch } = {}) {
  return forceDocker || platform !== "linux" || arch !== "x64" ? "docker" : "native";
}

export function parseCanonicalWasmGeneratorArgs(args) {
  const allowed = new Set(["--check", "--canonical"]);
  for (const argument of args) {
    if (!allowed.has(argument)) throw new Error(`unknown canonical WASM generator argument: ${argument}`);
  }
  return {
    checkOnly: args.includes("--check"),
    forceCanonical: args.includes("--canonical"),
  };
}

export function canonicalRustImage(rustVersion) {
  const image = pinnedRustImages[rustVersion];
  if (!image) throw new Error(`no pinned canonical Rust image for ${rustVersion}`);
  return image;
}

export async function readPinnedRustVersion(root) {
  const source = await readFile(resolve(root, "rust-toolchain.toml"), "utf8");
  const match = source.match(/^channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$/m);
  if (!match) throw new Error("rust-toolchain.toml must pin an exact stable Rust version");
  return match[1];
}

export async function hashPaths(root, paths) {
  const result = {};
  for (const relativePath of [...paths].sort()) {
    result[relativePath] = createHash("sha256").update(await readFile(resolve(root, relativePath))).digest("hex");
  }
  return result;
}

export async function snapshotCanonicalCargoSources({
  root,
  rustVersion,
  packageNames,
  additionalPaths = [],
  optionalPaths = [],
  cargoCommand,
  environment = process.env,
}) {
  validatePackageNames(packageNames);
  await assertNoAncestorCargoConfiguration(root);
  const cargo = cargoCommand || await cargoPath();
  const distRoot = resolve(root, "dist");
  await mkdir(distRoot, { recursive: true });
  const metadataRoot = await mkdtemp(resolve(distRoot, "canonical-cargo-metadata-"));
  const cargoHome = await createIsolatedCargoHome(metadataRoot);
  try {
    const metadata = JSON.parse(runCapture(cargo, [
      "metadata",
      "--locked",
      "--format-version",
      "1",
      "--no-deps",
    ], `read canonical Cargo metadata with ${cargo}`, root, canonicalEnvironment(environment, rustVersion, {
      CARGO_HOME: cargoHome,
    })));
    const paths = await collectCargoSourcePaths(root, metadata, packageNames, additionalPaths, optionalPaths);
    return { paths, hashes: await hashPaths(root, paths) };
  } finally {
    await rm(metadataRoot, { recursive: true, force: true });
  }
}

export function assertSourceSnapshotUnchanged(before, after) {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error("Cargo source inputs changed during canonical WASM build");
  }
}

export async function buildCanonicalWasmArtifacts({
  root,
  rustVersion,
  targets,
  forceDocker = false,
  buildMode = "auto",
  cargoCommand,
  rustcCommand,
  environment = process.env,
}) {
  validateTargets(targets);
  if (!new Set(["auto", "native", "docker"]).has(buildMode)) {
    throw new Error(`unsupported canonical WASM build mode: ${buildMode}`);
  }
  const selectedMode = buildMode === "auto"
    ? selectCanonicalWasmBuildMode({ forceDocker })
    : buildMode;
  return selectedMode === "native"
    ? await buildNativeArtifacts(root, rustVersion, targets, cargoCommand, rustcCommand, environment)
    : await buildDockerArtifacts(root, rustVersion, targets, environment);
}

async function buildNativeArtifacts(root, rustVersion, targets, cargoCommand, rustcCommand, environment) {
  await assertNoAncestorCargoConfiguration(root);
  const cargo = cargoCommand || await cargoPath();
  const rustc = rustcCommand || "rustc";
  const distRoot = resolve(root, "dist");
  await mkdir(distRoot, { recursive: true });
  const buildRoot = await mkdtemp(resolve(distRoot, "canonical-wasm-native-"));
  const cargoHome = await createIsolatedCargoHome(buildRoot);
  const cargoTargetDir = resolve(buildRoot, "target");
  const buildEnvironment = canonicalEnvironment(environment, rustVersion, {
    CARGO_HOME: cargoHome,
    CARGO_TARGET_DIR: cargoTargetDir,
    CARGO_ENCODED_RUSTFLAGS: [
      `--remap-path-prefix=${root}=/workspace`,
      `--remap-path-prefix=${cargoHome}=/cargo`,
    ].join("\u001f"),
  });
  try {
    verifyCanonicalRustc(rustc, rustVersion, root, buildEnvironment);
    run(cargo, [
      "build",
      "--locked",
      "--release",
      "--target",
      "wasm32-unknown-unknown",
      ...targets.flatMap(({ packageName }) => ["-p", packageName]),
    ], `build canonical WASM artifacts with ${cargo}`, root, buildEnvironment);
    return await readArtifacts(resolve(cargoTargetDir, "wasm32-unknown-unknown/release"), targets);
  } finally {
    await rm(buildRoot, { recursive: true, force: true });
  }
}

async function buildDockerArtifacts(root, rustVersion, targets, environment) {
  const distRoot = resolve(root, "dist");
  await mkdir(distRoot, { recursive: true });
  const outputRoot = await mkdtemp(resolve(distRoot, "canonical-wasm-docker-"));
  const image = canonicalRustImage(rustVersion);
  const script = [
    "set -euo pipefail",
    `rustc -Vv | grep -Fx 'release: ${rustVersion}'`,
    "rustc -Vv | grep -Fx 'host: x86_64-unknown-linux-gnu'",
    "rustup target add wasm32-unknown-unknown",
    "export CARGO_TARGET_DIR=/tmp/redevplugin-target",
    "export CARGO_ENCODED_RUSTFLAGS=$'--remap-path-prefix=/repo=/workspace\\x1f--remap-path-prefix=/usr/local/cargo=/cargo'",
    `cargo build --locked --release --target wasm32-unknown-unknown ${targets.map(({ packageName }) => `-p ${packageName}`).join(" ")}`,
    ...targets.map(({ artifact }) => `cp /tmp/redevplugin-target/wasm32-unknown-unknown/release/${artifact} /out/${artifact}`),
  ].join("\n");
  try {
    run("docker", [
      "run", "--rm",
      "--platform", "linux/amd64",
      "-v", `${root}:/repo:ro`,
      "-v", `${outputRoot}:/out`,
      "-w", "/repo",
      image,
      "bash", "-c", script,
    ], `build canonical WASM artifacts with ${image}`, root, environment);
    return await readArtifacts(outputRoot, targets);
  } finally {
    await rm(outputRoot, { recursive: true, force: true });
  }
}

async function collectCargoSourcePaths(root, metadata, packageNames, additionalPaths, optionalPaths) {
  if (!Array.isArray(metadata.packages)) throw new Error("Cargo metadata packages are unavailable");
  const packagesByName = new Map();
  const packagesByRoot = new Map();
  for (const packageEntry of metadata.packages) {
    if (typeof packageEntry.name !== "string" || typeof packageEntry.manifest_path !== "string") {
      throw new Error("Cargo metadata contains an invalid package entry");
    }
    const entries = packagesByName.get(packageEntry.name) || [];
    entries.push(packageEntry);
    packagesByName.set(packageEntry.name, entries);
    packagesByRoot.set(resolve(dirname(packageEntry.manifest_path)), packageEntry);
  }

  const selected = new Map();
  const queue = [];
  for (const packageName of packageNames) {
    const matches = packagesByName.get(packageName) || [];
    if (matches.length !== 1) throw new Error(`canonical Cargo package ${packageName} must resolve exactly once`);
    queue.push(matches[0]);
  }
  while (queue.length > 0) {
    const packageEntry = queue.shift();
    const packageRoot = resolve(dirname(packageEntry.manifest_path));
    if (selected.has(packageRoot)) continue;
    selected.set(packageRoot, packageEntry);
    for (const dependency of packageEntry.dependencies || []) {
      if (!dependency.path) continue;
      const dependencyEntry = packagesByRoot.get(resolve(dependency.path));
      if (!dependencyEntry) throw new Error(`local Cargo dependency is absent from metadata: ${dependency.path}`);
      queue.push(dependencyEntry);
    }
  }

  const paths = new Set();
  for (const packageRoot of [...selected.keys()].sort()) {
    await collectSourcePath(root, packageRoot, paths, true);
  }
  for (const sourcePath of additionalPaths) {
    await collectSourcePath(root, resolve(root, sourcePath), paths, true);
  }
  for (const sourcePath of optionalPaths) {
    await collectSourcePath(root, resolve(root, sourcePath), paths, false);
  }
  return [...paths].sort();
}

async function collectSourcePath(root, absolutePath, paths, required) {
  const relativePath = relative(root, absolutePath);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new Error(`canonical Cargo source path escapes repository root: ${absolutePath}`);
  }
  let entry;
  try {
    entry = await lstat(absolutePath);
  } catch (error) {
    if (!required && error?.code === "ENOENT") return;
    throw error;
  }
  if (entry.isSymbolicLink()) throw new Error(`canonical Cargo source path must not be a symlink: ${absolutePath}`);
  if (entry.isDirectory()) {
    const children = await readdir(absolutePath);
    for (const child of children.sort()) {
      if (child === ".git") continue;
      await collectSourcePath(root, resolve(absolutePath, child), paths, true);
    }
    return;
  }
  if (!entry.isFile()) throw new Error(`canonical Cargo source path must be a regular file: ${absolutePath}`);
  paths.add(relativePath.split(sep).join("/"));
}

async function createIsolatedCargoHome(parent) {
  const cargoHome = resolve(parent, "canonical-cargo-home");
  await mkdir(cargoHome, { recursive: true });
  return cargoHome;
}

async function assertNoAncestorCargoConfiguration(root) {
  let current = dirname(resolve(root));
  while (true) {
    for (const name of ["config.toml", "config"]) {
      const configPath = resolve(current, ".cargo", name);
      try {
        await lstat(configPath);
        throw new Error(`Cargo configuration outside the repository is forbidden: ${configPath}`);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function readArtifacts(directory, targets) {
  const artifacts = new Map();
  for (const { artifact } of targets) {
    artifacts.set(artifact, await readFile(resolve(directory, artifact)));
  }
  return artifacts;
}

function validatePackageNames(packageNames) {
  if (!Array.isArray(packageNames) || packageNames.length === 0) throw new Error("canonical Cargo package names are required");
  const unique = new Set();
  for (const packageName of packageNames) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(packageName)) throw new Error(`unsafe canonical Cargo package name: ${packageName}`);
    if (unique.has(packageName)) throw new Error(`duplicate canonical Cargo package name: ${packageName}`);
    unique.add(packageName);
  }
}

function validateTargets(targets) {
  if (!Array.isArray(targets) || targets.length === 0) throw new Error("canonical WASM targets are required");
  const packages = new Set();
  const artifacts = new Set();
  for (const { packageName, artifact } of targets) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(packageName) || !/^[A-Za-z0-9][A-Za-z0-9_.-]*\.wasm$/.test(artifact)) {
      throw new Error("canonical WASM target contains an unsafe package or artifact name");
    }
    if (packages.has(packageName) || artifacts.has(artifact)) {
      throw new Error("canonical WASM targets contain a duplicate package or artifact");
    }
    packages.add(packageName);
    artifacts.add(artifact);
  }
}

function canonicalEnvironment(environment, rustVersion, overrides = {}) {
  const result = {};
  for (const key of inheritedEnvironmentKeys) {
    if (environment[key]) result[key] = environment[key];
  }
  return {
    ...result,
    RUSTUP_TOOLCHAIN: rustVersion,
    CARGO_TERM_COLOR: "never",
    ...overrides,
  };
}

function verifyCanonicalRustc(command, rustVersion, cwd, environment) {
  const output = runCapture(command, ["-Vv"], `verify canonical rustc ${rustVersion}`, cwd, environment);
  if (!output.split(/\r?\n/).includes(`release: ${rustVersion}`)) {
    throw new Error(`canonical rustc release does not match ${rustVersion}`);
  }
  if (!output.split(/\r?\n/).includes("host: x86_64-unknown-linux-gnu")) {
    throw new Error("canonical rustc host must be x86_64-unknown-linux-gnu");
  }
}

function run(command, args, description, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8" });
  if (result.status === 0) return;
  process.stderr.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.error) throw new Error(`${description}: ${result.error.message}`);
  throw new Error(`${description} failed with status ${result.status}`);
}

function runCapture(command, args, description, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8" });
  if (result.status === 0) return result.stdout;
  process.stderr.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.error) throw new Error(`${description}: ${result.error.message}`);
  throw new Error(`${description} failed with status ${result.status}`);
}

async function cargoPath() {
  const bundled = resolve(homedir(), ".cargo/bin/cargo");
  try {
    await access(bundled);
    return bundled;
  } catch {
    return "cargo";
  }
}
