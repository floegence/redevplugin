#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { validateTarGzipArchive } from "./archive_contract.mjs";
import { runtimeTargetForBuildTriple, runtimeTargets } from "./runtime_targets.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const integrityOnly = args[0] === "--npm-integrity";
const positional = integrityOnly ? args.slice(1) : args;
const [rawArtifactDir, expectedVersion, expectedSourceCommit] = positional;
const artifactDir = resolve(rawArtifactDir ?? "");

if (!rawArtifactDir || positional.length !== 3 || !expectedVersion || !/^[0-9a-f]{40}$/.test(expectedSourceCommit ?? "")) {
  console.error("usage: verify_published_release.mjs <artifact-dir> <version> <source-commit>");
  console.error("       verify_published_release.mjs --npm-integrity <artifact-dir> <version> <source-commit>");
  process.exit(2);
}

const expectedBuildTriples = new Set(runtimeTargets.map((target) => target.buildTriple));
const expectedPlatformTargets = new Set(runtimeTargets.map((target) => target.platformTarget));
const expectedArchiveNames = new Set(runtimeTargets.map((target) => `redevplugin-v${expectedVersion}-${target.buildTriple}.tar.gz`));
const archives = readdirSync(artifactDir)
  .filter((entry) => entry.endsWith(".tar.gz"))
  .sort();
if (archives.length !== expectedArchiveNames.size || archives.some((archive) => !expectedArchiveNames.has(archive))) {
  throw new Error(`published release runtime archive set mismatch: ${JSON.stringify(archives)}`);
}

const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-published-release-"));
try {
  const bundles = archives.map((archive) => inspectArchive(join(artifactDir, archive)));
  const npmIdentities = new Set(bundles.map((bundle) => JSON.stringify(bundle.npm)));
  if (npmIdentities.size !== 1) {
    throw new Error("runtime archives do not contain the same npm tarball bytes");
  }
  const workerSDKIdentities = new Set(bundles.map((bundle) => JSON.stringify(bundle.workerSDK)));
  if (workerSDKIdentities.size !== 1) {
    throw new Error("runtime archives do not contain the same worker SDK crate bytes");
  }
  const compatibilityHashes = new Set(bundles.map((bundle) => bundle.compatibilitySHA256));
  if (compatibilityHashes.size !== 1) {
    throw new Error("runtime archives do not contain identical compatibility metadata");
  }
  const performanceEvidenceIdentities = new Set(bundles.map((bundle) => JSON.stringify(bundle.performanceEvidence)));
  if (performanceEvidenceIdentities.size !== 1) {
    throw new Error("runtime archives do not contain identical performance evidence bytes and hash");
  }
  const actualTargets = new Set(bundles.map((bundle) => bundle.runtimeTarget));
  if (actualTargets.size !== expectedPlatformTargets.size || [...expectedPlatformTargets].some((target) => !actualTargets.has(target))) {
    throw new Error(`runtime target matrix mismatch: ${JSON.stringify([...actualTargets].sort())}`);
  }
  const npm = bundles[0].npm;
  if (integrityOnly) process.stdout.write(`${npm.integrity}\n`);
  else console.log(`published ReDevPlugin ${expectedVersion} verified for ${bundles.length} runtime targets`);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function inspectArchive(archivePath) {
  const archiveName = basename(archivePath);
  const buildTriple = [...expectedBuildTriples].find((candidate) => archiveName.endsWith(`-${candidate}.tar.gz`));
  if (!buildTriple) {
    throw new Error(`${archiveName} does not identify a supported runtime build triple`);
  }
  const expectedRoot = archiveName.slice(0, -".tar.gz".length);
  validateTarGzipArchive(archivePath, {
    expectedRoot,
    label: `published runtime archive ${archiveName}`,
  });
  const extractRoot = mkdtempSync(join(tempRoot, "bundle-"));
  const extraction = spawnSync("tar", ["-xzf", archivePath, "-C", extractRoot], { encoding: "utf8" });
  if (extraction.status !== 0) {
    throw new Error(`cannot extract ${basename(archivePath)}: ${extraction.stderr || extraction.stdout}`);
  }
  const roots = readdirSync(extractRoot);
  if (roots.length !== 1 || roots[0] !== expectedRoot || !statSync(join(extractRoot, roots[0])).isDirectory()) {
    throw new Error(`${basename(archivePath)} extraction did not preserve its validated archive root`);
  }
  const bundleRoot = join(extractRoot, expectedRoot);
  const manifest = JSON.parse(readFileSync(join(bundleRoot, "release-manifest.json"), "utf8"));
  const expectedPlatformTarget = runtimeTargetForBuildTriple(buildTriple).platformTarget;
  if (manifest.runtime_target !== expectedPlatformTarget) {
    throw new Error(`${archiveName} runtime_target does not match build triple ${buildTriple}`);
  }
  if (manifest.version !== expectedVersion) {
    throw new Error(`${basename(archivePath)} version ${manifest.version} does not match ${expectedVersion}`);
  }
  if (manifest.source_commit !== expectedSourceCommit) {
    throw new Error(`${basename(archivePath)} source_commit does not match the release tag commit`);
  }
  const verification = spawnSync(
    "node",
    [join(root, "scripts", "verify_redevplugin_release_bundle.mjs"), "--skip-execution", bundleRoot, expectedVersion],
    { encoding: "utf8" },
  );
  if (verification.status !== 0) {
    throw new Error(`bundle verification failed for ${basename(archivePath)}: ${verification.stderr || verification.stdout}`);
  }
  const npmMetadata = manifest.npm_package;
  if (npmMetadata?.name !== "@floegence/redevplugin-ui" || typeof npmMetadata.path !== "string") {
    throw new Error(`${basename(archivePath)} has invalid npm package metadata`);
  }
  if (npmMetadata.version !== expectedVersion) {
    throw new Error(`${basename(archivePath)} npm package version mismatch`);
  }
  const npmPath = join(bundleRoot, npmMetadata.path);
  const npmBytes = readFileSync(npmPath);
  const npm = {
    name: npmMetadata.name,
    version: npmMetadata.version,
    filename: basename(npmMetadata.path),
    sha256: createHash("sha256").update(npmBytes).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(npmBytes).digest("base64")}`,
    size: npmBytes.length,
  };
  if (npm.sha256 !== npmMetadata.sha256 || npm.integrity !== npmMetadata.integrity || npm.size !== npmMetadata.size) {
    throw new Error(`${basename(archivePath)} npm package bytes do not match release-manifest.json`);
  }
  const workerSDKMetadata = manifest.worker_sdk;
  if (workerSDKMetadata?.name !== "redevplugin-worker-sdk" || typeof workerSDKMetadata.path !== "string") {
    throw new Error(`${basename(archivePath)} has invalid worker SDK metadata`);
  }
  if (workerSDKMetadata.version !== expectedVersion) {
    throw new Error(`${basename(archivePath)} worker SDK version mismatch`);
  }
  const workerSDKPath = join(bundleRoot, workerSDKMetadata.path);
  const workerSDKBytes = readFileSync(workerSDKPath);
  const workerSDK = {
    name: workerSDKMetadata.name,
    version: workerSDKMetadata.version,
    filename: basename(workerSDKMetadata.path),
    sha256: createHash("sha256").update(workerSDKBytes).digest("hex"),
    size: workerSDKBytes.length,
  };
  if (workerSDK.sha256 !== workerSDKMetadata.sha256 || workerSDK.size !== workerSDKMetadata.size) {
    throw new Error(`${basename(archivePath)} worker SDK bytes do not match release-manifest.json`);
  }
  const compatibilityBytes = readFileSync(join(bundleRoot, "compatibility.json"));
  const compatibilitySHA256 = createHash("sha256").update(compatibilityBytes).digest("hex");
  if (compatibilitySHA256 !== manifest.compatibility_sha256) {
    throw new Error(`${basename(archivePath)} compatibility digest mismatch`);
  }
  if (!statSync(join(bundleRoot, "bin", "redevplugin-runtime")).isFile()) {
    throw new Error(`${basename(archivePath)} is missing redevplugin-runtime`);
  }
  const performanceEvidenceBytes = readFileSync(join(bundleRoot, "performance-evidence.json"));
  const performanceEvidence = {
    sha256: createHash("sha256").update(performanceEvidenceBytes).digest("hex"),
    size: performanceEvidenceBytes.length,
    bytes_base64: performanceEvidenceBytes.toString("base64"),
  };
  return { runtimeTarget: manifest.runtime_target, compatibilitySHA256, npm, workerSDK, performanceEvidence };
}
