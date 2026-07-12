#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const integrityOnly = args[0] === "--npm-integrity";
const artifactDir = resolve(integrityOnly ? args[1] ?? "" : args[0] ?? "");
const expectedVersion = integrityOnly ? undefined : args[1];
const expectedSourceCommit = integrityOnly ? undefined : args[2];

if (!artifactDir || (!integrityOnly && (!expectedVersion || !/^[0-9a-f]{40}$/.test(expectedSourceCommit ?? "")))) {
  console.error("usage: verify_published_release.mjs <artifact-dir> <version> <source-commit>");
  console.error("       verify_published_release.mjs --npm-integrity <artifact-dir>");
  process.exit(2);
}

const expectedTargets = new Set([
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
]);
const archives = readdirSync(artifactDir)
  .filter((entry) => entry.endsWith(".tar.gz"))
  .sort();
if (archives.length !== expectedTargets.size) {
  throw new Error(`published release must contain ${expectedTargets.size} runtime archives, found ${archives.length}`);
}

const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-published-release-"));
try {
  const bundles = archives.map((archive) => inspectArchive(join(artifactDir, archive)));
  const npmIdentities = new Set(bundles.map((bundle) => JSON.stringify(bundle.npm)));
  if (npmIdentities.size !== 1) {
    throw new Error("runtime archives do not contain the same npm tarball bytes");
  }
  const compatibilityHashes = new Set(bundles.map((bundle) => bundle.compatibilitySHA256));
  if (compatibilityHashes.size !== 1) {
    throw new Error("runtime archives do not contain identical compatibility metadata");
  }
  const actualTargets = new Set(bundles.map((bundle) => bundle.runtimeTarget));
  if (actualTargets.size !== expectedTargets.size || [...expectedTargets].some((target) => !actualTargets.has(target))) {
    throw new Error(`runtime target matrix mismatch: ${JSON.stringify([...actualTargets].sort())}`);
  }
  const npm = bundles[0].npm;
  if (integrityOnly) {
    process.stdout.write(`${npm.integrity}\n`);
  } else {
    console.log(`published ReDevPlugin ${expectedVersion} verified for ${bundles.length} runtime targets`);
  }
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function inspectArchive(archivePath) {
  const extractRoot = mkdtempSync(join(tempRoot, "bundle-"));
  const extraction = spawnSync("tar", ["-xzf", archivePath, "-C", extractRoot], { encoding: "utf8" });
  if (extraction.status !== 0) {
    throw new Error(`cannot extract ${basename(archivePath)}: ${extraction.stderr || extraction.stdout}`);
  }
  const roots = readdirSync(extractRoot).filter((entry) => statSync(join(extractRoot, entry)).isDirectory());
  if (roots.length !== 1) {
    throw new Error(`${basename(archivePath)} must contain exactly one bundle root`);
  }
  const bundleRoot = join(extractRoot, roots[0]);
  const manifest = JSON.parse(readFileSync(join(bundleRoot, "release-manifest.json"), "utf8"));
  if (!integrityOnly) {
    if (manifest.version !== expectedVersion) {
      throw new Error(`${basename(archivePath)} version ${manifest.version} does not match ${expectedVersion}`);
    }
    if (manifest.source_commit !== expectedSourceCommit) {
      throw new Error(`${basename(archivePath)} source_commit does not match the release tag commit`);
    }
    const verification = spawnSync(
      "node",
      [join(root, "scripts", "verify_redevplugin_release_bundle.mjs"), "--structural-only", bundleRoot, expectedVersion],
      { encoding: "utf8" },
    );
    if (verification.status !== 0) {
      throw new Error(`bundle verification failed for ${basename(archivePath)}: ${verification.stderr || verification.stdout}`);
    }
  }
  const npmMetadata = manifest.npm_package;
  if (npmMetadata?.name !== "@floegence/redevplugin-ui" || typeof npmMetadata.path !== "string") {
    throw new Error(`${basename(archivePath)} has invalid npm package metadata`);
  }
  if (!integrityOnly && npmMetadata.version !== expectedVersion) {
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
  const compatibilityBytes = readFileSync(join(bundleRoot, "compatibility.json"));
  const compatibilitySHA256 = createHash("sha256").update(compatibilityBytes).digest("hex");
  if (compatibilitySHA256 !== manifest.compatibility_sha256) {
    throw new Error(`${basename(archivePath)} compatibility digest mismatch`);
  }
  if (!statSync(join(bundleRoot, "bin", "redevplugin-runtime")).isFile()) {
    throw new Error(`${basename(archivePath)} is missing redevplugin-runtime`);
  }
  return { runtimeTarget: manifest.runtime_target, compatibilitySHA256, npm };
}
