#!/usr/bin/env node

import { createHash } from "node:crypto";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { runtimeTargets } from "./runtime_targets.mjs";

const [rawSourceBundle, version, sourceCommit] = process.argv.slice(2);
if (!rawSourceBundle || !version || !/^[0-9a-f]{40}$/.test(sourceCommit ?? "")) {
  console.error("usage: test_published_release_verifier.mjs <source-bundle> <version> <source-commit>");
  process.exit(2);
}

const root = resolve(import.meta.dirname, "..");
const sourceBundle = resolve(rawSourceBundle);
const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-published-verifier-"));
const artifactDir = join(tempRoot, "artifacts");
const verifierRoot = join(tempRoot, "isolated-verifier");
const verifierScripts = join(verifierRoot, "scripts");
const publishedVerifier = join(verifierScripts, "verify_published_release.mjs");
const bundleVerifier = join(verifierScripts, "verify_redevplugin_release_bundle.mjs");
const rustToolchain = run("rustup", ["show", "active-toolchain"], "resolve release verifier Rust toolchain", { cwd: root }).trim().split(/\s+/, 1)[0];
if (!/^[A-Za-z0-9_.-]+$/.test(rustToolchain)) throw new Error("rustup returned an invalid release verifier toolchain");
const verifierEnvironment = { ...process.env, NPM_CONFIG_REGISTRY: "https://registry.invalid", RUSTUP_TOOLCHAIN: rustToolchain };
const targets = runtimeTargets.map((target) => ({ ...target, id: target.buildTriple }));

try {
  mkdirSync(artifactDir, { recursive: true });
  mkdirSync(verifierScripts, { recursive: true });
  cpSync(join(root, "scripts", "verify_published_release.mjs"), publishedVerifier);
  cpSync(join(root, "scripts", "verify_redevplugin_release_bundle.mjs"), bundleVerifier);
  cpSync(join(root, "scripts", "performance_contract.mjs"), join(verifierScripts, "performance_contract.mjs"));
  cpSync(join(root, "scripts", "runtime_targets.mjs"), join(verifierScripts, "runtime_targets.mjs"));
  const bundles = [];
  for (const target of targets) {
    const bundleRoot = join(tempRoot, `redevplugin-v${version}-${target.id}`);
    cpSync(sourceBundle, bundleRoot, { recursive: true });
    prepareStructuralFixture(bundleRoot, target);
    const archive = join(artifactDir, `${basename(bundleRoot)}.tar.gz`);
    run("tar", ["-C", tempRoot, "-czf", archive, basename(bundleRoot)], `archive ${target.id}`);
    bundles.push({ bundleRoot, target });
  }

  const expectedIntegrity = JSON.parse(readFileSync(join(bundles[0].bundleRoot, "release-manifest.json"), "utf8")).npm_package.integrity;
  const verifiedIntegrity = run(
    "node",
    [publishedVerifier, "--npm-integrity", artifactDir, version, sourceCommit],
    "read verified npm integrity",
    { cwd: verifierRoot, env: verifierEnvironment },
  ).trim();
  if (verifiedIntegrity !== expectedIntegrity) {
    throw new Error(`published verifier npm integrity mismatch: got ${verifiedIntegrity}, want ${expectedIntegrity}`);
  }
  if (existsSync(join(verifierRoot, "node_modules"))) {
    throw new Error("published verifier installed or reused dependencies outside its standalone consumer");
  }

  const archiveIdentityNegative = bundles[0];
  const archiveIdentityPath = join(artifactDir, `${basename(archiveIdentityNegative.bundleRoot)}.tar.gz`);
  const renamedArchiveIdentityPath = join(artifactDir, `unexpected-${archiveIdentityNegative.target.buildTriple}.tar.gz`);
  renameSync(archiveIdentityPath, renamedArchiveIdentityPath);
  assertPublishedVerifierRejects("runtime archive set mismatch", "unexpected runtime archive name");
  renameSync(renamedArchiveIdentityPath, archiveIdentityPath);

  const targetIdentityNegative = bundles[0];
  refreshReleaseManifest(targetIdentityNegative.bundleRoot, targets[1].platformTarget);
  archiveBundle(targetIdentityNegative);
  assertPublishedVerifierRejects(
    "runtime_target does not match build triple",
    "manifest target and archive build triple mismatch",
  );
  refreshReleaseManifest(targetIdentityNegative.bundleRoot, targetIdentityNegative.target.platformTarget);
  archiveBundle(targetIdentityNegative);

  const manifestContractNegative = bundles[0];
  const manifestContractPath = join(manifestContractNegative.bundleRoot, "release-manifest.json");
  const manifestContract = JSON.parse(readFileSync(manifestContractPath, "utf8"));
  manifestContract.schema_version = "redevplugin.release_manifest.v3";
  writeFileSync(manifestContractPath, JSON.stringify(manifestContract, null, 2) + "\n");
  archiveBundle(manifestContractNegative);
  assertPublishedVerifierRejects(
    "release manifest schema_version mismatch",
    "release manifest v3 downgrade in npm integrity mode",
    true,
  );
  manifestContract.schema_version = "redevplugin.release_manifest.v4";
  writeFileSync(manifestContractPath, JSON.stringify(manifestContract, null, 2) + "\n");
  archiveBundle(manifestContractNegative);

  const manifestFilesNegative = bundles[1];
  const manifestFilesPath = join(manifestFilesNegative.bundleRoot, "release-manifest.json");
  const manifestFiles = JSON.parse(readFileSync(manifestFilesPath, "utf8"));
  const originalGeneratedAt = manifestFiles.generated_at;
  manifestFiles.generated_at = "2026-07-19";
  writeFileSync(manifestFilesPath, JSON.stringify(manifestFiles, null, 2) + "\n");
  assertBundleVerifierRejects(manifestFilesNegative.bundleRoot, "must be an RFC 3339 date-time string", "date-only generated_at");
  manifestFiles.generated_at = originalGeneratedAt;
  manifestFiles.files[0].unexpected = true;
  writeFileSync(manifestFilesPath, JSON.stringify(manifestFiles, null, 2) + "\n");
  assertBundleVerifierRejects(manifestFilesNegative.bundleRoot, "files[0] keys mismatch", "open release manifest file entry");
  delete manifestFiles.files[0].unexpected;
  const originalPath = manifestFiles.files[0].path;
  manifestFiles.files[0].path = `${originalPath}?query`;
  writeFileSync(manifestFilesPath, JSON.stringify(manifestFiles, null, 2) + "\n");
  assertBundleVerifierRejects(manifestFilesNegative.bundleRoot, "closed release-manifest bundle path contract", "open release manifest path");
  manifestFiles.files[0].path = originalPath;
  [manifestFiles.files[0], manifestFiles.files[1]] = [manifestFiles.files[1], manifestFiles.files[0]];
  writeFileSync(manifestFilesPath, JSON.stringify(manifestFiles, null, 2) + "\n");
  assertBundleVerifierRejects(manifestFilesNegative.bundleRoot, "release manifest file list mismatch", "unsorted release manifest files");
  manifestFiles.files.sort((left, right) => left.path.localeCompare(right.path));
  writeFileSync(manifestFilesPath, JSON.stringify(manifestFiles, null, 2) + "\n");

  const performanceNegative = bundles[0];
  const performancePath = join(performanceNegative.bundleRoot, "performance-evidence.json");
  const originalPerformanceBytes = readFileSync(performancePath);
  const driftedPerformance = JSON.parse(originalPerformanceBytes.toString("utf8"));
  driftedPerformance.environment.node_version += "-cross-bundle-drift";
  writeFileSync(performancePath, JSON.stringify(driftedPerformance, null, 2) + "\n");
  refreshReleaseManifest(performanceNegative.bundleRoot, performanceNegative.target.platformTarget);
  archiveBundle(performanceNegative);
  assertPublishedVerifierRejects(
    "runtime archives do not contain identical performance evidence bytes and hash",
    "cross-bundle performance evidence drift",
  );
  writeFileSync(performancePath, originalPerformanceBytes);
  refreshReleaseManifest(performanceNegative.bundleRoot, performanceNegative.target.platformTarget);
  archiveBundle(performanceNegative);

  const sdkNegative = bundles[3];
  const sdkManifest = JSON.parse(readFileSync(join(sdkNegative.bundleRoot, "release-manifest.json"), "utf8"));
  const sdkCratePath = join(sdkNegative.bundleRoot, sdkManifest.worker_sdk.path);
  const sdkExtractRoot = join(tempRoot, "worker-sdk-mutation");
  mkdirSync(sdkExtractRoot, { recursive: true });
  run("tar", ["-xzf", sdkCratePath, "-C", sdkExtractRoot], "extract worker SDK mutation fixture");
  const sdkPackageRoot = `redevplugin-worker-sdk-${version}`;
  appendFileSync(join(sdkExtractRoot, sdkPackageRoot, "README.md"), "\nCross-bundle identity mutation fixture.\n");
  rmSync(sdkCratePath);
  run("tar", ["-C", sdkExtractRoot, "-czf", sdkCratePath, sdkPackageRoot], "repack worker SDK mutation fixture");
  refreshReleaseManifest(sdkNegative.bundleRoot, sdkNegative.target.platformTarget);
  const sdkArchive = join(artifactDir, `${basename(sdkNegative.bundleRoot)}.tar.gz`);
  rmSync(sdkArchive);
  run("tar", ["-C", tempRoot, "-czf", sdkArchive, basename(sdkNegative.bundleRoot)], "archive worker SDK mutation fixture");
  assertPublishedVerifierRejects("runtime archives do not contain the same worker SDK crate bytes", "cross-bundle worker SDK drift");

  const toolchainNegative = bundles[2];
  const toolchainLockPath = join(toolchainNegative.bundleRoot, "notices/package-lock.json");
  const originalToolchainLock = JSON.parse(readFileSync(toolchainLockPath, "utf8"));
  const originalTypeScript = originalToolchainLock.packages["node_modules/typescript"];
  const toolchainCases = [
    {
      label: "version range",
      expected: "TypeScript version must be exact stable semantic version text",
      mutate(lock) {
        lock.packages["node_modules/typescript"].version = `^${originalTypeScript.version}`;
      },
    },
    {
      label: "malformed semantic version",
      expected: "TypeScript version must be exact stable semantic version text",
      mutate(lock) {
        lock.packages["node_modules/typescript"].version = `${originalTypeScript.version}-alpha..1`;
      },
    },
    {
      label: "non-official registry URL",
      expected: "TypeScript resolved URL must be",
      mutate(lock) {
        lock.packages["node_modules/typescript"].resolved = "https://registry.example.invalid/typescript.tgz";
      },
    },
    {
      label: "non-SHA-512 integrity",
      expected: "TypeScript integrity must be sha512 SRI",
      mutate(lock) {
        lock.packages["node_modules/typescript"].integrity = "sha256-AA==";
      },
    },
    {
      label: "different SHA-512 integrity",
      expected: "standalone consumer TypeScript integrity mismatch",
      mutate(lock) {
        lock.packages["node_modules/typescript"].integrity = `sha512-${Buffer.alloc(64).toString("base64")}`;
      },
    },
    {
      label: "missing TypeScript entry",
      expected: "bundled package-lock TypeScript entry must be an object",
      mutate(lock) {
        delete lock.packages["node_modules/typescript"];
      },
    },
  ];
  for (const testCase of toolchainCases) {
    const lock = JSON.parse(JSON.stringify(originalToolchainLock));
    testCase.mutate(lock);
    writeFileSync(toolchainLockPath, JSON.stringify(lock, null, 2) + "\n");
    refreshReleaseManifest(toolchainNegative.bundleRoot, toolchainNegative.target.platformTarget);
    assertBundleVerifierRejects(toolchainNegative.bundleRoot, testCase.expected, testCase.label);
  }
  writeFileSync(toolchainLockPath, JSON.stringify(originalToolchainLock, null, 2) + "\n");
  refreshReleaseManifest(toolchainNegative.bundleRoot, toolchainNegative.target.platformTarget);

  const negative = bundles[0];
  patchExecutable(join(negative.bundleRoot, "bin", "redevplugin-runtime"), targets[1]);
  refreshReleaseManifest(negative.bundleRoot, negative.target.platformTarget);
  assertBundleVerifierRejects(negative.bundleRoot, "ELF machine mismatch", "wrong runtime target");

  const provenanceNegative = bundles[1];
  const provenanceManifestPath = join(provenanceNegative.bundleRoot, "release-manifest.json");
  const provenanceManifest = JSON.parse(readFileSync(provenanceManifestPath, "utf8"));
  const alternateSourceCommit = provenanceManifest.source_commit === "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ? "cccccccccccccccccccccccccccccccccccccccc"
    : "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const performanceEvidencePath = join(provenanceNegative.bundleRoot, "performance-evidence.json");
  const performanceEvidence = JSON.parse(readFileSync(performanceEvidencePath, "utf8"));
  performanceEvidence.source_commit = alternateSourceCommit;
  writeFileSync(performanceEvidencePath, JSON.stringify(performanceEvidence, null, 2) + "\n");
  refreshReleaseManifest(provenanceNegative.bundleRoot, provenanceNegative.target.platformTarget);
  const refreshedProvenanceManifest = JSON.parse(readFileSync(provenanceManifestPath, "utf8"));
  refreshedProvenanceManifest.source_commit = alternateSourceCommit;
  writeFileSync(provenanceManifestPath, JSON.stringify(refreshedProvenanceManifest, null, 2) + "\n");
  assertBundleVerifierRejects(
    provenanceNegative.bundleRoot,
    "host capability sample source_commit",
    "host capability sample from another source commit",
  );
  console.log("published release verifier matrix passed");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function prepareStructuralFixture(bundleRoot, target) {
  for (const path of ["bin/redevplugin", "bin/redevplugin-runtime"]) {
    patchExecutable(join(bundleRoot, path), target);
  }
  prepareReleasePerformanceFixture(bundleRoot);
  refreshReleaseManifest(bundleRoot, target.platformTarget);
}

function prepareReleasePerformanceFixture(bundleRoot) {
  const path = join(bundleRoot, "performance-evidence.json");
  const evidence = JSON.parse(readFileSync(path, "utf8"));
  for (const scenario of evidence.scenarios) {
    scenario.gate = "release";
    for (const metric of scenario.metrics) {
      metric.observed = metric.comparator === "eq" ? metric.limit : Math.min(metric.observed, metric.limit);
    }
  }
  writeFileSync(path, JSON.stringify(evidence, null, 2) + "\n");
}

function archiveBundle(bundle) {
  const archive = join(artifactDir, `${basename(bundle.bundleRoot)}.tar.gz`);
  rmSync(archive, { force: true });
  run("tar", ["-C", tempRoot, "-czf", archive, basename(bundle.bundleRoot)], `archive ${bundle.target.id}`);
}

function patchExecutable(path, target) {
  const bytes = readFileSync(path);
  if (bytes.length < 32) throw new Error(`${path} is too small`);
  bytes.fill(0, 0, 32);
  if (target.format === "elf") {
    Buffer.from("7f454c46", "hex").copy(bytes, 0);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes.writeUInt16LE(target.machine, 18);
  } else {
    Buffer.from("cffaedfe", "hex").copy(bytes, 0);
    bytes.writeUInt32LE(target.machine, 4);
  }
  writeFileSync(path, bytes, { mode: 0o755 });
}

function refreshReleaseManifest(bundleRoot, runtimeTarget) {
  const manifestPath = join(bundleRoot, "release-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.runtime_target = runtimeTarget;
  for (const file of manifest.files) {
    const bytes = readFileSync(join(bundleRoot, file.path));
    file.sha256 = createHash("sha256").update(bytes).digest("hex");
    file.size = bytes.length;
  }
  manifest.files.sort((left, right) => left.path.localeCompare(right.path));
  const workerSDKFile = manifest.files.find((file) => file.path === manifest.worker_sdk.path);
  if (!workerSDKFile) throw new Error("release manifest worker SDK file is missing");
  manifest.worker_sdk.sha256 = workerSDKFile.sha256;
  manifest.worker_sdk.size = workerSDKFile.size;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(bundleRoot, "SHA256SUMS"), manifest.files.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n");
}

function assertPublishedVerifierRejects(expectedMessage, label, integrityOnly = false) {
  const result = spawnSync(
    "node",
    [publishedVerifier, ...(integrityOnly ? ["--npm-integrity"] : []), artifactDir, version, sourceCommit],
    {
      cwd: verifierRoot,
      encoding: "utf8",
      env: verifierEnvironment,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const output = `${result.stderr ?? ""}${result.stdout ?? ""}`;
  if (result.status === 0 || !output.includes(expectedMessage)) {
    throw new Error(`published verifier accepted ${label} or returned the wrong diagnostic: ${output || result.error}`);
  }
}

function assertBundleVerifierRejects(bundleRoot, expectedMessage, label) {
  const result = spawnSync(
    "node",
    [bundleVerifier, "--skip-execution", bundleRoot, version],
    {
      cwd: verifierRoot,
      encoding: "utf8",
      env: verifierEnvironment,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const output = `${result.stderr ?? ""}${result.stdout ?? ""}`;
  if (result.status === 0 || !output.includes(expectedMessage)) {
    throw new Error(`bundle verifier accepted ${label} or returned the wrong diagnostic: ${output || result.error}`);
  }
}

function run(command, args, label, options = {}) {
  const result = spawnSync(command, args, { ...options, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr || result.stdout || result.error}`);
  }
  return result.stdout;
}
