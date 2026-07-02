#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";

const [rawBundleDir, rawExpectedVersion] = process.argv.slice(2);

if (!rawBundleDir) {
  console.error("usage: verify_redevplugin_release_bundle.mjs <bundle-dir> [expected-version]");
  process.exit(2);
}

const bundleDir = resolve(rawBundleDir);
const releaseManifestPath = join(bundleDir, "release-manifest.json");
const sha256SumsPath = join(bundleDir, "SHA256SUMS");
const manifest = readJSON(releaseManifestPath);
const expectedVersion = rawExpectedVersion || manifest.version;

verifyReleaseManifestShape(manifest, expectedVersion);
verifyManifestFiles(bundleDir, manifest);
verifyRequiredArtifacts(bundleDir);
verifyCompatibility(bundleDir, expectedVersion);
verifyRuntimeHello(bundleDir, expectedVersion);
verifyNpmTarball(bundleDir, expectedVersion);
verifyNoticeEvidence(bundleDir);

console.log(`release bundle verified: ${bundleDir}`);

function verifyReleaseManifestShape(manifest, expectedVersion) {
  assertObject(manifest, "release-manifest.json");
  assertEqual(manifest.schema_version, "redevplugin.release_manifest.v1", "release manifest schema_version");
  assertEqual(manifest.version, expectedVersion, "release manifest version");
  if (manifest.runtime_target !== null && typeof manifest.runtime_target !== "string") {
    fail("release manifest runtime_target must be a string or null");
  }
  if (!Number.isFinite(Date.parse(manifest.generated_at))) {
    fail("release manifest generated_at must be an ISO date-time string");
  }
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    fail("release manifest files must be a non-empty array");
  }
  const seen = new Set();
  for (const [index, file] of manifest.files.entries()) {
    assertObject(file, `release manifest files[${index}]`);
    assertBundlePath(file.path, `release manifest files[${index}].path`);
    assertHexSHA256(file.sha256, `release manifest files[${index}].sha256`);
    if (!Number.isSafeInteger(file.size) || file.size < 0) {
      fail(`release manifest files[${index}].size must be a non-negative safe integer`);
    }
    if (seen.has(file.path)) {
      fail(`release manifest contains duplicate file path ${file.path}`);
    }
    seen.add(file.path);
  }
}

function verifyManifestFiles(bundleDir, manifest) {
  const actualFiles = listBundleFiles(bundleDir);
  const manifestFiles = manifest.files.map((file) => ({
    path: file.path,
    sha256: file.sha256,
    size: file.size,
  }));
  manifestFiles.sort((a, b) => a.path.localeCompare(b.path));
  assertDeepEqual(manifestFiles, actualFiles, "release manifest file list");

  const expectedSums = manifestFiles.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n";
  const actualSums = readFileSync(sha256SumsPath, "utf8");
  assertEqual(actualSums, expectedSums, "SHA256SUMS content");
}

function verifyRequiredArtifacts(bundleDir) {
  const requiredFiles = [
    "AGENTS.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "bin/redevplugin",
    "bin/redevplugin-runtime",
    "compatibility.json",
    "contracts/spec/openapi/plugin-platform-v1.yaml",
    "contracts/spec/plugin/bridge-v1.schema.json",
    "contracts/spec/plugin/compatibility-manifest-v1.schema.json",
    "contracts/spec/plugin/ipc-v1.schema.json",
    "contracts/spec/plugin/manifest-v1.schema.json",
    "contracts/spec/plugin/release-manifest-v1.schema.json",
    "contracts/spec/plugin/token-ticket-v1.schema.json",
    "contracts/spec/plugin/worker-invocation-v1.schema.json",
    "notices/Cargo.lock",
    "notices/go.sum",
    "notices/package-lock.json",
  ];
  for (const path of requiredFiles) {
    assertFile(join(bundleDir, path), path);
  }
  assertExecutable(join(bundleDir, "bin/redevplugin"), "bin/redevplugin");
  assertExecutable(join(bundleDir, "bin/redevplugin-runtime"), "bin/redevplugin-runtime");
}

function verifyCompatibility(bundleDir, expectedVersion) {
  const compatibilityPath = join(bundleDir, "compatibility.json");
  const compatibility = readJSON(compatibilityPath);
  assertEqual(compatibility.schema_version, "redevplugin.compatibility.v1", "compatibility schema_version");
  for (const key of ["redevplugin_go_version", "redevplugin_ui_version", "redevplugin_runtime_version"]) {
    assertEqual(compatibility.matrix?.[key], expectedVersion, `compatibility matrix ${key}`);
  }
  const verifyOutput = execFileSync(
    join(bundleDir, "bin/redevplugin"),
    ["verify-compatibility", compatibilityPath, join(bundleDir, "contracts")],
    { encoding: "utf8" },
  );
  const summary = JSON.parse(verifyOutput);
  assertEqual(summary.ok, true, "verify-compatibility summary");
}

function verifyRuntimeHello(bundleDir, expectedVersion) {
  if (process.env.REDEVPLUGIN_SKIP_RUNTIME_EXEC === "1") {
    return;
  }
  const hello = '{"ipc_version":"rust-ipc-v1","frame_type":"hello","request_id":"hello-1","runtime_generation_id":"gen-1","payload":{}}\n';
  const output = execFileSync(join(bundleDir, "bin/redevplugin-runtime"), {
    input: hello,
    encoding: "utf8",
  }).trim().split("\n")[0];
  const ack = JSON.parse(output);
  assertEqual(ack.frame_type, "hello_ack", "runtime hello frame_type");
  assertEqual(ack.payload?.runtime_version, expectedVersion, "runtime hello version");
  assertEqual(ack.payload?.rust_ipc_version, "rust-ipc-v1", "runtime hello rust_ipc_version");
  assertEqual(ack.payload?.wasm_abi_version, "redevplugin-wasm-worker-v1", "runtime hello wasm_abi_version");
}

function verifyNpmTarball(bundleDir, expectedVersion) {
  const npmDir = join(bundleDir, "npm");
  const tarballs = readdirSync(npmDir).filter((name) => name.endsWith(".tgz"));
  assertEqual(tarballs.length, 1, "npm tarball count");
  const tmp = mkdtempSync(join(tmpdir(), "redevplugin-npm-"));
  try {
    execFileSync("tar", ["-xzf", join(npmDir, tarballs[0]), "-C", tmp]);
    const pkg = readJSON(join(tmp, "package", "package.json"));
    assertEqual(pkg.name, "@floegence/redevplugin-ui", "npm package name");
    assertEqual(pkg.version, expectedVersion, "npm package version");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function verifyNoticeEvidence(bundleDir) {
  const notice = readFileSync(join(bundleDir, "THIRD_PARTY_NOTICES.md"), "utf8");
  for (const expected of [
    "scripts/generate_third_party_notices.mjs",
    "notices/go.sum",
    "notices/package-lock.json",
    "notices/Cargo.lock",
    "cargo deny check",
    "## Rust Crates",
    "## npm Packages",
    "## Go Modules",
    "| wasmi |",
    "| typescript |",
    "| modernc.org/sqlite |",
    "Apache-2.0",
    "MIT",
  ]) {
    if (!notice.includes(expected)) {
      fail(`THIRD_PARTY_NOTICES.md must mention ${expected}`);
    }
  }
  if (notice.includes("UNKNOWN")) {
    fail("THIRD_PARTY_NOTICES.md must not contain UNKNOWN license evidence");
  }
  const cargoLock = readFileSync(join(bundleDir, "notices/Cargo.lock"), "utf8");
  for (const crate of ["wasmi", "redevplugin-runtime", "redevplugin-ipc"]) {
    if (!cargoLock.includes(`name = "${crate}"`)) {
      fail(`notices/Cargo.lock must include ${crate}`);
    }
  }
}

function listBundleFiles(root) {
  const files = [];
  walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return files;

  function walk(dir) {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      const rel = relative(root, path).replaceAll("\\", "/");
      if (rel === "release-manifest.json" || rel === "SHA256SUMS") {
        continue;
      }
      const linkStat = lstatSync(path);
      if (linkStat.isSymbolicLink()) {
        fail(`release bundle must not contain symlink ${rel}`);
      }
      const stat = statSync(path);
      if (stat.isDirectory()) {
        walk(path);
        continue;
      }
      if (!stat.isFile()) {
        fail(`release bundle entry must be a regular file: ${rel}`);
      }
      files.push({
        path: rel,
        sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
        size: stat.size,
      });
    }
  }
}

function readJSON(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function assertFile(path, label) {
  if (!existsSync(path) || !statSync(path).isFile()) {
    fail(`required release artifact missing: ${label}`);
  }
}

function assertExecutable(path, label) {
  assertFile(path, label);
  if (process.platform !== "win32" && (statSync(path).mode & 0o111) === 0) {
    fail(`required release artifact is not executable: ${label}`);
  }
}

function assertBundlePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  if (value.startsWith("/") || value.includes("\\") || value.split("/").includes("..") || /\s/.test(value)) {
    fail(`${label} must be a relative POSIX path without traversal or whitespace: ${value}`);
  }
}

function assertHexSHA256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase hex sha256`);
  }
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    fail(`${label} mismatch: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
  }
}

function assertDeepEqual(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} mismatch:\nactual=${JSON.stringify(actual, null, 2)}\nexpected=${JSON.stringify(expected, null, 2)}`);
  }
}

function fail(message) {
  console.error(`release bundle verification failed: ${message}`);
  process.exit(1);
}
