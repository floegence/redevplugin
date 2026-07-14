#!/usr/bin/env node

import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const [rawSourceBundle, version, sourceCommit] = process.argv.slice(2);
if (!rawSourceBundle || !version || !/^[0-9a-f]{40}$/.test(sourceCommit ?? "")) {
  console.error("usage: test_published_release_verifier.mjs <source-bundle> <version> <source-commit>");
  process.exit(2);
}

const root = resolve(import.meta.dirname, "..");
const sourceBundle = resolve(rawSourceBundle);
const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-published-verifier-"));
const artifactDir = join(tempRoot, "artifacts");
const targets = [
  { id: "x86_64-unknown-linux-gnu", format: "elf", machine: 62 },
  { id: "aarch64-unknown-linux-gnu", format: "elf", machine: 183 },
  { id: "x86_64-apple-darwin", format: "macho", machine: 0x01000007 },
  { id: "aarch64-apple-darwin", format: "macho", machine: 0x0100000c },
];

try {
  mkdirSync(artifactDir, { recursive: true });
  const bundles = [];
  for (const target of targets) {
    const bundleRoot = join(tempRoot, `redevplugin-v${version}-${target.id}`);
    cpSync(sourceBundle, bundleRoot, { recursive: true });
    prepareStructuralFixture(bundleRoot, target);
    const archive = join(artifactDir, `${basename(bundleRoot)}.tar.gz`);
    run("tar", ["-C", tempRoot, "-czf", archive, basename(bundleRoot)], `archive ${target.id}`);
    bundles.push({ bundleRoot, target });
  }

  run(
    "node",
    [join(root, "scripts", "verify_published_release.mjs"), artifactDir, version, sourceCommit],
    "verify structural runtime matrix",
  );

  const negative = bundles[0];
  patchExecutable(join(negative.bundleRoot, "bin", "redevplugin-runtime"), targets[1]);
  refreshReleaseManifest(negative.bundleRoot, negative.target.id);
  const rejected = spawnSync(
    "node",
    [join(root, "scripts", "verify_redevplugin_release_bundle.mjs"), "--structural-only", negative.bundleRoot, version],
    { encoding: "utf8" },
  );
  if (rejected.status === 0) {
    throw new Error("structural verifier accepted a runtime binary for the wrong target");
  }

  const provenanceNegative = bundles[1];
  const provenanceManifestPath = join(provenanceNegative.bundleRoot, "release-manifest.json");
  const provenanceManifest = JSON.parse(readFileSync(provenanceManifestPath, "utf8"));
  provenanceManifest.source_commit = provenanceManifest.source_commit === "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ? "cccccccccccccccccccccccccccccccccccccccc"
    : "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  writeFileSync(provenanceManifestPath, JSON.stringify(provenanceManifest, null, 2) + "\n");
  const provenanceRejected = spawnSync(
    "node",
    [join(root, "scripts", "verify_redevplugin_release_bundle.mjs"), "--structural-only", provenanceNegative.bundleRoot, version],
    { encoding: "utf8" },
  );
  if (provenanceRejected.status === 0 || !`${provenanceRejected.stderr}${provenanceRejected.stdout}`.includes("host capability sample source_commit")) {
    throw new Error("structural verifier accepted a host capability sample from another source commit");
  }
  console.log("published release structural verifier matrix passed");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function prepareStructuralFixture(bundleRoot, target) {
  for (const path of ["bin/redevplugin", "bin/redevplugin-runtime"]) {
    patchExecutable(join(bundleRoot, path), target);
  }
  refreshReleaseManifest(bundleRoot, target.id);
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
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(bundleRoot, "SHA256SUMS"), manifest.files.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n");
}

function run(command, args, label) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr || result.stdout || result.error}`);
  }
  return result.stdout;
}
