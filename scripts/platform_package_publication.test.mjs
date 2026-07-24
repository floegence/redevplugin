import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createPlatformPackagePublication,
  publicationAssetName,
  verifyPlatformPackagePublication,
  verifyPlatformReleaseDirectory,
} from "./platform_package_publication.mjs";

const version = "0.6.12";
const sourceCommit = "1".repeat(40);
const h1 = `h1:${Buffer.alloc(32, 1).toString("base64")}`;
const npmNames = ["@floegence/redevplugin-contracts", "@floegence/redevplugin-ui"];
const rustNames = [
  "redevplugin-contracts",
  "redevplugin-ipc",
  "redevplugin-wasm-abi",
  "redevplugin-target-classifier",
  "redevplugin-worker-sdk",
  "redevplugin-runtime",
];

test("publication creation binds exact registry readbacks and source identity", () => {
  const publication = validPublication();
  assert.doesNotThrow(() => verifyPlatformPackagePublication(
    Buffer.from(JSON.stringify(publication)),
    { expectedVersion: version, expectedCommit: sourceCommit },
  ));
  for (const mutate of [
    (value) => { value.workflow.path = ".github/workflows/other.yml"; },
    (value) => { value.source_commit = "2".repeat(40); },
    (value) => { value.npm_packages[0].name = value.npm_packages[1].name; },
    (value) => { value.rust_crates.pop(); },
    (value) => { value.extra = true; },
  ]) {
    const candidate = structuredClone(publication);
    mutate(candidate);
    assert.throws(() => verifyPlatformPackagePublication(Buffer.from(JSON.stringify(candidate))));
  }
});

test("GitHub Release readback permits exactly one publication asset", () => {
  const directory = mkdtempSync(join(tmpdir(), "redevplugin-platform-release-"));
  try {
    writeFileSync(join(directory, publicationAssetName), `${JSON.stringify(validPublication(), null, 2)}\n`);
    assert.doesNotThrow(() => verifyPlatformReleaseDirectory(directory, {
      expectedVersion: version,
      expectedCommit: sourceCommit,
    }));
    writeFileSync(join(directory, "unexpected.txt"), "unexpected\n");
    assert.throws(() => verifyPlatformReleaseDirectory(directory), /must be exactly/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("publication creation rejects substituted registry source commits", () => {
  const inputs = validReadbacks();
  inputs.rustReadback[3].source_commit = "f".repeat(40);
  assert.throws(() => createPlatformPackagePublication(inputs), /source commit mismatch/);
});

function validPublication() {
  return createPlatformPackagePublication(validReadbacks());
}

function validReadbacks() {
  const integrity = `sha512-${Buffer.alloc(64, 2).toString("base64")}`;
  const provenance = Buffer.alloc(64, 2).toString("hex");
  return {
    sourceCommit,
    goReadback: {
      module: "github.com/floegence/redevplugin",
      version: `v${version}`,
      h1,
      go_mod_h1: h1,
      source_commit: sourceCommit,
    },
    npmReadback: npmNames.map((name) => ({
      name,
      version,
      integrity,
      provenance_subject_sha512: provenance,
      source_commit: sourceCommit,
    })),
    rustReadback: rustNames.map((name, index) => ({
      name,
      version,
      registry_checksum_sha256: (index + 1).toString(16).repeat(64),
      source_commit: sourceCommit,
    })),
  };
}
