#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  assertNoFirstPartyBuildHooks,
  assertSafePackageEntryPaths,
  assertSafePackageMemberSizes,
  assertSafePackagedFile,
  buildRustSourcePackages,
  fetchOfficialRegistryIndex,
  rustSourcePackages,
  validateSourcePackageMetadata,
  writeRegistryEntry,
} from "./rust_source_packages.mjs";

test("official registry reads retry only transient failures within a closed budget", async () => {
  let attempts = 0;
  const response = await fetchOfficialRegistryIndex("https://index.crates.io/example", {
    retryDelaysMs: [0, 0, 0],
    fetchImpl: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("connect timeout");
      if (attempts === 2) return { ok: false, status: 503 };
      return { ok: true, status: 200 };
    },
  });
  assert.equal(response.status, 200);
  assert.equal(attempts, 3);

  attempts = 0;
  await assert.rejects(() => fetchOfficialRegistryIndex("https://index.crates.io/missing", {
    retryDelaysMs: [0, 0, 0],
    fetchImpl: async () => {
      attempts += 1;
      return { ok: false, status: 404 };
    },
  }), /returned 404/);
  assert.equal(attempts, 1);

  attempts = 0;
  await assert.rejects(() => fetchOfficialRegistryIndex("https://index.crates.io/down", {
    retryDelaysMs: [0, 0, 0],
    fetchImpl: async () => {
      attempts += 1;
      throw new Error("connect timeout");
    },
  }), /remained unavailable/);
  assert.equal(attempts, 3);
});

test("Cargo metadata build-code policy accepts inert manifests and rejects executable hooks", () => {
  const inert = { links: null, targets: [{ kind: ["lib"] }], dependencies: [] };
  assert.doesNotThrow(() => assertNoFirstPartyBuildHooks(inert, "inert crate"));
  for (const pkg of [
    { ...inert, links: "native-library" },
    { ...inert, targets: [{ kind: ["custom-build"] }] },
    { ...inert, targets: [{ kind: ["proc-macro"] }] },
    { ...inert, dependencies: [{ kind: "build" }] },
  ]) {
    assert.throws(() => assertNoFirstPartyBuildHooks(pkg, "active crate"), /forbidden build code/);
  }
});

test("Rust source package metadata matches the closed platform topology", () => {
  assert.deepEqual(rustSourcePackages.map(({ name, role }) => ({ name, role })), [
    { name: "redevplugin-contracts", role: "contracts" },
    { name: "redevplugin-ipc", role: "ipc" },
    { name: "redevplugin-wasm-abi", role: "wasm_abi" },
    { name: "redevplugin-target-classifier", role: "target_classifier" },
    { name: "redevplugin-worker-sdk", role: "worker_sdk" },
    { name: "redevplugin-runtime", role: "runtime" },
  ]);
  validateSourcePackageMetadata();
});

test("crate-local fixtures remain exact copies of their canonical repository inputs", () => {
  for (const [canonical, local] of [
    ["testdata/contracts/runtime-lease-signature-v1.json", "crates/redevplugin-ipc/testdata/runtime-lease-signature-v1.json"],
    ["testdata/contracts/runtime-lease-signature-v1-invocation.json", "crates/redevplugin-ipc/testdata/runtime-lease-signature-v1-invocation.json"],
    ["testdata/contracts/ipc/missing_required.json", "crates/redevplugin-ipc/testdata/ipc/missing_required.json"],
    ["testdata/contracts/ipc/replay_frame.json", "crates/redevplugin-ipc/testdata/ipc/replay_frame.json"],
    ["testdata/contracts/ipc/runtime_generation_mismatch.json", "crates/redevplugin-ipc/testdata/ipc/runtime_generation_mismatch.json"],
    ["testdata/contracts/ipc/unknown_enum.json", "crates/redevplugin-ipc/testdata/ipc/unknown_enum.json"],
    ["testdata/contracts/ipc/valid_hello_ack.json", "crates/redevplugin-ipc/testdata/ipc/valid_hello_ack.json"],
    ["testdata/contracts/ipc/valid_invoke_worker_result.json", "crates/redevplugin-ipc/testdata/ipc/valid_invoke_worker_result.json"],
    ["testdata/contracts/ipc/valid_validate_handle_grant.json", "crates/redevplugin-ipc/testdata/ipc/valid_validate_handle_grant.json"],
    ["testdata/contracts/wasm/invalid-final-opcode.hex", "crates/redevplugin-wasm-abi/testdata/wasm/invalid-final-opcode.hex"],
    ["testdata/contracts/wasm/table-maximum-exceeds-limit.hex", "crates/redevplugin-wasm-abi/testdata/wasm/table-maximum-exceeds-limit.hex"],
    ["testdata/contracts/runtime-lease-signature-v1-invocation.json", "crates/redevplugin-runtime/testdata/runtime-lease-signature-v1-invocation.json"],
    ["examples/plugins/memos/workers/memos.wasm", "crates/redevplugin-runtime/testdata/memos.wasm"],
  ]) {
    assert.equal(readFileSync(canonical).compare(readFileSync(local)), 0, local);
  }
  for (const { name } of rustSourcePackages) {
    const local = `crates/${name}/LICENSE`;
    assert.equal(readFileSync("LICENSE").compare(readFileSync(local)), 0, local);
  }
});

test("package file security rejects build hooks, native code, and credentials", () => {
  for (const [path, bytes, pattern] of [
    ["build.rs", Buffer.from("fn main() {}"), /forbidden package file/],
    ["src/native.o", Buffer.from([0x7f, 0x45, 0x4c, 0x46]), /forbidden package file|native executable/],
    ["src/renamed.bin", Buffer.from("!<arch>\n"), /native executable/],
    ["src/renamed.dat", Buffer.from([0x64, 0x86, 0x00, 0x00]), /native executable/],
    ["src/thumb.bin", Buffer.from([0xc2, 0x01, 0x00, 0x00]), /native executable/],
    ["src/ia64.bin", Buffer.from([0x00, 0x02, 0x00, 0x00]), /native executable/],
    ["src/arm64ec.bin", Buffer.from([0x41, 0xa6, 0x00, 0x00]), /native executable/],
    ["src/renamed.cache", Buffer.from([0xca, 0xfe, 0xba, 0xbf]), /native executable/],
    ["src/renamed.payload", Buffer.from([0x42, 0x43, 0xc0, 0xde]), /native executable/],
    ["testdata/private.txt", Buffer.from("-----BEGIN PRIVATE KEY-----\n"), /credential material/],
    ["testdata/token.txt", Buffer.from(`ghp_${"a".repeat(40)}`), /credential material/],
    [
      "testdata/binary-token.bin",
      Buffer.concat([Buffer.from([0x00, 0xff]), Buffer.from(`ghp_${"c".repeat(40)}`)]),
      /credential material/,
    ],
    [
      "testdata/large-token.txt",
      Buffer.concat([Buffer.alloc(2 * 1024 * 1024 + 1, 0x61), Buffer.from(`ghp_${"b".repeat(40)}`)]),
      /credential material/,
    ],
  ]) {
    assert.throws(() => assertSafePackagedFile(path, bytes), pattern);
  }
  assert.doesNotThrow(() => assertSafePackagedFile(
    "testdata/redaction.json",
    Buffer.from('{"token":"secret-token","path":"/Users/private/key"}\n'),
  ));
  assert.doesNotThrow(() => assertSafePackagedFile(
    "testdata/worker.wasm",
    Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
  ));
});

test("source archive security rejects path collisions and expansion limits", () => {
  assert.throws(() => assertSafePackageEntryPaths([
    "crate-0.6.0/",
    "crate-0.6.0/src/Foo.rs",
    "crate-0.6.0/src/foo.rs",
  ]), /case-colliding/);
  assert.throws(() => assertSafePackageEntryPaths([
    "crate-0.6.0/",
    "crate-0.6.0/src/Foo/a.rs",
    "crate-0.6.0/src/foo/b.rs",
  ]), /case-colliding/);
  assert.throws(() => assertSafePackageEntryPaths([
    "crate-0.6.0/",
    "crate-0.6.0/src/data",
    "crate-0.6.0/src/data/value.json",
  ]), /conflicting file and directory/);
  assert.throws(() => assertSafePackageEntryPaths(Array.from(
    { length: 4_097 },
    (_, index) => `crate-0.6.0/testdata/${index}.json`,
  )), /too many archive members/);
  assert.throws(() => assertSafePackageMemberSizes(new Map([
    ["crate-0.6.0/testdata/large.bin", 8 * 1024 * 1024 + 1],
  ])), /member .* exceeds the size limit/);
  assert.throws(() => assertSafePackageMemberSizes(new Map(Array.from(
    { length: 5 },
    (_, index) => [`crate-0.6.0/testdata/${index}.bin`, 8 * 1024 * 1024],
  ))), /uncompressed size limit/);
});

test("temporary registry coordinates are create-only", () => {
  const registry = mkdtempSync(join(tmpdir(), "redevplugin-registry-entry-"));
  try {
    const entry = {
      name: "redevplugin-contracts",
      vers: "0.6.0",
      deps: [],
      cksum: "a".repeat(64),
      features: {},
      yanked: false,
    };
    writeRegistryEntry(registry, entry);
    writeRegistryEntry(registry, entry);
    assert.throws(() => writeRegistryEntry(registry, { ...entry, cksum: "b".repeat(64) }), /different bytes/);
  } finally {
    rmSync(registry, { recursive: true, force: true });
  }
});

test("all Rust source crates package deterministically and test from an isolated registry", async () => {
  const result = await buildRustSourcePackages({ allowDirty: true });
  try {
    assert.deepEqual(result.artifacts.map(({ name, version, size, sha256 }) => ({
      name,
      version,
      validSize: size > 0,
      validDigest: /^[0-9a-f]{64}$/.test(sha256),
    })), rustSourcePackages.map(({ name }) => ({
      name,
      version: "0.6.0",
      validSize: true,
      validDigest: true,
    })));
  } finally {
    result.cleanup();
  }
});
