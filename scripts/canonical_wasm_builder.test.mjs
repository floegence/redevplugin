import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  assertSourceSnapshotUnchanged,
  buildCanonicalWasmArtifacts,
  canonicalRustImage,
  parseCanonicalWasmGeneratorArgs,
  selectCanonicalWasmBuildMode,
  snapshotCanonicalCargoSources,
} from "./canonical_wasm_builder.mjs";

test("native builds use a clean target, pinned rustc, and an environment allowlist", async () => {
  const root = await mkdtemp(join(tmpdir(), "redevplugin-canonical-wasm-"));
  try {
    const cargoTargetDir = resolve(root, "custom-target");
    const staleArtifact = resolve(root, "target/wasm32-unknown-unknown/release/example_worker.wasm");
    await mkdir(resolve(staleArtifact, ".."), { recursive: true });
    await writeFile(staleArtifact, "stale-root-artifact");

    const fakeCargo = resolve(root, "fake-cargo.sh");
    const fakeRustc = resolve(root, "fake-rustc.sh");
    const flagsCapture = resolve(root, "cargo-flags.txt");
    const environmentCapture = resolve(root, "cargo-environment.txt");
    const targetCapture = resolve(root, "cargo-target.txt");
    await writeFile(fakeCargo, `#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release"
printf 'fresh-configured-artifact' > "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/example_worker.wasm"
printf '%s' "$CARGO_ENCODED_RUSTFLAGS" > "${flagsCapture}"
env | sort > "${environmentCapture}"
printf '%s' "$CARGO_TARGET_DIR" > "${targetCapture}"
`);
    await writeFile(fakeRustc, `#!/usr/bin/env bash
cat <<'EOF'
rustc 1.88.0 (6b00bc388 2025-06-23)
binary: rustc
commit-hash: 6b00bc3880198600130e1cf62b8f8a93494488cc
commit-date: 2025-06-23
host: x86_64-unknown-linux-gnu
release: 1.88.0
LLVM version: 20.1.7
EOF
`);
    await chmod(fakeCargo, 0o755);
    await chmod(fakeRustc, 0o755);

    const artifacts = await buildCanonicalWasmArtifacts({
      root,
      rustVersion: "1.88.0",
      targets: [{ packageName: "example-worker", artifact: "example_worker.wasm" }],
      buildMode: "native",
      cargoCommand: fakeCargo,
      rustcCommand: fakeRustc,
      environment: {
        ...process.env,
        CARGO_TARGET_DIR: cargoTargetDir,
        CARGO_HOME: resolve(root, "ambient-cargo-home"),
        CARGO_ENCODED_RUSTFLAGS: "ambient-noncanonical-flag",
        RUSTFLAGS: "ambient-rustflags",
        RUSTC: "ambient-rustc",
        RUSTC_WRAPPER: "ambient-wrapper",
        RUSTUP_TOOLCHAIN: "nightly",
      },
    });

    assert.equal((await readFile(staleArtifact, "utf8")), "stale-root-artifact");
    assert.equal(artifacts.get("example_worker.wasm").toString(), "fresh-configured-artifact");
    const encodedFlags = await readFile(flagsCapture, "utf8");
    assert.doesNotMatch(encodedFlags, /ambient-noncanonical-flag/);
    assert.match(encodedFlags, /--remap-path-prefix=.*=\/workspace/);
    assert.match(encodedFlags, /--remap-path-prefix=.*=\/cargo/);
    const buildEnvironment = await readFile(environmentCapture, "utf8");
    assert.doesNotMatch(buildEnvironment, /ambient-rustflags|ambient-rustc|ambient-wrapper|nightly/);
    assert.doesNotMatch(buildEnvironment, /ambient-cargo-home/);
    assert.match(buildEnvironment, /^RUSTUP_TOOLCHAIN=1\.88\.0$/m);
    assert.match(buildEnvironment, /^CARGO_HOME=.*canonical-cargo-home$/m);
    const actualTargetDir = await readFile(targetCapture, "utf8");
    assert.notEqual(actualTargetDir, cargoTargetDir);
    assert.notEqual(actualTargetDir, resolve(root, "target"));
    assert.match(actualTargetDir, /canonical-wasm-native-/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("forced canonical checks use Docker even on the canonical Linux host", () => {
  assert.equal(selectCanonicalWasmBuildMode({ forceDocker: true, platform: "linux", arch: "x64" }), "docker");
  assert.equal(selectCanonicalWasmBuildMode({ forceDocker: false, platform: "linux", arch: "x64" }), "native");
  assert.equal(selectCanonicalWasmBuildMode({ forceDocker: false, platform: "darwin", arch: "arm64" }), "docker");
});

test("canonical Docker builds use an immutable Rust image", () => {
  assert.equal(
    canonicalRustImage("1.88.0"),
    "docker.io/library/rust:1.88.0-bookworm@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0",
  );
  assert.throws(() => canonicalRustImage("1.89.0"), /no pinned canonical Rust image/);
});

test("generator arguments and Cargo targets reject fail-open inputs", async () => {
  assert.deepEqual(parseCanonicalWasmGeneratorArgs(["--check", "--canonical"]), {
    checkOnly: true,
    forceCanonical: true,
  });
  assert.throws(() => parseCanonicalWasmGeneratorArgs(["--canonial"]), /unknown canonical WASM generator argument/);

  const base = { root: "/tmp", rustVersion: "1.88.0", buildMode: "native" };
  await assert.rejects(
    buildCanonicalWasmArtifacts({ ...base, targets: [{ packageName: "--help", artifact: "worker.wasm" }] }),
    /unsafe package or artifact name/,
  );
  await assert.rejects(
    buildCanonicalWasmArtifacts({
      ...base,
      targets: [
        { packageName: "worker", artifact: "worker.wasm" },
        { packageName: "worker", artifact: "worker-copy.wasm" },
      ],
    }),
    /duplicate package or artifact/,
  );
});

test("Cargo source snapshots include recursive local inputs and detect concurrent edits", async () => {
  const root = await mkdtemp(join(tmpdir(), "redevplugin-cargo-snapshot-"));
  try {
    const appRoot = resolve(root, "app");
    const dependencyRoot = resolve(root, "dependency");
    await mkdir(resolve(appRoot, "src/nested"), { recursive: true });
    await mkdir(resolve(appRoot, "src/target"), { recursive: true });
    await mkdir(resolve(dependencyRoot, "src"), { recursive: true });
    await mkdir(resolve(root, ".cargo"), { recursive: true });
    await mkdir(resolve(root, "scripts"), { recursive: true });
    await writeFile(resolve(root, "Cargo.lock"), "lock");
    await writeFile(resolve(root, "rust-toolchain.toml"), "toolchain");
    await writeFile(resolve(root, ".cargo/config.toml"), "[build]\n");
    await writeFile(resolve(root, "scripts/builder.mjs"), "export {};\n");
    await writeFile(resolve(appRoot, "Cargo.toml"), "[package]\nname='app'\nversion='0.0.0'\n");
    await writeFile(resolve(appRoot, "build.rs"), "fn main() {}\n");
    await writeFile(resolve(appRoot, "src/lib.rs"), "mod nested;\n");
    await writeFile(resolve(appRoot, "src/nested/mod.rs"), "pub fn value() {}\n");
    await writeFile(resolve(appRoot, "src/target/mod.rs"), "pub fn target_named_module() {}\n");
    await writeFile(resolve(dependencyRoot, "Cargo.toml"), "[package]\nname='dependency'\nversion='0.0.0'\n");
    await writeFile(resolve(dependencyRoot, "src/lib.rs"), "pub fn dependency() {}\n");

    const fakeCargo = resolve(root, "fake-cargo.mjs");
    const cargoHomeCapture = resolve(root, "metadata-cargo-home.txt");
    const metadata = {
      packages: [
        {
          name: "app",
          manifest_path: resolve(appRoot, "Cargo.toml"),
          dependencies: [{ name: "dependency", path: dependencyRoot }],
        },
        {
          name: "dependency",
          manifest_path: resolve(dependencyRoot, "Cargo.toml"),
          dependencies: [],
        },
      ],
    };
    await writeFile(fakeCargo, `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(cargoHomeCapture)}, process.env.CARGO_HOME || "");
process.stdout.write(${JSON.stringify(JSON.stringify(metadata))});
`);
    await chmod(fakeCargo, 0o755);

    const snapshotOptions = {
      root,
      rustVersion: "1.88.0",
      packageNames: ["app"],
      additionalPaths: ["Cargo.lock", "rust-toolchain.toml", "scripts/builder.mjs"],
      optionalPaths: [".cargo"],
      cargoCommand: fakeCargo,
    };
    const before = await snapshotCanonicalCargoSources(snapshotOptions);
    for (const expected of [
      ".cargo/config.toml",
      "app/Cargo.toml",
      "app/build.rs",
      "app/src/lib.rs",
      "app/src/nested/mod.rs",
      "app/src/target/mod.rs",
      "dependency/Cargo.toml",
      "dependency/src/lib.rs",
    ]) {
      assert.ok(before.paths.includes(expected), `missing source snapshot path ${expected}`);
    }
    assert.match(await readFile(cargoHomeCapture, "utf8"), /canonical-cargo-home$/);

    await writeFile(resolve(dependencyRoot, "src/new-module.rs"), "pub fn added() {}\n");
    const after = await snapshotCanonicalCargoSources(snapshotOptions);
    assert.throws(() => assertSourceSnapshotUnchanged(before, after), /Cargo source inputs changed during canonical WASM build/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Cargo source snapshots reject configuration inherited from repository ancestors", async () => {
  const parent = await mkdtemp(join(tmpdir(), "redevplugin-cargo-ancestor-"));
  const root = resolve(parent, "repository");
  try {
    await mkdir(resolve(parent, ".cargo"), { recursive: true });
    await mkdir(root, { recursive: true });
    await writeFile(resolve(parent, ".cargo/config.toml"), "[build]\nrustflags=['--cfg=ambient']\n");
    await assert.rejects(
      snapshotCanonicalCargoSources({
        root,
        rustVersion: "1.88.0",
        packageNames: ["app"],
        cargoCommand: "/usr/bin/false",
      }),
      /Cargo configuration outside the repository is forbidden/,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
