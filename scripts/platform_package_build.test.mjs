import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { verifyPlatformPackageBuild, verifyRustPublishMetadata } from "./platform_package_build.mjs";

const version = "0.6.4";
const sourceCommit = "1".repeat(40);
const contractSetSHA256 = "42768632672d3beef6410f0b87f53c8b124f1e56746bcc78beba52b6fd7da737";

test("platform package build manifest is closed, complete, and content addressed", () => {
  const fixture = createFixture();
  try {
    assert.doesNotThrow(() => verifyPlatformPackageBuild(fixture.manifestPath, { verifyArchives: false }));
    for (const mutate of [
      (value) => { value.extra = true; },
      (value) => { value.artifacts.pop(); },
      (value) => { value.artifacts[0].path = "../escape.tgz"; },
      (value) => { value.artifacts[0].sha256 = "0".repeat(64); },
      (value) => { value.artifacts[0].integrity = `sha512-${Buffer.alloc(64, 9).toString("base64")}`; },
      (value) => { value.artifacts[1].name = value.artifacts[0].name; },
      (value) => { [value.artifacts[2], value.artifacts[3]] = [value.artifacts[3], value.artifacts[2]]; },
    ]) {
      const candidate = structuredClone(fixture.manifest);
      mutate(candidate);
      writeFileSync(fixture.manifestPath, `${JSON.stringify(candidate, null, 2)}\n`);
      assert.throws(() => verifyPlatformPackageBuild(fixture.manifestPath, { verifyArchives: false }));
    }
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("Rust upload metadata is closed and binds the exact first-party dependency graph", () => {
  const directory = mkdtempSync(join(tmpdir(), "redevplugin-rust-publish-metadata-"));
  const path = join(directory, "rust-publish-metadata-v1.json");
  try {
    const valid = validRustPublishMetadata();
    writeFileSync(path, `${JSON.stringify(valid)}\n`);
    assert.doesNotThrow(() => verifyRustPublishMetadata(path, { version, sourceCommit }));
    for (const mutate of [
      (value) => { value.source_commit = "2".repeat(40); },
      (value) => { value.packages.pop(); },
      (value) => { value.packages[0].extra = true; },
      (value) => { value.packages[1].deps[0].version_req = "^0.6"; },
      (value) => { value.packages[5].deps[0].kind = "dev"; },
      (value) => { value.packages[0].deps.push(internalDependency("redevplugin-runtime", "normal")); },
    ]) {
      const candidate = structuredClone(valid);
      mutate(candidate);
      writeFileSync(path, `${JSON.stringify(candidate)}\n`);
      assert.throws(() => verifyRustPublishMetadata(path, { version, sourceCommit }));
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function validRustPublishMetadata() {
  const names = [
    "redevplugin-contracts",
    "redevplugin-ipc",
    "redevplugin-wasm-abi",
    "redevplugin-target-classifier",
    "redevplugin-worker-sdk",
    "redevplugin-runtime",
  ];
  const dependencies = new Map([
    ["redevplugin-ipc", [internalDependency("redevplugin-contracts", "dev")]],
    ["redevplugin-target-classifier", [internalDependency("redevplugin-contracts", "dev")]],
    ["redevplugin-runtime", [
      internalDependency("redevplugin-ipc", "normal"),
      internalDependency("redevplugin-wasm-abi", "normal"),
    ]],
  ]);
  return {
    schema_version: "redevplugin.rust_publish_metadata.v1",
    source_commit: sourceCommit,
    packages: names.map((name) => ({
      name,
      vers: version,
      deps: dependencies.get(name) ?? [],
      features: {},
      authors: [],
      description: `${name} fixture`,
      documentation: null,
      homepage: null,
      readme: `# ${name}\n`,
      readme_file: "README.md",
      keywords: [],
      categories: [],
      license: "MIT",
      license_file: null,
      repository: "https://github.com/floegence/redevplugin",
      badges: {},
      links: null,
      rust_version: "1.88.0",
    })),
  };
}

function internalDependency(name, kind) {
  return {
    name,
    version_req: `=${version}`,
    features: [],
    optional: false,
    default_features: true,
    target: null,
    kind,
    registry: null,
    explicit_name_in_toml: null,
  };
}

function createFixture() {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-platform-package-build-"));
  mkdirSync(join(root, "npm"));
  mkdirSync(join(root, "rust"));
  const coordinates = [
    ["npm", "@floegence/redevplugin-contracts", `npm/floegence-redevplugin-contracts-${version}.tgz`],
    ["npm", "@floegence/redevplugin-ui", `npm/floegence-redevplugin-ui-${version}.tgz`],
    ...[
      "redevplugin-contracts",
      "redevplugin-ipc",
      "redevplugin-wasm-abi",
      "redevplugin-target-classifier",
      "redevplugin-worker-sdk",
      "redevplugin-runtime",
    ].map((name) => ["rust", name, `rust/${name}-${version}.crate`]),
  ];
  const artifacts = coordinates.map(([kind, name, path], index) => {
    const bytes = Buffer.from(`fixture ${index} ${kind} ${name}\n`);
    writeFileSync(join(root, path), bytes);
    const artifact = {
      kind,
      name,
      version,
      path,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    if (kind === "npm") {
      artifact.integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
      artifact.sha512 = createHash("sha512").update(bytes).digest("hex");
    }
    return artifact;
  });
  artifacts.sort((left, right) => `${left.kind}:${left.name}`.localeCompare(`${right.kind}:${right.name}`));
  const manifest = {
    schema_version: "redevplugin.platform_package_build.v1",
    platform_version: version,
    source_commit: sourceCommit,
    contract_set_sha256: contractSetSHA256,
    artifacts,
  };
  const manifestPath = join(root, "platform-package-build-v1.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, manifestPath, manifest };
}
