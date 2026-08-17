import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRustPublishMetadata } from "./build_release_packages.mjs";

const sourceCommit = "1".repeat(40);

test("Rust upload metadata contains only the current source crate graph", () => {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-release-packages-"));
  try {
    const packages = ["redevplugin-runtime", "redevplugin-worker-sdk"].map((name) => {
      const packageRoot = join(root, name);
      const readme = join(packageRoot, "README.md");
      mkdirSync(packageRoot);
      writeFileSync(readme, `${name}\n`);
      return {
        name,
        version: "3.0.0",
        manifest_path: join(packageRoot, "Cargo.toml"),
        dependencies: [],
        features: {},
        authors: [],
        description: name,
        documentation: null,
        homepage: null,
        readme: "README.md",
        keywords: [],
        categories: [],
        license: "MIT",
        license_file: null,
        repository: "https://github.com/floegence/redevplugin",
        links: null,
        rust_version: "1.88.0",
      };
    });

    const metadata = createRustPublishMetadata({
      cargoMetadata: { packages },
      version: "3.0.0",
      sourceCommit,
    });
    assert.deepEqual(metadata.packages.map(({ name }) => name), [
      "redevplugin-runtime",
      "redevplugin-worker-sdk",
    ]);
    assert.equal(metadata.source_commit, sourceCommit);
    assert.equal("artifacts" in metadata, false);
    assert.equal("package_set" in metadata, false);
    assert.equal(metadata.packages[0].readme, readFileSync(join(root, "redevplugin-runtime", "README.md"), "utf8"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("release package helper does not recreate retired release facts", () => {
  const source = readFileSync(new URL("./build_release_packages.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /platform.package.(?:build|publication|set)|compatibility.manifest/i);
});
