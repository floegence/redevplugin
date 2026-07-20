#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return readFileSync(join(root, relativePath), "utf8");
}

const documents = {
  agents: read("AGENTS.md"),
  readme: read("README.md"),
  architecture: read("docs/architecture/plugin-platform-runtime.md"),
  release: read("docs/release/ci-and-release-gates.md"),
};

test("repository docs define the source-crate platform boundary", () => {
  for (const [label, source] of Object.entries(documents)) {
    assert.match(
      source,
      /ReDevPlugin publishes (?:the Rust runtime as|versioned)\s+source\s+crates/i,
      `${label} must declare the source-crate publication boundary`,
    );
    assert.match(
      source,
      /(?:host products?|a host product)[\s\S]{0,400}?(?:build|builds)[\s\S]{0,160}?runtime binary[\s\S]{0,160}?published [\w ]*source crates/i,
      `${label} must assign product runtime binary construction to the host`,
    );
  }
});

test("repository docs do not promise upstream OS runtime artifacts", () => {
  const forbidden = [
    /a released Rust `redevplugin-runtime` binary/i,
    /selects and bundles a released `redevplugin-runtime` binary/i,
    /signed `redevplugin-runtime` binaries for supported targets/i,
    /Tagged GitHub Releases publish:\s*\n\s*- runtime `\.tar\.gz` bundles/i,
  ];

  for (const [label, source] of Object.entries(documents)) {
    for (const pattern of forbidden) {
      assert.doesNotMatch(source, pattern, `${label} retains an upstream runtime artifact promise`);
    }
  }
});

test("release docs reserve OS artifacts for host products", () => {
  assert.match(
    documents.release,
    /ReDevPlugin GitHub Releases do not contain OS runtime binaries,\s+runtime archives,\s+installers,\s+or product signatures/i,
  );
  assert.match(
    documents.release,
    /host product owns the resulting binary,\s+SBOM,\s+provenance,\s+signature,\s+installer,\s+and product archive/i,
  );
});
