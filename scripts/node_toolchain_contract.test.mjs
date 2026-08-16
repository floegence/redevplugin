import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const nodeVersion = "26.7.0";
const nodeEngine = ">=26.0.0 <27";

function source(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

test("the repository root owns the exact Node toolchain contract", () => {
  assert.equal(source(".node-version"), `${nodeVersion}\n`);

  const manifest = JSON.parse(source("package.json"));
  const lock = JSON.parse(source("package-lock.json"));
  assert.equal(manifest.engines?.node, nodeEngine);
  assert.equal(lock.packages?.[""]?.engines?.node, nodeEngine);
});

test("every GitHub Node setup reads the repository authority", () => {
  for (const path of [".github/workflows/ci.yml", ".github/workflows/release.yml"]) {
    const workflow = source(path);
    const setupLines = [...workflow.matchAll(/^(\s*)- uses: actions\/setup-node@[^\n]+$/gm)];
    assert.ok(setupLines.length > 0, `${path} has no Node setup`);
    for (const setup of setupLines) {
      const start = setup.index;
      const remainder = workflow.slice(start + setup[0].length + 1);
      const nextStep = remainder.search(new RegExp(`^${setup[1]}- `, "m"));
      const block = workflow.slice(start, nextStep < 0 ? workflow.length : start + setup[0].length + 1 + nextStep);
      assert.doesNotMatch(block, /^\s+node-version:\s/m, `${path} hard-codes Node`);
      assert.match(block, /^\s+node-version-file:\s/m, `${path} omits node-version-file`);
    }
  }
});

test("local gates and author scaffolds name the Node 26 authority", () => {
  const gate = source("scripts/check_redevplugin_pre_push.sh");
  assert.match(gate, /\.node-version/);
  assert.match(gate, /Node\.js \$\{REQUIRED_NODE_VERSION\} is required/);
  assert.doesNotMatch(gate, /Node\.js 24|!= "24"/);

  const scaffold = source("cmd/redevplugin/main.go");
  assert.match(scaffold, /Requirements: Node\.js 26, npm, Rust/);
  assert.doesNotMatch(scaffold, /Node\.js 24/);
});

test("first-party performance fixtures describe the selected Node 26 runtime", () => {
  for (const path of [
    "scripts/performance_contract.test.mjs",
    "pkg/protocol/performance_evidence_schema_test.go",
  ]) {
    const contents = source(path);
    assert.match(contents, /node_version[^\n]*v26\.7\.0/);
    assert.doesNotMatch(contents, /node_version[^\n]*v24/);
  }
});

test("public browser packages do not claim a Node runtime requirement", () => {
  for (const path of [
    "packages/redevplugin-contracts/package.json",
    "packages/redevplugin-ui/package.json",
  ]) {
    assert.equal(JSON.parse(source(path)).engines?.node, undefined, path);
  }
});

test("repository guidance names .node-version as the Node authority", () => {
  const guide = source("AGENTS.md");
  assert.match(guide, /`\.node-version` is the single source of truth for the first-party Node\.js toolchain/);
});
