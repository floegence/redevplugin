import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const jobsSource = workflow.slice(workflow.indexOf("\njobs:\n") + "\njobs:\n".length);

test("ordinary GitHub CI stays bounded and delegates only to the quick gate", () => {
  assert.match(workflow, /^name: Quick CI$/m);
  assert.match(workflow, /^\s{4}name: Quick CI$/m);
  assert.match(workflow, /^\s{4}timeout-minutes: 5$/m);
  assert.match(workflow, /\.\/scripts\/check_redevplugin_quick_ci\.sh/);
  assert.deepEqual(
    [...jobsSource.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map((match) => match[1]),
    ["quick-ci"],
  );
  assert.deepEqual(
    [...workflow.matchAll(/^\s+- run: (.+)$/gm)].map((match) => match[1]),
    ["./scripts/check_redevplugin_quick_ci.sh"],
  );

  for (const forbidden of [
    "check_redevplugin_pre_push",
    "playwright",
    "docker",
    "cargo test",
    "go test",
    "npm ci",
    "performance",
    "stress",
  ]) {
    assert.doesNotMatch(workflow, new RegExp(forbidden, "i"));
  }
});

test("quick gate checks the committed tree instead of trusting a clean checkout", () => {
  const gate = readFileSync(new URL("./check_redevplugin_quick_ci.sh", import.meta.url), "utf8");
  assert.match(gate, /\.\/scripts\/check_redevplugin_tree_whitespace\.sh/);
});

test("tree whitespace gate catches an error retained from an earlier pushed commit", () => {
  const root = mkdtempSync(path.join(tmpdir(), "redevplugin-quick-ci-whitespace-"));
  const gate = fileURLToPath(new URL("./check_redevplugin_tree_whitespace.sh", import.meta.url));
  const git = (...args) => spawnSync("git", args, { cwd: root, encoding: "utf8" });
  try {
    assert.equal(git("init", "--quiet").status, 0);
    assert.equal(git("config", "user.name", "Quick CI Test").status, 0);
    assert.equal(git("config", "user.email", "quick-ci@example.invalid").status, 0);
    writeFileSync(path.join(root, "bad.txt"), "retained whitespace   \n");
    assert.equal(git("add", "bad.txt").status, 0);
    assert.equal(git("commit", "--quiet", "-m", "bad first commit").status, 0);
    writeFileSync(path.join(root, "later.txt"), "clean\n");
    assert.equal(git("add", "later.txt").status, 0);
    assert.equal(git("commit", "--quiet", "-m", "clean later commit").status, 0);

    const result = spawnSync(gate, [root], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /bad\.txt:1: trailing whitespace/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("complex scheduled CI is not retained outside the main pre-push gate", () => {
  assert.throws(
    () => readFileSync(new URL("../.github/workflows/stress.yml", import.meta.url), "utf8"),
    { code: "ENOENT" },
  );
});
