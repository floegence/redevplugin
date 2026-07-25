import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

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
  assert.match(gate, /git diff-tree --check --root -r --no-commit-id HEAD/);
});

test("complex scheduled CI is not retained outside the main pre-push gate", () => {
  assert.throws(
    () => readFileSync(new URL("../.github/workflows/stress.yml", import.meta.url), "utf8"),
    { code: "ENOENT" },
  );
});
