import assert from "node:assert/strict";
import test from "node:test";

import { verifyQuickCIEvidence } from "./verify_quick_ci_evidence.mjs";

const sha = "0123456789abcdef0123456789abcdef01234567";

function run(overrides = {}) {
  let request;
  const workflowRun = {
    id: 42,
    head_sha: sha,
    head_branch: "main",
    event: "push",
    path: ".github/workflows/ci.yml",
    status: "completed",
    conclusion: "success",
    html_url: "https://github.com/floegence/redevplugin/actions/runs/42",
    ...overrides.run,
  };
  const fetchImpl = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ workflow_runs: overrides.runs ?? [workflowRun] }), {
      status: overrides.status ?? 200,
    });
  };
  return {
    request: () => request,
    result: verifyQuickCIEvidence({ repository: "floegence/redevplugin", sha, token: "test-token", fetchImpl }),
  };
}

test("accepts one successful exact-SHA main push Quick CI run", async () => {
  const invocation = run();
  assert.deepEqual(await invocation.result, {
    run_id: 42,
    url: "https://github.com/floegence/redevplugin/actions/runs/42",
    source_sha: sha,
  });
  const request = invocation.request();
  assert.equal(request.url.searchParams.get("branch"), "main");
  assert.equal(request.url.searchParams.get("event"), "push");
  assert.equal(request.url.searchParams.get("head_sha"), sha);
  assert.equal(request.options.headers.authorization, "Bearer test-token");
});

for (const [name, overrides, message] of [
  ["missing", { runs: [] }, "found 0"],
  ["in progress", { run: { status: "in_progress", conclusion: null } }, "in_progress/unknown"],
  ["failed", { run: { status: "completed", conclusion: "failure" } }, "completed/failure"],
  ["wrong SHA", { run: { head_sha: "f".repeat(40) } }, "found 0"],
  ["manual dispatch", { run: { event: "workflow_dispatch" } }, "found 0"],
]) {
  test(`rejects ${name} Quick CI evidence`, async () => {
    await assert.rejects(run(overrides).result, new RegExp(message));
  });
}

test("rejects ambiguous duplicate successful runs", async () => {
  const first = {
    id: 1,
    head_sha: sha,
    head_branch: "main",
    event: "push",
    path: ".github/workflows/ci.yml",
    status: "completed",
    conclusion: "success",
  };
  await assert.rejects(run({ runs: [first, { ...first, id: 2 }] }).result, /found 2/);
});

test("fails closed on an unavailable GitHub API", async () => {
  await assert.rejects(run({ status: 503 }).result, /HTTP 503/);
});
