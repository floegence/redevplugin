import assert from "node:assert/strict";
import test from "node:test";

import { verifyQuickCIEvidence } from "./verify_quick_ci_evidence.mjs";

const sha = "0123456789abcdef0123456789abcdef01234567";

function workflowRun(event, overrides = {}) {
  return {
    id: event === "push" ? 42 : 84,
    head_sha: sha,
    head_branch: "main",
    event,
    path: ".github/workflows/ci.yml",
    status: "completed",
    conclusion: "success",
    html_url: `https://github.com/floegence/redevplugin/actions/runs/${event === "push" ? 42 : 84}`,
    ...overrides,
  };
}

function run(overrides = {}) {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    const event = url.searchParams.get("event");
    const response = overrides.responses?.[event] ?? {};
    const runs = response.runs ?? overrides[`${event}Runs`] ?? [workflowRun(event)];
    return new Response(JSON.stringify({ workflow_runs: runs }), {
      status: response.status ?? overrides.status ?? 200,
    });
  };
  return {
    requests,
    result: verifyQuickCIEvidence({ repository: "floegence/redevplugin", sha, token: "test-token", fetchImpl }),
  };
}

test("prefers one successful exact-SHA main push Quick CI run", async () => {
  const invocation = run();
  assert.deepEqual(await invocation.result, {
    run_id: 42,
    url: "https://github.com/floegence/redevplugin/actions/runs/42",
    source_sha: sha,
    event: "push",
  });
  assert.equal(invocation.requests.length, 1);
  const [{ url, options }] = invocation.requests;
  assert.equal(url.searchParams.get("branch"), "main");
  assert.equal(url.searchParams.get("event"), "push");
  assert.equal(url.searchParams.get("head_sha"), sha);
  assert.equal(options.headers.authorization, "Bearer test-token");
});

test("accepts one successful exact-SHA main workflow dispatch only when push evidence is absent", async () => {
  const invocation = run({ pushRuns: [], workflow_dispatchRuns: [workflowRun("workflow_dispatch")] });
  assert.deepEqual(await invocation.result, {
    run_id: 84,
    url: "https://github.com/floegence/redevplugin/actions/runs/84",
    source_sha: sha,
    event: "workflow_dispatch",
  });
  assert.deepEqual(invocation.requests.map(({ url }) => url.searchParams.get("event")), ["push", "workflow_dispatch"]);
  for (const { url } of invocation.requests) {
    assert.equal(url.searchParams.get("branch"), "main");
    assert.equal(url.searchParams.get("head_sha"), sha);
    assert.equal(url.pathname, "/repos/floegence/redevplugin/actions/workflows/ci.yml/runs");
  }
});

for (const [name, runValue, message] of [
  ["in progress", workflowRun("push", { status: "in_progress", conclusion: null }), "in_progress/unknown"],
  ["failed", workflowRun("push", { conclusion: "failure" }), "completed/failure"],
  ["cancelled", workflowRun("push", { conclusion: "cancelled" }), "completed/cancelled"],
]) {
  test(`rejects ${name} push evidence without falling back to manual dispatch`, async () => {
    const invocation = run({ pushRuns: [runValue], workflow_dispatchRuns: [workflowRun("workflow_dispatch")] });
    await assert.rejects(invocation.result, new RegExp(message));
    assert.deepEqual(invocation.requests.map(({ url }) => url.searchParams.get("event")), ["push"]);
  });
}

for (const [name, runValue] of [
  ["wrong SHA", workflowRun("workflow_dispatch", { head_sha: "f".repeat(40) })],
  ["wrong branch", workflowRun("workflow_dispatch", { head_branch: "release" })],
  ["pull request", workflowRun("pull_request")],
  ["scheduled", workflowRun("schedule")],
  ["wrong workflow", workflowRun("workflow_dispatch", { path: ".github/workflows/other.yml" })],
]) {
  test(`rejects ${name} workflow dispatch evidence`, async () => {
    await assert.rejects(run({ pushRuns: [], workflow_dispatchRuns: [runValue] }).result, /found 0/);
  });
}

for (const [name, overrides, message] of [
  ["missing", { pushRuns: [], workflow_dispatchRuns: [] }, "found 0"],
  ["in progress", { pushRuns: [], workflow_dispatchRuns: [workflowRun("workflow_dispatch", { status: "in_progress", conclusion: null })] }, "in_progress/unknown"],
  ["failed", { pushRuns: [], workflow_dispatchRuns: [workflowRun("workflow_dispatch", { conclusion: "failure" })] }, "completed/failure"],
  ["cancelled", { pushRuns: [], workflow_dispatchRuns: [workflowRun("workflow_dispatch", { conclusion: "cancelled" })] }, "completed/cancelled"],
]) {
  test(`rejects ${name} workflow dispatch evidence`, async () => {
    await assert.rejects(run(overrides).result, new RegExp(message));
  });
}

test("rejects ambiguous duplicate push runs without falling back", async () => {
  const invocation = run({ pushRuns: [workflowRun("push", { id: 1 }), workflowRun("push", { id: 2 })] });
  await assert.rejects(invocation.result, /found 2/);
  assert.deepEqual(invocation.requests.map(({ url }) => url.searchParams.get("event")), ["push"]);
});

test("rejects ambiguous duplicate workflow dispatch runs", async () => {
  await assert.rejects(run({
    pushRuns: [],
    workflow_dispatchRuns: [workflowRun("workflow_dispatch", { id: 1 }), workflowRun("workflow_dispatch", { id: 2 })],
  }).result, /found 2/);
});

test("fails closed on an unavailable GitHub API", async () => {
  await assert.rejects(run({ responses: { push: { status: 503, runs: [] } } }).result, /HTTP 503/);
});

test("fails closed when the bounded fallback request is unavailable", async () => {
  await assert.rejects(run({
    responses: {
      push: { runs: [] },
      workflow_dispatch: { status: 503, runs: [] },
    },
  }).result, /HTTP 503/);
});
