#!/usr/bin/env node

import { fileURLToPath } from "node:url";

const maximumResponseBytes = 2 * 1024 * 1024;
const repositoryPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const shaPattern = /^[0-9a-f]{40}$/;

function required(value, label) {
  const clean = String(value ?? "").trim();
  if (!clean) throw new Error(`${label} is required`);
  return clean;
}

export async function verifyQuickCIEvidence({ repository, sha, token, fetchImpl = globalThis.fetch }) {
  const cleanRepository = required(repository, "repository");
  const cleanSHA = required(sha, "source SHA");
  const cleanToken = required(token, "GitHub token");
  if (!repositoryPattern.test(cleanRepository)) throw new Error("repository is invalid");
  if (!shaPattern.test(cleanSHA)) throw new Error("source SHA is invalid");
  if (typeof fetchImpl !== "function") throw new Error("fetch implementation is required");

  const workflowPath = ".github/workflows/ci.yml";
  const headers = {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${cleanToken}`,
    "user-agent": "redevplugin-release-preflight",
    "x-github-api-version": "2022-11-28",
  };

  async function query(event) {
    const url = new URL(`https://api.github.com/repos/${cleanRepository}/actions/workflows/ci.yml/runs`);
    url.searchParams.set("branch", "main");
    url.searchParams.set("event", event);
    url.searchParams.set("head_sha", cleanSHA);
    url.searchParams.set("per_page", "100");
    const response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(15_000) });
    const raw = await response.text();
    if (!response.ok) throw new Error(`Quick CI evidence request failed with HTTP ${response.status}`);
    if (raw.length > maximumResponseBytes) throw new Error("Quick CI evidence response exceeds its size limit");

    let payload;
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new Error("Quick CI evidence response is invalid JSON");
    }
    if (!payload || !Array.isArray(payload.workflow_runs)) {
      throw new Error("Quick CI evidence response is missing workflow runs");
    }
    return payload.workflow_runs.filter((run) => (
      run
      && run.head_sha === cleanSHA
      && run.head_branch === "main"
      && run.event === event
      && run.path === workflowPath
    ));
  }

  function acceptExactlyOne(matches, event) {
    if (matches.length !== 1) {
      throw new Error(`expected exactly one Quick CI ${event} run for ${cleanSHA}, found ${matches.length}`);
    }
    const [run] = matches;
    if (run.status !== "completed" || run.conclusion !== "success") {
      throw new Error(`Quick CI run ${run.id ?? "unknown"} is ${run.status ?? "unknown"}/${run.conclusion ?? "unknown"}`);
    }
    return { run_id: run.id, url: run.html_url, source_sha: cleanSHA, event };
  }

  const pushRuns = await query("push");
  if (pushRuns.length !== 0) return acceptExactlyOne(pushRuns, "push");
  return acceptExactlyOne(await query("workflow_dispatch"), "workflow_dispatch");
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || value.startsWith("--") || values.has(key)) {
      throw new Error("usage: verify_quick_ci_evidence.mjs --repository <owner/repo> --sha <commit>");
    }
    values.set(key, value);
  }
  for (const key of values.keys()) {
    if (key !== "--repository" && key !== "--sha") {
      throw new Error("usage: verify_quick_ci_evidence.mjs --repository <owner/repo> --sha <commit>");
    }
  }
  return { repository: values.get("--repository"), sha: values.get("--sha") };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const args = parseArguments(process.argv.slice(2));
    const evidence = await verifyQuickCIEvidence({ ...args, token: process.env.GH_TOKEN });
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
