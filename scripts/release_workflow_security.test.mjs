import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parse } from "yaml";

const workflow = parse(readFileSync(".github/workflows/release.yml", "utf8"));

test("privileged release jobs never checkout or execute candidate repository scripts", () => {
  const privileged = ["publish-rust", "publish-npm-contracts", "publish-npm-ui", "attest-publication", "publish-release"];
  for (const jobName of privileged) {
    const job = workflow.jobs?.[jobName];
    assert.ok(job, `missing privileged job ${jobName}`);
    const steps = Array.isArray(job.steps) ? job.steps : [];
    assert.equal(steps.some((step) => typeof step.uses === "string" && step.uses.startsWith("actions/checkout@")), false, `${jobName} must not checkout candidate source`);
    for (const step of steps) {
      if (typeof step.run !== "string") continue;
      assert.doesNotMatch(step.run, /^\s*(?:(?:node|npm|cargo|go|bash)\s+|\.\/scripts\/)[^\n]*(?:scripts\/|Cargo\.toml|go\.mod|package\.json)/m, `${jobName} executes candidate repository code`);
    }
  }
});

test("Rust publication is artifact-only and has no repository write permission", () => {
  const job = workflow.jobs["publish-rust"];
  assert.deepEqual(job.permissions, { contents: "read", "id-token": "write" });
  const steps = job.steps;
  assert.ok(steps.some((step) => step.uses?.startsWith("actions/download-artifact@")));
  assert.ok(steps.some((step) => step.uses?.startsWith("rust-lang/crates-io-auth-action@")));
  const source = steps.map((step) => step.run ?? "").join("\n");
  assert.doesNotMatch(source, /cargo\s+publish/);
  assert.doesNotMatch(source, /node\s+scripts\//);
  assert.match(source, /api\/v1\/crates\/new/);
  assert.match(source, /method="PUT"/);
  assert.match(source, /"Authorization": token/);
  assert.doesNotMatch(source, /Bearer \{token\}/);
  assert.match(source, /explicit_name_in_toml/);
  assert.match(source, /readme_file/);
  assert.match(source, /struct\.pack\("<I", len\(metadata_bytes\)\)/);
  assert.match(source, /struct\.pack\("<I", len\(crate_bytes\)\)/);
  assert.match(source, /"Content-Type": "application\/octet-stream"/);
  assert.match(source, /"Accept": "application\/json"/);
});

test("inline privileged Python is syntactically valid", () => {
  for (const jobName of ["publish-rust", "publish-npm-contracts", "publish-npm-ui", "attest-publication", "publish-release"]) {
    for (const step of workflow.jobs[jobName].steps) {
      if (typeof step.run !== "string") continue;
      for (const match of step.run.matchAll(/<<'PY'\n([\s\S]*?)\nPY(?:\n|$)/g)) {
        const result = spawnSync("python3", ["-c", "import sys; compile(sys.stdin.read(), '<workflow>', 'exec')"], {
          input: match[1],
          encoding: "utf8",
        });
        assert.equal(result.status, 0, `${jobName} inline Python syntax: ${result.stderr}`);
      }
    }
  }
});

test("GitHub release publication keeps the exact-one asset contract", () => {
  const source = readFileSync(".github/workflows/release.yml", "utf8");
  assert.match(source, /name=platform-package-publication-v1\.json/);
  assert.match(source, /--jq length\)\" = 1/);
  assert.match(source, /content_type.*CONTENT_TYPE/);
});
