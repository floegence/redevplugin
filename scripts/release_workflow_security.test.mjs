import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parse } from "yaml";

const workflow = parse(readFileSync(".github/workflows/release.yml", "utf8"));
const recovery = parse(readFileSync(".github/workflows/recover-release.yml", "utf8"));

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

test("artifact downloads expose files at the declared release paths", () => {
  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    const downloads = (job.steps ?? []).filter(
      (step) => step.uses?.startsWith("actions/download-artifact@") && step.with?.["artifact-ids"] !== undefined,
    );
    for (const step of downloads) {
      assert.equal(step.with["merge-multiple"], true, `${jobName} must flatten downloaded artifacts`);
    }
  }
});

test("npm publication jobs pin a trusted-publishing capable npm", () => {
  for (const jobName of ["publish-npm-contracts", "publish-npm-ui"]) {
    const source = (workflow.jobs[jobName].steps ?? []).map((step) => step.run ?? "").join("\n");
    assert.match(source, /npm i -g npm@11\.18\.0/, `${jobName} must pin npm trusted publishing support`);
  }
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

test("inline recovery Python is syntactically valid", () => {
  for (const step of recovery.jobs.preflight.steps) {
    if (typeof step.run !== "string") continue;
    for (const match of step.run.matchAll(/<<'PY'\n([\s\S]*?)\nPY(?:\n|$)/g)) {
      const result = spawnSync("python3", ["-c", "import sys; compile(sys.stdin.read(), '<workflow>', 'exec')"], {
        input: match[1],
        encoding: "utf8",
      });
      assert.equal(result.status, 0, `recovery inline Python syntax: ${result.stderr}`);
    }
  }
});

test("GitHub release publication keeps the exact-one asset contract", () => {
  const source = readFileSync(".github/workflows/release.yml", "utf8");
  assert.match(source, /name=platform-package-publication-v1\.json/);
  assert.match(source, /--jq length\)\" = 1/);
  assert.match(source, /content_type.*CONTENT_TYPE/);
});

test("release readback jobs install their required runtime and output directories", () => {
  const rustSteps = workflow.jobs["verify-rust"].steps;
  assert.ok(rustSteps.some((step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version"] === 24));
  assert.ok(rustSteps.some((step) => step.run === "npm ci"));
  const goSource = workflow.jobs["verify-go"].steps.map((step) => step.run ?? "").join("\n");
  assert.match(goSource, /mkdir -p dist/);
  const releaseSteps = workflow.jobs["verify-release"].steps;
  assert.ok(releaseSteps.some((step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version"] === 24));
  assert.ok(releaseSteps.some((step) => step.run === "npm ci"));
});

test("manual recovery binds one failed release run and its immutable package artifact", () => {
  assert.ok(recovery.on?.workflow_dispatch?.inputs?.tag?.required);
  assert.ok(recovery.on?.workflow_dispatch?.inputs?.release_run_id?.required);
  assert.deepEqual(recovery.jobs.preflight.permissions, { actions: "read", contents: "read" });
  const source = recovery.jobs.preflight.steps.map((step) => step.run ?? "").join("\n");
  assert.match(source, /GITHUB_REF.*refs\/heads\/main/);
  assert.match(source, /git merge-base --is-ancestor.*origin\/main/);
  assert.match(source, /"event": "push"/);
  assert.match(source, /"path": "\.github\/workflows\/release\.yml"/);
  assert.match(source, /"conclusion": "failure"/);
  assert.match(source, /platform-packages-\{source_commit\}/);
  assert.match(source, /len\(matches\) != 1/);
  assert.match(source, /assert_github_release_absent\.sh/);

  const download = recovery.jobs["reconstruct-publication"].steps.find(
    (step) => step.uses?.startsWith("actions/download-artifact@") && step.with?.["run-id"] !== undefined,
  );
  assert.ok(download);
  assert.equal(download.with["artifact-ids"], "${{ needs.preflight.outputs.package-artifact-id }}");
  assert.equal(download.with["run-id"], "${{ inputs.release_run_id }}");
  assert.equal(download.with["merge-multiple"], true);
  const artifactSource = recovery.jobs["reconstruct-publication"].steps
    .find((step) => step.name === "Verify original immutable package artifact").run;
  assert.match(artifactSource, /manifest\.platform_version !== process\.env\.VERSION/);
  assert.match(artifactSource, /manifest\.source_commit !== process\.env\.SOURCE_COMMIT/);
});

test("manual recovery separates untrusted readback from privileged publication", () => {
  assert.deepEqual(recovery.jobs["reconstruct-publication"].permissions, { actions: "read", contents: "read" });
  for (const jobName of ["attest-publication", "publish-release"]) {
    const job = recovery.jobs[jobName];
    assert.equal(job.environment, "release");
    assert.equal(job.steps.some((step) => step.uses?.startsWith("actions/checkout@")), false);
    for (const step of job.steps) {
      assert.doesNotMatch(step.run ?? "", /node scripts\/|\.\/scripts\//, `${jobName} executes repository scripts`);
    }
  }
  const publishSource = recovery.jobs["publish-release"].steps.map((step) => step.run ?? "").join("\n");
  assert.match(publishSource, /--draft/);
  assert.match(publishSource, /trap cleanup EXIT/);
  assert.match(publishSource, /name=platform-package-publication-v1\.json/);
  assert.match(publishSource, /content_type.*CONTENT_TYPE/);
  assert.match(publishSource, /-F draft=false/);
});
