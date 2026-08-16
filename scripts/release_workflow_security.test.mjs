import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parse } from "yaml";

const workflow = parse(readFileSync(".github/workflows/release.yml", "utf8"));
const quickCIEvidenceVerifier = readFileSync("scripts/verify_quick_ci_evidence.mjs", "utf8");

test("privileged release jobs never checkout or execute candidate repository scripts", () => {
  const privileged = ["release-admission", "publish-rust", "publish-npm-contracts", "publish-npm-ui", "attest-publication", "publish-release"];
  for (const jobName of privileged) {
    const job = workflow.jobs?.[jobName];
    if (!job) continue;
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
  assert.doesNotMatch(source, /spec\/plugin\/platform-package-set-v3\.json/);
});

test("standard release submits each missing crate at most once and only polls afterward", () => {
  const source = workflow.jobs["publish-rust"].steps.find(
    (step) => step.name === "Publish exact crate graph in dependency order",
  ).run;
  assert.match(source, /for attempt in range\(20\):/);
  assert.match(source, /if remote is not None:\n\s+raise SystemExit\(f"\{name\}@\{version\} already exists with different bytes"\)/);
  assert.match(source, /if submitted:\n\s+time\.sleep\(6\)\n\s+continue/);
  const submitted = source.indexOf("submitted = True");
  const request = source.indexOf('"https://crates.io/api/v1/crates/new"');
  const upload = source.indexOf("urllib.request.urlopen(request, timeout=60)");
  assert.ok(request >= 0 && request < submitted && submitted < upload);
  assert.equal(source.match(/method="PUT"/g)?.length, 1);
  assert.equal(source.match(/submitted = True/g)?.length, 1);
});

test("standard release binds the immutable package verifier to the release source", () => {
  const normalStep = workflow.jobs["publish-rust"].steps.find(
    (step) => step.name === "Verify immutable package artifact",
  );
  assert.ok(normalStep, "normal Rust publication must verify the complete package artifact");
  assert.equal(normalStep.env.SOURCE_COMMIT, "${{ github.sha }}");
  assert.equal(normalStep.env.VERSION, "${{ needs.preflight.outputs.version }}");
});

test("privileged Rust verifiers pin a tomllib-capable Python", () => {
  const steps = workflow.jobs["publish-rust"].steps;
  const setupIndex = steps.findIndex((step) => step.uses?.startsWith("actions/setup-python@"));
  const verifyIndex = steps.findIndex((step) => step.name === "Verify immutable package artifact");
  assert.ok(setupIndex >= 0 && setupIndex < verifyIndex);
  assert.equal(steps[setupIndex].uses, "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1");
  assert.equal(steps[setupIndex].with["python-version"], "3.13");
});

test("Rust artifact verification binds a closed metadata set independently of publish order", () => {
  const packageSet = JSON.parse(readFileSync("spec/plugin/platform-package-set-v3.json", "utf8"));
  const expected = packageSet.rust_crates.map(({ name }) => name).sort();
  const source = workflow.jobs["publish-rust"].steps.find(
    (step) => step.name === "Verify immutable package artifact",
  ).run;
  assert.match(source, /len\(metadata\["packages"\]\) != len\(expected_rust\)/);
  assert.match(source, /\{item\.get\("name"\) for item in metadata\["packages"\]\} != expected_rust/);
  for (const name of expected) assert.match(source, new RegExp(`expected_rust[\\s\\S]*${name}`));

  const publishSource = workflow.jobs["publish-rust"].steps.find(
    (step) => step.name === "Publish exact crate graph in dependency order",
  ).run;
  assert.match(publishSource, /order = \["redevplugin-runtime", "redevplugin-worker-sdk"\]/);
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

test("standard publication uses one resumable release transaction", () => {
  const source = workflow.jobs["publish-release"].steps.map((step) => step.run ?? "").join("\n");
  const syntax = spawnSync("bash", ["-n"], { input: source, encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(source, /redevplugin-release-transaction-v1 source_commit=/);
  assert.match(source, /git\/ref\/tags\/\$TAG/);
  assert.match(source, /git\/tags\/\$object_sha/);
  assert.match(source, /test "\$object_sha" = "\$SOURCE_COMMIT"/);
  assert.doesNotMatch(source, /\.target_commitish == \$source/);
  assert.match(source, /gh api --paginate --slurp/);
  assert.match(source, /normalize_duplicate_releases/);
  assert.match(source, /validate_empty_bound_draft/);
  assert.match(source, /validate_exact_bound_public/);
  assert.match(source, /release lookup found non-reconcilable exact-tag duplicates/);
  assert.match(source, /test "\$\(jq length "\$assets_json"\)" = 0/);
  assert.match(source, /\.draft \| type == "boolean"/);
  assert.match(source, /ensure_draft_asset/);
  assert.match(source, /exact_asset_matches/);
  assert.match(source, /cmp -s "\$manifest" "\$downloaded"/);
  assert.match(source, /reconcile_public/);
  assert.match(source, /name=platform-package-publication-v2\.json/);
  assert.match(source, /length == 1/);
  assert.match(source, /\.\[0\]\.content_type == \$content_type/);
  assert.match(source, /\.\[0\]\.state == "uploaded"/);
  assert.match(source, /jq -r '\.\[0\]\.url'.*\)\" = \"\$asset_url\"/);
  assert.match(source, /test "\$upload_url" = "https:\/\/uploads\.github\.com\/repos\/\$\{GITHUB_REPOSITORY\}\/releases\/\$\{release_id\}\/assets"/);
  assert.match(source, /\{draft: false, make_latest: "true"\}/);
  assert.match(source, /-X DELETE[\s\S]*releases\/assets\/\$asset_id/);
  assert.match(source, /-X DELETE[\s\S]{0,500}releases\/\$duplicate_id/);
  assert.doesNotMatch(source, /-X DELETE[\s\S]{0,500}releases\/\$release_id/);

  const control = source.slice(source.lastIndexOf("for attempt in 1 2 3 4; do"));
  const ordered = [
    "lookup_release || lookup_status=$?",
    "create_draft",
    "ensure_draft_asset",
    "jq -n '{draft: false, make_latest: \"true\"}'",
    "-X PATCH",
    "if reconcile_public; then",
  ].map((token) => control.indexOf(token));
  assert.ok(ordered.every((index) => index >= 0));
  assert.deepEqual([...ordered].sort((left, right) => left - right), ordered);

  const normalAdmission = workflow.jobs["release-admission"];
  assert.deepEqual(normalAdmission.permissions, { contents: "write" });
  assert.equal(normalAdmission.environment, "release");
  assert.equal(normalAdmission.steps[0].env.ALLOW_PUBLIC, "false");
  assert.match(normalAdmission.steps[0].run, /gh api --paginate --slurp/);
  assert.match(normalAdmission.steps[0].run, /normalize_duplicate_releases/);
  assert.match(normalAdmission.steps[0].run, /validate_empty_bound_draft/);
  assert.match(normalAdmission.steps[0].run, /release admission found non-reconcilable exact-tag duplicates/);
  assert.match(normalAdmission.steps[0].run, /\.draft == true/);
  assert.match(normalAdmission.steps[0].run, /type == "array" and length == 0/);
  assert.match(normalAdmission.steps[0].run, /gh api --method DELETE[\s\S]{0,200}releases\/\$\{duplicate_id\}/);
  assert.doesNotMatch(normalAdmission.steps[0].run, /gh api --method DELETE[\s\S]{0,200}releases\/\$\{release_id\}/);
  assert.match(normalAdmission.steps[0].run, /normal release admission refuses an existing public Release/);
  for (const jobName of ["publish-rust", "publish-npm-contracts", "publish-npm-ui", "attest-publication", "publish-release"]) {
    assert.ok(workflow.jobs[jobName].needs.includes("release-admission"), `${jobName} must wait for release admission`);
  }
});

test("final public verification can read the completion attestation", () => {
  assert.deepEqual(workflow.jobs["verify-release"].permissions, {
    attestations: "read",
    contents: "read",
  });
});

test("release readback jobs install their required runtime and output directories", () => {
  const rustSteps = workflow.jobs["verify-rust"].steps;
  assert.ok(rustSteps.some((step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version-file"] === ".node-version"));
  assert.ok(rustSteps.some((step) => step.run === "npm ci"));
  const goSource = workflow.jobs["verify-go"].steps.map((step) => step.run ?? "").join("\n");
  assert.match(goSource, /mkdir -p dist/);
  const publicationSteps = workflow.jobs["create-publication"].steps;
  assert.ok(publicationSteps.some((step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version-file"] === ".node-version"));
  assert.ok(publicationSteps.some((step) => step.run === "npm ci"));
  const releaseSteps = workflow.jobs["verify-release"].steps;
  assert.ok(releaseSteps.some((step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["node-version-file"] === ".node-version"));
  assert.ok(releaseSteps.some((step) => step.run === "npm ci"));
});

test("privileged npm publication reads the package-build Node authority before setup", () => {
  const packageBuildSource = workflow.jobs["package-build"].steps.map((step) => step.run ?? "").join("\n");
  assert.match(packageBuildSource, /install -m 0644 \.node-version dist\/platform-packages\/\.node-version/);
  for (const jobName of ["publish-npm-contracts", "publish-npm-ui"]) {
    const steps = workflow.jobs[jobName].steps;
    const downloadIndex = steps.findIndex((step) => step.uses?.startsWith("actions/download-artifact@"));
    const setupIndex = steps.findIndex((step) => step.uses?.startsWith("actions/setup-node@"));
    assert.ok(downloadIndex >= 0 && downloadIndex < setupIndex, `${jobName} must download the authority before setup-node`);
    assert.equal(steps[setupIndex].with["node-version-file"], "dist/platform-packages/.node-version");
  }
});

test("npm readbacks delegate bounded retry classification to the verifier", () => {
  for (const [document, jobName] of [
    [workflow, "verify-npm-contracts"],
    [workflow, "verify-npm"],
  ]) {
    const source = document.jobs[jobName].steps.map((step) => step.run ?? "").join("\n");
    assert.match(source, /node scripts\/verify_npm_registry_release\.mjs/, `${jobName} must use the typed verifier`);
    assert.doesNotMatch(source, /for attempt in \$\(seq 1 20\)/, `${jobName} must not retry unclassified verifier failures`);
  }
});

test("release preflight binds the tag to the exact remote main tip", () => {
  assert.deepEqual(workflow.jobs.preflight.permissions, { actions: "read", contents: "read" });
  const source = workflow.jobs.preflight.steps.map((step) => step.run ?? "").join("\n");
  assert.match(source, /test "\$GITHUB_SHA" = "\$\(git rev-parse origin\/main\)"/);
  assert.doesNotMatch(source, /merge-base --is-ancestor "\$GITHUB_SHA" origin\/main/);
  assert.match(source, /verify_quick_ci_evidence\.mjs --repository "\$GITHUB_REPOSITORY" --sha "\$GITHUB_SHA"/);
  assert.ok(
    source.indexOf("verify_quick_ci_evidence.mjs") > source.indexOf("git rev-parse origin/main"),
    "Quick CI evidence must be checked only after the exact main tip is established",
  );
});

test("release preflight uses a strict bounded Quick CI fallback evidence path", () => {
  assert.match(quickCIEvidenceVerifier, /query\("push"\)/);
  assert.match(quickCIEvidenceVerifier, /query\("workflow_dispatch"\)/);
  assert.match(quickCIEvidenceVerifier, /if \(pushRuns\.length !== 0\) return acceptExactlyOne\(pushRuns, "push"\)/);
  assert.match(quickCIEvidenceVerifier, /run\.head_sha === cleanSHA/);
  assert.match(quickCIEvidenceVerifier, /run\.head_branch === "main"/);
  assert.match(quickCIEvidenceVerifier, /run\.path === workflowPath/);
  assert.match(quickCIEvidenceVerifier, /run\.status !== "completed" \|\| run\.conclusion !== "success"/);
  assert.doesNotMatch(quickCIEvidenceVerifier, /latest successful|most recent|sort.*created_at/i);
});

test("release package build requires both hosted runtime containment targets", () => {
  const containment = workflow.jobs["runtime-containment"];
  assert.deepEqual(containment.strategy.matrix.include, [
    { runner: "ubuntu-24.04", arch: "amd64" },
    { runner: "ubuntu-24.04-arm", arch: "arm64" },
  ]);
  assert.ok(containment.steps.some((step) =>
    step.run?.includes("TestContainedRuntimeProcessExecutesSealedRuntimeAndValidatesAcknowledgement")));
  assert.ok(workflow.jobs["package-build"].needs.includes("runtime-containment"));
});

test("standard release names only the two public Rust source crates", () => {
  const packageBuild = workflow.jobs["package-build"].steps
    .find((step) => step.name?.startsWith("Build and verify"));
  assert.equal(packageBuild.name, "Build and verify two npm packages and two source crates");
  const workflowSource = readFileSync(".github/workflows/release.yml", "utf8");
  for (const retired of ["redevplugin-ipc", "redevplugin-wasm-abi", "redevplugin-target-classifier"]) {
    assert.doesNotMatch(workflowSource, new RegExp(`(?:order|package|crate|name)[^\\n]{0,120}${retired}`));
  }
});
