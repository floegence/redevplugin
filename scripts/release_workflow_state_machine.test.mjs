import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { parse } from "yaml";

const repositoryRoot = resolve(import.meta.dirname, "..");
const workflow = parse(readFileSync(join(repositoryRoot, ".github/workflows/release.yml"), "utf8"));
const recovery = parse(readFileSync(join(repositoryRoot, ".github/workflows/recover-release.yml"), "utf8"));
const publicationSource = workflow.jobs["publish-release"].steps.find((step) => step.run)?.run;
const recoverySource = recovery.jobs["publish-release"].steps.find((step) => step.run)?.run;
const admissionSource = workflow.jobs["release-admission"].steps.find((step) => step.run)?.run;
const recoveryAdmissionSource = recovery.jobs["release-admission"].steps.find((step) => step.run)?.run;
const preflightScript = join(repositoryRoot, "scripts/verify_github_release_reconciliation_candidate.sh");

const repository = "floegence/redevplugin";
const tag = "v0.6.24";
const sourceCommit = "1".repeat(40);
const otherCommit = "2".repeat(40);
const contentType = "application/vnd.floegence.redevplugin-platform-publication.v1+json";
const assetName = "platform-package-publication-v1.json";
const manifestBytes = Buffer.from('{"schema_version":1,"platform_version":"0.6.24"}\n');
const marker = `<!-- redevplugin-release-transaction-v1 source_commit=${sourceCommit} -->`;

assert.equal(publicationSource, recoverySource);
assert.equal(admissionSource, recoveryAdmissionSource);

const mockCommandSource = String.raw`#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";

const statePath = process.env.MOCK_GITHUB_STATE;
const command = basename(process.argv[1]);
const args = process.argv.slice(2);
const state = JSON.parse(readFileSync(statePath, "utf8"));

function save() {
  writeFileSync(statePath, JSON.stringify(state));
}

function record(event) {
  state.events.push(event);
  save();
}

function option(name) {
  const index = args.lastIndexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

function header(name) {
  const prefix = name.toLowerCase() + ":";
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] === "-H" && args[index + 1].toLowerCase().startsWith(prefix)) {
      return args[index + 1].slice(prefix.length).trim();
    }
  }
  return undefined;
}

function output(body, status = 200, failure = false) {
  const outputPath = option("-o");
  if (outputPath && outputPath !== "/dev/null") {
    writeFileSync(outputPath, body);
  } else if (!outputPath && body.length > 0) {
    process.stdout.write(body);
  }
  if (args.includes("-w")) process.stdout.write(String(status));
  save();
  process.exit(failure ? 1 : 0);
}

function releaseView(release) {
  return {
    ...release,
    upload_url: "https://uploads.github.com/repos/" + state.repository + "/releases/" + release.id + "/assets{?name,label}",
  };
}

function allReleases() {
  return [state.release, ...(state.extraReleases ?? [])].filter(Boolean);
}

function findRelease(id) {
  return allReleases().find((release) => release.id === id);
}

function assetsForRelease(id) {
  if (state.release?.id === id) return state.assets;
  return state.extraReleaseAssets?.[String(id)] ?? [];
}

if (command === "sleep") {
  const killPoint = state.release && state.assets.length === 0 && state.release.draft && state.killAfterCreate
    ? "create"
    : state.release && state.assets.length === 1 && !state.release.draft && state.killAfterPatch
        ? "patch"
        : null;
  if (killPoint && !state.killed) {
    state.killed = true;
    record("sigkill-after-" + killPoint);
    process.kill(Number(process.env.MOCK_WORKFLOW_PID), "SIGKILL");
  }
  process.exit(0);
}

if (command === "gh") {
  const endpoint = args.at(-1);
  if (endpoint.includes("/releases?per_page=100")) {
    const releases = allReleases().map(releaseView);
    record("list-releases");
    if (state.invalidReleasePages) output(Buffer.from("not-json"));
    output(Buffer.from(JSON.stringify([releases])));
  }
  const releaseMatch = endpoint.match(/\/releases\/(\d+)$/);
  if (releaseMatch && !args.includes("--method")) {
    const release = findRelease(Number(releaseMatch[1]));
    record("get-release-gh");
    if (!release) output(Buffer.from("{}"), 404, true);
    output(Buffer.from(JSON.stringify(releaseView(release))));
  }
  const releaseAssetsMatch = endpoint.match(/\/releases\/(\d+)\/assets\?per_page=100$/);
  if (releaseAssetsMatch) {
    const id = Number(releaseAssetsMatch[1]);
    record("list-assets-gh:" + id);
    if (!findRelease(id)) output(Buffer.from("[]"), 404, true);
    if (state.assetsUnavailable) output(Buffer.from(""), 503, true);
    if (state.invalidAssetsJson) output(Buffer.from("not-json"));
    output(Buffer.from(JSON.stringify(assetsForRelease(id).map(({ bytes, ...asset }) => asset))));
  }
  if (releaseMatch && args.includes("--method") && option("--method") === "DELETE") {
    const id = Number(releaseMatch[1]);
    if (state.release?.id === id) state.release = null;
    state.extraReleases = state.extraReleases.filter((release) => release.id !== id);
    delete state.extraReleaseAssets?.[String(id)];
    record("delete-release-gh:" + id);
    output(Buffer.from(""), 204, state.deleteReleaseResponseLost);
  }
  output(Buffer.from("{}"), 404, true);
}

if (command !== "curl") process.exit(127);

const url = [...args].reverse().find((value) => /^https:\/\//.test(value));
const method = option("-X") ?? "GET";
const apiPrefix = "https://api.github.com/repos/" + state.repository;

if (method === "GET" && url === apiPrefix + "/git/ref/tags/" + state.tag) {
  record("get-tag-ref");
  output(Buffer.from(JSON.stringify({ ref: "refs/tags/" + state.tag, object: state.tagRef })));
}

const tagObjectMatch = url?.match(/\/git\/tags\/([0-9a-f]{40})$/);
if (method === "GET" && tagObjectMatch) {
  const sha = tagObjectMatch[1];
  const object = state.tagObjects[sha];
  record("get-tag-object:" + sha);
  if (!object) output(Buffer.from("{}"), 404);
  output(Buffer.from(JSON.stringify({ sha, object })));
}

const releaseMatch = url?.match(/\/releases\/(\d+)$/);
if (method === "GET" && releaseMatch) {
  const release = findRelease(Number(releaseMatch[1]));
  record("get-release");
  if (!release) output(Buffer.from("{}"), 404);
  output(Buffer.from(JSON.stringify(releaseView(release))));
}

const curlReleaseAssetsMatch = url?.match(/\/releases\/(\d+)\/assets\?per_page=100$/);
if (method === "GET" && curlReleaseAssetsMatch) {
  const id = Number(curlReleaseAssetsMatch[1]);
  record("list-assets:" + id);
  if (!findRelease(id)) output(Buffer.from("[]"), 404);
  if (state.assetsUnavailable) output(Buffer.from(""), 503, true);
  if (state.invalidAssetsJson) output(Buffer.from("not-json"));
  output(Buffer.from(JSON.stringify(assetsForRelease(id).map(({ bytes, ...asset }) => asset))));
}

const assetMatch = url?.match(/\/releases\/assets\/(\d+)$/);
if (method === "GET" && assetMatch) {
  const asset = [...state.assets, ...Object.values(state.extraReleaseAssets ?? {}).flat()]
    .find(({ id }) => id === Number(assetMatch[1]));
  record("download-asset:" + assetMatch[1]);
  if (!asset) output(Buffer.from(""), 404);
  if (state.downloadUnavailable) output(Buffer.from(""), 503, true);
  output(Buffer.from(asset.bytes, "base64"));
}

if (method === "POST" && url === apiPrefix + "/releases") {
  const payloadPath = option("--data-binary").replace(/^@/, "");
  const payload = JSON.parse(readFileSync(payloadPath, "utf8"));
  if (!state.release) {
    state.release = {
      id: 101,
      tag_name: payload.tag_name,
      prerelease: payload.prerelease,
      draft: payload.draft,
      body: payload.body,
    };
  }
  record("create-release");
  output(Buffer.from(JSON.stringify(releaseView(state.release))), 201, state.createResponseLost);
}

if (method === "POST" && url?.startsWith("https://uploads.github.com/repos/" + state.repository + "/releases/")) {
  if (state.uploadBeforeMutation) {
    record("upload-rejected-before-mutation");
    output(Buffer.from(""), 503, true);
  }
  const payloadPath = option("--data-binary").replace(/^@/, "");
  const bytes = readFileSync(payloadPath);
  const id = state.nextAssetId++;
  state.assets.push({
    id,
    name: new URL(url).searchParams.get("name"),
    content_type: header("Content-Type"),
    state: "uploaded",
    size: bytes.length,
    url: apiPrefix + "/releases/assets/" + id,
    bytes: bytes.toString("base64"),
  });
  record("upload-asset");
  if (state.killAfterUpload && !state.killed) {
    state.killed = true;
    record("sigkill-after-upload");
    process.kill(Number(process.env.MOCK_WORKFLOW_PID), "SIGKILL");
  }
  output(Buffer.from("{}"), 201, state.uploadResponseLost);
}

if (method === "DELETE" && assetMatch) {
  const id = Number(assetMatch[1]);
  state.assets = state.assets.filter((asset) => asset.id !== id);
  record("delete-asset:" + id);
  output(Buffer.from(""), 204, state.deleteResponseLost);
}

if (method === "DELETE" && releaseMatch) {
  const id = Number(releaseMatch[1]);
  if (state.release?.id === id) state.release = null;
  state.extraReleases = state.extraReleases.filter((release) => release.id !== id);
  delete state.extraReleaseAssets?.[String(id)];
  record("delete-release:" + id);
  if (state.killAfterReleaseDelete && !state.killed) {
    state.killed = true;
    record("sigkill-after-release-delete");
    process.kill(Number(process.env.MOCK_WORKFLOW_PID), "SIGKILL");
  }
  output(Buffer.from(""), 204, state.deleteReleaseResponseLost);
}

if (method === "PATCH" && releaseMatch) {
  const release = findRelease(Number(releaseMatch[1]));
  if (!release) output(Buffer.from("{}"), 404);
  if (state.patchMode !== "unchanged") release.draft = false;
  record("publish-release");
  output(Buffer.from(JSON.stringify(releaseView(release))), 200, state.patchMode === "response-lost");
}

output(Buffer.from("{}"), 404, true);
`;

function tagState(depth = 0, finalCommit = sourceCommit) {
  if (depth === 0) return { tagRef: { type: "commit", sha: finalCommit }, tagObjects: {} };
  const shas = Array.from({ length: depth }, (_, index) => (index + 10).toString(16).padStart(40, "0"));
  const tagObjects = {};
  for (let index = 0; index < shas.length; index += 1) {
    tagObjects[shas[index]] = index === shas.length - 1
      ? { type: "commit", sha: finalCommit }
      : { type: "tag", sha: shas[index + 1] };
  }
  return { tagRef: { type: "tag", sha: shas[0] }, tagObjects };
}

function release(draft = true, body = marker, id = 101) {
  return { id, tag_name: tag, prerelease: false, draft, body };
}

function asset({
  id = 201,
  name = assetName,
  type = contentType,
  status = "uploaded",
  bytes = manifestBytes,
} = {}) {
  return {
    id,
    name,
    content_type: type,
    state: status,
    size: bytes.length,
    url: `https://api.github.com/repos/${repository}/releases/assets/${id}`,
    bytes: bytes.toString("base64"),
  };
}

function createFixture(overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-release-state-"));
  const bin = join(root, "bin");
  const runnerTemp = join(root, "runner-temp");
  mkdirSync(bin);
  mkdirSync(runnerTemp);
  mkdirSync(join(root, "dist/publication"), { recursive: true });
  writeFileSync(join(root, "dist/publication", assetName), manifestBytes);
  for (const command of ["gh", "curl", "sleep"]) {
    const path = join(bin, command);
    writeFileSync(path, mockCommandSource);
    chmodSync(path, 0o755);
  }
  const statePath = join(root, "state.json");
  const state = {
    repository,
    tag,
    release: null,
    extraReleases: [],
    extraReleaseAssets: {},
    assets: [],
    nextAssetId: 300,
    events: [],
    createResponseLost: false,
    uploadResponseLost: false,
    deleteResponseLost: false,
    deleteReleaseResponseLost: false,
    patchMode: "apply",
    killAfterCreate: false,
    killAfterUpload: false,
    killAfterPatch: false,
    killAfterReleaseDelete: false,
    killed: false,
    invalidReleasePages: false,
    invalidAssetsJson: false,
    assetsUnavailable: false,
    downloadUnavailable: false,
    uploadBeforeMutation: false,
    ...tagState(),
    ...overrides,
  };
  writeFileSync(statePath, JSON.stringify(state));
  return {
    root,
    statePath,
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      MOCK_GITHUB_STATE: statePath,
      RUNNER_TEMP: runnerTemp,
      GH_TOKEN: "test-token",
      GITHUB_API_URL: "https://api.github.com",
      GITHUB_REPOSITORY: repository,
      SOURCE_COMMIT: sourceCommit,
      TAG: tag,
      CONTENT_TYPE: contentType,
    },
    readState: () => JSON.parse(readFileSync(statePath, "utf8")),
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function executePublication(fixture) {
  return spawnSync("bash", ["-c", 'export MOCK_WORKFLOW_PID=$$; exec bash "$@"', "state-machine", "-c", publicationSource], {
    cwd: fixture.root,
    env: fixture.env,
    encoding: "utf8",
    timeout: 20_000,
  });
}

function assertPublished(fixture, result) {
  assert.equal(result.status, 0, result.stderr);
  const state = fixture.readState();
  assert.equal(state.release.draft, false);
  assert.equal(state.assets.length, 1);
  assert.equal(state.extraReleases.length, 0);
  assert.equal(Buffer.from(state.assets[0].bytes, "base64").compare(manifestBytes), 0);
  return state;
}

test("publication shell converges across interruption and response-loss fixtures", async (t) => {
  const cases = [
    ["fresh create", {}],
    ["exact orphan draft", { release: release(), assets: [asset()] }],
    ["create response lost", { createResponseLost: true }],
    ["upload response lost", { uploadResponseLost: true }],
    ["wrong draft asset", { release: release(), assets: [asset({ name: "wrong.json" })] }],
    ["multiple draft assets", { release: release(), assets: [asset({ id: 201 }), asset({ id: 202, name: "other.json" })] }],
    ["delete response lost", { release: release(), assets: [asset({ name: "wrong.json" })], deleteResponseLost: true }],
    ["publish response lost", { release: release(), assets: [asset()], patchMode: "response-lost" }],
    ["duplicate empty drafts", { release: release(), extraReleases: [release(true, marker, 102)] }],
    ["duplicate draft delete response lost", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      deleteReleaseResponseLost: true,
    }],
    ["three-level annotated tag", { ...tagState(3) }],
  ];
  for (const [name, overrides] of cases) {
    await t.test(name, () => {
      const fixture = createFixture(overrides);
      try {
        const state = assertPublished(fixture, executePublication(fixture));
        if (name.includes("asset") || name.includes("delete")) {
          assert.ok(state.events.some((event) => event.startsWith("delete-asset:") || event.startsWith("delete-release:")));
        }
      } finally {
        fixture.cleanup();
      }
    });
  }
});

test("duplicate draft deletion is adopted after SIGKILL", () => {
  const fixture = createFixture({
    release: release(),
    extraReleases: [release(true, marker, 102)],
    killAfterReleaseDelete: true,
  });
  try {
    const interrupted = executePublication(fixture);
    assert.equal(interrupted.signal, "SIGKILL");
    const state = assertPublished(fixture, executePublication(fixture));
    assert.equal(state.events.filter((event) => event === "delete-release:102").length, 1);
  } finally {
    fixture.cleanup();
  }
});

test("duplicate reconciliation deterministically retains the lowest release ID", () => {
  const fixture = createFixture({
    release: release(),
    extraReleases: [release(true, marker, 103), release(true, marker, 102)],
  });
  try {
    const state = assertPublished(fixture, executePublication(fixture));
    assert.deepEqual(
      state.events.filter((event) => event.startsWith("delete-release:")),
      ["delete-release:102", "delete-release:103"],
    );
  } finally {
    fixture.cleanup();
  }
});

test("durable state is adopted after SIGKILL at each mutation boundary", async (t) => {
  const cases = [
    ["create", { killAfterCreate: true }, 1, 1, 1],
    ["upload", { release: release(), killAfterUpload: true }, 0, 1, 1],
    ["patch", { release: release(), assets: [asset()], killAfterPatch: true }, 0, 0, 1],
  ];
  for (const [point, overrides, creates, uploads, patches] of cases) {
    await t.test(point, () => {
      const fixture = createFixture(overrides);
      try {
        const interrupted = executePublication(fixture);
        assert.equal(interrupted.signal, "SIGKILL");
        const state = assertPublished(fixture, executePublication(fixture));
        assert.equal(state.events.filter((event) => event === "create-release").length, creates);
        assert.equal(state.events.filter((event) => event === "upload-asset").length, uploads);
        assert.equal(state.events.filter((event) => event === "publish-release").length, patches);
      } finally {
        fixture.cleanup();
      }
    });
  }
});

test("publication shell fails closed without mutating authoritative public state", async (t) => {
  const wrongBytes = Buffer.from('{"schema_version":9,"platform_version":"0.6.24"}\n');
  const cases = [
    ["PATCH did not apply", { release: release(), assets: [asset()], patchMode: "unchanged" }],
    ["published wrong bytes", { release: release(false), assets: [asset({ bytes: wrongBytes })] }],
    ["published wrong metadata", { release: release(false), assets: [asset({ type: "application/json" })] }],
    ["published multiple assets", { release: release(false), assets: [asset(), asset({ id: 202 })] }],
    ["duplicate draft has assets", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      extraReleaseAssets: { "102": [asset({ id: 202 })] },
    }],
    ["duplicate includes public release", { release: release(), extraReleases: [release(false, marker, 102)] }],
    ["duplicate has wrong marker", { release: release(), extraReleases: [release(true, "unrelated", 102)] }],
    ["duplicate asset list invalid JSON", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      invalidAssetsJson: true,
    }],
    ["duplicate asset list unavailable", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      assetsUnavailable: true,
    }],
    ["wrong source commit", { ...tagState(0, otherCommit) }],
    ["annotated tag depth exceeded", { ...tagState(4) }],
  ];
  for (const [name, overrides] of cases) {
    await t.test(name, () => {
      const fixture = createFixture(overrides);
      try {
        const before = fixture.readState();
        const result = executePublication(fixture);
        assert.notEqual(result.status, 0, `fixture unexpectedly succeeded: ${name}`);
        const after = fixture.readState();
        if (before.release?.draft === false || name.includes("source") || name.includes("depth") || name.includes("duplicate")) {
          assert.equal(after.events.some((event) => event.startsWith("delete-asset:")
            || event.startsWith("delete-release:")
            || event === "upload-asset"
            || event === "publish-release"), false);
        }
        if (name === "PATCH did not apply") assert.equal(after.release.draft, true);
      } finally {
        fixture.cleanup();
      }
    });
  }
});

test("verification failures never mutate a bound draft", async (t) => {
  const cases = [
    ["asset download unavailable", { release: release(), assets: [asset()], downloadUnavailable: true }],
    ["asset list invalid JSON", { release: release(), assets: [asset()], invalidAssetsJson: true }],
    ["release list invalid JSON", { invalidReleasePages: true }],
    ["upload rejected before mutation", { release: release(), uploadBeforeMutation: true }],
  ];
  for (const [name, overrides] of cases) {
    await t.test(name, () => {
      const fixture = createFixture(overrides);
      try {
        const before = fixture.readState();
        const result = executePublication(fixture);
        assert.notEqual(result.status, 0, `fixture unexpectedly succeeded: ${name}`);
        const after = fixture.readState();
        assert.deepEqual(after.release, before.release);
        assert.deepEqual(after.assets, before.assets);
        assert.equal(after.events.some((event) => event.startsWith("delete-asset:")
          || event.startsWith("delete-release:")
          || event.startsWith("delete-release-gh:")
          || event === "upload-asset"
          || event === "publish-release"
          || event === "create-release"), false);
      } finally {
        fixture.cleanup();
      }
    });
  }

  await t.test("local manifest missing", () => {
    const fixture = createFixture({ release: release(), assets: [asset()] });
    try {
      rmSync(join(fixture.root, "dist/publication", assetName));
      const before = fixture.readState();
      const result = executePublication(fixture);
      assert.notEqual(result.status, 0);
      const after = fixture.readState();
      assert.deepEqual(after.release, before.release);
      assert.deepEqual(after.assets, before.assets);
      assert.deepEqual(after.events, before.events);
    } finally {
      fixture.cleanup();
    }
  });
});

function executePreflight(fixture) {
  return spawnSync("bash", [preflightScript, repository, tag, sourceCommit], {
    cwd: fixture.root,
    env: fixture.env,
    encoding: "utf8",
    timeout: 10_000,
  });
}

function executeAdmission(fixture, allowPublic) {
  return spawnSync("bash", ["-c", admissionSource], {
    cwd: fixture.root,
    env: { ...fixture.env, ALLOW_PUBLIC: allowPublic ? "true" : "false" },
    encoding: "utf8",
    timeout: 10_000,
  });
}

test("local pre-tag and write-authorized workflow admission accept only exact transaction state", async (t) => {
  const cases = [
    ["absent", {}, true],
    ["valid draft", { release: release() }, true],
    ["valid public", { release: release(false) }, "recovery-only"],
    ["wrong marker", { release: release(true, "unrelated") }, false],
    ["wrong source marker", { release: release(true, `<!-- redevplugin-release-transaction-v1 source_commit=${otherCommit} -->`) }, false],
    ["multiple empty drafts", { release: release(), extraReleases: [release(true, marker, 102)] }, "workflow-only"],
    ["multiple empty drafts with delete response loss", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      deleteReleaseResponseLost: true,
    }, "workflow-only"],
    ["multiple drafts with assets", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      extraReleaseAssets: { "102": [asset({ id: 202 })] },
    }, false],
    ["multiple drafts with wrong marker", {
      release: release(),
      extraReleases: [release(true, "unrelated", 102)],
    }, false],
    ["multiple drafts include public", {
      release: release(),
      extraReleases: [release(false, marker, 102)],
    }, false],
    ["multiple drafts with invalid asset JSON", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      invalidAssetsJson: true,
    }, false],
    ["multiple drafts with unavailable assets", {
      release: release(),
      extraReleases: [release(true, marker, 102)],
      assetsUnavailable: true,
    }, false],
  ];
  const modes = [
    ["local pre-tag", executePreflight, false, false],
    ["normal workflow admission", (fixture) => executeAdmission(fixture, false), false, true],
    ["recovery workflow admission", (fixture) => executeAdmission(fixture, true), true, true],
  ];
  for (const [mode, execute, allowsPublic, allowsDuplicateRepair] of modes) {
    for (const [name, overrides, accepted] of cases) {
      await t.test(`${mode}: ${name}`, () => {
        const fixture = createFixture(overrides);
        try {
          const result = execute(fixture);
          const expected = accepted === "recovery-only"
            ? allowsPublic
            : accepted === "workflow-only"
              ? allowsDuplicateRepair
              : accepted;
          assert.equal(result.status === 0, expected, `${name}: ${result.stderr}`);
          const mutationEvents = fixture.readState().events.filter((event) =>
            event.startsWith("delete-release-gh:")
            || event.startsWith("delete-release:")
            || event.startsWith("delete-asset:")
            || event === "upload-asset"
            || event === "publish-release"
            || event === "create-release");
          if (accepted === "workflow-only" && allowsDuplicateRepair) {
            assert.deepEqual(mutationEvents, ["delete-release-gh:102"]);
          } else {
            assert.deepEqual(mutationEvents, []);
          }
        } finally {
          fixture.cleanup();
        }
      });
    }
  }
});
