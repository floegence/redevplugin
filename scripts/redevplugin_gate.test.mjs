import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { acquireLock, digest, evidenceKey, execute, executionEnvironment, failureKind, normalizedGoConfiguration, runStage, sourceFingerprint, stages, verifyBaselines } from "./redevplugin_gate.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-gate-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "-q", "-b", "feature");
  git("config", "user.name", "Gate Test"); git("config", "user.email", "gate@example.invalid");
  mkdirSync(join(root, "node_modules")); writeFileSync(join(root, "node_modules/dependency"), "fixed");
  writeFileSync(join(root, ".gitignore"), "node_modules/\ndist/\n");
  writeFileSync(join(root, "Cargo.lock"), "rust-lock");
  writeFileSync(join(root, "package-lock.json"), "npm-lock");
  writeFileSync(join(root, "source.txt"), "source");
  git("add", "."); git("commit", "-qm", "initial");
  const cache = join(root, ".git/evidence");
  let executions = 0;
  const run = async (_command, _root, log) => { executions += 1; writeFileSync(log, "passed\n"); return { code: 0, signal: null }; };
  const stage = { id: "fixture", command: "test", outputs: [] };
  return { root, cache, git, stage, run, environment: { toolchain: "fixed", host: "local" }, count: () => executions };
}

test("identical stage inputs survive an unrelated commit identity and branch fast-forward", async (t) => {
  const f = fixture(t);
  assert.equal((await runStage(f)).reused, false);
  f.git("commit", "--allow-empty", "-qm", "identity only");
  f.git("branch", "main"); f.git("switch", "main");
  assert.equal((await runStage(f)).reused, true);
  assert.equal(f.count(), 1);
});

test("exact-commit measurement evidence cannot be relabeled", async (t) => {
  const f = fixture(t); f.stage.commitBound = true;
  await runStage(f);
  f.git("commit", "--allow-empty", "-qm", "new identity");
  assert.equal((await runStage(f)).reused, false);
  assert.equal(f.count(), 2);
});

test("source, scripts, lockfiles, environment and installed dependency bytes invalidate receipts", async (t) => {
  const f = fixture(t); await runStage(f);
  for (const path of ["source.txt", "package-lock.json", "new-script.mjs"]) {
    writeFileSync(join(f.root, path), "changed " + path); f.git("add", "."); f.git("commit", "-qm", path);
    assert.equal((await runStage(f)).reused, false);
  }
  f.environment.toolchain = "new"; assert.equal((await runStage(f)).reused, false);
  writeFileSync(join(f.root, "node_modules/dependency"), "changed dependency");
  assert.equal((await runStage(f)).reused, false);
  assert.equal(f.count(), 6);
});

test("Rust source closure excludes only unrelated npm inputs and includes new Rust files", (t) => {
  const f = fixture(t); const rust = stages.find(({ id }) => id === "rust");
  const before = sourceFingerprint(f.root, rust);
  writeFileSync(join(f.root, "package-lock.json"), "changed npm"); f.git("add", "."); f.git("commit", "-qm", "npm");
  assert.equal(sourceFingerprint(f.root, rust), before);
  mkdirSync(join(f.root, "crates")); writeFileSync(join(f.root, "crates/new.rs"), "new rust");
  f.git("add", "."); f.git("commit", "-qm", "rust");
  assert.notEqual(sourceFingerprint(f.root, rust), before);
});

test("expired, future dated, damaged and missing evidence causes a rerun", async (t) => {
  const f = fixture(t); f.stage.ttl = 100;
  const first = await runStage({ ...f, now: () => 1000 });
  assert.equal((await runStage({ ...f, now: () => 1050 })).reused, true);
  assert.equal((await runStage({ ...f, now: () => 999 })).reused, false);
  assert.equal((await runStage({ ...f, now: () => 1200 })).reused, false);
  writeFileSync(join(f.cache, first.key + ".json"), "broken");
  const result = await runStage({ ...f, now: () => 1200 }); assert.equal(result.reused, false);
  writeFileSync(join(f.cache, "logs", result.receipt.log), "altered");
  assert.equal((await runStage({ ...f, now: () => 1200 })).reused, false);
});

test("missing or changed declared artifacts invalidate evidence", async (t) => {
  const f = fixture(t); f.stage.outputs = ["dist/result.json"];
  const run = async (command, root, log) => { mkdirSync(join(root, "dist"), { recursive: true }); writeFileSync(join(root, "dist/result.json"), "artifact"); return f.run(command, root, log); };
  await runStage({ ...f, run });
  rmSync(join(f.root, "dist/result.json"));
  assert.equal((await runStage({ ...f, run })).reused, false);
  writeFileSync(join(f.root, "dist/result.json"), "tampered");
  assert.equal((await runStage({ ...f, run })).reused, false);
});

test("a failed stage retains independent successes and never creates passing evidence", async (t) => {
  const f = fixture(t); await runStage(f);
  const failing = { ...f.stage, id: "download", command: "download" };
  const run = async (_command, _root, log) => { writeFileSync(log, "error: failed to download\n"); return { code: 1, signal: null }; };
  await assert.rejects(runStage({ ...f, stage: failing, run }), /failed \(environment\)/);
  const failure = JSON.parse(readFileSync(join(f.cache, "last-failure.json")));
  assert.equal(failure.kind, "environment");
  assert.throws(() => readFileSync(join(f.cache, failure.key + ".json")), { code: "ENOENT" });
  assert.equal((await runStage(f)).reused, true);
  assert.equal((await runStage({ ...f, stage: failing })).reused, false);
});

test("fresh audit, explicit fresh execution and interrupted execution cannot reuse old success", async (t) => {
  const f = fixture(t); await runStage(f);
  assert.equal((await runStage({ ...f, fresh: true })).reused, false);
  f.stage.fresh = true; await runStage(f); assert.equal((await runStage(f)).reused, false);
  const run = async (_command, _root, log) => { writeFileSync(log, "interrupted\n"); return { code: null, signal: "SIGTERM" }; };
  await assert.rejects(runStage({ ...f, run }), /interrupted/);
});

test("source mutation during a command and an initially dirty checkout fail closed", async (t) => {
  const f = fixture(t);
  const run = async (command, root, log) => { writeFileSync(join(root, "source.txt"), "mutation"); return f.run(command, root, log); };
  await assert.rejects(runStage({ ...f, run }), /source_changed/);
  await assert.rejects(runStage(f), /requires a clean/);
});

test("failure classification never retries assertions or interprets unknown failures as transport", () => {
  assert.equal(failureKind({}, { code: 1 }, "AssertionError: error: failed to download"), "check");
  assert.equal(failureKind({}, { code: 1 }, "1 moderate severity vulnerability"), "check");
  const cargoTimeout = "error: failed to get `base64` as a dependency\nCaused by:\n  download of config.json failed\nCaused by:\n  failed to download from `https://index.crates.io/config.json`\nCaused by:\n  [28] Timeout was reached (Connection timed out after 30031 milliseconds)";
  assert.equal(failureKind({}, { code: 101 }, cargoTimeout), "environment");
  assert.equal(failureKind({}, { code: 101 }, "AssertionError: " + cargoTimeout), "check");
  assert.equal(failureKind({}, { code: 1 }, "unknown"), "check");
  assert.equal(failureKind({}, { signal: "SIGTERM" }, ""), "interrupted");
});

test("concurrent runs cannot write to the same evidence directory", (t) => {
  const f = fixture(t); const release = acquireLock(f.cache);
  assert.throws(() => acquireLock(f.cache), /another gate is running/);
  release(); acquireLock(f.cache)();
});

test("missing and mismatched baseline tags fail before heavy stages", (t) => {
  const f = fixture(t); mkdirSync(join(f.root, "testdata/quality"), { recursive: true });
  const path = "testdata/quality/probe.js"; writeFileSync(join(f.root, path), "probe");
  const probe = { path, sha256: digest("probe") };
  const commit = f.git("rev-parse", "HEAD");
  const contract = { comparison_probes: [{ baseline_release: "0.5.1", baseline_commit: commit, runner: probe, comparison_logic: probe, baseline_probe: probe, candidate_probe: probe, shared_probe: probe }] };
  writeFileSync(join(f.root, "testdata/quality/performance.json"), JSON.stringify(contract));
  assert.throws(() => verifyBaselines(f.root));
  f.git("tag", "v0.5.1"); assert.deepEqual(verifyBaselines(f.root), [{ ref: "v0.5.1", commit }]);
  writeFileSync(join(f.root, path), "changed"); assert.throws(() => verifyBaselines(f.root), /hash mismatch/);
});

test("the fixed stage plan preserves original coverage and moves cheap blockers first", () => {
  assert.deepEqual(stages.map(({ id }) => id), ["prepare", "audit", "contracts", "go", "web", "canonical-bridge", "rust", "rust-source", "performance", "stress", "property", "runtime-platform"]);
  assert.ok(stages.find(({ id }) => id === "audit").fresh);
  assert.ok(stages.find(({ id }) => id === "prepare").fresh);
  const packageJSON = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  assert.equal(packageJSON.scripts.check, "npm run check:contracts && npm run check:web");
  for (const gate of ["test:contracts", "test:ui", "test:browser-harness:smoke", "property-gates", "canonical-wasm:test"]) assert.ok(packageJSON.scripts["check:web"].includes("npm run " + gate));
  for (const gate of ["openapi-contract:test", "release-metadata:check", "release-workflow-security:test"]) assert.ok(packageJSON.scripts["check:contracts"].includes("npm run " + gate));
  const key = evidenceKey(stages[0], { inputs: "x" }, {});
  assert.notEqual(key, evidenceKey({ ...stages[0], command: "changed" }, { inputs: "x" }, {}));
});


test("only declared build inputs enter the execution environment", () => {
  const env = executionEnvironment({ PATH: "/tools", GOWORK: "off", GOFLAGS: "-tags=test", RUSTFLAGS: "changed", CARGO_HOME: "/cargo", REDEVPLUGIN_TEST: "on", PLAYWRIGHT_BROWSERS_PATH: "/browser", SSH_CONNECTION: "session 1", XDG_SESSION_ID: "session 2", SECRET_UNRELATED: "must not pass" });
  assert.equal(env.PATH, "/tools");
  assert.equal(env.GOFLAGS, "-tags=test");
  assert.equal(env.RUSTFLAGS, "changed");
  assert.equal(env.SSH_CONNECTION, undefined);
  assert.equal(env.SECRET_UNRELATED, undefined);
  assert.deepEqual(env, executionEnvironment({ ...env, SSH_CONNECTION: "another session" }));
});

test("real execution records complete stdout and stderr and preserves failure status", async (t) => {
  const f = fixture(t);
  const path = join(f.root, ".git/real.log");
  const result = await execute("printf stdout; printf stderr >&2; exit 7", f.root, path);
  assert.equal(result.code, 7);
  const log = readFileSync(path, "utf8");
  assert.ok(log.includes("stdout")); assert.ok(log.includes("stderr"));
});


test("Go temporary work directory identity is normalized without discarding compiler flags", () => {
  const a = { GOOS: "linux", GOGCCFLAGS: "-fPIC -ffile-prefix-map=/tmp/go-build123=/tmp/go-build -pthread" };
  const b = { ...a, GOGCCFLAGS: "-fPIC -ffile-prefix-map=/tmp/go-build999=/tmp/go-build -pthread" };
  assert.deepEqual(normalizedGoConfiguration(a), normalizedGoConfiguration(b));
  assert.notDeepEqual(normalizedGoConfiguration(a), normalizedGoConfiguration({ ...b, GOGCCFLAGS: b.GOGCCFLAGS + " -O3" }));
});
