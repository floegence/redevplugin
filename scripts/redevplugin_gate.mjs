#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { canonicalRustImage, readPinnedRustVersion } from "./canonical_wasm_builder.mjs";

const day = 24 * 60 * 60 * 1000;
const repository = resolve(import.meta.dirname, "..");
const commonInputs = ["scripts/", ".githooks/", "AGENTS.md", ".node-version", "rust-toolchain.toml"];
export const stages = [
  { id: "prepare", fresh: true, kind: "environment", command: "npm ci && go mod download && cargo fetch --locked && rustup target add wasm32-unknown-unknown && npx playwright install chromium && node scripts/redevplugin_gate.mjs --resources" },
  { id: "audit", fresh: true, command: "REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh" },
  { id: "contracts", command: "npm run check:contracts" },
  { id: "go", command: "test -z \"$(gofmt -l .)\" && go list ./cmd/... ./examples/... ./pkg/... && go test -p=1 ./cmd/... ./examples/... ./pkg/... ./internal/resourceio && golangci-lint run ./cmd/... ./examples/... ./pkg/..." },
  { id: "web", command: "REDEVPLUGIN_WEB_EVIDENCE_DIR=dist/web-pre-push npm run check:web", outputs: ["packages/redevplugin-contracts/dist", "packages/redevplugin-ui/dist", "dist/web-pre-push"] },
  { id: "canonical-bridge", command: "npm run examples:check:canonical && npm run scaffold:check:canonical && ./scripts/check_redevplugin_ui_bridge.sh" },
  // Rust compilation and its crate-local fixtures do not read npm dependencies.
  { id: "rust", inputs: [...commonInputs, "Cargo.toml", "Cargo.lock", "crates/", ".cargo/", "VERSION", "deny.toml", "spec/", "testdata/", "LICENSE"], nodeDependencies: false, command: "cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace" },
  { id: "rust-source", commitBound: true, command: "npm run rust-source-packages:test" },
  { id: "performance", commitBound: true, ttl: day, command: "npm run performance:release", outputs: ["dist/performance-evidence.json", "dist/performance-evidence.route-authorization-diagnostic.json"] },
  { id: "stress", commitBound: true, ttl: day, command: "mkdir -p dist && ./scripts/check_redevplugin_stress.sh --release --summary dist/redevplugin-pre-push-stress.json", outputs: ["dist/redevplugin-pre-push-stress.json"] },
  { id: "property", ttl: day, command: "./scripts/check_redevplugin_property_gates.sh --stress" },
  { id: "runtime-platform", commitBound: true, command: "./scripts/check_redevplugin_runtime_contract.sh --ci && ./scripts/check_redevplugin_platform.sh --ci" },
];

export function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}
function jsonDigest(value) { return digest(JSON.stringify(value)); }
function command(root, name, args) {
  return execFileSync(name, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
export function sourceState(root) {
  if (command(root, "git", ["status", "--porcelain", "--untracked-files=normal"])) throw new Error("gate requires a clean tracked and untracked worktree");
  return { commit: command(root, "git", ["rev-parse", "HEAD"]), tree: command(root, "git", ["rev-parse", "HEAD^{tree}"]) };
}
export function sourceFingerprint(root, stage) {
  const entries = command(root, "git", ["ls-files", "--stage", "-z"]).split("\0").filter(Boolean);
  const selected = entries.filter((entry) => {
    const path = entry.slice(entry.indexOf("\t") + 1);
    return !stage.inputs || stage.inputs.some((input) => input.endsWith("/") ? path.startsWith(input) : path === input);
  });
  return jsonDigest(selected);
}
export function pathDigest(path) {
  const hash = createHash("sha256");
  function walk(file, relative) {
    const stat = lstatSync(file);
    hash.update(JSON.stringify([relative, stat.mode & 0o777, stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : "file"]));
    if (stat.isDirectory()) for (const name of readdirSync(file).sort()) walk(join(file, name), relative + "/" + name);
    else if (stat.isSymbolicLink()) hash.update(readlinkSync(file));
    else if (stat.isFile()) hash.update(readFileSync(file));
    else throw new Error("unsupported evidence file: " + file);
  }
  walk(path, ".");
  return hash.digest("hex");
}
function artifactDigests(root, paths) {
  return Object.fromEntries(paths.map((path) => [path, pathDigest(join(root, path))]));
}
export function evidenceKey(stage, source, environment) {
  return jsonDigest({ schema: 1, stage, source, environment });
}
function atomicJSON(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = path + "." + randomUUID();
  writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  renameSync(temporary, path);
}
export function reusableReceipt({ cache, root, key, stage, now = Date.now() }) {
  try {
    const envelope = JSON.parse(readFileSync(join(cache, key + ".json"), "utf8"));
    const receipt = envelope.receipt;
    if (envelope.sha256 !== jsonDigest(receipt) || receipt.schema !== 1 || receipt.key !== key || receipt.stage !== stage.id || receipt.status !== "passed") return null;
    if (!Number.isSafeInteger(receipt.finishedAt) || receipt.finishedAt > now || now - receipt.finishedAt > (stage.ttl ?? 7 * day)) return null;
    if (!/^[a-zA-Z0-9-]+\.log$/.test(receipt.log)) return null;
    if (digest(readFileSync(join(cache, "logs", receipt.log))) !== receipt.logSha256) return null;
    if (JSON.stringify(receipt.outputs) !== JSON.stringify(artifactDigests(root, stage.outputs ?? []))) return null;
    return receipt;
  } catch { return null; }
}
export function failureKind(stage, status, log) {
  if (status.signal) return "interrupted";
  if (stage.kind === "environment") return "environment";
  if (/(?:AssertionError|ERR_ASSERTION|severity vulnerabilit|threshold_failed)/m.test(log)) return "check";
  if (/(?:error: failed to download|failed to get successful HTTP response|npm error (?:code (?:ECONNRESET|ETIMEDOUT|EAI_AGAIN)|audit endpoint)|network socket disconnected|Could not resolve host|remained unavailable)/i.test(log)) return "environment";
  return "check";
}
export function execute(commandText, root, logPath) {
  return new Promise((resolveResult, reject) => {
    const fd = openSync(logPath, "wx", 0o600);
    const child = spawn("bash", ["-euo", "pipefail", "-c", commandText], { cwd: root, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const append = (chunk, stream) => { stream.write(chunk); writeFileSync(fd, chunk); };
    child.stdout.on("data", (chunk) => append(chunk, process.stdout));
    child.stderr.on("data", (chunk) => append(chunk, process.stderr));
    let interrupted = false;
    let closed = false;
    let killTimer;
    const killGroup = (signal) => {
      try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== "ESRCH") throw error; }
    };
    const terminate = () => {
      interrupted = true;
      killGroup("SIGTERM");
      killTimer = setTimeout(() => killGroup("SIGKILL"), 5000);
    };
    process.once("SIGTERM", terminate);
    process.once("SIGINT", terminate);
    const cleanup = () => {
      if (closed) return;
      closed = true;
      clearTimeout(killTimer);
      closeSync(fd);
      process.removeListener("SIGTERM", terminate);
      process.removeListener("SIGINT", terminate);
    };
    child.once("error", (error) => { cleanup(); reject(error); });
    child.once("close", (code, signal) => { cleanup(); resolveResult({ code: interrupted ? null : code, signal: interrupted ? "SIGTERM" : signal }); });
  });
}
export async function runStage({ root, cache, stage, environment, fresh = false, run = execute, now = Date.now }) {
  const state = sourceState(root);
  const inputs = sourceFingerprint(root, stage);
  const source = { inputs, ...(stage.commitBound ? { commit: state.commit } : {}) };
  const dependencies = stage.nodeDependencies === false || stage.fresh ? null : pathDigest(join(root, "node_modules"));
  const key = evidenceKey(stage, source, { ...environment, dependencies });
  const previous = !fresh && !stage.fresh && reusableReceipt({ root, cache, stage, key, now: now() });
  if (previous) {
    process.stdout.write("==> " + stage.id + " [reused; recorded at " + new Date(previous.finishedAt).toISOString() + "]\n");
    return { stage: stage.id, key, reused: true, inputs, dependencies, receipt: previous };
  }
  mkdirSync(join(cache, "logs"), { recursive: true, mode: 0o700 });
  rmSync(join(cache, key + ".json"), { force: true });
  const log = stage.id + "-" + randomUUID() + ".log";
  const logPath = join(cache, "logs", log);
  const startedAt = now();
  process.stdout.write("==> " + stage.id + " [running]\n");
  let status;
  try { status = await run(stage.command, root, logPath); }
  catch (error) { status = { code: null, signal: null, error: error.message }; }
  const bytes = existsSync(logPath) ? readFileSync(logPath) : Buffer.from(status.error ?? "execution did not start");
  let sourceUnchanged = false;
  try { sourceUnchanged = JSON.stringify(sourceState(root)) === JSON.stringify(state); } catch { /* A mutation invalidates this stage. */ }
  const dependenciesUnchanged = dependencies === null || dependencies === pathDigest(join(root, "node_modules"));
  if (status.code !== 0 || !sourceUnchanged || !dependenciesUnchanged) {
    const failure = { schema: 1, stage: stage.id, key, source: state, startedAt, finishedAt: now(), status: "failed", kind: sourceUnchanged && dependenciesUnchanged ? failureKind(stage, status, bytes.toString()) : "source_changed", execution: status, log, logSha256: digest(bytes) };
    atomicJSON(join(cache, "last-failure.json"), failure);
    throw new Error(stage.id + " failed (" + failure.kind + "); completed independent receipts remain available; log: " + logPath);
  }
  const receipt = { schema: 1, stage: stage.id, key, source: state, startedAt, finishedAt: now(), status: "passed", log, logSha256: digest(bytes), outputs: artifactDigests(root, stage.outputs ?? []) };
  atomicJSON(join(cache, key + ".json"), { receipt, sha256: jsonDigest(receipt) });
  return { stage: stage.id, key, reused: false, inputs, dependencies, receipt };
}
export function verifyBaselines(root) {
  const contract = JSON.parse(readFileSync(join(root, "testdata/quality/performance.json"), "utf8"));
  return contract.comparison_probes.map((probe) => {
    const ref = "v" + probe.baseline_release;
    const commit = command(root, "git", ["rev-parse", ref + "^{commit}"]);
    if (commit !== probe.baseline_commit) throw new Error("performance baseline tag mismatch: " + ref);
    for (const item of [probe.runner, probe.comparison_logic, probe.baseline_probe, probe.candidate_probe, probe.shared_probe]) {
      if (digest(readFileSync(join(root, item.path))) !== item.sha256) throw new Error("performance probe hash mismatch: " + item.path);
    }
    return { ref, commit };
  });
}
export function executionEnvironment(input) {
  const names = new Set(["HOME", "PATH", "SHELL", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE", "TZ", "CC", "CXX", "AR", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "CI", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]);
  return Object.fromEntries(Object.entries(input).filter(([key]) => names.has(key) || /^(?:GO[A-Z_]|CGO_|RUST|CARGO_|NODE_|npm_config_|NPM_CONFIG_|REDEVPLUGIN_|PLAYWRIGHT_|LC_|DOCKER_)/.test(key)).sort(([a], [b]) => a.localeCompare(b)));
}
export function normalizedGoConfiguration(configuration) {
  // Go allocates a new work directory even for `go env`; keep every other flag.
  return { ...configuration, GOGCCFLAGS: configuration.GOGCCFLAGS?.replace(/-ffile-prefix-map=([^ ]*\/)?go-build[0-9]+=/g, "-ffile-prefix-map=<go-work>=") };
}
function environmentIdentity(root, mode) {
  const tools = Object.fromEntries([
    ["go", ["version"]], ["node", ["--version"]], ["npm", ["--version"]], ["rustc", ["-vV"]], ["cargo", ["--version"]], ["rustup", ["show", "active-toolchain"]], ["golangci-lint", ["--version"]], ["cargo-deny", ["--version"]], ["bash", ["--version"]], ["cc", ["--version"]], ["git", ["--version"]], ["docker", ["version", "--format", "json"]],
  ].map(([name, args]) => [name, command(root, name, args)]));
  const configFiles = [join(os.homedir(), ".cargo/config"), join(os.homedir(), ".cargo/config.toml"), join(process.env.CARGO_HOME ?? join(os.homedir(), ".cargo"), "config"), join(process.env.CARGO_HOME ?? join(os.homedir(), ".cargo"), "config.toml"), join(os.homedir(), ".npmrc"), "/etc/os-release", "/proc/sys/kernel/random/boot_id"];
  const configurations = configFiles.map((path) => [path, existsSync(path) ? pathDigest(path) : null]);
  const env = executionEnvironment(process.env);
  const require = createRequire(join(root, "package.json"));
  const chromium = require("playwright").chromium;
  const browser = pathDigest(chromium.executablePath());
  return { mode, root: realpathSync(root), host: os.hostname(), platform: os.platform(), release: os.release(), arch: os.arch(), cpus: os.cpus().map(({ model }) => model), parallelism: os.availableParallelism(), memory: os.totalmem(), tools, browser, configurations, environmentSha256: jsonDigest(env), goConfigSha256: jsonDigest(normalizedGoConfiguration(JSON.parse(command(root, "go", ["env", "-json"])))), baselines: verifyBaselines(root) };
}
async function prepareResources(root) {
  const image = canonicalRustImage(await readPinnedRustVersion(root));
  try { command(root, "docker", ["image", "inspect", image]); }
  catch { execFileSync("docker", ["pull", image], { cwd: root, stdio: "inherit" }); }
  const require = createRequire(join(root, "package.json"));
  const browser = await require("playwright").chromium.launch({ headless: true });
  await browser.close();
}
export function acquireLock(cache) {
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  const path = join(cache, "running.json");
  try { writeFileSync(path, JSON.stringify({ pid: process.pid, host: os.hostname() }), { flag: "wx", mode: 0o600 }); }
  catch (error) {
    if (error.code !== "EEXIST") throw error;
    const owner = JSON.parse(readFileSync(path, "utf8"));
    if (owner.host !== os.hostname() || !Number.isSafeInteger(owner.pid) || owner.pid < 1) throw new Error("gate lock needs inspection: " + path);
    try { process.kill(owner.pid, 0); } catch (failure) {
      if (failure.code === "ESRCH") throw new Error("stale gate lock; confirm its recorded process has stopped before removing: " + path);
      throw failure;
    }
    throw new Error("another gate is running for this checkout: " + path);
  }
  return () => rmSync(path, { force: true });
}
async function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => !["--ci", "--fresh", "--preflight", "--resources"].includes(arg))) throw new Error("unknown gate argument");
  const environment = executionEnvironment(process.env);
  for (const key of Object.keys(process.env)) if (!(key in environment)) delete process.env[key];
  Object.assign(process.env, environment);
  sourceState(repository);
  verifyBaselines(repository);
  if (args.includes("--preflight")) return;
  if (args.includes("--resources")) { await prepareResources(repository); return; }
  const cache = join(command(repository, "git", ["rev-parse", "--path-format=absolute", "--git-common-dir"]), "redevplugin-gate");
  const unlock = acquireLock(cache);
  try {
    rmSync(join(cache, "last-complete.json"), { force: true });
    const initial = sourceState(repository);
    const mode = args.includes("--ci") ? "ci" : "local";
    const results = [];
    let environment = { mode, preparing: true };
    for (const original of stages) {
      const stage = original.id === "prepare" && mode === "ci" ? { ...original, command: original.command.replace("install chromium", "install --with-deps chromium") } : original;
      results.push(await runStage({ root: repository, cache, stage, environment, fresh: args.includes("--fresh") }));
      if (stage.id === "prepare") environment = environmentIdentity(repository, mode);
    }
    if (JSON.stringify(sourceState(repository)) !== JSON.stringify(initial) || JSON.stringify(environmentIdentity(repository, mode)) !== JSON.stringify(environment)) throw new Error("source or execution environment changed during the gate");
    for (const result of results) {
      const stage = stages.find(({ id }) => id === result.stage);
      if (sourceFingerprint(repository, stage) !== result.inputs || (result.dependencies !== null && pathDigest(join(repository, "node_modules")) !== result.dependencies)) throw new Error("stage inputs changed before completion: " + result.stage);
      if (!reusableReceipt({ root: repository, cache, key: result.key, stage })) throw new Error("stage evidence changed or expired before completion: " + result.stage);
    }
    atomicJSON(join(cache, "last-complete.json"), { schema: 1, source: initial, completedAt: Date.now(), environment, stages: results });
    process.stdout.write("ReDevPlugin pre-push gate passed; receipt: " + join(cache, "last-complete.json") + "\n");
  } finally { unlock(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
