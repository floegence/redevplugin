import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "..");
const auditScript = join(repositoryRoot, "scripts/check_redevplugin_release_audit.sh");

const mockSource = String.raw`#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";

const statePath = process.env.MOCK_AUDIT_STATE;
const state = JSON.parse(readFileSync(statePath, "utf8"));
const command = basename(process.argv[1]);
state.events.push(command + ":" + process.argv.slice(2).join(" "));

if (command === "npm") {
  state.npmCalls += 1;
  const result = state.npmResults[Math.min(state.npmCalls - 1, state.npmResults.length - 1)];
  writeFileSync(statePath, JSON.stringify(state));
  const stream = result.status === 0 ? process.stdout : process.stderr;
  stream.write(result.output + "\n");
  process.exit(result.status);
}

writeFileSync(statePath, JSON.stringify(state));
process.exit(0);
`;

function executeAudit(npmResults) {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-release-audit-"));
  const bin = join(root, "bin");
  const home = join(root, "home");
  const statePath = join(root, "state.json");
  mkdirSync(bin);
  mkdirSync(home);
  for (const command of ["npm", "go", "cargo", "cargo-deny", "sleep"]) {
    const path = join(bin, command);
    writeFileSync(path, mockSource);
    chmodSync(path, 0o755);
  }
  writeFileSync(statePath, JSON.stringify({ npmCalls: 0, npmResults, events: [] }));
  const result = spawnSync("bash", [auditScript], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      HOME: home,
      PATH: `${bin}:${process.env.PATH}`,
      MOCK_AUDIT_STATE: statePath,
    },
    encoding: "utf8",
    timeout: 10_000,
  });
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  rmSync(root, { recursive: true, force: true });
  return { result, state };
}

test("npm audit retries transient endpoint failures and then continues", () => {
  const { result, state } = executeAudit([
    { status: 1, output: "npm error audit endpoint returned an error" },
    { status: 1, output: "npm error network socket disconnected" },
    { status: 0, output: "found 0 vulnerabilities" },
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(state.npmCalls, 3);
  assert.equal(state.events.filter((event) => event.startsWith("sleep:")).length, 2);
  assert.ok(state.events.some((event) => event.startsWith("go:run ")));
  assert.ok(state.events.includes("cargo:deny check"));
});

test("npm audit stops after the closed transient retry budget", () => {
  const { result, state } = executeAudit([
    { status: 1, output: "npm error audit endpoint returned an error" },
  ]);
  assert.equal(result.status, 1);
  assert.equal(state.npmCalls, 4);
  assert.equal(state.events.filter((event) => event.startsWith("sleep:")).length, 3);
  assert.equal(state.events.some((event) => event.startsWith("go:")), false);
});

test("npm audit does not retry a deterministic vulnerability finding", () => {
  const { result, state } = executeAudit([
    { status: 1, output: "1 moderate severity vulnerability" },
  ]);
  assert.equal(result.status, 1);
  assert.equal(state.npmCalls, 1);
  assert.equal(state.events.some((event) => event.startsWith("sleep:")), false);
  assert.equal(state.events.some((event) => event.startsWith("go:")), false);
});
