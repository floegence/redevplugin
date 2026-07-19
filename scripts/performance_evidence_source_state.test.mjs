#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

for (const testCase of [
  {
    name: "source commit mismatch",
    expected: "source_commit must equal the checked-out HEAD",
    mutate: async () => {},
    sourceCommit: () => "0".repeat(40),
  },
  {
    name: "unstaged tracked change",
    expected: "requires a clean tracked working tree",
    mutate: async ({ repo }) => writeFile(join(repo, "fixture.txt"), "unstaged\n"),
  },
  {
    name: "staged tracked change",
    expected: "requires a clean Git index",
    mutate: async ({ repo }) => {
      await writeFile(join(repo, "fixture.txt"), "staged\n");
      git(repo, "add", "fixture.txt");
    },
  },
  {
    name: "non-ignored untracked file",
    expected: "requires no non-ignored untracked files",
    mutate: async ({ repo }) => writeFile(join(repo, "untracked.txt"), "untracked\n"),
  },
]) {
  test(`performance evidence rejects ${testCase.name} before writing output`, async (t) => {
    const fixture = await createFixture(t);
    await testCase.mutate(fixture);
    const sourceCommit = testCase.sourceCommit?.(fixture) ?? git(fixture.repo, "rev-parse", "HEAD").trim();
    const result = spawnSync(process.execPath, [
      join(fixture.repo, "scripts/generate_redevplugin_performance_evidence.mjs"),
      "--output", fixture.output,
      "--measurements", join(fixture.base, "missing-measurements.ndjson"),
      "--compatibility", join(fixture.base, "missing-compatibility.json"),
      "--version", "0.5.0",
      "--source-commit", sourceCommit,
      "--gate", "release",
    ], {
      cwd: fixture.repo,
      encoding: "utf8",
      stdio: "pipe",
    });
    assert.notEqual(result.status, 0, `${testCase.name} unexpectedly generated evidence`);
    assert.match(result.stderr, new RegExp(testCase.expected));
    await assert.rejects(readFile(fixture.output), { code: "ENOENT" });
  });
}

test("release performance evidence rejects an external runtime override", async (t) => {
  const fixture = await createFixture(t);
  const sourceCommit = git(fixture.repo, "rev-parse", "HEAD").trim();
  const result = spawnSync("bash", [
    join(fixture.repo, "scripts/check_redevplugin_performance.sh"),
    "--release",
    "--output", fixture.output,
    "--version", "0.5.0",
    "--source-commit", sourceCommit,
  ], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: { ...process.env, REDEVPLUGIN_PERFORMANCE_RUNTIME: join(fixture.base, "foreign-runtime") },
    stdio: "pipe",
  });
  assert.notEqual(result.status, 0, "release gate accepted an external runtime override");
  assert.match(result.stderr, /must build redevplugin-runtime from the clean checked-out HEAD/);
  await assert.rejects(readFile(fixture.output), { code: "ENOENT" });
});

async function createFixture(t) {
  const base = await mkdtemp(join(tmpdir(), "redevplugin-performance-source-state-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const repo = join(base, "repo");
  await mkdir(join(repo, "scripts"), { recursive: true });
  await copyFile(
    join(root, "scripts/generate_redevplugin_performance_evidence.mjs"),
    join(repo, "scripts/generate_redevplugin_performance_evidence.mjs"),
  );
  await copyFile(
    join(root, "scripts/performance_contract.mjs"),
    join(repo, "scripts/performance_contract.mjs"),
  );
  await copyFile(
    join(root, "scripts/rfc3339.mjs"),
    join(repo, "scripts/rfc3339.mjs"),
  );
  await copyFile(
    join(root, "scripts/check_redevplugin_performance.sh"),
    join(repo, "scripts/check_redevplugin_performance.sh"),
  );
  await symlink(join(root, "node_modules"), join(repo, "node_modules"), "dir");
  await writeFile(join(repo, ".gitignore"), "node_modules/\n");
  await writeFile(join(repo, "fixture.txt"), "clean\n");
  git(repo, "init", "--quiet");
  git(repo, "config", "user.name", "ReDevPlugin Tests");
  git(repo, "config", "user.email", "tests@redevplugin.invalid");
  git(repo, "add", ".");
  git(repo, "commit", "--quiet", "-m", "test fixture");
  return { base, repo, output: join(base, "performance-evidence.json") };
}

function git(repo, ...args) {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}
