#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { arch, cpus, platform } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright";

import { readPerformanceContract, validatePerformanceEvidence } from "./performance_contract.mjs";

const options = parseArgs(process.argv.slice(2));
assertEvidenceSourceState(options.sourceCommit);
const compatibility = JSON.parse(readFileSync(resolve(options.compatibility), "utf8"));
const performanceContract = readPerformanceContract(join(import.meta.dirname, "../spec/plugin/performance-contract-v4.json"));
const scenarios = readMeasurements(resolve(options.measurements));
const comparisons = readMeasurements(resolve(options.comparisons));
const chromiumVersion = execFileSync(chromium.executablePath(), ["--version"], { encoding: "utf8" }).trim();
const evidence = {
  schema_version: "redevplugin.performance_evidence.v4",
  release_version: options.version,
  source_commit: options.sourceCommit,
  generated_at: options.generatedAt || new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(".000Z", "Z"),
  environment: {
    os: platform(),
    arch: arch(),
    logical_cpus: cpus().length,
    go_version: execFileSync("go", ["version"], { encoding: "utf8" }).trim(),
    node_version: process.version,
    rustc_version: execFileSync("rustc", ["--version"], { encoding: "utf8" }).trim(),
    chromium_version: chromiumVersion,
  },
  scenarios: scenarios.sort((left, right) => left.id.localeCompare(right.id)),
  comparisons: comparisons.sort((left, right) => left.id.localeCompare(right.id)),
  contract_hashes: compatibility.contracts
    .map((contract) => ({ id: contract.id, sha256: contract.sha256 }))
    .sort((left, right) => left.id.localeCompare(right.id)),
};
validatePerformanceEvidence(evidence, performanceContract, {
  expectedGate: options.gate,
  releaseVersion: options.version,
  sourceCommit: options.sourceCommit,
  generatedAt: evidence.generated_at,
  contractHashes: compatibility.contracts,
});
writeFileSync(resolve(options.output), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });

function assertEvidenceSourceState(sourceCommit) {
  const repositoryRoot = resolve(import.meta.dirname, "..");
  const head = runGit(repositoryRoot, ["rev-parse", "HEAD"], "resolve the repository HEAD").trim();
  if (sourceCommit !== head) {
    throw new Error(`performance evidence source_commit must equal the checked-out HEAD: got ${sourceCommit}, want ${head}`);
  }

  assertGitDiffQuiet(
    repositoryRoot,
    ["diff", "--quiet", "--"],
    "performance evidence requires a clean tracked working tree",
  );
  assertGitDiffQuiet(
    repositoryRoot,
    ["diff", "--cached", "--quiet", "--"],
    "performance evidence requires a clean Git index",
  );

  const untracked = runGit(
    repositoryRoot,
    ["ls-files", "--others", "--exclude-standard", "-z"],
    "inspect non-ignored untracked files",
  ).split("\0").filter(Boolean);
  if (untracked.length > 0) {
    throw new Error(`performance evidence requires no non-ignored untracked files: ${untracked.join(", ")}`);
  }
}

function assertGitDiffQuiet(repositoryRoot, args, message) {
  const result = spawnSync("git", args, { cwd: repositoryRoot, encoding: "utf8", stdio: "pipe" });
  if (result.status === 0) return;
  if (result.status === 1) throw new Error(message);
  const detail = (result.stderr || result.stdout || result.error?.message || "unknown Git failure").trim();
  throw new Error(`unable to verify the Git worktree for performance evidence: ${detail}`);
}

function runGit(repositoryRoot, args, operation) {
  try {
    return execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    const detail = (error.stderr || error.stdout || error.message || "unknown Git failure").toString().trim();
    throw new Error(`unable to ${operation}: ${detail}`);
  }
}

function readMeasurements(path) {
  const lines = readFileSync(path, "utf8").split("\n").map((line) => line.trim()).filter(Boolean);
  return lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new Error(`invalid performance measurement line ${index + 1}: ${error.message}`);
    }
  });
}

function parseArgs(args) {
  const options = { output: "", measurements: "", comparisons: "", compatibility: "", version: "", sourceCommit: "", generatedAt: "", gate: "" };
  for (let index = 0; index < args.length; index += 1) {
    const value = args[++index] ?? "";
    if (args[index - 1] === "--output") options.output = value;
    else if (args[index - 1] === "--measurements") options.measurements = value;
    else if (args[index - 1] === "--comparisons") options.comparisons = value;
    else if (args[index - 1] === "--compatibility") options.compatibility = value;
    else if (args[index - 1] === "--version") options.version = value;
    else if (args[index - 1] === "--source-commit") options.sourceCommit = value;
    else if (args[index - 1] === "--generated-at") options.generatedAt = value;
    else if (args[index - 1] === "--gate") options.gate = value;
    else throw new Error(`unknown argument: ${args[index - 1]}`);
  }
  for (const key of ["output", "measurements", "comparisons", "compatibility", "version", "sourceCommit", "gate"]) {
    if (!options[key]) throw new Error(`--${key.replaceAll(/[A-Z]/g, (match) => `-${match.toLowerCase()}`)} is required`);
  }
  if (!["smoke", "full", "release"].includes(options.gate)) throw new Error(`invalid performance evidence gate ${options.gate}`);
  return options;
}
