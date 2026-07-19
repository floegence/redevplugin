#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readPerformanceContract } from "./performance_contract.mjs";
import {
  assertRouteAuthorizationThresholds,
  buildRouteAuthorizationComparisonReport,
  buildRepeatedRouteAuthorizationScenarios,
} from "./route_authorization_comparison.mjs";

const root = resolve(import.meta.dirname, "..");
const contractPath = join(root, "spec/plugin/performance-contract-v2.json");
const probeID = "httpadapter.route-authorization-v051";

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const contract = readPerformanceContract(contractPath);
  const probe = readComparisonProbe(contract, probeID);
  verifyProbeSources(probe);
  verifyBaseline(probe);
  const temporaryRoot = mkdtempSync(join(tmpdir(), "redevplugin-route-authorization-"));
  try {
    const baselineRoot = join(temporaryRoot, "baseline");
    const archivePath = join(temporaryRoot, "baseline.tar");
    mkdirSync(baselineRoot, { recursive: true });
    run("git", ["archive", "--format=tar", "--output", archivePath, probe.baseline_commit], root);
    run("tar", ["-xf", archivePath, "-C", baselineRoot], root);
    cpSync(join(root, probe.shared_probe.path), join(baselineRoot, probe.shared_probe.path));
    cpSync(join(root, probe.baseline_probe.path), join(baselineRoot, "pkg/httpadapter/route_authorization_performance_test.go"));

    const gomaxprocs = String(options.gomaxprocs);
    const candidateCommit = run("git", ["rev-parse", "HEAD"], root).trim();
    const baselineBinary = join(temporaryRoot, "baseline-httpadapter.test");
    const candidateBinary = join(temporaryRoot, "candidate-httpadapter.test");
    buildProfileBinary(baselineRoot, baselineBinary);
    buildProfileBinary(root, candidateBinary);
    const profilePaths = {
      baseline: Array.from({ length: probe.repetitions }, (_, index) => join(temporaryRoot, `baseline-${index + 1}.json`)),
      candidate: Array.from({ length: probe.repetitions }, (_, index) => join(temporaryRoot, `candidate-${index + 1}.json`)),
    };
    const runIndexes = { baseline: 0, candidate: 0 };
    for (const variant of buildInterleavedRunOrder(probe.repetitions)) {
      const index = runIndexes[variant]++;
      runProfile(
        variant === "baseline" ? baselineBinary : candidateBinary,
        variant === "baseline" ? baselineRoot : root,
        profilePaths[variant][index],
        variant === "baseline" ? probe.baseline_commit : candidateCommit,
        gomaxprocs,
      );
    }
    const baselineProfiles = profilePaths.baseline.map((path) => JSON.parse(readFileSync(path)));
    const candidateProfiles = profilePaths.candidate.map((path) => JSON.parse(readFileSync(path)));

    const comparison = buildRouteAuthorizationComparisonReport(probe, baselineProfiles, candidateProfiles);
    const scenarios = buildRepeatedRouteAuthorizationScenarios(baselineProfiles, candidateProfiles, options.gate);
    if (options.gate !== "smoke") assertRouteAuthorizationThresholds(scenarios);
    mkdirSync(dirname(options.output), { recursive: true });
    for (const scenario of scenarios) {
      appendFileSync(options.output, `${JSON.stringify(scenario)}\n`, { mode: 0o600 });
    }
    mkdirSync(dirname(options.comparisonOutput), { recursive: true });
    appendFileSync(options.comparisonOutput, `${JSON.stringify(comparison)}\n`, { mode: 0o600 });
    const summary = {
      gomaxprocs: options.gomaxprocs,
      comparison,
      scenarios,
    };
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function buildProfileBinary(repositoryRoot, output) {
  run("go", ["test", "-c", "-o", output, "./pkg/httpadapter"], repositoryRoot, { GOWORK: "off" });
}

function runProfile(binary, repositoryRoot, output, commit, gomaxprocs) {
  run(binary, ["-test.run", "^TestRouteAuthorizationPerformanceEvidence$", "-test.count=1"], repositoryRoot, {
    GOWORK: "off",
    GOMAXPROCS: gomaxprocs,
    REDEVPLUGIN_ROUTE_AUTHORIZATION_PROFILE: output,
    REDEVPLUGIN_ROUTE_AUTHORIZATION_COMMIT: commit,
  });
}

export function buildInterleavedRunOrder(repetitions) {
  if (repetitions !== 3) throw new Error("route authorization runner requires exactly three repetitions");
  return ["baseline", "candidate", "candidate", "baseline", "baseline", "candidate"];
}

function readComparisonProbe(contract, id) {
  const probe = contract.comparison_probes.find((candidate) => candidate.id === id);
  if (!probe) throw new Error(`performance contract is missing comparison probe ${id}`);
  return probe;
}

function verifyProbeSources(probe) {
  for (const source of [probe.runner, probe.comparison_logic, probe.baseline_probe, probe.candidate_probe, probe.shared_probe]) {
    const actual = sha256(readFileSync(join(root, source.path)));
    if (actual !== source.sha256) {
      throw new Error(`performance comparison probe hash mismatch for ${source.path}: got ${actual}, want ${source.sha256}`);
    }
  }
}

function verifyBaseline(probe) {
  const taggedCommit = run("git", ["rev-parse", `v${probe.baseline_release}^{commit}`], root).trim();
  if (taggedCommit !== probe.baseline_commit) {
    throw new Error(`performance baseline tag mismatch: got ${taggedCommit}, want ${probe.baseline_commit}`);
  }
}

function sha256(raw) {
  return createHash("sha256").update(raw).digest("hex");
}

function run(command, args, cwd, extraEnvironment = {}) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...extraEnvironment },
  });
}

function parseArgs(args) {
  const options = {
    output: "",
    comparisonOutput: "",
    gate: "",
    gomaxprocs: Math.min(8, availableParallelism()),
  };
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    if (name === "--output") options.output = resolve(args[++index] || "");
    else if (name === "--comparison-output") options.comparisonOutput = resolve(args[++index] || "");
    else if (name === "--gate") options.gate = args[++index] || "";
    else if (name === "--gomaxprocs") options.gomaxprocs = Number(args[++index]);
    else throw new Error(`unknown argument ${name}`);
  }
  if (!options.output) throw new Error("--output is required");
  if (!options.comparisonOutput) throw new Error("--comparison-output is required");
  if (!["smoke", "full", "release"].includes(options.gate)) throw new Error(`invalid --gate ${options.gate}`);
  if (!Number.isSafeInteger(options.gomaxprocs) || options.gomaxprocs < 1) throw new Error("--gomaxprocs must be a positive integer");
  return options;
}
