#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { arch, cpus, platform } from "node:os";
import { resolve } from "node:path";
import { chromium } from "playwright";

const options = parseArgs(process.argv.slice(2));
const compatibility = JSON.parse(readFileSync(resolve(options.compatibility), "utf8"));
const scenarios = readMeasurements(resolve(options.measurements));
validateScenarios(scenarios, options.gate);
const chromiumVersion = execFileSync(chromium.executablePath(), ["--version"], { encoding: "utf8" }).trim();
const evidence = {
  schema_version: "redevplugin.performance_evidence.v1",
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
  contract_hashes: compatibility.contracts
    .map((contract) => ({ id: contract.id, sha256: contract.sha256 }))
    .sort((left, right) => left.id.localeCompare(right.id)),
};
validateEvidence(evidence);
writeFileSync(resolve(options.output), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });

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

function validateScenarios(scenarios, gate) {
  const required = [
    "runtime.blocked-hostcall-isolation",
    "runtime.cache-single-flight",
    "runtime.cancel-queued",
    "runtime.cancel-running",
    "runtime.warm-invocations",
    "stream.event-backpressure",
    "stream.idle-waiters",
    "stream.sqlite-batch-read",
    "ui.chromium-renderer",
    "ui.keyed-reversal",
    "ui.single-leaf-reconciliation",
  ];
  if (scenarios.length !== required.length) {
    throw new Error(`performance evidence scenario count ${scenarios.length} does not match ${required.length}`);
  }
  const ids = scenarios.map((scenario) => scenario.id).sort();
  if (JSON.stringify(ids) !== JSON.stringify(required)) {
    throw new Error(`performance evidence scenario IDs mismatch: ${ids.join(", ")}`);
  }
  for (const scenario of scenarios) {
    if (scenario.gate !== gate || scenario.status !== "pass" || !Number.isSafeInteger(scenario.sample_count) || scenario.sample_count < 1) {
      throw new Error(`performance scenario ${scenario.id} has invalid gate, status, or sample_count`);
    }
    if (!Array.isArray(scenario.metrics) || scenario.metrics.length === 0) {
      throw new Error(`performance scenario ${scenario.id} has no metrics`);
    }
    const metricNames = new Set();
    for (const metric of scenario.metrics) {
      if (metricNames.has(metric.name)) throw new Error(`performance scenario ${scenario.id} duplicates metric ${metric.name}`);
      metricNames.add(metric.name);
      if (!Number.isFinite(metric.observed) || metric.observed < 0 || !Number.isFinite(metric.limit) || metric.limit < 0) {
        throw new Error(`performance scenario ${scenario.id} metric ${metric.name} is not finite and non-negative`);
      }
      const passed = metric.comparator === "eq" ? metric.observed === metric.limit : metric.comparator === "lte" ? metric.observed <= metric.limit : false;
      if (!passed) throw new Error(`performance scenario ${scenario.id} metric ${metric.name} failed: ${metric.observed} ${metric.comparator} ${metric.limit}`);
    }
  }
}

function validateEvidence(evidence) {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/.test(evidence.release_version)) {
    throw new Error(`invalid performance evidence release version ${evidence.release_version}`);
  }
  if (!/^[0-9a-f]{40}$/.test(evidence.source_commit)) throw new Error("performance evidence source_commit is invalid");
  if (!Number.isFinite(Date.parse(evidence.generated_at))) throw new Error("performance evidence generated_at is invalid");
  if (!Array.isArray(evidence.contract_hashes) || evidence.contract_hashes.length === 0) throw new Error("performance evidence contract hashes are missing");
  const contractIDs = new Set();
  for (const contract of evidence.contract_hashes) {
    if (!/^[a-z][a-z0-9-]+$/.test(contract.id) || contractIDs.has(contract.id) || !/^[0-9a-f]{64}$/.test(contract.sha256)) {
      throw new Error(`performance evidence contract hash is invalid: ${JSON.stringify(contract)}`);
    }
    contractIDs.add(contract.id);
  }
}

function parseArgs(args) {
  const options = { output: "", measurements: "", compatibility: "", version: "", sourceCommit: "", generatedAt: "", gate: "" };
  for (let index = 0; index < args.length; index += 1) {
    const value = args[++index] ?? "";
    if (args[index - 1] === "--output") options.output = value;
    else if (args[index - 1] === "--measurements") options.measurements = value;
    else if (args[index - 1] === "--compatibility") options.compatibility = value;
    else if (args[index - 1] === "--version") options.version = value;
    else if (args[index - 1] === "--source-commit") options.sourceCommit = value;
    else if (args[index - 1] === "--generated-at") options.generatedAt = value;
    else if (args[index - 1] === "--gate") options.gate = value;
    else throw new Error(`unknown argument: ${args[index - 1]}`);
  }
  for (const key of ["output", "measurements", "compatibility", "version", "sourceCommit", "gate"]) {
    if (!options[key]) throw new Error(`--${key.replaceAll(/[A-Z]/g, (match) => `-${match.toLowerCase()}`)} is required`);
  }
  if (!["full", "release"].includes(options.gate)) throw new Error(`invalid performance evidence gate ${options.gate}`);
  return options;
}
