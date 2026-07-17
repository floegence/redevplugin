#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { resolve } from "node:path";

import {
  readPerformanceContract,
  validatePerformanceEvidence,
  validatePerformanceScenarios,
} from "./performance_contract.mjs";

const contractPath = resolve(import.meta.dirname, "../spec/plugin/performance-contract-v1.json");

test("performance contract accepts its exact scenario and metric shape", () => {
  const contract = readPerformanceContract(contractPath);
  const scenarios = measurementsFrom(contract, "release");

  assert.doesNotThrow(() => validatePerformanceScenarios(scenarios, contract, {
    expectedGate: "release",
    allowSmoke: false,
  }));
});

test("performance contract rejects scenario and metric drift", () => {
  const contract = readPerformanceContract(contractPath);
  const cases = [
    ["missing scenario", (value) => value.pop(), "scenario IDs"],
    ["extra scenario", (value) => value.push({ ...structuredClone(value[0]), id: "runtime.extra" }), "scenario IDs"],
    ["missing metric", (value) => value[0].metrics.pop(), "metric names"],
    ["extra metric", (value) => value[0].metrics.push({ ...value[0].metrics[0], name: "extra" }), "metric names"],
    ["duplicate metric", (value) => value[0].metrics.push(structuredClone(value[0].metrics[0])), "duplicate metric"],
    ["sample count drift", (value) => value[0].sample_count += 1, "sample_count"],
    ["unit drift", (value) => value[0].metrics[0].unit = "bytes", "unit"],
    ["comparator drift", (value) => value[0].metrics[0].comparator = value[0].metrics[0].comparator === "eq" ? "lte" : "eq", "comparator"],
    ["limit drift", (value) => value[0].metrics[0].limit += 1, "limit"],
    ["mixed gates", (value) => value[0].gate = "smoke", "gate"],
  ];

  for (const [label, mutate, diagnostic] of cases) {
    const scenarios = measurementsFrom(contract, "release");
    mutate(scenarios);
    assert.throws(
      () => validatePerformanceScenarios(scenarios, contract, { expectedGate: "release", allowSmoke: false }),
      new RegExp(diagnostic),
      label,
    );
  }
});

test("performance evidence metadata and contract hashes are closed and immutable", () => {
  const contract = readPerformanceContract(contractPath);
  const contractHashes = [{ id: "performance-contract", sha256: "a".repeat(64) }];
  const evidence = {
    schema_version: "redevplugin.performance_evidence.v1",
    release_version: "0.5.0",
    source_commit: "b".repeat(40),
    generated_at: "2026-07-17T00:00:00Z",
    environment: {
      os: "linux",
      arch: "x64",
      logical_cpus: 8,
      go_version: "go version go1.24.0 linux/amd64",
      node_version: "v24.0.0",
      rustc_version: "rustc 1.88.0",
      chromium_version: "Chromium 138.0.0",
    },
    scenarios: measurementsFrom(contract, "release"),
    contract_hashes: contractHashes,
  };
  const options = {
    expectedGate: "release",
    releaseVersion: evidence.release_version,
    sourceCommit: evidence.source_commit,
    generatedAt: evidence.generated_at,
    contractHashes,
  };
  assert.doesNotThrow(() => validatePerformanceEvidence(evidence, contract, options));
  for (const [label, mutate, diagnostic] of [
    ["release version", (value) => value.release_version = "0.5.1", "release_version mismatch"],
    ["source commit", (value) => value.source_commit = "c".repeat(40), "source_commit mismatch"],
    ["generated at", (value) => value.generated_at = "2026-07-18T00:00:00Z", "generated_at mismatch"],
    ["contract hashes", (value) => value.contract_hashes[0].sha256 = "d".repeat(64), "contract hashes mismatch"],
  ]) {
    const drifted = structuredClone(evidence);
    mutate(drifted);
    assert.throws(() => validatePerformanceEvidence(drifted, contract, options), new RegExp(diagnostic), label);
  }
});

test("performance contract is a closed unique machine contract", () => {
  const raw = JSON.parse(readFileSync(contractPath, "utf8"));
  assert.deepEqual(Object.keys(raw).sort(), ["scenarios", "schema_version"]);
  assert.equal(raw.schema_version, "redevplugin.performance_contract.v1");
  assert.equal(raw.scenarios.length, 11);
  assert.equal(new Set(raw.scenarios.map((scenario) => scenario.id)).size, 11);
});

function measurementsFrom(contract, gate) {
  return contract.scenarios.map((scenario) => ({
    id: scenario.id,
    gate,
    status: "pass",
    sample_count: scenario.sample_count,
    metrics: scenario.metrics.map((metric) => ({
      ...metric,
      observed: metric.comparator === "eq" ? metric.limit : Math.max(0, metric.limit - 1),
    })),
  }));
}
