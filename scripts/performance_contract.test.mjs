#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { resolve } from "node:path";

import {
  readPerformanceContract,
  validatePerformanceEvidence,
  validatePerformanceScenarios,
} from "./performance_contract.mjs";
import {
  buildRouteAuthorizationComparisonReport,
  buildRepeatedRouteAuthorizationScenarios,
  buildRouteAuthorizationScenarios,
  canonicalProfileSHA256,
} from "./route_authorization_comparison.mjs";

const contractPath = resolve(import.meta.dirname, "../spec/plugin/performance-contract-v3.json");

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
    schema_version: "redevplugin.performance_evidence.v3",
    release_version: "0.6.0",
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
    scenarios: measurementsFrom(contract, "release", "b".repeat(40)),
    comparisons: [comparisonFrom(contract, "b".repeat(40))],
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
  for (const generatedAt of [
    "2026-02-30T00:00:00Z",
    "2026-07-17T24:00:00Z",
    "2026-07-17T00:00:00+24:00",
    "2026-07-17T00:00:00",
  ]) {
    const invalid = structuredClone(evidence);
    invalid.generated_at = generatedAt;
    assert.throws(
      () => validatePerformanceEvidence(invalid, contract, { ...options, generatedAt: undefined }),
      /generated_at is invalid/,
      generatedAt,
    );
  }
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

test("performance evidence requires provenance for every pinned comparison probe", () => {
  const contract = readPerformanceContract(contractPath);
  const evidence = {
    schema_version: "redevplugin.performance_evidence.v3",
    release_version: "0.6.0",
    source_commit: "b".repeat(40),
    generated_at: "2026-07-20T00:00:00Z",
    environment: {
      os: "linux",
      arch: "x64",
      logical_cpus: 8,
      go_version: "go version go1.26.0 linux/amd64",
      node_version: "v24.0.0",
      rustc_version: "rustc 1.88.0",
      chromium_version: "Chromium 138.0.0",
    },
    scenarios: measurementsFrom(contract, "release"),
    contract_hashes: [{ id: "performance-contract", sha256: "a".repeat(64) }],
  };
  assert.throws(
    () => validatePerformanceEvidence(evidence, contract, {
      expectedGate: "release",
      releaseVersion: evidence.release_version,
      sourceCommit: evidence.source_commit,
      generatedAt: evidence.generated_at,
      contractHashes: evidence.contract_hashes,
    }),
    /comparison provenance/,
  );
});

test("performance evidence rejects malformed raw route authorization profiles", () => {
  const contract = readPerformanceContract(contractPath);
  const contractHashes = [{ id: "performance-contract", sha256: "a".repeat(64) }];
  const evidence = {
    schema_version: "redevplugin.performance_evidence.v3",
    release_version: "0.6.0",
    source_commit: "b".repeat(40),
    generated_at: "2026-07-20T00:00:00Z",
    environment: {
      os: "linux",
      arch: "x64",
      logical_cpus: 8,
      go_version: "go version go1.26.0 linux/amd64",
      node_version: "v24.0.0",
      rustc_version: "rustc 1.88.0",
      chromium_version: "Chromium 138.0.0",
    },
    scenarios: measurementsFrom(contract, "release", "b".repeat(40)),
    comparisons: [comparisonFrom(contract, "b".repeat(40))],
    contract_hashes: contractHashes,
  };
  const options = {
    expectedGate: "release",
    releaseVersion: evidence.release_version,
    sourceCommit: evidence.source_commit,
    generatedAt: evidence.generated_at,
    contractHashes,
  };
  const cases = [
    ["empty operating system", (profile) => profile.environment.os = "", /environment/],
    ["zero logical CPUs", (profile) => profile.environment.logical_cpus = 0, /environment/],
    ["zero median", (profile) => profile.measurements[0].median_nanoseconds = 0, /median_nanoseconds/],
    ["p95 below median", (profile) => profile.measurements[0].p95_nanoseconds = profile.measurements[0].median_nanoseconds - 1, /percentile order/],
    ["p99 below p95", (profile) => profile.measurements[0].p99_nanoseconds = profile.measurements[0].p95_nanoseconds - 1, /percentile order/],
    ["reordered measurements", (profile) => profile.measurements.reverse(), /sample shape/],
  ];
  for (const [label, mutate, diagnostic] of cases) {
    const invalid = structuredClone(evidence);
    const run = invalid.comparisons[0].runs[0];
    mutate(run.candidate_profile);
    run.candidate_profile_sha256 = canonicalProfileSHA256(run.candidate_profile);
    assert.throws(() => validatePerformanceEvidence(invalid, contract, options), diagnostic, label);
  }
});

test("performance contract is a closed unique machine contract", () => {
  const raw = JSON.parse(readFileSync(contractPath, "utf8"));
  assert.deepEqual(Object.keys(raw).sort(), ["comparison_probes", "scenarios", "schema_version"]);
  assert.equal(raw.schema_version, "redevplugin.performance_contract.v3");
  assert.equal(raw.scenarios.length, 25);
  assert.equal(new Set(raw.scenarios.map((scenario) => scenario.id)).size, 25);
});

test("performance contract closes the platform acceptance targets", () => {
  const contract = readPerformanceContract(contractPath);
  const scenarios = new Map(contract.scenarios.map((scenario) => [scenario.id, scenario]));
  const targets = {
    "httpadapter.route-authorization-c1": ["p95_relative", "basis_points", "lte", 11000],
    "httpadapter.route-authorization-c100": ["p95_relative", "basis_points", "lte", 11000],
    "httpadapter.route-authorization-c1000": ["p95_relative", "basis_points", "lte", 11000],
    "plugindata.namespace-cache-warm": ["relative_allocations", "basis_points", "lte", 3000],
    "connectivity.http-keepalive": ["p95_relative_to_connect", "basis_points", "lte", 7000],
    "runtime.ipc-writer-burst": ["peak_rss_bytes", "bytes", "lte", 67108864],
    "pluginpkg.package-owned-materialization": ["peak_rss_relative_to_cloned", "basis_points", "lte", 6500],
    "pluginpkg.wasm-inspection-cache": ["inspector_calls", "count", "eq", 1],
    "registry.sqlite-authorization-scaling": ["p95_1000_grants_relative_to_1", "basis_points", "lte", 20000],
    "operation.memory-store-snapshot": ["relative_allocations", "basis_points", "lte", 2000],
    "stream.memory-store-snapshot": ["relative_allocations", "basis_points", "lte", 2000],
    "runtime.scheduler-indexed-cancel": ["index_lookups", "count", "eq", 10000],
    "runtime.module-cache-indexed-eviction": ["index_pops_per_eviction", "basis_points", "eq", 10000],
    "connectivity.udp-limiter-scaling": ["bucket_capacity", "count", "eq", 65536],
  };
  for (const [scenarioID, [metricName, unit, comparator, limit]] of Object.entries(targets)) {
    const scenario = scenarios.get(scenarioID);
    assert.ok(scenario, `missing scenario ${scenarioID}`);
    const metric = scenario.metrics.find((candidate) => candidate.name === metricName);
    assert.deepEqual(metric, { name: metricName, unit, comparator, limit });
  }
});

test("performance contract pins the immutable v0.5.1 route authorization probe", () => {
  const contract = readPerformanceContract(contractPath);
  assert.equal(contract.comparison_probes.length, 1);
  const probe = contract.comparison_probes[0];
  assert.equal(probe.id, "httpadapter.route-authorization-v051");
  assert.equal(probe.baseline_release, "0.5.1");
  assert.equal(probe.baseline_commit, "3febcc59bbdb2118a4f105781b4c743bc11ba09f");
  assert.equal(probe.repetitions, 3);
  assert.equal(probe.requests_per_sample, 32);
  assert.deepEqual(probe.measured_batches, [
    { concurrency: 1, batches: 1000, samples: 32000 },
    { concurrency: 100, batches: 64, samples: 204800 },
    { concurrency: 1000, batches: 64, samples: 2048000 },
  ]);
  for (const source of [probe.runner, probe.comparison_logic, probe.baseline_probe, probe.candidate_probe, probe.shared_probe]) {
    const raw = readFileSync(resolve(import.meta.dirname, "..", source.path));
    assert.equal(createHash("sha256").update(raw).digest("hex"), source.sha256, source.path);
  }
});

function measurementsFrom(contract, gate, sourceCommit = "b".repeat(40)) {
  const comparisonScenarios = buildRepeatedRouteAuthorizationScenarios(
    repeatedProfiles("v0.5.1", "3febcc59bbdb2118a4f105781b4c743bc11ba09f", [100, 102, 98]),
    repeatedProfiles("v0.6.0", sourceCommit, [104, 103, 105]),
    gate,
  );
  const comparisonByID = new Map(comparisonScenarios.map((scenario) => [scenario.id, scenario]));
  return contract.scenarios.map((scenario) => comparisonByID.get(scenario.id) ?? ({
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

function comparisonFrom(contract, sourceCommit) {
  return buildRouteAuthorizationComparisonReport(
    contract.comparison_probes[0],
    repeatedProfiles("v0.5.1", "3febcc59bbdb2118a4f105781b4c743bc11ba09f", [100, 102, 98]),
    repeatedProfiles("v0.6.0", sourceCommit, [104, 103, 105]),
  );
}

function repeatedProfiles(variant, commit, latencies) {
  return latencies.map((latency) => routeAuthorizationProfile(variant, commit, latency));
}

function routeAuthorizationProfile(variant, commit, latency) {
  return {
    schema_version: "redevplugin.route_authorization_performance.v1",
    variant,
    commit,
    environment: {
      os: "linux",
      arch: "amd64",
      logical_cpus: 8,
      gomaxprocs: 8,
      go_version: "go1.26.0",
    },
    warmup_count: 8,
    requests_per_sample: 32,
    measurements: [
      routeAuthorizationMeasurement(1, 1000, 32000, latency),
      routeAuthorizationMeasurement(100, 64, 204800, latency),
      routeAuthorizationMeasurement(1000, 64, 2048000, latency),
    ],
  };
}

function routeAuthorizationMeasurement(concurrency, batchCount, sampleCount, latency) {
  return {
    concurrency,
    batch_count: batchCount,
    sample_count: sampleCount,
    median_nanoseconds: latency,
    p95_nanoseconds: latency,
    p99_nanoseconds: latency,
    allocations_per_request: 7,
    bytes_per_request: 1040,
  };
}
