import assert from "node:assert/strict";
import test from "node:test";

import { buildInterleavedRunOrder } from "./measure_http_route_authorization_performance.mjs";

import {
  assertRouteAuthorizationThresholds,
  buildRouteAuthorizationComparisonReport,
  buildRepeatedRouteAuthorizationScenarios,
  buildRouteAuthorizationScenarios,
  canonicalProfileSHA256,
  validateRouteAuthorizationComparisonReport,
} from "./route_authorization_comparison.mjs";

test("route authorization comparison emits closed c1 c100 and c1000 scenarios", () => {
  const baseline = profile("v0.5.1", 100, 10, 1000);
  const candidate = profile("v0.6.0", 105, 10.5, 1040);
  const scenarios = buildRouteAuthorizationScenarios(baseline, candidate, "full");
  assert.deepEqual(scenarios.map((scenario) => [scenario.id, scenario.sample_count]), [
    ["httpadapter.route-authorization-c1", 32000],
    ["httpadapter.route-authorization-c100", 204800],
    ["httpadapter.route-authorization-c1000", 2048000],
  ]);
  for (const scenario of scenarios) {
    assert.deepEqual(scenario.metrics.map((metric) => [metric.name, metric.limit]), [
      ["p95_relative", 11000],
      ["p99_relative", 11500],
      ["allocations_increase", 1],
      ["allocated_bytes_relative", 10500],
    ]);
  }
  assert.doesNotThrow(() => assertRouteAuthorizationThresholds(scenarios));
});

test("route authorization comparison rejects runner drift and threshold failures", () => {
  const baseline = profile("v0.5.1", 100, 10, 1000);
  const drifted = profile("v0.6.0", 100, 10, 1000);
  drifted.environment.gomaxprocs = 4;
  assert.throws(() => buildRouteAuthorizationScenarios(baseline, drifted, "full"), /different runner environments/);

  const regressed = profile("v0.6.0", 120, 12, 1200);
  const scenarios = buildRouteAuthorizationScenarios(baseline, regressed, "full");
  assert.throws(() => assertRouteAuthorizationThresholds(scenarios), /exceeds/);
});

test("route authorization allocation regression preserves fractional request averages", () => {
  const baseline = profile("v0.5.1", 100, 7.51, 1000);
  const candidate = profile("v0.6.0", 100, 9.49, 1000);
  const scenarios = buildRouteAuthorizationScenarios(baseline, candidate, "full");
  for (const scenario of scenarios) {
    assert.equal(scenario.metrics.find((metric) => metric.name === "allocations_increase").observed, 1.98);
  }
  assert.throws(() => assertRouteAuthorizationThresholds(scenarios), /allocations_increase 1.98 exceeds 1/);
});

test("route authorization comparison uses the ratio of independent profile medians", () => {
  const baselines = [
    profile("v0.5.1", 100, 10, 1000),
    profile("v0.5.1", 200, 10, 1000),
    profile("v0.5.1", 300, 10, 1000),
  ];
  const candidates = [
    profile("v0.6.0", 210, 11, 1040),
    profile("v0.6.0", 300, 11, 1040),
    profile("v0.6.0", 220, 11, 1040),
  ];
  const scenarios = buildRepeatedRouteAuthorizationScenarios(baselines, candidates, "full");
  for (const scenario of scenarios) {
    assert.equal(scenario.metrics.find((metric) => metric.name === "p95_relative").observed, 11000);
    assert.equal(scenario.metrics.find((metric) => metric.name === "p99_relative").observed, 11000);
    assert.equal(scenario.metrics.find((metric) => metric.name === "allocations_increase").observed, 1);
    assert.equal(scenario.metrics.find((metric) => metric.name === "allocated_bytes_relative").observed, 10400);
  }
  assert.deepEqual(
    buildRepeatedRouteAuthorizationScenarios(baselines, [...candidates].reverse(), "full"),
    scenarios,
  );
});

test("route authorization comparison provenance closes nine raw profile runs", () => {
  const probe = {
    id: "httpadapter.route-authorization-v051",
    baseline_release: "0.5.1",
    baseline_commit: "a".repeat(40),
    repetitions: 9,
  };
  const baselines = Array.from({ length: probe.repetitions }, () => profile("v0.5.1", 100, 10, 1000));
  const candidates = Array.from({ length: probe.repetitions }, () => profile("v0.6.0", 104, 11, 1040));
  const report = buildRouteAuthorizationComparisonReport(probe, baselines, candidates);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(baselines, candidates, "release");

  assert.equal(report.runs.length, 9);
  assert.doesNotThrow(() => validateRouteAuthorizationComparisonReport(report, probe, "b".repeat(40), scenarios));

  const missingRun = structuredClone(report);
  missingRun.runs.pop();
  assert.throws(
    () => validateRouteAuthorizationComparisonReport(missingRun, probe, "b".repeat(40), scenarios),
    /candidate commit|repetition/,
  );

  const tamperedHash = structuredClone(report);
  tamperedHash.runs[1].candidate_profile_sha256 = "0".repeat(64);
  assert.throws(
    () => validateRouteAuthorizationComparisonReport(tamperedHash, probe, "b".repeat(40), scenarios),
    /profile hash/,
  );

  const tamperedScenario = structuredClone(scenarios);
  tamperedScenario[0].metrics[0].observed += 1;
  assert.throws(
    () => validateRouteAuthorizationComparisonReport(report, probe, "b".repeat(40), tamperedScenario),
    /do not match the signed profiles/,
  );
});

test("route authorization profile hashes are independent of object key order", () => {
  const original = profile("v0.6.0", 104, 11, 1040);
  const reordered = Object.fromEntries(Object.entries(original).reverse());
  reordered.environment = Object.fromEntries(Object.entries(original.environment).reverse());
  reordered.measurements = original.measurements.map((measurement) => Object.fromEntries(Object.entries(measurement).reverse()));
  assert.equal(canonicalProfileSHA256(reordered), canonicalProfileSHA256(original));
});

test("route authorization runner balances baseline and candidate process order", () => {
  assert.deepEqual(buildInterleavedRunOrder(9), [
    "baseline", "candidate",
    "candidate", "baseline",
    "baseline", "candidate",
    "candidate", "baseline",
    "baseline", "candidate",
    "candidate", "baseline",
    "baseline", "candidate",
    "candidate", "baseline",
    "baseline", "candidate",
  ]);
  assert.throws(() => buildInterleavedRunOrder(3), /exactly nine repetitions/);
});

function profile(variant, latency, allocations, bytes) {
  return {
    schema_version: "redevplugin.route_authorization_performance.v1",
    variant,
    commit: variant === "v0.5.1" ? "a".repeat(40) : "b".repeat(40),
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
      measurement(1, 1000, 32000, latency, allocations, bytes),
      measurement(100, 64, 204800, latency, allocations, bytes),
      measurement(1000, 64, 2048000, latency, allocations, bytes),
    ],
  };
}

function measurement(concurrency, batchCount, sampleCount, latency, allocations, bytes) {
  return {
    concurrency,
    batch_count: batchCount,
    sample_count: sampleCount,
    median_nanoseconds: latency,
    p95_nanoseconds: latency,
    p99_nanoseconds: latency,
    allocations_per_request: allocations,
    bytes_per_request: bytes,
  };
}
