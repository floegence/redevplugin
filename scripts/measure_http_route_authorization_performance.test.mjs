import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildInterleavedRunOrder,
  buildRouteAuthorizationDiagnostic,
  persistRouteAuthorizationDiagnostic,
} from "./measure_http_route_authorization_performance.mjs";
import {
  assertRouteAuthorizationThresholds,
  buildRouteAuthorizationAttempt,
  buildRouteAuthorizationComparisonReport,
  buildRepeatedRouteAuthorizationScenarios,
  canonicalProfileSHA256,
  canonicalValueSHA256,
  decideRouteAuthorizationAttempt,
  validateRouteAuthorizationComparisonReport,
} from "./route_authorization_comparison.mjs";

const runOrder = buildInterleavedRunOrder(9);

test("route authorization keeps request tails at c1 and uses batch throughput at high concurrency", () => {
  const attempt = stableAttempt(1, 100, 105, 10, 10.5, 1000, 1040);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "full");
  assert.deepEqual(scenarios.map((scenario) => [scenario.id, scenario.sample_count]), [
    ["httpadapter.route-authorization-c1", 32000],
    ["httpadapter.route-authorization-c100", 204800],
    ["httpadapter.route-authorization-c1000", 2048000],
  ]);
  assert.deepEqual(scenarios[0].metrics.map((metric) => metric.name), [
    "p95_relative", "p99_relative", "allocations_increase", "allocated_bytes_relative",
  ]);
  for (const scenario of scenarios.slice(1)) {
    assert.deepEqual(scenario.metrics.map((metric) => metric.name), [
      "batch_median_relative", "batch_p95_relative", "allocations_increase", "allocated_bytes_relative",
    ]);
  }
  assert.doesNotThrow(() => assertRouteAuthorizationThresholds(scenarios));
});

test("high-concurrency scheduler tails do not masquerade as handler regressions", () => {
  const baselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 10, 1000));
  const candidates = Array.from({ length: 9 }, (_, index) => profile("v0.6.0", 100, 10, 1000));
  const tails = [700000, 61000, 158000, 62000, 76000, 710000, 68000, 77000, 63000];
  candidates.forEach((candidate, index) => {
    candidate.measurements[1].p99_nanoseconds = tails[index];
    candidate.measurements[2].p99_nanoseconds = tails.at(-(index + 1));
  });
  const attempt = buildRouteAuthorizationAttempt(probe(), 1, runOrder, baselines, candidates);
  assert.equal(attempt.noise_qualification.status, "qualified");
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "release");
  assert.doesNotThrow(() => assertRouteAuthorizationThresholds(scenarios));
});

test("paired ratios preserve local AB/BA comparison instead of independent medians", () => {
  const baselineLatencies = [100, 200, 300, 100, 200, 300, 100, 200, 300];
  const candidateLatencies = [210, 300, 220, 210, 300, 220, 210, 300, 220];
  const baselines = baselineLatencies.map((latency) => profile("v0.5.1", latency, 10, 1000));
  const candidates = candidateLatencies.map((latency) => profile("v0.6.0", latency, 11, 1040));
  const attempt = buildRouteAuthorizationAttempt(probe(), 1, runOrder, baselines, candidates);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "full");
  for (const scenario of scenarios) {
    const metricName = scenario.id.endsWith("c1") ? "p95_relative" : "batch_median_relative";
    assert.equal(scenario.metrics.find((metric) => metric.name === metricName).observed, 15000);
  }
});

test("noise qualification is cross-platform, bounded, and cannot retry stable regressions", () => {
  const noisyBaselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 10, 1000));
  const noisyCandidates = Array.from({ length: 9 }, (_, index) => profile("v0.6.0", index === 8 ? 180 : 100, 10, 1000));
  const first = buildRouteAuthorizationAttempt(probe(), 1, runOrder, noisyBaselines, noisyCandidates);
  assert.equal(first.noise_qualification.status, "noisy");
  assert.equal(decideRouteAuthorizationAttempt(first, [], "release", 3), "retrying_noise");

  const third = buildRouteAuthorizationAttempt(probe(), 3, runOrder, noisyBaselines, noisyCandidates);
  assert.equal(decideRouteAuthorizationAttempt(third, [], "release", 3), "noise_exhausted");

  const stableRegression = stableAttempt(1, 100, 120, 10, 10, 1000, 1000);
  assert.equal(stableRegression.noise_qualification.status, "qualified");
  const failedScenarios = buildRepeatedRouteAuthorizationScenarios(stableRegression, "release");
  assert.equal(decideRouteAuthorizationAttempt(stableRegression, failedScenarios, "release", 3), "threshold_failed");
});

test("batch p95 tolerates bounded tails while batch median keeps the strict noise budget", () => {
  const ratios = [1, 1.12, 0.88, 1.05, 0.95, 1.1, 0.9, 1.08, 1];
  const baselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 10, 1000));
  const candidates = Array.from({ length: 9 }, () => profile("v0.6.0", 100, 10, 1000));
  for (const baseline of baselines) {
    for (const measurement of baseline.measurements.slice(1)) measurement.batch_p95_nanoseconds_per_request = 200;
  }
  candidates.forEach((candidate, index) => {
    for (const measurement of candidate.measurements.slice(1)) {
      measurement.batch_p95_nanoseconds_per_request = 200 * ratios[index];
    }
  });
  const attempt = buildRouteAuthorizationAttempt(probe(), 1, runOrder, baselines, candidates);
  assert.equal(attempt.noise_qualification.status, "qualified");
  const p95Metric = attempt.noise_qualification.metrics.find((metric) => metric.id === "c100.batch_p95_relative");
  assert.ok(p95Metric.relative_mad_basis_points > 750);
  assert.ok(p95Metric.relative_mad_basis_points <= 1250);
  const medianMetric = attempt.noise_qualification.metrics.find((metric) => metric.id === "c100.batch_median_relative");
  assert.equal(medianMetric.relative_mad_limit_basis_points, 750);
});

test("comparison provenance closes every noisy and accepted raw attempt", () => {
  const noisyBaselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 10, 1000));
  const noisyCandidates = Array.from({ length: 9 }, (_, index) => profile("v0.6.0", index === 8 ? 180 : 100, 10, 1000));
  const noisy = buildRouteAuthorizationAttempt(probe(), 1, runOrder, noisyBaselines, noisyCandidates);
  const accepted = stableAttempt(2, 100, 104, 10, 11, 1000, 1040);
  const report = buildRouteAuthorizationComparisonReport(probe(), [noisy, accepted], 2);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(accepted, "release");
  assert.equal(report.attempts.length, 2);
  assert.equal(report.attempts[0].runs.length, 9);
  assert.doesNotThrow(() => validateRouteAuthorizationComparisonReport(report, probe(), "b".repeat(40), scenarios));

  const tampered = structuredClone(report);
  tampered.attempts[0].runs[0].candidate_profile_sha256 = "0".repeat(64);
  assert.throws(
    () => validateRouteAuthorizationComparisonReport(tampered, probe(), "b".repeat(40), scenarios),
    /attempt identity|profile evidence/,
  );

  const qualifiedRetry = structuredClone(report);
  qualifiedRetry.attempts[0] = stableAttempt(1, 100, 104, 10, 11, 1000, 1040);
  assert.throws(
    () => validateRouteAuthorizationComparisonReport(qualifiedRetry, probe(), "b".repeat(40), scenarios),
    /retried a qualified attempt/,
  );
});

test("diagnostics close raw attempts and the final decision under one canonical hash", () => {
  const noisyBaselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 10, 1000));
  const noisyCandidates = Array.from({ length: 9 }, (_, index) => profile("v0.6.0", index === 8 ? 180 : 100, 10, 1000));
  const noisy = buildRouteAuthorizationAttempt(probe(), 1, runOrder, noisyBaselines, noisyCandidates);
  const accepted = stableAttempt(2, 100, 104, 10, 11, 1000, 1040);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(accepted, "release");
  const diagnostic = buildRouteAuthorizationDiagnostic(probe(), "b".repeat(40), "accepted", [noisy, accepted], 2, scenarios);
  const { diagnostic_sha256: digest, ...payload } = diagnostic;
  assert.equal(digest, canonicalValueSHA256(payload));
  assert.deepEqual(diagnostic.attempts, [noisy, accepted]);
  assert.equal(diagnostic.attempts[0].noise_qualification.status, "noisy");
  assert.equal(diagnostic.attempts[1].noise_qualification.status, "qualified");
  assert.equal(diagnostic.accepted_attempt, 2);
  assert.equal(diagnostic.decision, "accepted");
  assert.equal(diagnostic.schema_version, "redevplugin.route_authorization_diagnostic.v2");
  assert.equal(diagnostic.threshold_results.length, 3);
  assert.equal(Object.hasOwn(diagnostic.threshold_results[0], "status"), false);
  assert.equal(Object.hasOwn(diagnostic.threshold_results[0], "gate"), false);
  assert.ok(diagnostic.threshold_results.every((result) => result.metrics.every((metric) => metric.passed)));

  diagnostic.attempts[0].runs[0].candidate_profile.p99_nanoseconds = 1;
  const { diagnostic_sha256: tamperedDigest, ...tamperedPayload } = diagnostic;
  assert.notEqual(tamperedDigest, canonicalValueSHA256(tamperedPayload));
});

test("threshold failure diagnostics expose failed raw results without pass status", () => {
  const attempt = stableAttempt(1, 100, 120, 10, 10, 1000, 1000);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "release");
  assert.equal(decideRouteAuthorizationAttempt(attempt, scenarios, "release", 3), "threshold_failed");
  const diagnostic = buildRouteAuthorizationDiagnostic(
    probe(),
    "b".repeat(40),
    "threshold_failed",
    [attempt],
    1,
    scenarios,
  );
  assert.equal(diagnostic.decision, "threshold_failed");
  assert.equal(Object.hasOwn(diagnostic, "scenarios"), false);
  assert.ok(diagnostic.threshold_results.some((result) => result.metrics.some((metric) => !metric.passed)));
  for (const result of diagnostic.threshold_results) {
    assert.deepEqual(Object.keys(result).sort(), ["id", "metrics", "sample_count"]);
  }
  const { diagnostic_sha256: digest, ...payload } = diagnostic;
  assert.equal(digest, canonicalValueSHA256(payload));
});

test("diagnostics are persisted as the exact hashed artifact before gate failure", (t) => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "redevplugin-route-authorization-diagnostic-"));
  t.after(() => rmSync(temporaryRoot, { recursive: true, force: true }));
  const attempt = stableAttempt(1, 100, 120, 10, 10, 1000, 1000);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "release");
  const diagnostic = buildRouteAuthorizationDiagnostic(
    probe(),
    "b".repeat(40),
    "threshold_failed",
    [attempt],
    1,
    scenarios,
  );
  const path = join(temporaryRoot, "diagnostic.json");
  let emitted = "";
  persistRouteAuthorizationDiagnostic(path, diagnostic, { write: (value) => { emitted += value; } });
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), diagnostic);
  assert.deepEqual(JSON.parse(emitted), { route_authorization_diagnostic: diagnostic });
  const { diagnostic_sha256: digest, ...payload } = diagnostic;
  assert.equal(digest, canonicalValueSHA256(payload));
});

test("route authorization rejects environment drift and preserves fractional allocations", () => {
  const baselines = Array.from({ length: 9 }, () => profile("v0.5.1", 100, 7.51, 1000));
  const candidates = Array.from({ length: 9 }, () => profile("v0.6.0", 100, 9.49, 1000));
  candidates[0].environment.os = "darwin";
  assert.throws(
    () => buildRouteAuthorizationAttempt(probe(), 1, runOrder, baselines, candidates),
    /different runner environments/,
  );
  candidates[0].environment.os = "linux";
  const attempt = buildRouteAuthorizationAttempt(probe(), 1, runOrder, baselines, candidates);
  const scenarios = buildRepeatedRouteAuthorizationScenarios(attempt, "full");
  assert.equal(scenarios[0].metrics.find((metric) => metric.name === "allocations_increase").observed, 1.98);
  assert.throws(() => assertRouteAuthorizationThresholds(scenarios), /allocations_increase 1.98 exceeds 1/);
});

test("profile hashes are key-order independent and process order is balanced", () => {
  const original = profile("v0.6.0", 104, 11, 1040);
  const reordered = Object.fromEntries(Object.entries(original).reverse());
  reordered.environment = Object.fromEntries(Object.entries(original.environment).reverse());
  reordered.measurements = original.measurements.map((measurement) => Object.fromEntries(Object.entries(measurement).reverse()));
  assert.equal(canonicalProfileSHA256(reordered), canonicalProfileSHA256(original));
  assert.deepEqual(runOrder, [
    "baseline", "candidate", "candidate", "baseline", "baseline", "candidate",
    "candidate", "baseline", "baseline", "candidate", "candidate", "baseline",
    "baseline", "candidate", "candidate", "baseline", "baseline", "candidate",
  ]);
  assert.throws(() => buildInterleavedRunOrder(3), /exactly nine repetitions/);
});

function probe() {
  return {
    id: "httpadapter.route-authorization-v051",
    baseline_release: "0.5.1",
    baseline_commit: "a".repeat(40),
    repetitions: 9,
    max_attempts: 3,
    noise_qualification: {
      batch_median_relative: {
        relative_mad_limit_basis_points: 750,
        maximum_relative_deviation_limit_basis_points: 2500,
        order_bias_limit_basis_points: 750,
      },
      batch_p95_relative: {
        relative_mad_limit_basis_points: 1250,
        maximum_relative_deviation_limit_basis_points: 5000,
        order_bias_limit_basis_points: 2000,
      },
    },
  };
}

function stableAttempt(attemptNumber, baselineLatency, candidateLatency, baselineAllocations, candidateAllocations, baselineBytes, candidateBytes) {
  const baselines = Array.from({ length: 9 }, () => profile("v0.5.1", baselineLatency, baselineAllocations, baselineBytes));
  const candidates = Array.from({ length: 9 }, () => profile("v0.6.0", candidateLatency, candidateAllocations, candidateBytes));
  return buildRouteAuthorizationAttempt(probe(), attemptNumber, runOrder, baselines, candidates);
}

function profile(variant, latency, allocations, bytes) {
  return {
    schema_version: "redevplugin.route_authorization_performance.v2",
    variant,
    commit: variant === "v0.5.1" ? "a".repeat(40) : "b".repeat(40),
    environment: { os: "linux", arch: "amd64", logical_cpus: 8, gomaxprocs: 8, go_version: "go1.26.0" },
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
    batch_median_nanoseconds_per_request: latency,
    batch_p95_nanoseconds_per_request: latency,
    allocations_per_request: allocations,
    bytes_per_request: bytes,
  };
}
