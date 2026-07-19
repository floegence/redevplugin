import assert from "node:assert/strict";
import test from "node:test";

import {
  buildRepeatedRouteAuthorizationScenarios,
  buildRouteAuthorizationComparisonReport,
  validateRouteAuthorizationComparisonReport,
} from "./route_authorization_comparison.mjs";
import {
  preparePublishedReleasePerformanceFixture,
  rebindPublishedReleasePerformanceSourceCommit,
} from "./published_release_verifier_fixture.mjs";

test("published release fixture derives release comparison scenarios from synchronized raw profiles", () => {
  const baselineCommit = "a".repeat(40);
  const candidateCommit = "b".repeat(40);
  const probe = {
    id: "httpadapter.route-authorization-v051",
    baseline_release: "0.5.1",
    baseline_commit: baselineCommit,
    repetitions: 3,
  };
  const baselines = Array.from({ length: 3 }, () => profile("v0.5.1", baselineCommit, 100));
  const candidates = Array.from({ length: 3 }, () => profile("v0.6.0", candidateCommit, 160));
  const evidence = {
    scenarios: [
      {
        id: "runtime.synthetic",
        gate: "smoke",
        status: "pass",
        sample_count: 1,
        metrics: [{ name: "latency", unit: "milliseconds", observed: 20, limit: 10, comparator: "lte" }],
      },
      ...buildRepeatedRouteAuthorizationScenarios(baselines, candidates, "smoke"),
    ],
    comparisons: [buildRouteAuthorizationComparisonReport(probe, baselines, candidates)],
  };

  const prepared = preparePublishedReleasePerformanceFixture(evidence);

  assert.notStrictEqual(prepared, evidence);
  assert.equal(evidence.scenarios[0].gate, "smoke");
  assert.equal(prepared.scenarios[0].gate, "release");
  assert.equal(prepared.scenarios[0].metrics[0].observed, 10);
  assert.doesNotThrow(() => validateRouteAuthorizationComparisonReport(
    prepared.comparisons[0],
    probe,
    candidateCommit,
    prepared.scenarios,
  ));
  for (const run of prepared.comparisons[0].runs) {
    assert.deepEqual(run.candidate_profile.measurements, run.baseline_profile.measurements);
  }
});

test("published release fixture rebinds every comparison candidate to a new source commit", () => {
  const baselineCommit = "a".repeat(40);
  const candidateCommit = "b".repeat(40);
  const reboundCommit = "c".repeat(40);
  const probe = {
    id: "httpadapter.route-authorization-v051",
    baseline_release: "0.5.1",
    baseline_commit: baselineCommit,
    repetitions: 3,
  };
  const baselines = Array.from({ length: 3 }, () => profile("v0.5.1", baselineCommit, 100));
  const candidates = Array.from({ length: 3 }, () => profile("v0.6.0", candidateCommit, 100));
  const scenarios = buildRepeatedRouteAuthorizationScenarios(baselines, candidates, "release");
  const evidence = {
    source_commit: candidateCommit,
    scenarios,
    comparisons: [buildRouteAuthorizationComparisonReport(probe, baselines, candidates)],
  };

  const rebound = rebindPublishedReleasePerformanceSourceCommit(evidence, reboundCommit);

  assert.equal(evidence.source_commit, candidateCommit);
  assert.equal(rebound.source_commit, reboundCommit);
  assert.doesNotThrow(() => validateRouteAuthorizationComparisonReport(
    rebound.comparisons[0],
    probe,
    reboundCommit,
    rebound.scenarios,
  ));
});

function profile(variant, commit, latency) {
  return {
    schema_version: "redevplugin.route_authorization_performance.v1",
    variant,
    commit,
    environment: { os: "linux", arch: "arm64", logical_cpus: 8, gomaxprocs: 8, go_version: "go1.26.5" },
    warmup_count: 8,
    requests_per_sample: 32,
    measurements: [
      measurement(1, 1000, 32000, latency),
      measurement(100, 64, 204800, latency),
      measurement(1000, 64, 2048000, latency),
    ],
  };
}

function measurement(concurrency, batchCount, sampleCount, latency) {
  return {
    concurrency,
    batch_count: batchCount,
    sample_count: sampleCount,
    median_nanoseconds: latency - 20,
    p95_nanoseconds: latency,
    p99_nanoseconds: latency + 20,
    allocations_per_request: 10,
    bytes_per_request: 1000,
  };
}
