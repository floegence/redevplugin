import { readFileSync } from "node:fs";

import { isStrictRFC3339DateTime } from "./rfc3339.mjs";
import { validateRouteAuthorizationComparisonReport } from "./route_authorization_comparison.mjs";

const scenarioIDPattern = /^[a-z][a-z0-9._-]+$/;
const metricNamePattern = /^[a-z][a-z0-9._-]+$/;
const metricUnits = new Set(["milliseconds", "count", "bytes", "queries", "long_tasks", "basis_points"]);
const metricComparators = new Set(["eq", "lte"]);
const semanticVersionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/;
const gitCommitPattern = /^[0-9a-f]{40}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const repositoryPathPattern = /^(?:[a-z0-9._-]+\/)*[a-z0-9._-]+$/;

export function readPerformanceContract(path) {
  const contract = JSON.parse(readFileSync(path, "utf8"));
  validatePerformanceContract(contract);
  return contract;
}

export function validatePerformanceContract(contract) {
  assertRecord(contract, "performance contract");
  assertExactKeys(contract, ["schema_version", "comparison_probes", "scenarios"], "performance contract");
  if (contract.schema_version !== "redevplugin.performance_contract.v4") {
    throw new Error(`unsupported performance contract schema_version ${JSON.stringify(contract.schema_version)}`);
  }
  validateComparisonProbes(contract.comparison_probes);
  if (!Array.isArray(contract.scenarios) || contract.scenarios.length === 0) {
    throw new Error("performance contract scenarios must be a non-empty array");
  }
  const scenarioIDs = new Set();
  for (const [index, scenario] of contract.scenarios.entries()) {
    const label = `performance contract scenarios[${index}]`;
    assertRecord(scenario, label);
    assertExactKeys(scenario, ["id", "sample_count", "metrics"], label);
    if (typeof scenario.id !== "string" || !scenarioIDPattern.test(scenario.id) || scenarioIDs.has(scenario.id)) {
      throw new Error(`${label}.id is invalid or duplicated`);
    }
    if (!Number.isSafeInteger(scenario.sample_count) || scenario.sample_count < 1) {
      throw new Error(`${label}.sample_count must be a positive integer`);
    }
    if (!Array.isArray(scenario.metrics) || scenario.metrics.length === 0) {
      throw new Error(`${label}.metrics must be a non-empty array`);
    }
    const metricNames = new Set();
    for (const [metricIndex, metric] of scenario.metrics.entries()) {
      const metricLabel = `${label}.metrics[${metricIndex}]`;
      assertRecord(metric, metricLabel);
      assertExactKeys(metric, ["name", "unit", "comparator", "limit"], metricLabel);
      if (typeof metric.name !== "string" || !metricNamePattern.test(metric.name) || metricNames.has(metric.name)) {
        throw new Error(`${metricLabel}.name is invalid or duplicated`);
      }
      if (!metricUnits.has(metric.unit)) throw new Error(`${metricLabel}.unit is invalid`);
      if (!metricComparators.has(metric.comparator)) throw new Error(`${metricLabel}.comparator is invalid`);
      if (!Number.isFinite(metric.limit) || metric.limit < 0) throw new Error(`${metricLabel}.limit must be finite and non-negative`);
      metricNames.add(metric.name);
    }
    scenarioIDs.add(scenario.id);
  }
}

function validateComparisonProbes(probes) {
  if (!Array.isArray(probes) || probes.length === 0) {
    throw new Error("performance contract comparison_probes must be a non-empty array");
  }
  const ids = new Set();
  for (const [index, probe] of probes.entries()) {
    const label = `performance contract comparison_probes[${index}]`;
    assertRecord(probe, label);
    assertExactKeys(probe, [
      "id",
      "baseline_release",
      "baseline_commit",
      "repetitions",
      "max_attempts",
      "warmup_batches",
      "requests_per_sample",
      "measured_batches",
      "noise_qualification",
      "runner",
      "comparison_logic",
      "baseline_probe",
      "candidate_probe",
      "shared_probe",
    ], label);
    if (typeof probe.id !== "string" || !scenarioIDPattern.test(probe.id) || ids.has(probe.id)) {
      throw new Error(`${label}.id is invalid or duplicated`);
    }
    if (typeof probe.baseline_release !== "string" || !semanticVersionPattern.test(probe.baseline_release)) {
      throw new Error(`${label}.baseline_release is invalid`);
    }
    if (typeof probe.baseline_commit !== "string" || !gitCommitPattern.test(probe.baseline_commit)) {
      throw new Error(`${label}.baseline_commit is invalid`);
    }
    if (probe.repetitions !== 9) {
      throw new Error(`${label}.repetitions must be exactly 9`);
    }
    if (probe.max_attempts !== 3) {
      throw new Error(`${label}.max_attempts must be exactly 3`);
    }
    if (!Number.isSafeInteger(probe.warmup_batches) || probe.warmup_batches < 8) {
      throw new Error(`${label}.warmup_batches must be at least 8`);
    }
    if (!Number.isSafeInteger(probe.requests_per_sample) || probe.requests_per_sample < 1) {
      throw new Error(`${label}.requests_per_sample must be positive`);
    }
    assertRecord(probe.noise_qualification, `${label}.noise_qualification`);
    assertExactKeys(probe.noise_qualification, ["batch_median_relative", "batch_p95_relative"], `${label}.noise_qualification`);
    for (const [metric, expected] of Object.entries({
      batch_median_relative: [750, 2500, 750],
      batch_p95_relative: [1250, 5000, 2000],
    })) {
      const limits = probe.noise_qualification[metric];
      assertRecord(limits, `${label}.noise_qualification.${metric}`);
      assertExactKeys(limits, [
        "relative_mad_limit_basis_points",
        "maximum_relative_deviation_limit_basis_points",
        "order_bias_limit_basis_points",
      ], `${label}.noise_qualification.${metric}`);
      if (limits.relative_mad_limit_basis_points !== expected[0] ||
          limits.maximum_relative_deviation_limit_basis_points !== expected[1] ||
          limits.order_bias_limit_basis_points !== expected[2]) {
        throw new Error(`${label}.noise_qualification.${metric} limits are invalid`);
      }
    }
    if (!Array.isArray(probe.measured_batches) || probe.measured_batches.length === 0) {
      throw new Error(`${label}.measured_batches must be a non-empty array`);
    }
    const concurrencies = new Set();
    for (const [batchIndex, batch] of probe.measured_batches.entries()) {
      const batchLabel = `${label}.measured_batches[${batchIndex}]`;
      assertRecord(batch, batchLabel);
      assertExactKeys(batch, ["concurrency", "batches", "samples"], batchLabel);
      if (!Number.isSafeInteger(batch.concurrency) || batch.concurrency < 1 || concurrencies.has(batch.concurrency) ||
          !Number.isSafeInteger(batch.batches) || batch.batches < 64 ||
          !Number.isSafeInteger(batch.samples) || batch.samples !== batch.concurrency * batch.batches * probe.requests_per_sample) {
        throw new Error(`${batchLabel} is invalid`);
      }
      concurrencies.add(batch.concurrency);
    }
    for (const sourceName of ["runner", "comparison_logic", "baseline_probe", "candidate_probe", "shared_probe"]) {
      const source = probe[sourceName];
      const sourceLabel = `${label}.${sourceName}`;
      assertRecord(source, sourceLabel);
      assertExactKeys(source, ["path", "sha256"], sourceLabel);
      if (typeof source.path !== "string" || !repositoryPathPattern.test(source.path) ||
          typeof source.sha256 !== "string" || !sha256Pattern.test(source.sha256)) {
        throw new Error(`${sourceLabel} is invalid`);
      }
    }
    ids.add(probe.id);
  }
}

export function validatePerformanceScenarios(scenarios, contract, options) {
  validatePerformanceContract(contract);
  if (!Array.isArray(scenarios)) throw new Error("performance evidence scenarios must be an array");
  const expectedGate = options?.expectedGate;
  const allowSmoke = options?.allowSmoke === true;
  const scenarioByID = new Map();
  const scenarioGates = new Set();
  for (const [index, scenario] of scenarios.entries()) {
    const label = `performance evidence scenarios[${index}]`;
    assertRecord(scenario, label);
    assertExactKeys(scenario, ["id", "gate", "status", "sample_count", "metrics"], label);
    if (typeof scenario.id !== "string" || scenarioByID.has(scenario.id)) {
      throw new Error(`${label}.id is invalid or duplicated`);
    }
    if (scenario.status !== "pass") throw new Error(`performance scenario ${scenario.id} status must be pass`);
    if (expectedGate !== undefined && scenario.gate !== expectedGate) {
      throw new Error(`performance scenario ${scenario.id} gate ${JSON.stringify(scenario.gate)} does not match ${expectedGate}`);
    }
    if (expectedGate === undefined && scenario.gate !== "release" && !(allowSmoke && scenario.gate === "smoke")) {
      throw new Error(`performance scenario ${scenario.id} gate must be release${allowSmoke ? " or smoke" : ""}`);
    }
    scenarioGates.add(scenario.gate);
    scenarioByID.set(scenario.id, scenario);
  }
  if (scenarioGates.size !== 1) {
    throw new Error(`performance evidence scenarios must use one gate, got ${[...scenarioGates].sort().join(", ")}`);
  }

  const expectedScenarioIDs = contract.scenarios.map((scenario) => scenario.id).sort();
  const actualScenarioIDs = [...scenarioByID.keys()].sort();
  if (!sameJSON(actualScenarioIDs, expectedScenarioIDs)) {
    throw new Error(`performance evidence scenario IDs mismatch: got ${actualScenarioIDs.join(", ")}, want ${expectedScenarioIDs.join(", ")}`);
  }

  for (const expectedScenario of contract.scenarios) {
    const scenario = scenarioByID.get(expectedScenario.id);
    if (scenario.sample_count !== expectedScenario.sample_count) {
      throw new Error(`performance scenario ${scenario.id} sample_count mismatch: got ${scenario.sample_count}, want ${expectedScenario.sample_count}`);
    }
    if (!Array.isArray(scenario.metrics)) throw new Error(`performance scenario ${scenario.id} metrics must be an array`);
    const metricByName = new Map();
    for (const [index, metric] of scenario.metrics.entries()) {
      const label = `performance scenario ${scenario.id} metrics[${index}]`;
      assertRecord(metric, label);
      assertExactKeys(metric, ["name", "unit", "observed", "limit", "comparator"], label);
      if (typeof metric.name !== "string" || metricByName.has(metric.name)) {
        throw new Error(`performance scenario ${scenario.id} has invalid or duplicate metric ${JSON.stringify(metric.name)}`);
      }
      if (!Number.isFinite(metric.observed) || metric.observed < 0) {
        throw new Error(`performance scenario ${scenario.id} metric ${metric.name} observed must be finite and non-negative`);
      }
      metricByName.set(metric.name, metric);
    }
    const expectedMetricNames = expectedScenario.metrics.map((metric) => metric.name).sort();
    const actualMetricNames = [...metricByName.keys()].sort();
    if (!sameJSON(actualMetricNames, expectedMetricNames)) {
      throw new Error(`performance scenario ${scenario.id} metric names mismatch: got ${actualMetricNames.join(", ")}, want ${expectedMetricNames.join(", ")}`);
    }
    for (const expectedMetric of expectedScenario.metrics) {
      const metric = metricByName.get(expectedMetric.name);
      for (const property of ["unit", "comparator", "limit"]) {
        if (metric[property] !== expectedMetric[property]) {
          throw new Error(`performance scenario ${scenario.id} metric ${metric.name} ${property} mismatch: got ${JSON.stringify(metric[property])}, want ${JSON.stringify(expectedMetric[property])}`);
        }
      }
      if (scenario.gate !== "smoke" && !metricPassed(metric)) {
        throw new Error(`performance scenario ${scenario.id} metric ${metric.name} failed: ${metric.observed} ${metric.comparator} ${metric.limit}`);
      }
    }
  }
}

export function validatePerformanceEvidence(evidence, contract, options) {
  assertRecord(evidence, "performance evidence");
  if (!Object.hasOwn(evidence, "comparisons")) {
    throw new Error("performance evidence comparison provenance is required");
  }
  assertExactKeys(evidence, [
    "schema_version",
    "release_version",
    "source_commit",
    "generated_at",
    "environment",
    "scenarios",
    "comparisons",
    "contract_hashes",
  ], "performance evidence");
  if (evidence.schema_version !== "redevplugin.performance_evidence.v4") {
    throw new Error(`performance evidence schema_version mismatch: ${JSON.stringify(evidence.schema_version)}`);
  }
  if (typeof evidence.release_version !== "string" || !semanticVersionPattern.test(evidence.release_version)) {
    throw new Error(`performance evidence release_version is invalid: ${JSON.stringify(evidence.release_version)}`);
  }
  if (options?.releaseVersion !== undefined && evidence.release_version !== options.releaseVersion) {
    throw new Error(`performance evidence release_version mismatch: got ${evidence.release_version}, want ${options.releaseVersion}`);
  }
  if (typeof evidence.source_commit !== "string" || !gitCommitPattern.test(evidence.source_commit)) {
    throw new Error("performance evidence source_commit is invalid");
  }
  if (options?.sourceCommit !== undefined && evidence.source_commit !== options.sourceCommit) {
    throw new Error(`performance evidence source_commit mismatch: got ${evidence.source_commit}, want ${options.sourceCommit}`);
  }
  if (!isStrictRFC3339DateTime(evidence.generated_at)) {
    throw new Error("performance evidence generated_at is invalid");
  }
  if (options?.generatedAt !== undefined && evidence.generated_at !== options.generatedAt) {
    throw new Error(`performance evidence generated_at mismatch: got ${evidence.generated_at}, want ${options.generatedAt}`);
  }

  assertRecord(evidence.environment, "performance evidence environment");
  assertExactKeys(evidence.environment, [
    "os",
    "arch",
    "logical_cpus",
    "go_version",
    "node_version",
    "rustc_version",
    "chromium_version",
  ], "performance evidence environment");
  for (const key of ["os", "arch", "go_version", "node_version", "rustc_version", "chromium_version"]) {
    if (typeof evidence.environment[key] !== "string" || evidence.environment[key].length === 0) {
      throw new Error(`performance evidence environment ${key} must be a non-empty string`);
    }
  }
  if (!Number.isSafeInteger(evidence.environment.logical_cpus) || evidence.environment.logical_cpus < 1) {
    throw new Error("performance evidence environment logical_cpus must be a positive integer");
  }

  validatePerformanceScenarios(evidence.scenarios, contract, {
    expectedGate: options?.expectedGate,
    allowSmoke: options?.allowSmoke,
  });
  validateComparisonProvenance(evidence.comparisons, contract.comparison_probes, evidence.source_commit, evidence.scenarios);

  if (!Array.isArray(evidence.contract_hashes)) throw new Error("performance evidence contract_hashes must be an array");
  const contractHashes = new Map();
  for (const [index, entry] of evidence.contract_hashes.entries()) {
    const label = `performance evidence contract_hashes[${index}]`;
    assertRecord(entry, label);
    assertExactKeys(entry, ["id", "sha256"], label);
    if (typeof entry.id !== "string" || !/^[a-z][a-z0-9-]+$/.test(entry.id) || contractHashes.has(entry.id)) {
      throw new Error(`${label}.id is invalid or duplicated`);
    }
    if (typeof entry.sha256 !== "string" || !sha256Pattern.test(entry.sha256)) {
      throw new Error(`${label}.sha256 is invalid`);
    }
    contractHashes.set(entry.id, entry.sha256);
  }
  if (options?.contractHashes !== undefined) {
    const expectedHashes = normalizedContractHashes(options.contractHashes);
    const actualHashes = normalizedContractHashes(evidence.contract_hashes);
    if (!sameJSON(actualHashes, expectedHashes)) {
      throw new Error(`performance evidence contract hashes mismatch: got ${JSON.stringify(actualHashes)}, want ${JSON.stringify(expectedHashes)}`);
    }
  }
}

function validateComparisonProvenance(comparisons, probes, sourceCommit, scenarios) {
  if (!Array.isArray(comparisons)) {
    throw new Error("performance evidence comparison provenance must be an array");
  }
  const comparisonByID = new Map();
  for (const comparison of comparisons) {
    if (typeof comparison?.id !== "string" || comparisonByID.has(comparison.id)) {
      throw new Error("performance evidence comparison provenance has an invalid or duplicate id");
    }
    comparisonByID.set(comparison.id, comparison);
  }
  const expectedIDs = probes.map((probe) => probe.id).sort();
  const actualIDs = [...comparisonByID.keys()].sort();
  if (!sameJSON(actualIDs, expectedIDs)) {
    throw new Error(`performance evidence comparison provenance IDs mismatch: got ${actualIDs.join(",")}, want ${expectedIDs.join(",")}`);
  }
  for (const probe of probes) {
    if (probe.id === "httpadapter.route-authorization-v051") {
      validateRouteAuthorizationComparisonReport(comparisonByID.get(probe.id), probe, sourceCommit, scenarios);
      continue;
    }
    throw new Error(`unsupported performance comparison probe ${probe.id}`);
  }
}

function metricPassed(metric) {
  return metric.comparator === "eq" ? metric.observed === metric.limit : metric.observed <= metric.limit;
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!sameJSON(actual, wanted)) {
    throw new Error(`${label} keys mismatch: got ${actual.join(", ")}, want ${wanted.join(", ")}`);
  }
}

function sameJSON(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function normalizedContractHashes(entries) {
  if (!Array.isArray(entries)) throw new Error("expected contract hashes must be an array");
  return entries
    .map((entry) => ({ id: entry.id, sha256: entry.sha256 }))
    .sort((left, right) => left.id.localeCompare(right.id));
}
