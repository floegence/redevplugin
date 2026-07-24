import { createHash } from "node:crypto";

const profileSchemaVersion = "redevplugin.route_authorization_performance.v2";
const comparisonID = "httpadapter.route-authorization-v051";
const gitCommitPattern = /^[0-9a-f]{40}$/;

export function buildRouteAuthorizationAttempt(probe, attemptNumber, runOrder, baselineProfiles, candidateProfiles) {
  if (!Array.isArray(baselineProfiles) || !Array.isArray(candidateProfiles) ||
      baselineProfiles.length !== probe.repetitions || candidateProfiles.length !== probe.repetitions) {
    throw new Error("route authorization comparison repetition count is invalid");
  }
  if (!Number.isSafeInteger(attemptNumber) || attemptNumber < 1 || attemptNumber > probe.max_attempts) {
    throw new Error("route authorization comparison attempt number is invalid");
  }
  validateRunOrder(runOrder, probe.repetitions);
  const environment = baselineProfiles[0]?.environment;
  for (const profile of baselineProfiles) {
    validateRouteAuthorizationProfile(profile, "v0.5.1");
    if (!sameRunnerEnvironment(profile.environment, environment)) throw new Error("route authorization profiles were measured on different runner environments");
  }
  for (const profile of candidateProfiles) {
    validateRouteAuthorizationProfile(profile, "v0.6.0");
    if (!sameRunnerEnvironment(profile.environment, environment)) throw new Error("route authorization profiles were measured on different runner environments");
  }
  if (probe.id !== comparisonID || baselineProfiles.some((profile) => profile.commit !== probe.baseline_commit)) {
		throw new Error("route authorization comparison probe does not match the pinned baseline");
	}
	const candidateCommit = candidateProfiles[0].commit;
	if (candidateProfiles.some((profile) => profile.commit !== candidateCommit)) {
		throw new Error("route authorization candidate profiles do not share one commit");
	}
	const attempt = {
		attempt: attemptNumber,
		run_order: [...runOrder],
		environment: { ...environment },
		runs: baselineProfiles.map((baselineProfile, index) => ({
			pair_index: index,
			first_variant: runOrder[index * 2],
			baseline_profile_sha256: canonicalProfileSHA256(baselineProfile),
			candidate_profile_sha256: canonicalProfileSHA256(candidateProfiles[index]),
			baseline_profile: baselineProfile,
			candidate_profile: candidateProfiles[index],
		})),
	};
	attempt.noise_qualification = qualifyRouteAuthorizationAttempt(probe, attempt);
	attempt.attempt_sha256 = canonicalValueSHA256(attempt);
	return attempt;
}

export function buildRouteAuthorizationComparisonReport(probe, attempts, acceptedAttempt) {
  if (!Array.isArray(attempts) || attempts.length < 1 || attempts.length > probe.max_attempts) {
    throw new Error("route authorization comparison attempts are incomplete");
  }
  const accepted = attempts.find((attempt) => attempt.attempt === acceptedAttempt);
  if (!accepted || accepted.noise_qualification.status !== "qualified") {
    throw new Error("route authorization comparison accepted attempt is invalid");
  }
  const candidateCommit = accepted.runs[0].candidate_profile.commit;
  if (attempts.some((attempt) => attempt.runs.some((run) => run.candidate_profile.commit !== candidateCommit))) {
    throw new Error("route authorization comparison attempts do not share one candidate commit");
  }
  return {
    id: probe.id,
    baseline_release: probe.baseline_release,
    baseline_commit: probe.baseline_commit,
    candidate_commit: candidateCommit,
    accepted_attempt: acceptedAttempt,
    attempts,
  };
}

export function buildRepeatedRouteAuthorizationScenarios(attempt, gate) {
  return buildRouteAuthorizationScenarios(attempt, gate);
}

export function buildRouteAuthorizationScenarios(attempt, gate) {
  if (!attempt || !Array.isArray(attempt.runs) || attempt.runs.length === 0) {
    throw new Error("route authorization comparison attempt is incomplete");
  }
  return [1, 100, 1000].map((concurrency, measurementIndex) => {
    const pairs = attempt.runs.map((run) => {
      const baseline = run.baseline_profile.measurements[measurementIndex];
      const candidate = run.candidate_profile.measurements[measurementIndex];
      if (baseline.concurrency !== concurrency || candidate.concurrency !== concurrency ||
          baseline.batch_count !== candidate.batch_count || baseline.sample_count !== candidate.sample_count) {
        throw new Error(`route authorization sample shape mismatch for concurrency ${concurrency}`);
      }
      return { baseline, candidate };
    });
    const latencyMetrics = concurrency === 1
      ? [
          metric("p95_relative", "basis_points", median(pairs.map(({ baseline, candidate }) => ratioBasisPoints(candidate.p95_nanoseconds, baseline.p95_nanoseconds))), 11000),
          metric("p99_relative", "basis_points", median(pairs.map(({ baseline, candidate }) => ratioBasisPoints(candidate.p99_nanoseconds, baseline.p99_nanoseconds))), 11500),
        ]
      : [
          metric("batch_median_relative", "basis_points", median(pairs.map(({ baseline, candidate }) => ratioBasisPoints(candidate.batch_median_nanoseconds_per_request, baseline.batch_median_nanoseconds_per_request))), 11000),
          metric("batch_p95_relative", "basis_points", median(pairs.map(({ baseline, candidate }) => ratioBasisPoints(candidate.batch_p95_nanoseconds_per_request, baseline.batch_p95_nanoseconds_per_request))), 11500),
        ];
    return {
      id: `httpadapter.route-authorization-c${concurrency}`,
      gate,
      status: "pass",
      sample_count: pairs[0].candidate.sample_count,
      metrics: [
        ...latencyMetrics,
        metric("allocations_increase", "count", median(pairs.map(({ baseline, candidate }) => Math.max(0, candidate.allocations_per_request - baseline.allocations_per_request))), 1),
        metric("allocated_bytes_relative", "basis_points", median(pairs.map(({ baseline, candidate }) => ratioBasisPoints(candidate.bytes_per_request, baseline.bytes_per_request))), 10500),
      ],
    };
  });
}

export function qualifyRouteAuthorizationAttempt(probe, attempt) {
  const metrics = [];
  for (const [measurementIndex, concurrency] of [[1, 100], [2, 1000]]) {
    for (const [name, field] of [
      ["batch_median_relative", "batch_median_nanoseconds_per_request"],
      ["batch_p95_relative", "batch_p95_nanoseconds_per_request"],
    ]) {
      const limits = probe.noise_qualification[name];
      const ratios = attempt.runs.map((run) => ratioBasisPoints(
        run.candidate_profile.measurements[measurementIndex][field],
        run.baseline_profile.measurements[measurementIndex][field],
      ));
      const center = median(ratios);
      const relativeMAD = relativeDeviationBasisPoints(median(ratios.map((value) => Math.abs(value - center))), center);
      const maximumRelativeDeviation = relativeDeviationBasisPoints(Math.max(...ratios.map((value) => Math.abs(value - center))), center);
      const baselineFirst = ratios.filter((_, index) => attempt.runs[index].first_variant === "baseline");
      const candidateFirst = ratios.filter((_, index) => attempt.runs[index].first_variant === "candidate");
      const orderBias = relativeDeviationBasisPoints(Math.abs(median(baselineFirst) - median(candidateFirst)), center);
      metrics.push({
        id: `c${concurrency}.${name}`,
        median_basis_points: roundMetric(center),
        relative_mad_basis_points: roundMetric(relativeMAD),
        relative_mad_limit_basis_points: limits.relative_mad_limit_basis_points,
        maximum_relative_deviation_basis_points: roundMetric(maximumRelativeDeviation),
        maximum_relative_deviation_limit_basis_points: limits.maximum_relative_deviation_limit_basis_points,
        order_bias_basis_points: roundMetric(orderBias),
        order_bias_limit_basis_points: limits.order_bias_limit_basis_points,
      });
    }
  }
  const reasons = [];
  for (const metric of metrics) {
    if (metric.relative_mad_basis_points > metric.relative_mad_limit_basis_points) reasons.push(`${metric.id}.relative_mad`);
    if (metric.maximum_relative_deviation_basis_points > metric.maximum_relative_deviation_limit_basis_points) reasons.push(`${metric.id}.maximum_relative_deviation`);
    if (metric.order_bias_basis_points > metric.order_bias_limit_basis_points) reasons.push(`${metric.id}.order_bias`);
  }
  return {
    status: reasons.length === 0 ? "qualified" : "noisy",
    reasons,
    metrics,
  };
}

export function assertRouteAuthorizationThresholds(scenarios) {
  for (const scenario of scenarios) {
    for (const metric of scenario.metrics) {
      if (metric.observed > metric.limit) {
        throw new Error(`${scenario.id} ${metric.name} ${metric.observed} exceeds ${metric.limit}`);
      }
    }
  }
}

export function decideRouteAuthorizationAttempt(attempt, scenarios, gate, maxAttempts) {
  if (attempt.noise_qualification.status === "noisy") {
    return attempt.attempt < maxAttempts ? "retrying_noise" : "noise_exhausted";
  }
  if (gate !== "smoke" && scenarios.some((scenario) => scenario.metrics.some((metric) => metric.observed > metric.limit))) {
    return "threshold_failed";
  }
  return "accepted";
}

function relativeDeviationBasisPoints(deviation, center) {
  if (!Number.isFinite(deviation) || deviation < 0 || !Number.isFinite(center) || center <= 0) {
    throw new Error("route authorization noise qualification requires positive finite values");
  }
  return deviation / center * 10000;
}

export function validateRouteAuthorizationComparisonReport(report, probe, sourceCommit, scenarios) {
  assertRecord(report, "route authorization comparison report");
  assertExactKeys(report, [
    "id",
    "baseline_release",
    "baseline_commit",
    "candidate_commit",
    "accepted_attempt",
    "attempts",
  ], "route authorization comparison report");
  if (report.id !== probe.id || report.baseline_release !== probe.baseline_release || report.baseline_commit !== probe.baseline_commit) {
    throw new Error("route authorization comparison provenance does not match the performance contract");
  }
  if (report.candidate_commit !== sourceCommit || !Array.isArray(report.attempts) || report.attempts.length < 1 ||
      report.attempts.length > probe.max_attempts || report.accepted_attempt !== report.attempts.length) {
    throw new Error("route authorization comparison candidate commit does not match performance evidence source_commit");
  }
  for (const [attemptIndex, attempt] of report.attempts.entries()) {
    validateRouteAuthorizationAttempt(attempt, probe, sourceCommit, attemptIndex + 1);
    if (attemptIndex < report.attempts.length - 1 && attempt.noise_qualification.status !== "noisy") {
      throw new Error("route authorization comparison retried a qualified attempt");
    }
  }
  const accepted = report.attempts.at(-1);
  if (accepted.noise_qualification.status !== "qualified") {
    throw new Error("route authorization comparison accepted a noisy attempt");
  }
  const comparisonScenarios = scenarios
    .filter((scenario) => scenario.id.startsWith("httpadapter.route-authorization-c"))
    .sort((left, right) => left.id.localeCompare(right.id));
  if (comparisonScenarios.length !== 3) {
    throw new Error("route authorization comparison scenarios are incomplete");
  }
  const expected = buildRouteAuthorizationScenarios(accepted, comparisonScenarios[0].gate)
    .sort((left, right) => left.id.localeCompare(right.id));
  if (JSON.stringify(comparisonScenarios) !== JSON.stringify(expected)) {
    throw new Error("route authorization comparison scenarios do not match the signed profiles");
  }
}

function validateRouteAuthorizationAttempt(attempt, probe, sourceCommit, expectedAttempt) {
  assertRecord(attempt, `route authorization comparison attempt ${expectedAttempt}`);
  assertExactKeys(attempt, ["attempt", "run_order", "environment", "runs", "noise_qualification", "attempt_sha256"], `route authorization comparison attempt ${expectedAttempt}`);
  if (attempt.attempt !== expectedAttempt || attempt.attempt_sha256 !== canonicalValueSHA256({
    attempt: attempt.attempt,
    run_order: attempt.run_order,
    environment: attempt.environment,
    runs: attempt.runs,
    noise_qualification: attempt.noise_qualification,
  })) {
    throw new Error("route authorization comparison attempt identity is invalid");
  }
  validateRunOrder(attempt.run_order, probe.repetitions);
  if (!Array.isArray(attempt.runs) || attempt.runs.length !== probe.repetitions) {
    throw new Error("route authorization comparison attempt run count is invalid");
  }
  for (const [index, run] of attempt.runs.entries()) {
    assertRecord(run, `route authorization comparison run ${index}`);
    assertExactKeys(run, ["pair_index", "first_variant", "baseline_profile_sha256", "candidate_profile_sha256", "baseline_profile", "candidate_profile"], `route authorization comparison run ${index}`);
    if (run.pair_index !== index || run.first_variant !== attempt.run_order[index * 2] ||
        run.baseline_profile.commit !== probe.baseline_commit || run.candidate_profile.commit !== sourceCommit) {
      throw new Error("route authorization comparison profile identity is invalid");
    }
    validateRouteAuthorizationProfile(run.baseline_profile, "v0.5.1");
    validateRouteAuthorizationProfile(run.candidate_profile, "v0.6.0");
    if (!sameRunnerEnvironment(run.baseline_profile.environment, attempt.environment) ||
        !sameRunnerEnvironment(run.candidate_profile.environment, attempt.environment) ||
        run.baseline_profile_sha256 !== canonicalProfileSHA256(run.baseline_profile) ||
        run.candidate_profile_sha256 !== canonicalProfileSHA256(run.candidate_profile)) {
      throw new Error("route authorization comparison profile evidence is invalid");
    }
  }
  const expectedNoise = qualifyRouteAuthorizationAttempt(probe, attempt);
  if (JSON.stringify(attempt.noise_qualification) !== JSON.stringify(expectedNoise)) {
    throw new Error("route authorization comparison noise qualification is invalid");
  }
}

function validateRunOrder(runOrder, repetitions) {
  if (!Array.isArray(runOrder) || runOrder.length !== repetitions * 2) {
    throw new Error("route authorization comparison run order is invalid");
  }
  for (let index = 0; index < repetitions; index += 1) {
    const pair = runOrder.slice(index * 2, index * 2 + 2);
    const expected = index % 2 === 0 ? ["baseline", "candidate"] : ["candidate", "baseline"];
    if (JSON.stringify(pair) !== JSON.stringify(expected)) {
      throw new Error("route authorization comparison run order is not balanced AB/BA");
    }
  }
}

export function canonicalProfileSHA256(profile) {
  return canonicalValueSHA256(profile);
}

export function canonicalValueSHA256(value) {
  return createHash("sha256").update(canonicalJSON(value)).digest("hex");
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJSON(item)).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function validateRouteAuthorizationProfile(profile, variant) {
  assertRecord(profile, `${variant} route authorization profile`);
  assertExactKeys(profile, [
    "schema_version",
    "variant",
    "commit",
    "environment",
    "warmup_count",
    "requests_per_sample",
    "measurements",
  ], `${variant} route authorization profile`);
  if (profile.schema_version !== profileSchemaVersion || profile.variant !== variant ||
      typeof profile.commit !== "string" || !gitCommitPattern.test(profile.commit) ||
      profile.warmup_count !== 8 || profile.requests_per_sample !== 32 ||
      !Array.isArray(profile.measurements) || profile.measurements.length !== 3) {
    throw new Error(`invalid ${variant} route authorization profile`);
  }
  assertRecord(profile.environment, `${variant} route authorization profile environment`);
  assertExactKeys(profile.environment, ["os", "arch", "logical_cpus", "gomaxprocs", "go_version"], `${variant} route authorization profile environment`);
  if (typeof profile.environment.os !== "string" || profile.environment.os.length === 0 ||
      typeof profile.environment.arch !== "string" || profile.environment.arch.length === 0 ||
      typeof profile.environment.go_version !== "string" || profile.environment.go_version.length === 0 ||
      !Number.isSafeInteger(profile.environment.logical_cpus) || profile.environment.logical_cpus < 1 ||
      !Number.isSafeInteger(profile.environment.gomaxprocs) || profile.environment.gomaxprocs < 1) {
    throw new Error(`invalid ${variant} route authorization profile environment`);
  }
  const expected = [[1, 1000, 32000], [100, 64, 204800], [1000, 64, 2048000]];
  for (const [index, measurement] of profile.measurements.entries()) {
    assertRecord(measurement, `${variant} route authorization measurement`);
    assertExactKeys(measurement, [
      "concurrency",
      "batch_count",
      "sample_count",
      "median_nanoseconds",
      "p95_nanoseconds",
      "p99_nanoseconds",
      "batch_median_nanoseconds_per_request",
      "batch_p95_nanoseconds_per_request",
      "allocations_per_request",
      "bytes_per_request",
    ], `${variant} route authorization measurement`);
    const sampleShape = expected[index];
    if (measurement.concurrency !== sampleShape[0] || measurement.batch_count !== sampleShape[1] || measurement.sample_count !== sampleShape[2]) {
      throw new Error(`invalid ${variant} route authorization sample shape`);
    }
    for (const key of ["median_nanoseconds", "p95_nanoseconds", "p99_nanoseconds"]) {
      if (!Number.isSafeInteger(measurement[key]) || measurement[key] < 1) {
        throw new Error(`invalid ${variant} route authorization ${key}`);
      }
    }
    if (measurement.p95_nanoseconds < measurement.median_nanoseconds || measurement.p99_nanoseconds < measurement.p95_nanoseconds) {
      throw new Error(`invalid ${variant} route authorization percentile order`);
    }
    for (const key of ["batch_median_nanoseconds_per_request", "batch_p95_nanoseconds_per_request", "allocations_per_request", "bytes_per_request"]) {
      if (!Number.isFinite(measurement[key]) || measurement[key] < 0) {
        throw new Error(`invalid ${variant} route authorization ${key}`);
      }
    }
    if (measurement.batch_median_nanoseconds_per_request <= 0 ||
        measurement.batch_p95_nanoseconds_per_request < measurement.batch_median_nanoseconds_per_request) {
      throw new Error(`invalid ${variant} route authorization batch percentile order`);
    }
  }
}

function sameRunnerEnvironment(left, right) {
  return left?.os === right?.os && left?.arch === right?.arch &&
    left?.logical_cpus === right?.logical_cpus && left?.gomaxprocs === right?.gomaxprocs &&
    left?.go_version === right?.go_version;
}

function metric(name, unit, observed, limit) {
  return { name, unit, observed: roundMetric(observed), limit, comparator: "lte" };
}

function ratioBasisPoints(candidate, baseline) {
  if (!Number.isFinite(candidate) || candidate < 0 || !Number.isFinite(baseline) || baseline <= 0) {
    throw new Error("route authorization ratio requires finite values and a positive baseline");
  }
  return candidate / baseline * 10000;
}

function roundMetric(value) {
	return Math.round(value * 1_000_000) / 1_000_000;
}

function median(values) {
	const ordered = [...values].sort((left, right) => left - right);
	return ordered[Math.floor(ordered.length / 2)];
}

function assertRecord(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} keys mismatch: got ${actual.join(",")}, want ${wanted.join(",")}`);
  }
}
