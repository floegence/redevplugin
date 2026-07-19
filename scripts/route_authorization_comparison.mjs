import { createHash } from "node:crypto";

const profileSchemaVersion = "redevplugin.route_authorization_performance.v1";
const comparisonID = "httpadapter.route-authorization-v051";
const gitCommitPattern = /^[0-9a-f]{40}$/;

export function buildRouteAuthorizationComparisonReport(probe, baselineProfiles, candidateProfiles) {
  if (!Array.isArray(baselineProfiles) || !Array.isArray(candidateProfiles) ||
      baselineProfiles.length !== probe.repetitions || candidateProfiles.length !== probe.repetitions) {
    throw new Error("route authorization comparison repetition count is invalid");
  }
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
	return {
		id: probe.id,
		baseline_release: probe.baseline_release,
		baseline_commit: probe.baseline_commit,
		candidate_commit: candidateCommit,
		runs: baselineProfiles.map((baselineProfile, index) => ({
			baseline_profile_sha256: canonicalProfileSHA256(baselineProfile),
			candidate_profile_sha256: canonicalProfileSHA256(candidateProfiles[index]),
			baseline_profile: baselineProfile,
			candidate_profile: candidateProfiles[index],
		})),
	};
}

export function buildRepeatedRouteAuthorizationScenarios(baselineProfiles, candidateProfiles, gate) {
  if (!Array.isArray(baselineProfiles) || !Array.isArray(candidateProfiles) || baselineProfiles.length === 0 || baselineProfiles.length !== candidateProfiles.length) {
    throw new Error("route authorization comparison profiles are incomplete");
  }
  const runs = baselineProfiles.map((baseline, index) => buildRouteAuthorizationScenarios(baseline, candidateProfiles[index], gate));
  return runs[0].map((scenario, scenarioIndex) => ({
    ...scenario,
    metrics: scenario.metrics.map((metric, metricIndex) => ({
      ...metric,
      observed: median(runs.map((run) => run[scenarioIndex].metrics[metricIndex].observed)),
    })),
  }));
}

export function buildRouteAuthorizationScenarios(baselineProfile, candidateProfile, gate) {
  validateRouteAuthorizationProfile(baselineProfile, "v0.5.1");
  validateRouteAuthorizationProfile(candidateProfile, "v0.6.0");
  if (!sameRunnerEnvironment(baselineProfile.environment, candidateProfile.environment)) {
    throw new Error("route authorization profiles were measured on different runner environments");
  }
  const baselineByConcurrency = new Map(baselineProfile.measurements.map((measurement) => [measurement.concurrency, measurement]));
  return candidateProfile.measurements.map((candidate) => {
    const baseline = baselineByConcurrency.get(candidate.concurrency);
    if (!baseline || baseline.batch_count !== candidate.batch_count || baseline.sample_count !== candidate.sample_count) {
      throw new Error(`route authorization sample shape mismatch for concurrency ${candidate.concurrency}`);
    }
    return {
      id: `httpadapter.route-authorization-c${candidate.concurrency}`,
      gate,
      status: "pass",
      sample_count: candidate.sample_count,
      metrics: [
        metric("p95_relative", "basis_points", ratioBasisPoints(candidate.p95_nanoseconds, baseline.p95_nanoseconds), 11000),
        metric("p99_relative", "basis_points", ratioBasisPoints(candidate.p99_nanoseconds, baseline.p99_nanoseconds), 11500),
        metric("allocations_increase", "count", Math.max(0, candidate.allocations_per_request - baseline.allocations_per_request), 1),
        metric("allocated_bytes_relative", "basis_points", ratioBasisPoints(candidate.bytes_per_request, baseline.bytes_per_request), 10500),
      ],
    };
  });
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

export function validateRouteAuthorizationComparisonReport(report, probe, sourceCommit, scenarios) {
  assertRecord(report, "route authorization comparison report");
  assertExactKeys(report, [
    "id",
    "baseline_release",
    "baseline_commit",
    "candidate_commit",
    "runs",
  ], "route authorization comparison report");
  if (report.id !== probe.id || report.baseline_release !== probe.baseline_release || report.baseline_commit !== probe.baseline_commit) {
    throw new Error("route authorization comparison provenance does not match the performance contract");
  }
  if (report.candidate_commit !== sourceCommit || !Array.isArray(report.runs) || report.runs.length !== probe.repetitions) {
    throw new Error("route authorization comparison candidate commit does not match performance evidence source_commit");
  }
	const baselineProfiles = [];
	const candidateProfiles = [];
	for (const [index, run] of report.runs.entries()) {
		assertRecord(run, `route authorization comparison run ${index}`);
		assertExactKeys(run, ["baseline_profile_sha256", "candidate_profile_sha256", "baseline_profile", "candidate_profile"], `route authorization comparison run ${index}`);
		if (run.baseline_profile.commit !== probe.baseline_commit || run.candidate_profile.commit !== sourceCommit) {
			throw new Error("route authorization comparison profile commit is invalid");
		}
		if (run.baseline_profile_sha256 !== canonicalProfileSHA256(run.baseline_profile) ||
			run.candidate_profile_sha256 !== canonicalProfileSHA256(run.candidate_profile)) {
			throw new Error("route authorization comparison profile hash is invalid");
		}
		baselineProfiles.push(run.baseline_profile);
		candidateProfiles.push(run.candidate_profile);
	}
  const comparisonScenarios = scenarios
    .filter((scenario) => scenario.id.startsWith("httpadapter.route-authorization-c"))
    .sort((left, right) => left.id.localeCompare(right.id));
  if (comparisonScenarios.length !== 3) {
    throw new Error("route authorization comparison scenarios are incomplete");
  }
	const expected = buildRepeatedRouteAuthorizationScenarios(
		baselineProfiles,
		candidateProfiles,
		comparisonScenarios[0].gate,
  ).sort((left, right) => left.id.localeCompare(right.id));
  if (JSON.stringify(comparisonScenarios) !== JSON.stringify(expected)) {
    throw new Error("route authorization comparison scenarios do not match the signed profiles");
  }
}

export function canonicalProfileSHA256(profile) {
  return createHash("sha256").update(canonicalJSON(profile)).digest("hex");
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
    for (const key of ["allocations_per_request", "bytes_per_request"]) {
      if (!Number.isFinite(measurement[key]) || measurement[key] < 0) {
        throw new Error(`invalid ${variant} route authorization ${key}`);
      }
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
