import {
  buildRepeatedRouteAuthorizationScenarios,
  canonicalProfileSHA256,
} from "./route_authorization_comparison.mjs";

const routeAuthorizationComparisonID = "httpadapter.route-authorization-v051";
const routeAuthorizationScenarioPrefix = "httpadapter.route-authorization-c";
const gitCommitPattern = /^[0-9a-f]{40}$/;

export function preparePublishedReleasePerformanceFixture(evidence) {
  const prepared = structuredClone(evidence);
  if (!Array.isArray(prepared.scenarios) || !Array.isArray(prepared.comparisons)) {
    throw new Error("published release performance fixture requires scenarios and comparisons");
  }

  const derivedScenarios = new Map();
  for (const comparison of prepared.comparisons) {
    if (comparison?.id !== routeAuthorizationComparisonID || !Array.isArray(comparison.runs)) {
      throw new Error("published release performance fixture has an unsupported comparison");
    }
    const baselineProfiles = [];
    const candidateProfiles = [];
    for (const run of comparison.runs) {
      const baselineProfile = run?.baseline_profile;
      const candidateProfile = run?.candidate_profile;
      if (!Array.isArray(baselineProfile?.measurements) || candidateProfile === null || typeof candidateProfile !== "object") {
        throw new Error("published release performance fixture has an invalid comparison run");
      }
      candidateProfile.measurements = baselineProfile.measurements.map((measurement) => ({ ...measurement }));
      run.baseline_profile_sha256 = canonicalProfileSHA256(baselineProfile);
      run.candidate_profile_sha256 = canonicalProfileSHA256(candidateProfile);
      baselineProfiles.push(baselineProfile);
      candidateProfiles.push(candidateProfile);
    }
    for (const scenario of buildRepeatedRouteAuthorizationScenarios(baselineProfiles, candidateProfiles, "release")) {
      if (derivedScenarios.has(scenario.id)) {
        throw new Error(`published release performance fixture derived duplicate scenario ${scenario.id}`);
      }
      derivedScenarios.set(scenario.id, scenario);
    }
  }

  const consumedDerivedScenarios = new Set();
  prepared.scenarios = prepared.scenarios.map((scenario) => {
    const derived = derivedScenarios.get(scenario.id);
    if (derived) {
      consumedDerivedScenarios.add(scenario.id);
      return derived;
    }
    if (typeof scenario?.id === "string" && scenario.id.startsWith(routeAuthorizationScenarioPrefix)) {
      throw new Error(`published release performance fixture cannot derive scenario ${scenario.id}`);
    }
    return {
      ...scenario,
      gate: "release",
      metrics: scenario.metrics.map((metric) => ({
        ...metric,
        observed: metric.comparator === "eq" ? metric.limit : Math.min(metric.observed, metric.limit),
      })),
    };
  });
  if (consumedDerivedScenarios.size !== derivedScenarios.size) {
    throw new Error("published release performance fixture is missing a derived comparison scenario");
  }
  return prepared;
}

export function rebindPublishedReleasePerformanceSourceCommit(evidence, sourceCommit) {
  if (typeof sourceCommit !== "string" || !gitCommitPattern.test(sourceCommit)) {
    throw new Error("published release performance fixture source commit is invalid");
  }
  const rebound = structuredClone(evidence);
  if (!Array.isArray(rebound.comparisons)) {
    throw new Error("published release performance fixture requires comparisons");
  }
  rebound.source_commit = sourceCommit;
  for (const comparison of rebound.comparisons) {
    if (comparison?.id !== routeAuthorizationComparisonID || !Array.isArray(comparison.runs)) {
      throw new Error("published release performance fixture has an unsupported comparison");
    }
    comparison.candidate_commit = sourceCommit;
    for (const run of comparison.runs) {
      const candidateProfile = run?.candidate_profile;
      if (candidateProfile === null || typeof candidateProfile !== "object") {
        throw new Error("published release performance fixture has an invalid comparison run");
      }
      candidateProfile.commit = sourceCommit;
      run.candidate_profile_sha256 = canonicalProfileSHA256(candidateProfile);
    }
  }
  return rebound;
}
