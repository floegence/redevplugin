#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
ARTIFACT_DIR=""
SKIP_COSIGN=0

usage() {
  cat <<'USAGE'
Usage: scripts/verify_redevplugin_release_artifacts.sh [--skip-cosign] <artifact-dir>

Verifies a downloaded ReDevPlugin GitHub Release artifact directory:
  - SHA256SUMS covers every runtime tarball and redevplugin-release-stress.json
  - release stress evidence reports an ok release-mode run with required counters
  - every runtime tarball, the stress summary, and SHA256SUMS have .sig/.bundle
  - cosign verifies each signed artifact unless --skip-cosign is passed

Set REDEVPLUGIN_COSIGN_CERT_IDENTITY_REGEXP to override the expected GitHub
Actions keyless signing identity regexp. The default is the tagged release
workflow identity for github.com/floegence/redevplugin.

Requires node for structured stress-evidence JSON validation.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-cosign)
      SKIP_COSIGN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$ARTIFACT_DIR" ]]; then
        echo "unexpected argument: $1" >&2
        usage >&2
        exit 2
      fi
      ARTIFACT_DIR="$1"
      shift
      ;;
  esac
done

if [[ -z "$ARTIFACT_DIR" || ! -d "$ARTIFACT_DIR" ]]; then
  usage >&2
  exit 2
fi

ARTIFACT_DIR=$(cd -- "$ARTIFACT_DIR" >/dev/null 2>&1 && pwd)
SUMS_FILE="$ARTIFACT_DIR/SHA256SUMS"
STRESS_FILE="$ARTIFACT_DIR/redevplugin-release-stress.json"

require_file() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    echo "required release artifact missing: $path" >&2
    exit 1
  fi
}

require_file "$SUMS_FILE"
require_file "$STRESS_FILE"

SUM_PATHS=()
while read -r rel; do
  [[ -z "$rel" ]] && continue
  SUM_PATHS+=("$rel")
done < <(awk '{ print $2 }' "$SUMS_FILE")
if [[ "${#SUM_PATHS[@]}" -eq 0 ]]; then
  echo "SHA256SUMS is empty" >&2
  exit 1
fi

path_in_sums() {
  local want=$1
  local rel
  for rel in "${SUM_PATHS[@]}"; do
    if [[ "$rel" == "$want" ]]; then
      return 0
    fi
  done
  return 1
}

tarball_count=0
stress_covered=0
for rel in "${SUM_PATHS[@]}"; do
  if [[ -z "$rel" || "$rel" = /* || "$rel" == *".."* ]]; then
    echo "invalid SHA256SUMS path: $rel" >&2
    exit 1
  fi
  require_file "$ARTIFACT_DIR/$rel"
  if [[ "$rel" == *.tar.gz ]]; then
    tarball_count=$((tarball_count + 1))
  fi
  if [[ "$rel" == "redevplugin-release-stress.json" ]]; then
    stress_covered=1
  fi
done

if [[ "$tarball_count" -eq 0 ]]; then
  echo "SHA256SUMS must cover at least one runtime tarball" >&2
  exit 1
fi
if [[ "$stress_covered" -ne 1 ]]; then
  echo "SHA256SUMS must cover redevplugin-release-stress.json" >&2
  exit 1
fi
for tarball in "$ARTIFACT_DIR"/*.tar.gz; do
  [[ -e "$tarball" ]] || continue
  tarball_name=$(basename "$tarball")
  if ! path_in_sums "$tarball_name"; then
    echo "runtime tarball is not covered by SHA256SUMS: $tarball_name" >&2
    exit 1
  fi
done

verify_checksums() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$ARTIFACT_DIR" && sha256sum -c SHA256SUMS)
    return
  fi
  if ! command -v shasum >/dev/null 2>&1; then
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
  while read -r expected rel; do
    [[ -z "${expected:-}" || -z "${rel:-}" ]] && continue
    actual=$(shasum -a 256 "$ARTIFACT_DIR/$rel" | awk '{ print $1 }')
    if [[ "$actual" != "$expected" ]]; then
      echo "checksum mismatch for $rel: got $actual, want $expected" >&2
      exit 1
    fi
  done <"$SUMS_FILE"
}

verify_stress_summary() {
  if ! command -v node >/dev/null 2>&1; then
    echo "node is required to validate release stress evidence counters" >&2
    exit 1
  fi
  STRESS_FILE="$STRESS_FILE" node <<'NODE'
const fs = require("fs");

const path = process.env.STRESS_FILE;

function fail(message) {
  console.error(`invalid release stress summary: ${message}`);
  process.exit(1);
}

function object(value, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  return value;
}

function integer(value, label) {
  if (!Number.isInteger(value)) {
    fail(`${label} must be an integer`);
  }
  return value;
}

function counter(evidenceByCategory, category, name) {
  const evidence = evidenceByCategory.get(category);
  if (!evidence) {
    fail(`missing stress evidence category ${category}`);
  }
  return integer(object(evidence.counters, `${category}.counters`)[name], `${category}.counters.${name}`);
}

function requireAtLeast(evidenceByCategory, category, name, minimum) {
  const value = counter(evidenceByCategory, category, name);
  if (value < minimum) {
    fail(`${category}.counters.${name} = ${value}, want >= ${minimum}`);
  }
  return value;
}

let summary;
try {
  summary = JSON.parse(fs.readFileSync(path, "utf8"));
} catch (error) {
  fail(`cannot parse ${path}: ${error.message}`);
}

object(summary, "summary");
if (summary.ok !== true) {
  fail("ok must be true");
}
if (summary.mode !== "release") {
  fail(`mode = ${JSON.stringify(summary.mode)}, want "release"`);
}

const requiredCategories = [
  "stream_backpressure",
  "connectivity_classifier",
  "runtime_revoke_ack",
  "storage_quota",
  "csp_report_flood",
];
const stressCategories = new Set(array(summary.stress_categories, "stress_categories"));
for (const category of requiredCategories) {
  if (!stressCategories.has(category)) {
    fail(`stress_categories missing ${category}`);
  }
}

const evidenceByCategory = new Map();
for (const evidence of array(summary.stress_evidence, "stress_evidence")) {
  object(evidence, "stress_evidence entry");
  if (typeof evidence.category !== "string" || evidence.category.length === 0) {
    fail("stress_evidence entry category must be a non-empty string");
  }
  if (evidenceByCategory.has(evidence.category)) {
    fail(`duplicate stress evidence category ${evidence.category}`);
  }
  evidenceByCategory.set(evidence.category, evidence);
}

const steps = array(summary.steps, "steps");
for (const stepName of ["stress_evidence", "release_bundle"]) {
  const step = steps.find((candidate) => object(candidate, "step").name === stepName);
  if (!step) {
    fail(`steps missing ${stepName}`);
  }
  if (step.status !== 0) {
    fail(`step ${stepName} status = ${step.status}, want 0`);
  }
}

const streamWorkers = requireAtLeast(evidenceByCategory, "stream_backpressure", "workers", 1);
const backpressureDenials = requireAtLeast(evidenceByCategory, "stream_backpressure", "backpressure_denials", 1);
if (backpressureDenials < streamWorkers) {
  fail(`stream_backpressure backpressure_denials ${backpressureDenials} must cover workers ${streamWorkers}`);
}
requireAtLeast(evidenceByCategory, "stream_backpressure", "core_operation_checks", 1);

requireAtLeast(evidenceByCategory, "connectivity_classifier", "minted_grants", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "stale_grant_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "blocked_resolved_ips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "connector_policy_count", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_redirects_not_followed", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "dns_rebinding_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_proxy_env_ignored", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_connect_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "alt_svc_headers_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "proxy_auth_headers_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_source_mismatch_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_rate_limit_denials", 1);

requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "attempts", 1);
const p95Ms = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "p95_ms", 0);
const maxMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "max_ms", 0);
const thresholdMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "threshold_ms", 1);
const hardTimeoutMs = requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "hard_timeout_ms", 1);
if (p95Ms > thresholdMs) {
  fail(`runtime_revoke_ack p95_ms ${p95Ms} exceeds threshold_ms ${thresholdMs}`);
}
if (maxMs >= hardTimeoutMs) {
  fail(`runtime_revoke_ack max_ms ${maxMs} must be below hard_timeout_ms ${hardTimeoutMs}`);
}
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_actor", 1);
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_socket", 1);
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_stream", 1);
requireAtLeast(evidenceByCategory, "runtime_revoke_ack", "closed_storage", 1);

const storageWrites = requireAtLeast(evidenceByCategory, "storage_quota", "writes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "quota_denials", 1);
const imported = requireAtLeast(evidenceByCategory, "storage_quota", "imported", 1);
if (imported !== storageWrites) {
  fail(`storage_quota imported ${imported} must equal writes ${storageWrites}`);
}
requireAtLeast(evidenceByCategory, "storage_quota", "usage_bytes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_quota_denials", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_usage_files", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "file_quota_files", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_quota_denials", 2);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_rollback_checks", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_page_count", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sidecar_files", 4);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sidecar_bytes", 1);
requireAtLeast(evidenceByCategory, "storage_quota", "sqlite_sparse_logical_bytes", 1);

const cspAttempts = requireAtLeast(evidenceByCategory, "csp_report_flood", "attempts", 1);
const acceptedReports = requireAtLeast(evidenceByCategory, "csp_report_flood", "accepted_reports", 1);
const rateLimitedReports = requireAtLeast(evidenceByCategory, "csp_report_flood", "rate_limited_reports", 1);
if (acceptedReports + rateLimitedReports !== cspAttempts) {
  fail(`csp_report_flood accepted + rate_limited must equal attempts ${cspAttempts}`);
}
const diagnosticEvents = requireAtLeast(evidenceByCategory, "csp_report_flood", "diagnostic_events", 1);
if (diagnosticEvents !== acceptedReports) {
  fail(`csp_report_flood diagnostic_events ${diagnosticEvents} must equal accepted_reports ${acceptedReports}`);
}
const auditEvents = counter(evidenceByCategory, "csp_report_flood", "audit_events");
if (auditEvents !== 0) {
  fail(`csp_report_flood audit_events = ${auditEvents}, want 0`);
}
if (counter(evidenceByCategory, "csp_report_flood", "unique_sandbox_origins") !== 1) {
  fail("csp_report_flood must report exactly one sandbox origin");
}
if (counter(evidenceByCategory, "csp_report_flood", "unique_active_fingerprints") !== 1) {
  fail("csp_report_flood must report exactly one active fingerprint");
}
NODE
}

verify_signature_files() {
  local rel=$1
  require_file "$ARTIFACT_DIR/${rel}.sig"
  require_file "$ARTIFACT_DIR/${rel}.bundle"
}

verify_cosign() {
  local rel=$1
  if [[ "$SKIP_COSIGN" -eq 1 ]]; then
    return
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required; pass --skip-cosign only for local fixture checks" >&2
    exit 1
  fi
  local identity_regexp=${REDEVPLUGIN_COSIGN_CERT_IDENTITY_REGEXP:-'^https://github.com/floegence/redevplugin/.github/workflows/release.yml@refs/tags/v.*$'}
  local oidc_issuer=${REDEVPLUGIN_COSIGN_OIDC_ISSUER:-'https://token.actions.githubusercontent.com'}
  cosign verify-blob \
    --bundle "$ARTIFACT_DIR/${rel}.bundle" \
    --signature "$ARTIFACT_DIR/${rel}.sig" \
    --certificate-identity-regexp "$identity_regexp" \
    --certificate-oidc-issuer "$oidc_issuer" \
    "$ARTIFACT_DIR/$rel"
}

verify_checksums
verify_stress_summary

for rel in "${SUM_PATHS[@]}" "SHA256SUMS"; do
  verify_signature_files "$rel"
  verify_cosign "$rel"
done

echo "redevplugin release artifacts verified: $ARTIFACT_DIR"
