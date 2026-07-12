#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
ARTIFACT_DIR=""
SKIP_COSIGN=0
RELEASE_TAG=""

usage() {
  cat <<'USAGE'
Usage: scripts/verify_redevplugin_release_artifacts.sh [--skip-cosign] [--tag vX.Y.Z] <artifact-dir>

Verifies a downloaded ReDevPlugin GitHub Release artifact directory:
  - SHA256SUMS covers the exact four-target runtime matrix, stress summary, and A2 evidence files
  - release stress evidence reports an ok release-mode run with required counters
  - A2 evidence proves opaque origin, exact sandbox/CSP, and credential isolation
  - every covered artifact and SHA256SUMS have .sig/.bundle
  - cosign verifies each signed artifact unless --skip-cosign is passed

Cosign verification requires --tag and binds the certificate identity to that
exact release tag and the release.yml workflow in github.com/floegence/redevplugin.

Requires node for structured stress-evidence JSON validation.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-cosign)
      SKIP_COSIGN=1
      shift
      ;;
    --tag)
      if [[ $# -lt 2 || -n "$RELEASE_TAG" ]]; then
        echo "--tag requires exactly one value" >&2
        exit 2
      fi
      RELEASE_TAG="$2"
      shift 2
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
if [[ -n "$RELEASE_TAG" && ! "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release tag: $RELEASE_TAG" >&2
  exit 2
fi
if [[ "$SKIP_COSIGN" -ne 1 && -z "$RELEASE_TAG" ]]; then
  echo "--tag is required when cosign verification is enabled" >&2
  exit 2
fi

ARTIFACT_DIR=$(cd -- "$ARTIFACT_DIR" >/dev/null 2>&1 && pwd)
SUMS_FILE="$ARTIFACT_DIR/SHA256SUMS"
STRESS_FILE="$ARTIFACT_DIR/redevplugin-release-stress.json"
A2_FILE="$ARTIFACT_DIR/redevplugin-a2-acceptance.json"
A2_SUPPORTED_SCREENSHOT="$ARTIFACT_DIR/redevplugin-a2-supported.png"
A2_UNSUPPORTED_SCREENSHOT="$ARTIFACT_DIR/redevplugin-a2-unsupported.png"

require_file() {
  local path=$1
  if [[ ! -f "$path" ]]; then
    echo "required release artifact missing: $path" >&2
    exit 1
  fi
}

require_file "$SUMS_FILE"
require_file "$STRESS_FILE"
require_file "$A2_FILE"
require_file "$A2_SUPPORTED_SCREENSHOT"
require_file "$A2_UNSUPPORTED_SCREENSHOT"

RUNTIME_TARGETS=(
  "x86_64-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

if [[ -n "$RELEASE_TAG" ]]; then
  RELEASE_VERSION=${RELEASE_TAG#v}
else
  first_tarball=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f -name 'redevplugin-v*.tar.gz' -print | sort | head -n 1)
  if [[ -z "$first_tarball" ]]; then
    echo "cannot infer release version from runtime tarballs" >&2
    exit 1
  fi
  first_tarball=$(basename "$first_tarball")
  RELEASE_VERSION=${first_tarball#redevplugin-v}
  matched_target=""
  for target in "${RUNTIME_TARGETS[@]}"; do
    suffix="-${target}.tar.gz"
    if [[ "$RELEASE_VERSION" == *"$suffix" ]]; then
      RELEASE_VERSION=${RELEASE_VERSION%"$suffix"}
      matched_target="$target"
      break
    fi
  done
  if [[ -z "$matched_target" || ! "$RELEASE_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "cannot infer a valid release version from $first_tarball" >&2
    exit 1
  fi
fi

EXPECTED_SUM_PATHS=()
for target in "${RUNTIME_TARGETS[@]}"; do
  EXPECTED_SUM_PATHS+=("redevplugin-v${RELEASE_VERSION}-${target}.tar.gz")
done
EXPECTED_SUM_PATHS+=(
  "redevplugin-release-stress.json"
  "redevplugin-a2-acceptance.json"
  "redevplugin-a2-supported.png"
  "redevplugin-a2-unsupported.png"
)

SUM_PATHS=()
while read -r rel; do
  [[ -z "$rel" ]] && continue
  SUM_PATHS+=("$rel")
done < <(awk '{ print $2 }' "$SUMS_FILE")
if [[ "${#SUM_PATHS[@]}" -eq 0 ]]; then
  echo "SHA256SUMS is empty" >&2
  exit 1
fi

compare_sorted_lists() {
  local label=$1
  if ! diff -u \
      <(printf '%s\n' "${EXPECTED_SUM_PATHS[@]}" | LC_ALL=C sort) \
      <(printf '%s\n' "${SUM_PATHS[@]}" | LC_ALL=C sort) >&2; then
    echo "$label does not contain the exact expected release artifact set" >&2
    exit 1
  fi
}

compare_sorted_lists "SHA256SUMS"

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

stress_covered=0
a2_report_covered=0
a2_supported_screenshot_covered=0
a2_unsupported_screenshot_covered=0
for rel in "${SUM_PATHS[@]}"; do
  if [[ -z "$rel" || "$rel" = /* || "$rel" == *".."* ]]; then
    echo "invalid SHA256SUMS path: $rel" >&2
    exit 1
  fi
  require_file "$ARTIFACT_DIR/$rel"
  if [[ "$rel" == "redevplugin-release-stress.json" ]]; then
    stress_covered=1
  fi
  [[ "$rel" == "redevplugin-a2-acceptance.json" ]] && a2_report_covered=1
  [[ "$rel" == "redevplugin-a2-supported.png" ]] && a2_supported_screenshot_covered=1
  [[ "$rel" == "redevplugin-a2-unsupported.png" ]] && a2_unsupported_screenshot_covered=1
done

if [[ "$stress_covered" -ne 1 ]]; then
  echo "SHA256SUMS must cover redevplugin-release-stress.json" >&2
  exit 1
fi
if [[ "$a2_report_covered" -ne 1 || "$a2_supported_screenshot_covered" -ne 1 || "$a2_unsupported_screenshot_covered" -ne 1 ]]; then
  echo "SHA256SUMS must cover the A2 acceptance report and both screenshots" >&2
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

EXPECTED_RELEASE_FILES=("${EXPECTED_SUM_PATHS[@]}" "SHA256SUMS")
for rel in "${EXPECTED_SUM_PATHS[@]}" "SHA256SUMS"; do
  EXPECTED_RELEASE_FILES+=("${rel}.sig" "${rel}.bundle")
done
actual_release_files=()
while IFS= read -r path; do
  actual_release_files+=("$(basename "$path")")
done < <(find "$ARTIFACT_DIR" -maxdepth 1 -type f -print)
expected_file=$(mktemp)
actual_file=$(mktemp)
printf '%s\n' "${EXPECTED_RELEASE_FILES[@]}" | LC_ALL=C sort >"$expected_file"
printf '%s\n' "${actual_release_files[@]}" | LC_ALL=C sort >"$actual_file"
if ! cmp -s "$expected_file" "$actual_file"; then
  echo "GitHub Release directory does not contain the exact expected signed asset set" >&2
  diff -u "$expected_file" "$actual_file" >&2 || true
  rm -f "$expected_file" "$actual_file"
  exit 1
fi
rm -f "$expected_file" "$actual_file"

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
  "operation_cancel_dispatch",
  "connectivity_classifier",
  "runtime_revoke_ack",
  "storage_quota",
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
const streamCloseRequests = requireAtLeast(evidenceByCategory, "stream_backpressure", "stream_close_requests", 1);
const closedStreams = requireAtLeast(evidenceByCategory, "stream_backpressure", "closed_streams", 1);
if (closedStreams !== streamCloseRequests) {
  fail(`stream_backpressure closed_streams ${closedStreams} must equal stream_close_requests ${streamCloseRequests}`);
}
const postCloseAppendDenials = requireAtLeast(evidenceByCategory, "stream_backpressure", "post_close_append_denials", 1);
if (postCloseAppendDenials !== closedStreams) {
  fail(`stream_backpressure post_close_append_denials ${postCloseAppendDenials} must equal closed_streams ${closedStreams}`);
}
const streamCloseAudits = requireAtLeast(evidenceByCategory, "stream_backpressure", "stream_close_audit_events", 1);
if (streamCloseAudits !== closedStreams) {
  fail(`stream_backpressure stream_close_audit_events ${streamCloseAudits} must equal closed_streams ${closedStreams}`);
}
requireAtLeast(evidenceByCategory, "stream_backpressure", "stream_close_status_checked", 1);

const operationCancelRegistered = requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "operations_registered", 2);
const operationCancelRequested = requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "cancel_requested_records", 2);
if (operationCancelRequested !== operationCancelRegistered) {
  fail(`operation_cancel_dispatch cancel_requested_records ${operationCancelRequested} must equal operations_registered ${operationCancelRegistered}`);
}
requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "successful_dispatches", 1);
requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "failed_dispatches", 1);
requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "http_503_failures", 1);
requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "runtime_unavailable_errors", 1);
const operationCancelAudits = requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "audit_cancel_requested_events", 2);
if (operationCancelAudits !== operationCancelRequested) {
  fail(`operation_cancel_dispatch audit_cancel_requested_events ${operationCancelAudits} must equal cancel_requested_records ${operationCancelRequested}`);
}
requireAtLeast(evidenceByCategory, "operation_cancel_dispatch", "adapter_context_fields_checked", 8);

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
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_chunks", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "http_stream_cancelled_reads", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_database_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "tcp_cancelled_reads", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_source_mismatch_dropped", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "udp_rate_limit_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_round_trips", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_request_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_response_denials", 1);
requireAtLeast(evidenceByCategory, "connectivity_classifier", "websocket_cancelled_reads", 1);

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
NODE
}

verify_a2_evidence() {
  A2_FILE="$A2_FILE" A2_SUPPORTED_SCREENSHOT="$A2_SUPPORTED_SCREENSHOT" A2_UNSUPPORTED_SCREENSHOT="$A2_UNSUPPORTED_SCREENSHOT" node <<'NODE'
const fs = require("fs");

function fail(message) {
  console.error(`invalid A2 acceptance evidence: ${message}`);
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(process.env.A2_FILE, "utf8"));
const exactKeys = (value, keys) => {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};
const allTrue = (value, keys, label) => {
  if (!exactKeys(value, keys)) fail(`${label} fields are invalid`);
  for (const key of keys) if (value[key] !== true) fail(`${label}.${key} must be true`);
};
const requireTrueFields = (value, keys, label) => {
  for (const key of keys) if (value[key] !== true) fail(`${label}.${key} must be true`);
};
if (!exactKeys(report, ["schema_version", "evidence_source", "scenarios"]) ||
    report.schema_version !== "redevplugin.a2_acceptance.v1" ||
    report.evidence_source !== "go-host-http-adapter-rust-runtime-chromium" ||
    !Array.isArray(report.scenarios) || report.scenarios.length !== 2) {
  fail("report schema or scenario count is invalid");
}
const expectedCSP = "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'";
const expectedAllow = "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'";
const scenarioKeys = [
  "credentialless_scenario", "credentialless", "sandbox", "allow", "referrer_policy", "csp",
  "frame_origin", "opaque_origin", "isolation", "worker_probe", "platform_dynamic_import_gate",
  "parent_credentials_absent", "credential_query_absent", "direct_worker_network_absent",
  "strict_request_allowlist", "websocket_absent", "service_worker_absent", "opening_progress",
  "first_paint_before_lazy_asset", "real_stream_redeemed", "confirmation_disposal_aborted",
  "server_disposed", "disposed",
];
const isolationKeys = [
  "parent_dom_blocked", "parent_cookie_blocked", "parent_local_storage_blocked",
  "parent_session_storage_blocked", "indexeddb_blocked", "cache_storage_blocked",
  "direct_fetch_blocked", "service_worker_blocked",
];
const workerProbeKeys = [
  "dedicated_worker",
  "fetch_blocked",
  "websocket_blocked",
  "nested_worker_blocked",
  "indexeddb_blocked",
  "cache_storage_blocked",
  "broadcast_channel_blocked",
  "global_postmessage_blocked",
  "navigator_storage_blocked",
  "eval_blocked",
  "function_constructor_blocked",
  "prototype_descriptors_sealed",
  "message_port_prototype_sealed",
  "prototype_fetch_blocked",
  "prototype_indexeddb_blocked",
  "prototype_nested_blob_worker_blocked",
  "all_blocked",
];
const scenarioProofKeys = [
  "opaque_origin", "platform_dynamic_import_gate", "parent_credentials_absent", "credential_query_absent",
  "direct_worker_network_absent", "strict_request_allowlist", "websocket_absent", "service_worker_absent",
  "opening_progress", "first_paint_before_lazy_asset", "real_stream_redeemed",
  "confirmation_disposal_aborted", "server_disposed", "disposed",
];
const scenarios = new Map(report.scenarios.map((scenario) => [scenario?.credentialless_scenario, scenario]));
for (const name of ["supported", "unsupported"]) {
  const scenario = scenarios.get(name);
  if (!exactKeys(scenario, scenarioKeys) || scenario.credentialless !== (name === "supported") ||
      scenario.sandbox !== "allow-scripts" || scenario.allow !== expectedAllow ||
      scenario.referrer_policy !== "no-referrer" || scenario.csp !== expectedCSP || scenario.frame_origin !== "null") {
    fail(`${name} sandbox identity is invalid`);
  }
  requireTrueFields(scenario, scenarioProofKeys, name);
  allTrue(scenario.isolation, isolationKeys, `${name}.isolation`);
  allTrue(scenario.worker_probe, workerProbeKeys, `${name}.worker_probe`);
}
for (const path of [process.env.A2_SUPPORTED_SCREENSHOT, process.env.A2_UNSUPPORTED_SCREENSHOT]) {
  const bytes = fs.readFileSync(path);
  if (bytes.length < 8 || bytes.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") fail(`${path} is not a PNG screenshot`);
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
  local identity="https://github.com/floegence/redevplugin/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}"
  cosign verify-blob \
    --bundle "$ARTIFACT_DIR/${rel}.bundle" \
    --signature "$ARTIFACT_DIR/${rel}.sig" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$ARTIFACT_DIR/$rel"
}

verify_checksums
verify_stress_summary
verify_a2_evidence

for rel in "${SUM_PATHS[@]}" "SHA256SUMS"; do
  verify_signature_files "$rel"
  verify_cosign "$rel"
done

echo "redevplugin release artifacts verified: $ARTIFACT_DIR"
