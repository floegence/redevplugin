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
  node "$ROOT_DIR/scripts/verify_redevplugin_release_stress.mjs" "$STRESS_FILE"
}

verify_a2_evidence() {
  node "$ROOT_DIR/scripts/verify_redevplugin_a2_evidence.mjs" \
    "$A2_FILE" \
    "$A2_SUPPORTED_SCREENSHOT" \
    "$A2_UNSUPPORTED_SCREENSHOT"
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
