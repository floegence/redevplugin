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
  - release stress evidence reports an ok release-mode run
  - every runtime tarball, the stress summary, and SHA256SUMS have .sig/.bundle
  - cosign verifies each signed artifact unless --skip-cosign is passed

Set REDEVPLUGIN_COSIGN_CERT_IDENTITY_REGEXP to override the expected GitHub
Actions keyless signing identity regexp. The default is the tagged release
workflow identity for github.com/floegence/redevplugin.
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
  grep -q '"ok": true' "$STRESS_FILE"
  grep -q '"mode": "release"' "$STRESS_FILE"
  grep -q '"stress_evidence"' "$STRESS_FILE"
  grep -q '"release_bundle"' "$STRESS_FILE"
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
