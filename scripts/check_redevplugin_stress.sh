#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

MODE="fast"
SUMMARY_PATH=""
PINNED_GO_LINUX_IMAGE="docker.io/library/golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36"

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_stress.sh [--fast|--full|--release] [--summary PATH]

Runs the host-neutral ReDevPlugin stress gate.

Modes:
  --fast      Race-sensitive broker/lifecycle packages plus pkg/stress tests.
  --full      Fast gate plus platform/browser/runtime-contract/package-publication smoke.
  --release   Full gate plus validation of the exact release stress summary.

The script always writes a JSON summary with structured stress_evidence counters
to stdout. When --summary is provided, the same JSON summary is also written to
PATH. Non-Linux hosts require Docker to collect the Linux-only runtime revoke
evidence in every mode.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast)
      MODE="fast"
      shift
      ;;
    --full)
      MODE="full"
      shift
      ;;
    --release)
      MODE="release"
      shift
      ;;
    --summary)
      if [[ $# -lt 2 ]]; then
        echo "--summary requires a path" >&2
        exit 2
      fi
      SUMMARY_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$MODE" in
  fast|full|release) ;;
  *)
    echo "invalid mode: $MODE" >&2
    exit 2
    ;;
esac

STEPS=()
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
STATUS=0
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-stress.XXXXXX")
STRESS_EVIDENCE_FILE="$TMP_DIR/stress-evidence.ndjson"

json_step() {
  local name=$1
  local status=$2
  local duration_ms=$3
  printf '{"name":"%s","status":%s,"duration_ms":%s}' "$name" "$status" "$duration_ms"
}

run_step() {
  local name=$1
  shift
  local start
  local end
  local status
  start=$(date +%s)
  echo "==> $name" >&2
  set +e
  "$@"
  status=$?
  set -e
  end=$(date +%s)
  STEPS+=("$(json_step "$name" "$status" "$(((end - start) * 1000))")")
  if [[ "$status" -ne 0 ]]; then
    STATUS=$status
  fi
  return "$status"
}

render_summary() {
  local completed_at
  local ok
  local categories
  local steps_json
  local evidence_json
  completed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [[ "$STATUS" -eq 0 ]]; then
    ok=true
  else
    ok=false
  fi
  categories='["go_race","execution_cancel_ownership","connectivity_classifier","runtime_revoke_ack","storage_quota"]'
  if [[ "$MODE" != "fast" ]]; then
    categories='["go_race","execution_cancel_ownership","connectivity_classifier","runtime_revoke_ack","storage_quota","browser_harness","runtime_contract","release_package_build","release_manifest_verifier"]'
  fi
  steps_json=$(IFS=,; echo "${STEPS[*]}")
  evidence_json=$(stress_evidence_json)
  cat <<JSON
{
  "ok": $ok,
  "mode": "$MODE",
  "started_at": "$STARTED_AT",
  "completed_at": "$completed_at",
  "stress_categories": $categories,
  "stress_evidence": $evidence_json,
  "steps": [$steps_json]
}
JSON
}

publish_summary() {
  local summary=$1
  echo "$summary"
  if [[ -n "$SUMMARY_PATH" ]]; then
    mkdir -p "$(dirname -- "$SUMMARY_PATH")"
    printf '%s\n' "$summary" >"$SUMMARY_PATH"
  fi
}

write_summary() {
  publish_summary "$(render_summary)"
}

write_summary_file() {
  local path=$1
  publish_summary "$(cat "$path")"
}

stress_evidence_json() {
  if [[ ! -s "$STRESS_EVIDENCE_FILE" ]]; then
    printf '[]'
    return
  fi
  awk '
    BEGIN {
      printf "["
    }
    NF {
      if (count > 0) {
        printf ","
      }
      printf "%s", $0
      count += 1
    }
    END {
      printf "]"
    }
  ' "$STRESS_EVIDENCE_FILE"
}

collect_stress_evidence() {
  GOWORK=off REDEVPLUGIN_STRESS_EVIDENCE_PATH="$STRESS_EVIDENCE_FILE" go test -count=1 ./pkg/stress
  if [[ "$(uname -s)" == "Linux" ]]; then
    return
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to collect Linux runtime stress evidence on non-Linux hosts" >&2
    return 1
  fi

  local host_arch
  local go_module_cache
  local platform
  host_arch=$(uname -m)
  go_module_cache=$(go env GOMODCACHE)
  if [[ ! -d "$go_module_cache" ]]; then
    echo "Go module cache is unavailable after the host stress test: $go_module_cache" >&2
    return 1
  fi
  case "$host_arch" in
    arm64|aarch64)
      platform="linux/arm64"
      ;;
    x86_64|amd64)
      platform="linux/amd64"
      ;;
    *)
      echo "unsupported host architecture for Linux runtime stress evidence: $host_arch" >&2
      return 1
      ;;
  esac

  docker run --rm \
    --network none \
    --platform "$platform" \
    --mount "type=bind,src=$ROOT_DIR,dst=/repo,readonly" \
    --mount "type=bind,src=$TMP_DIR,dst=/evidence" \
    --mount "type=bind,src=$go_module_cache,dst=/go/pkg/mod,readonly" \
    --workdir /repo \
    --env GOWORK=off \
    --env GOMODCACHE=/go/pkg/mod \
    --env REDEVPLUGIN_STRESS_EVIDENCE_PATH=/evidence/stress-evidence.ndjson \
    "$PINNED_GO_LINUX_IMAGE" \
    go test -count=1 -run '^TestStressGateRuntimeRevokeACKP95$' ./pkg/stress
}

cleanup() {
  if [[ -n "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

if [[ "$MODE" != "fast" ]]; then
  run_step npm_ci npm ci || {
    write_summary
    exit "$STATUS"
  }
fi

run_step go_race_core env GOWORK=off go test -p=1 -race ./pkg/bridge ./pkg/connectivity ./pkg/host ./pkg/httpadapter ./pkg/registry ./internal/runtimeclient ./pkg/storage ./pkg/stress || {
  write_summary
  exit "$STATUS"
}

run_step connectivity_stress_evidence env GOWORK=off REDEVPLUGIN_STRESS_EVIDENCE_PATH="$STRESS_EVIDENCE_FILE" go test -count=1 -run '^TestStressGateConnectivityClassifierEvidence$' ./pkg/connectivity || {
	write_summary
	exit "$STATUS"
}

run_step stress_evidence collect_stress_evidence || {
  write_summary
  exit "$STATUS"
}

if [[ "$MODE" != "fast" ]]; then
	run_step go_all env GOWORK=off go test -p=1 ./cmd/... ./examples/... ./pkg/... || {
    write_summary
    exit "$STATUS"
  }
  run_step browser_harness npm run test:browser-harness:smoke || {
    write_summary
    exit "$STATUS"
  }
  run_step runtime_contract ./scripts/check_redevplugin_runtime_contract.sh || {
    write_summary
    exit "$STATUS"
  }
	run_step release_package_build node --test scripts/build_release_packages.test.mjs || {
    write_summary
    exit "$STATUS"
  }
	run_step release_manifest_verifier node --test scripts/platform_release_manifest.test.mjs scripts/verify_rust_registry_release.test.mjs || {
    write_summary
    exit "$STATUS"
  }
fi

if [[ "$MODE" == "release" ]]; then
  release_summary="$TMP_DIR/release-summary.json"
  render_summary >"$release_summary"
  set +e
  node scripts/verify_redevplugin_release_stress.mjs "$release_summary"
  release_summary_status=$?
  set -e
  if [[ "$release_summary_status" -ne 0 ]]; then
    STATUS=$release_summary_status
    render_summary >"$release_summary"
    write_summary_file "$release_summary"
    exit "$STATUS"
  fi
  write_summary_file "$release_summary"
  exit "$STATUS"
fi

write_summary
exit "$STATUS"
