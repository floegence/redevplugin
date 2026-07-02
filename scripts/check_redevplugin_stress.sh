#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

MODE="fast"
SUMMARY_PATH=""

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_stress.sh [--fast|--full|--release] [--summary PATH]

Runs the host-neutral ReDevPlugin stress gate.

Modes:
  --fast      Race-sensitive broker/lifecycle packages plus pkg/stress tests.
  --full      Fast gate plus platform/browser/runtime-contract/release-bundle smoke.
  --release   Alias for --full; intended for release-blocking local use.

The script always writes a JSON summary to stdout. When --summary is provided,
the same JSON summary is also written to PATH.
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
TMP_DIR=""

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

write_summary() {
  local completed_at
  local ok
  local categories
  local steps_json
  completed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [[ "$STATUS" -eq 0 ]]; then
    ok=true
  else
    ok=false
  fi
  categories='["go_race","stream_backpressure","connectivity_classifier","storage_quota"]'
  if [[ "$MODE" != "fast" ]]; then
    categories='["go_race","stream_backpressure","connectivity_classifier","storage_quota","browser_demo","runtime_contract","release_bundle"]'
  fi
  steps_json=$(IFS=,; echo "${STEPS[*]}")
  local summary
  summary=$(cat <<JSON
{
  "ok": $ok,
  "mode": "$MODE",
  "started_at": "$STARTED_AT",
  "completed_at": "$completed_at",
  "stress_categories": $categories,
  "steps": [$steps_json]
}
JSON
)
  echo "$summary"
  if [[ -n "$SUMMARY_PATH" ]]; then
    mkdir -p "$(dirname -- "$SUMMARY_PATH")"
    printf '%s\n' "$summary" >"$SUMMARY_PATH"
  fi
}

cleanup() {
  if [[ -n "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

cd "$ROOT_DIR"

run_step go_race_core env GOWORK=off go test -race ./pkg/bridge ./pkg/connectivity ./pkg/host ./pkg/httpadapter ./pkg/operation ./pkg/storage ./pkg/stream ./pkg/stress || {
  write_summary
  exit "$STATUS"
}

if [[ "$MODE" != "fast" ]]; then
  if [[ ! -x node_modules/.bin/tsc || ! -d node_modules/playwright ]]; then
    run_step npm_ci npm ci || {
      write_summary
      exit "$STATUS"
    }
  fi
  run_step go_all env GOWORK=off go test ./... || {
    write_summary
    exit "$STATUS"
  }
  run_step browser_demo npm run test:demo:browser || {
    write_summary
    exit "$STATUS"
  }
  run_step runtime_contract ./scripts/check_redevplugin_runtime_contract.sh || {
    write_summary
    exit "$STATUS"
  }
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-stress-release.XXXXXX")
  run_step release_bundle ./scripts/build_redevplugin_release.sh --version 0.0.0-stress.0 --out-dir "$TMP_DIR/release" || {
    write_summary
    exit "$STATUS"
  }
fi

write_summary
exit "$STATUS"
