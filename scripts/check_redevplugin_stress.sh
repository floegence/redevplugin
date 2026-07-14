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
  --release   Full gate plus validation of the exact release stress summary.

The script always writes a JSON summary with structured stress_evidence counters
to stdout. When --summary is provided, the same JSON summary is also written to
PATH.
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
  categories='["go_race","stream_backpressure","operation_cancel_ownership","connectivity_classifier","runtime_revoke_ack","storage_quota"]'
  if [[ "$MODE" != "fast" ]]; then
    categories='["go_race","stream_backpressure","operation_cancel_ownership","connectivity_classifier","runtime_revoke_ack","storage_quota","browser_demo","runtime_contract","release_bundle","published_release_verifier"]'
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

run_step stress_evidence env GOWORK=off REDEVPLUGIN_STRESS_EVIDENCE_PATH="$STRESS_EVIDENCE_FILE" go test -count=1 ./pkg/stress || {
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
  run_step release_bundle ./scripts/build_redevplugin_release.sh --version 0.3.1 --out-dir "$TMP_DIR/release" || {
    write_summary
    exit "$STATUS"
  }
  run_step published_release_verifier node scripts/test_published_release_verifier.mjs "$TMP_DIR/release" 0.3.1 "$(git rev-parse HEAD)" || {
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
