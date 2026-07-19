#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
MODE="full"
OUTPUT="$ROOT_DIR/dist/performance-evidence.json"
VERSION=""
SOURCE_COMMIT=""
GENERATED_AT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast|--smoke|--full|--release)
      MODE="${1#--}"
      shift
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --source-commit)
      SOURCE_COMMIT="$2"
      shift 2
      ;;
    --generated-at)
      GENERATED_AT="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"
if [[ "$MODE" == "fast" ]]; then
  GOWORK=off REDEVPLUGIN_PERFORMANCE_GATE=fast go test ./pkg/runtimeclient -run '^(TestRuntimeLimitsMustBeExplicitAndValid|TestRuntimeAdmissionCancellationDoesNotConsumeCapacity|TestRuntimeAdmissionPreservesQueueCapacityForOtherPlugins|TestProcessSupervisorMultiplexesSameShardInvocations|TestProcessSupervisorControlIPCRemainsAvailableWhenInvocationAdmissionIsFull|TestProcessSupervisorDrainsCanceledInvocationWithoutInvalidatingRuntime)$' -count=1
  GOWORK=off REDEVPLUGIN_PERFORMANCE_GATE=fast go test ./pkg/stream -run '^(TestPerformanceStreamWaitersAndBackpressure|TestSQLiteEmptyObservationDoesNotAcquireWriteGate|TestPerformanceSQLiteStreamBatchDelivery)$' -count=1
  npm run typecheck
  npm run test:ui
  exit 0
fi

if [[ -z "$VERSION" ]]; then
  VERSION=$(node --input-type=module -e 'import { readFileSync } from "node:fs"; const match = readFileSync("CHANGELOG.md", "utf8").match(/^## v([^\s]+)$/m); if (!match) process.exit(1); process.stdout.write(match[1]);')
fi
if [[ -z "$SOURCE_COMMIT" ]]; then
  SOURCE_COMMIT=$(git rev-parse HEAD)
fi
HEAD_COMMIT=$(git rev-parse HEAD)
if [[ "$SOURCE_COMMIT" != "$HEAD_COMMIT" ]]; then
  echo "performance evidence source commit $SOURCE_COMMIT does not match HEAD $HEAD_COMMIT" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "performance evidence requires a clean tracked and untracked worktree" >&2
  exit 1
fi
RUNTIME_PATH="${REDEVPLUGIN_PERFORMANCE_RUNTIME:-}"
if [[ "$MODE" == "release" && -n "$RUNTIME_PATH" ]]; then
  echo "release performance evidence must build redevplugin-runtime from the clean checked-out HEAD" >&2
  exit 1
fi
if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$ROOT_DIR/$OUTPUT"
fi
mkdir -p "$(dirname -- "$OUTPUT")"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-performance.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT
MEASUREMENTS="$TMP_DIR/measurements.ndjson"
COMPARISONS="$TMP_DIR/comparisons.ndjson"
COMPATIBILITY="$TMP_DIR/compatibility.json"

npm run contracts:check
npm --prefix packages/redevplugin-ui run build
if [[ -z "$RUNTIME_PATH" ]]; then
  REDEVPLUGIN_RUNTIME_VERSION="$VERSION" cargo build --release -p redevplugin-runtime
  RUNTIME_PATH="$ROOT_DIR/target/release/redevplugin-runtime"
elif [[ ! -x "$RUNTIME_PATH" ]]; then
  echo "configured performance runtime is not executable: $RUNTIME_PATH" >&2
  exit 1
fi
GOWORK=off REDEVPLUGIN_PERFORMANCE_RUNTIME="$RUNTIME_PATH" REDEVPLUGIN_PERFORMANCE_RUNTIME_VERSION="$VERSION" REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/host -run '^TestPerformanceRuntime' -count=1
REDEVPLUGIN_RUNTIME_VERSION="$VERSION" REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  cargo test --release -p redevplugin-runtime ipc_writer_burst_performance_evidence -- --nocapture
REDEVPLUGIN_RUNTIME_VERSION="$VERSION" REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  cargo test --release -p redevplugin-runtime indexed_cancel_performance_evidence -- --nocapture
REDEVPLUGIN_RUNTIME_VERSION="$VERSION" REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  cargo test --release -p redevplugin-runtime indexed_eviction_performance_evidence -- --nocapture
REDEVPLUGIN_RUNTIME_VERSION="$VERSION" \
  cargo test --release -p redevplugin-runtime module_cache::tests::recency_index_matches_cached_entries_after_hits_and_evictions -- --exact
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/connectivity -run '^TestPerformance' -count=1
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/plugindata -run '^TestPerformance' -count=1
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/pluginpkg -run '^TestPerformance' -count=1
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/registry -run '^TestPerformance' -count=1
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/operation -run '^TestPerformance' -count=1
GOWORK=off REDEVPLUGIN_PERFORMANCE_MEASUREMENTS="$MEASUREMENTS" REDEVPLUGIN_PERFORMANCE_GATE="$MODE" \
  go test ./pkg/stream -run '^TestPerformance' -count=1
node scripts/measure_http_route_authorization_performance.mjs \
  --output "$MEASUREMENTS" \
  --comparison-output "$COMPARISONS" \
  --gate "$MODE"
node scripts/measure_redevplugin_ui_performance.mjs --output "$MEASUREMENTS" --gate "$MODE"
node scripts/measure_redevplugin_renderer_performance.mjs --output "$MEASUREMENTS" --gate "$MODE"
GOWORK=off go run ./cmd/redevplugin version >"$COMPATIBILITY"

ARGS=(
  --output "$OUTPUT"
  --measurements "$MEASUREMENTS"
  --comparisons "$COMPARISONS"
  --compatibility "$COMPATIBILITY"
  --version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
  --gate "$MODE"
)
if [[ -n "$GENERATED_AT" ]]; then
  ARGS+=(--generated-at "$GENERATED_AT")
fi
node scripts/generate_redevplugin_performance_evidence.mjs "${ARGS[@]}"
echo "redevplugin performance evidence created at $OUTPUT"
