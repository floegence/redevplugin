#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
MODE="fast"

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_property_gates.sh [--fast|--stress|--release]

Modes:
  --fast      Run Go fuzz seed corpus and Rust property tests once.
  --stress    Run each high-risk Go parser fuzz target for at least 30 seconds.
  --release   Run the fixed corpus, property tests, and persisted regression corpus.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast|--stress|--release)
      MODE="${1#--}"
      shift
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

cd "$ROOT_DIR"

GO_FUZZ_PACKAGES=(
  ./pkg/pluginpkg
  ./pkg/releasecontract
  ./pkg/manifest
  ./pkg/capability
  ./pkg/runtimeclient
  ./pkg/stream
  ./pkg/plugindata
)
GO_FUZZ_TARGETS=(
  FuzzReadPackageZip
  FuzzDecodeReleaseContracts
  FuzzDecode
  FuzzPrepareResponseData
  FuzzReadIPCFrame
  FuzzMemoryStreamState
  FuzzSQLiteTokens
)

run_fixed_corpus() {
  echo "==> Go fuzz seed corpus" >&2
  GOWORK=off go test -run '^Fuzz' -count=1 "${GO_FUZZ_PACKAGES[@]}"
  echo "==> Rust property tests" >&2
  cargo test --workspace --all-targets
}

run_regression_corpus() {
  # Persisted Go and proptest regression inputs are executed by the normal
  # test runners; this explicit pass makes release coverage auditable.
  echo "==> regression corpus" >&2
  GOWORK=off go test -run '^Fuzz' -count=1 "${GO_FUZZ_PACKAGES[@]}"
  cargo test --workspace --all-targets
}

run_fuzz_stress() {
  local index package target
  for index in "${!GO_FUZZ_PACKAGES[@]}"; do
    package="${GO_FUZZ_PACKAGES[$index]}"
    target="${GO_FUZZ_TARGETS[$index]}"
    echo "==> $target (30s)" >&2
    GOWORK=off go test "$package" -run '^$' -fuzz="^${target}$" -fuzztime=30s -count=1
  done
}

case "$MODE" in
  fast)
    run_fixed_corpus
    ;;
  release)
    run_regression_corpus
    ;;
  stress)
    run_fixed_corpus
    run_fuzz_stress
    ;;
  *)
    echo "invalid mode: $MODE" >&2
    exit 2
    ;;
esac

echo "redevplugin property gates passed ($MODE)"
