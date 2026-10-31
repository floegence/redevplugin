#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
ARGS=()

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_pre_push.sh [--ci] [--fresh]

Runs every non-GitHub-infrastructure gate required before updating main.
The --ci mode selects hosted Linux browser dependency installation for manual
runner reproduction. Ordinary push, pull-request, and tag workflows never
invoke this complete gate.
Successful stages may reuse verified input-bound evidence. --fresh recomputes
every stage. Audits and dependency preparation always run.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci)
      ARGS+=(--ci)
      shift
      ;;
    --fresh)
      ARGS+=(--fresh)
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
export GOWORK=off

if [[ -n "${HOME:-}" && -d "$HOME/.cargo/bin" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
  export PATH
fi

for command_name in cargo go node npm rustc rustup; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required for the ReDevPlugin pre-push gate" >&2
    exit 1
  fi
done

GO_BIN_DIR=$(go env GOPATH)/bin
PATH="$GO_BIN_DIR:$PATH"
export PATH

REQUIRED_GO_VERSION=$(awk '$1 == "go" { print $2; exit }' go.mod)
if [[ "$(go env GOVERSION)" != "go${REQUIRED_GO_VERSION}" ]]; then
  echo "Go ${REQUIRED_GO_VERSION} is required; found $(go env GOVERSION)" >&2
  exit 1
fi
REQUIRED_NODE_VERSION=$(tr -d '\r\n' < .node-version)
if [[ "$(node -p 'process.versions.node')" != "$REQUIRED_NODE_VERSION" ]]; then
  echo "Node.js ${REQUIRED_NODE_VERSION} is required; found $(node --version)" >&2
  exit 1
fi

REQUIRED_RUST_VERSION=$(sed -n 's/^channel = "\([0-9.]*\)"/\1/p' rust-toolchain.toml)
if [[ "$(rustc --version | awk '{print $2}')" != "$REQUIRED_RUST_VERSION" ]]; then
  echo "Rust $REQUIRED_RUST_VERSION is required" >&2
  exit 1
fi

# Check immutable prerequisites before downloads or expensive test work.
node scripts/redevplugin_gate.mjs --preflight
for script in scripts/*.sh .githooks/pre-push; do
  bash -n "$script"
done
for script in scripts/*.mjs; do
  node --check "$script"
done
./scripts/test_redevplugin_pre_push_hook.sh
node --test scripts/node_toolchain_contract.test.mjs scripts/stress_platform_policy.test.mjs scripts/redevplugin_gate.test.mjs

if ! golangci-lint --version 2>/dev/null | grep -Eq 'version v?2\.15\.0([[:space:]]|$)'; then
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
fi
if [[ "$(cargo-deny --version 2>/dev/null || true)" != "cargo-deny 0.19.9" ]]; then
  cargo install cargo-deny@0.19.9 --locked
fi

exec node scripts/redevplugin_gate.mjs "${ARGS[@]}"
