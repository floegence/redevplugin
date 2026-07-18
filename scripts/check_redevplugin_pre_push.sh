#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
MODE="local"

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_pre_push.sh [--ci]

Runs every non-GitHub-infrastructure gate required before updating main.
The --ci mode selects the Linux browser dependency installation used by the
GitHub workflow; it does not skip any repository gate.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci)
      MODE="ci"
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
if [[ "$(node -p 'process.versions.node.split(".")[0]')" != "24" ]]; then
  echo "Node.js 24 is required; found $(node --version)" >&2
  exit 1
fi

if ! golangci-lint --version 2>/dev/null | grep -Eq 'version v?1\.64\.5([[:space:]]|$)'; then
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5
fi
if [[ "$(cargo-deny --version 2>/dev/null || true)" != "cargo-deny 0.19.9" ]]; then
  cargo install cargo-deny@0.19.9 --locked
fi

echo "==> shell and JavaScript syntax"
for script in scripts/*.sh; do
  bash -n "$script"
done
for script in scripts/*.mjs; do
  node --check "$script"
done
./scripts/test_redevplugin_pre_push_hook.sh

echo "==> npm dependencies"
npm ci
if [[ "$MODE" == "ci" ]]; then
  npx playwright install --with-deps chromium
else
  npx playwright install chromium
fi

echo "==> Rust WASM target"
rustup target add wasm32-unknown-unknown

echo "==> Go format, package list, tests, and lint"
test -z "$(gofmt -l .)"
go list ./cmd/... ./examples/... ./pkg/...
go test ./cmd/... ./examples/... ./pkg/...
golangci-lint run ./cmd/... ./examples/... ./pkg/...

echo "==> TypeScript, contract, browser, and property checks"
REDEVPLUGIN_A2_EVIDENCE_DIR=dist/a2-pre-push npm run check
npm run examples:check:canonical
npm run scaffold:check:canonical
./scripts/check_redevplugin_ui_bridge.sh

echo "==> deterministic performance gate"
npm run performance:fast

echo "==> Rust format, lint, tests, and dependency policy"
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check

echo "==> release audit"
REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 ./scripts/check_redevplugin_release_audit.sh

echo "==> stress and property gates"
mkdir -p dist
./scripts/check_redevplugin_stress.sh --fast --summary dist/redevplugin-pre-push-stress.json
./scripts/check_redevplugin_property_gates.sh --fast

echo "==> runtime and platform contracts"
./scripts/check_redevplugin_runtime_contract.sh --ci
./scripts/check_redevplugin_platform.sh --ci

echo "==> release bundle smoke and published verifier"
SMOKE_VERSION=$(node scripts/resolve_redevplugin_smoke_version.mjs ci.local)
SMOKE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-pre-push-release.XXXXXX")
cleanup() {
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT
./scripts/build_redevplugin_release.sh \
  --performance-gate smoke \
  --version "$SMOKE_VERSION" \
  --out-dir "$SMOKE_DIR/release"
"$SMOKE_DIR/release/bin/redevplugin" verify-compatibility \
  "$SMOKE_DIR/release/compatibility.json" \
  "$SMOKE_DIR/release/contracts"
node scripts/verify_redevplugin_release_bundle.mjs \
  --skip-execution \
  --allow-smoke \
  "$SMOKE_DIR/release" \
  "$SMOKE_VERSION"
node scripts/test_published_release_verifier.mjs \
  "$SMOKE_DIR/release" \
  "$SMOKE_VERSION" \
  "$(git rev-parse HEAD)"

echo "ReDevPlugin pre-push gate passed"
