#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

cd "$ROOT_DIR"

echo "==> npm_audit"
npm audit --audit-level=moderate

echo "==> go_vulncheck"
GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@latest ./...

echo "==> cargo_deny"
if ! command -v cargo-deny >/dev/null 2>&1; then
  if [[ "${REDEVPLUGIN_INSTALL_AUDIT_TOOLS:-0}" != "1" ]]; then
    echo "cargo-deny is required; set REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 to install it for this run" >&2
    exit 1
  fi
  cargo install cargo-deny --locked
fi
cargo deny check
