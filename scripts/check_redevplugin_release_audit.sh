#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

cd "$ROOT_DIR"

echo "==> npm_audit"
npm_audit_log=$(mktemp "${TMPDIR:-/tmp}/redevplugin-npm-audit.XXXXXX")
cleanup() {
	rm -f "$npm_audit_log"
}
trap cleanup EXIT

is_transient_npm_audit_failure() {
	grep -Eiq \
		'audit endpoint returned an error|network socket disconnected|ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENETUNREACH|HTTP (429|502|503|504)' \
		"$npm_audit_log"
}

for attempt in 1 2 3 4; do
	npm_audit_status=0
	npm audit --audit-level=moderate >"$npm_audit_log" 2>&1 || npm_audit_status=$?
	cat "$npm_audit_log"
	if [[ "$npm_audit_status" -eq 0 ]]; then
		break
	fi
	if ! is_transient_npm_audit_failure || [[ "$attempt" -eq 4 ]]; then
		exit "$npm_audit_status"
	fi
	echo "npm audit availability failure; retrying ($attempt/4)" >&2
	sleep "$attempt"
done

echo "==> go_vulncheck"
GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 \
	./cmd/... \
	./examples/... \
	./pkg/...

echo "==> cargo_deny"
if ! command -v cargo-deny >/dev/null 2>&1; then
  if [[ "${REDEVPLUGIN_INSTALL_AUDIT_TOOLS:-0}" != "1" ]]; then
    echo "cargo-deny is required; set REDEVPLUGIN_INSTALL_AUDIT_TOOLS=1 to install it for this run" >&2
    exit 1
  fi
  cargo install cargo-deny@0.19.9 --locked
fi
cargo deny check
