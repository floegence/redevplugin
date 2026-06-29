#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./...
  go run ./cmd/redevplugin validate testdata/generated_plugins/minimal/manifest.json >/dev/null
  tmp_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-minimal.XXXXXX.redeven-plugin")
  tmp_signed_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-minimal-signed.XXXXXX.redeven-plugin")
  tmp_private_key=$(mktemp "${TMPDIR:-/tmp}/redevplugin-private.XXXXXX.json")
  tmp_public_key=$(mktemp "${TMPDIR:-/tmp}/redevplugin-public.XXXXXX.json")
  trap 'rm -f "$tmp_package" "$tmp_signed_package" "$tmp_private_key" "$tmp_public_key"' EXIT
  go run ./cmd/redevplugin package testdata/generated_plugins/minimal "$tmp_package" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_package" >/dev/null
  go run ./cmd/redevplugin keygen test-key "$tmp_private_key" "$tmp_public_key" >/dev/null
  go run ./cmd/redevplugin sign "$tmp_package" "$tmp_private_key" "$tmp_signed_package" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_signed_package" | grep -q '"signed": true'
  go run ./cmd/redevplugin install-verified "$tmp_signed_package" "$tmp_public_key" | grep -q '"trust_state": "verified"'
  go run ./cmd/redevplugin install-local "$tmp_package" >/dev/null
  go run ./cmd/redevplugin enable "$tmp_package" >/dev/null
  go run ./cmd/redevplugin disable "$tmp_package" >/dev/null
  go run ./cmd/redevplugin uninstall "$tmp_package" >/dev/null
  ./scripts/check_redevplugin_ui_bridge.sh
)

if command -v npm >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    npm run typecheck
  )
else
  echo "npm not found; skipping TypeScript check" >&2
fi
