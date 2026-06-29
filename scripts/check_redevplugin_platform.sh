#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./...
  go run ./cmd/redevplugin validate testdata/generated_plugins/minimal/manifest.json >/dev/null
  tmp_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-minimal.XXXXXX.redeven-plugin")
  go run ./cmd/redevplugin package testdata/generated_plugins/minimal "$tmp_package" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_package" >/dev/null
  rm -f "$tmp_package"
)

if command -v npm >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    npm run typecheck
  )
else
  echo "npm not found; skipping TypeScript check" >&2
fi
