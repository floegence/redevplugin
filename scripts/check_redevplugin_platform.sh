#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./...
)

if command -v npm >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    npm run typecheck
  )
else
  echo "npm not found; skipping TypeScript check" >&2
fi

