#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./pkg/protocol ./pkg/httpadapter
)

if command -v cargo >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    cargo test --workspace
  )
else
  echo "cargo not found; skipping Rust runtime contract check" >&2
fi

