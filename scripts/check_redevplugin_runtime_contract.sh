#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./pkg/protocol ./pkg/httpadapter
  grep -q '"target_classifier_version": { "const": "target-classifier-v1" }' spec/plugin/network-grant-v1.schema.json
  grep -q '"transport": { "enum": \["http", "websocket", "tcp", "udp"\] }' spec/plugin/network-grant-v1.schema.json
)

if command -v cargo >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    cargo test --workspace
  )
else
  echo "cargo not found; skipping Rust runtime contract check" >&2
fi
