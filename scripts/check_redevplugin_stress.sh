#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test -race ./pkg/bridge ./pkg/connectivity ./pkg/host ./pkg/httpadapter ./pkg/operation ./pkg/storage
)
