#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
SDK_SRC="$ROOT_DIR/packages/redevplugin-ui/src"

if grep -R 'postMessage([^,]*,[[:space:]]*["'\'']\*["'\'']' "$SDK_SRC" >/dev/null; then
  echo "redevplugin-ui must not use wildcard postMessage targetOrigin" >&2
  exit 1
fi
