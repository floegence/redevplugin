#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)}
cd "$ROOT_DIR"

empty_tree=$(git hash-object -t tree /dev/null)
git diff --check "$empty_tree" HEAD --
