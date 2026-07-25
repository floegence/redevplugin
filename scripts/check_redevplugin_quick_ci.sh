#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
cd "$ROOT_DIR"
export GOWORK=off

echo "==> repository diff and source formatting"
git diff --check
git diff-tree --check --root -r --no-commit-id HEAD
test -z "$(gofmt -l $(git ls-files '*.go'))"
cargo fmt --check

echo "==> shell and JavaScript syntax"
for script in scripts/*.sh .githooks/pre-push; do
  bash -n "$script"
done
for script in scripts/*.mjs; do
  node --check "$script"
done

echo "==> quick CI policy"
node --test scripts/quick_ci_policy.test.mjs

echo "ReDevPlugin quick CI passed"
