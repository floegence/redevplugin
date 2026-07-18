#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-pre-push-hook.XXXXXX")
cleanup() {
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

REPO="$TEST_ROOT/repo"
LOG="$TEST_ROOT/gate.log"
mkdir -p "$REPO/scripts"
git -C "$REPO" init -q -b main
git -C "$REPO" config user.email test@example.invalid
git -C "$REPO" config user.name "ReDevPlugin Hook Test"
cp "$ROOT_DIR/.githooks/pre-push" "$REPO/pre-push"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "%s\\n" gate-ran >> "$HOOK_LOG"' >"$REPO/scripts/check_redevplugin_pre_push.sh"
chmod +x "$REPO/pre-push" "$REPO/scripts/check_redevplugin_pre_push.sh"
printf 'tracked\n' >"$REPO/tracked.txt"
git -C "$REPO" add .
git -C "$REPO" commit -q -m initial
first=$(git -C "$REPO" rev-parse HEAD)
zero40=$(printf '%040d' 0)
zero64=$(printf '%064d' 0)

run_hook() {
  local input=$1
  set +e
  (cd "$REPO" && HOOK_LOG="$LOG" ./pre-push origin test < <(printf '%s\n' "$input"))
  local status=$?
  set -e
  return "$status"
}

run_hook "refs/heads/main $first refs/heads/main $zero40"
test "$(wc -l <"$LOG" | tr -d ' ')" -eq 1
run_hook "refs/heads/feature $first refs/heads/feature $zero40
refs/heads/main $first refs/heads/main $zero40"
test "$(wc -l <"$LOG" | tr -d ' ')" -eq 2
run_hook "refs/heads/feature $first refs/heads/feature $zero40"
test "$(wc -l <"$LOG" | tr -d ' ')" -eq 2

if run_hook "(delete) $zero40 refs/heads/main $first"; then
  echo "hook accepted main deletion" >&2
  exit 1
fi
if run_hook "(delete) $zero64 refs/heads/main $first"; then
  echo "hook accepted SHA-256-shaped main deletion" >&2
  exit 1
fi
if run_hook "refs/heads/feature $first refs/heads/main $zero40"; then
  echo "hook accepted a non-main local ref for main" >&2
  exit 1
fi
if run_hook "refs/heads/main deadbeef refs/heads/main $zero40"; then
  echo "hook accepted a mismatched local object" >&2
  exit 1
fi

git -C "$REPO" checkout -q -b side
printf 'side\n' >"$REPO/side.txt"
git -C "$REPO" add side.txt
git -C "$REPO" commit -q -m side
side=$(git -C "$REPO" rev-parse HEAD)
git -C "$REPO" checkout -q main
if run_hook "refs/heads/main $first refs/heads/main $side"; then
  echo "hook accepted a non-fast-forward main update" >&2
  exit 1
fi

printf 'dirty\n' >>"$REPO/tracked.txt"
if run_hook "refs/heads/main $first refs/heads/main $zero40"; then
  echo "hook accepted a dirty worktree" >&2
  exit 1
fi
git -C "$REPO" checkout -- tracked.txt
git -C "$REPO" checkout -q -b feature
if run_hook "refs/heads/main $first refs/heads/main $zero40"; then
  echo "hook accepted a main push from a feature worktree" >&2
  exit 1
fi

echo "pre-push hook behavior tests passed"
