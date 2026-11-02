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

# Exercise the actual Git hook environment in a linked worktree. The gate's
# nested repository must not change the source branch, index, or local config.
git -C "$REPO" switch -q main
mkdir -p "$REPO/.githooks"
cp "$ROOT_DIR/.githooks/pre-push" "$REPO/.githooks/pre-push"
cat >"$REPO/scripts/check_redevplugin_pre_push.sh" <<'GATE'
#!/usr/bin/env bash
set -euo pipefail
for key in $(git rev-parse --local-env-vars); do
  if printenv "$key" >/dev/null; then
    echo "gate inherited repository-local environment: $key" >&2
    exit 1
  fi
done
nested=$(mktemp -d)
trap 'rm -rf "$nested"' EXIT
git -C "$nested" init -q -b fixture
git -C "$nested" config user.name Fixture
git -C "$nested" config user.email fixture@example.invalid
printf 'fixture\n' >"$nested/file"
git -C "$nested" add .
git -C "$nested" commit -qm fixture
GATE
chmod +x "$REPO/.githooks/pre-push" "$REPO/scripts/check_redevplugin_pre_push.sh"
git -C "$REPO" add .
git -C "$REPO" commit -qm 'install real hook'
git -C "$REPO" config core.hooksPath .githooks
expected=$(git -C "$REPO" rev-parse HEAD)
git init -q --bare "$TEST_ROOT/remote.git"
git -C "$REPO" remote add origin "$TEST_ROOT/remote.git"
git -C "$REPO" switch -q --detach
git -C "$REPO" worktree add -q "$TEST_ROOT/linked" main
git -C "$TEST_ROOT/linked" push -q origin main
test "$(git -C "$TEST_ROOT/linked" rev-parse HEAD)" = "$expected"
test "$(git -C "$TEST_ROOT/linked" symbolic-ref --short HEAD)" = main
test -z "$(git -C "$TEST_ROOT/linked" status --porcelain)"
test "$(git -C "$REPO" config user.name)" = 'ReDevPlugin Hook Test'
test "$(git -C "$REPO" config --bool core.bare)" = false
test "$(git --git-dir="$TEST_ROOT/remote.git" rev-parse refs/heads/main)" = "$expected"
git -C "$REPO" worktree remove "$TEST_ROOT/linked"

echo "pre-push hook behavior tests passed"
