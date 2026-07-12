#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_platform.sh [--ci]

Runs the ReDevPlugin platform gate. --ci is accepted as an explicit no-op so
documentation, local runs, and CI can share the same command shape.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

export GOWORK=off

(
  cd "$ROOT_DIR"
  go list ./...
  go test ./...
  tmp_compatibility_manifest=$(mktemp "${TMPDIR:-/tmp}/redevplugin-compatibility.XXXXXX.json")
  tmp_scaffold_dir=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-scaffold.XXXXXX")
  tmp_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-minimal.XXXXXX.redevplugin")
  tmp_fixture_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-generated-fixture.XXXXXX.redevplugin")
  tmp_signed_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-minimal-signed.XXXXXX.redevplugin")
  tmp_malicious_package=$(mktemp "${TMPDIR:-/tmp}/redevplugin-malicious.XXXXXX.redevplugin")
  tmp_malicious_log=$(mktemp "${TMPDIR:-/tmp}/redevplugin-malicious.XXXXXX.log")
  tmp_private_key=$(mktemp "${TMPDIR:-/tmp}/redevplugin-private.XXXXXX.json")
  tmp_public_key=$(mktemp "${TMPDIR:-/tmp}/redevplugin-public.XXXXXX.json")
  tmp_storage_root=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-storage.XXXXXX")
  tmp_dev_state_root=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-dev-state.XXXXXX")
  trap 'rm -rf "$tmp_scaffold_dir" "$tmp_storage_root" "$tmp_dev_state_root"; rm -f "$tmp_compatibility_manifest" "$tmp_package" "$tmp_fixture_package" "$tmp_signed_package" "$tmp_malicious_package" "$tmp_malicious_log" "$tmp_private_key" "$tmp_public_key"' EXIT
  go run ./cmd/redevplugin version >"$tmp_compatibility_manifest"
  go run ./cmd/redevplugin verify-compatibility "$tmp_compatibility_manifest" . | grep -q '"ok": true'
  for generated_fixture in testdata/generated_plugins/minimal testdata/generated_plugins/networked testdata/generated_plugins/storage testdata/generated_plugins/method-contract; do
    go run ./cmd/redevplugin validate "$generated_fixture/manifest.json" >/dev/null
    rm -f "$tmp_fixture_package"
    go run ./cmd/redevplugin package "$generated_fixture" "$tmp_fixture_package" >/dev/null
    go run ./cmd/redevplugin validate "$tmp_fixture_package" >/dev/null
  done
  malicious_fixture_count=0
  for malicious_fixture in testdata/generated_plugins/malicious-build/*; do
    [[ -d "$malicious_fixture" ]] || continue
    malicious_fixture_count=$((malicious_fixture_count + 1))
    rm -f "$tmp_malicious_package" "$tmp_malicious_log"
    if go run ./cmd/redevplugin package "$malicious_fixture" "$tmp_malicious_package" >"$tmp_malicious_log" 2>&1; then
      echo "malicious generated plugin fixture unexpectedly packaged: $malicious_fixture" >&2
      exit 1
    fi
    grep -Eq 'package manager lifecycle script|package manager dependency field|Cargo build|Cargo proc macro|Cargo native linker|Cargo dependency section' "$tmp_malicious_log"
  done
  if [[ "$malicious_fixture_count" -eq 0 ]]; then
    echo "missing malicious generated plugin fixtures" >&2
    exit 1
  fi
  go run ./cmd/redevplugin scaffold com.example.smoke "Smoke Plugin" "$tmp_scaffold_dir" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_scaffold_dir/manifest.json" >/dev/null
  go run ./cmd/redevplugin package "$tmp_scaffold_dir" "$tmp_package" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_package" >/dev/null
  go run ./cmd/redevplugin keygen test-key "$tmp_private_key" "$tmp_public_key" >/dev/null
  go run ./cmd/redevplugin sign "$tmp_package" "$tmp_private_key" "$tmp_signed_package" >/dev/null
  go run ./cmd/redevplugin validate "$tmp_signed_package" | grep -q '"signed": true'
  go run ./cmd/redevplugin install-verified "$tmp_signed_package" "$tmp_public_key" | grep -q '"trust_state": "verified"'
  go run ./cmd/redevplugin inspect-storage "$tmp_storage_root" | grep -q '"namespace_count": 0'
  go run ./cmd/redevplugin install-local "$tmp_package" >/dev/null
  go run ./cmd/redevplugin enable "$tmp_package" >/dev/null
  go run ./cmd/redevplugin disable "$tmp_package" >/dev/null
  go run ./cmd/redevplugin uninstall "$tmp_package" >/dev/null
  go run ./cmd/redevplugin dev-install "$tmp_dev_state_root" "$tmp_package" | grep -q '"enable_state": "disabled"'
  go run ./cmd/redevplugin dev-enable "$tmp_dev_state_root" | grep -q '"enable_state": "enabled"'
  dev_open_output=$(go run ./cmd/redevplugin dev-open "$tmp_dev_state_root" "com.example.smoke.view")
  grep -q '"surface_instance_id":' <<<"$dev_open_output"
  grep -q '"bridge_nonce":' <<<"$dev_open_output"
  grep -q '"asset_ticket_id":' <<<"$dev_open_output"
  go run ./cmd/redevplugin dev-disable "$tmp_dev_state_root" | grep -q '"enable_state": "disabled"'
  go run ./cmd/redevplugin dev-uninstall "$tmp_dev_state_root" --delete-data | grep -q '"retained_data_state": "deleted"'
  ./scripts/check_redevplugin_ui_bridge.sh
)

if command -v npm >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    npm run typecheck
    npm run test:demo
    npm run test:demo:browser
  )
else
  echo "npm not found; skipping TypeScript check" >&2
fi
