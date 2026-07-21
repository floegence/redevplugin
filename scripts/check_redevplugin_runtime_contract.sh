#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_runtime_contract.sh [--ci]

Validates the active runtime, package-set, and package-publication contracts.
--ci is accepted so local and hosted gates use the same command shape.
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

cd "$ROOT_DIR"
export GOWORK=off

for command_name in cargo go node npm grep; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required for the runtime contract gate" >&2
    exit 1
  fi
done

echo "==> active contract inventory"
for required in \
  spec/openapi/plugin-platform-v8.yaml \
  spec/plugin/compatibility-manifest-v8.schema.json \
  spec/plugin/error-codes-v6.schema.json \
  spec/plugin/ipc-v6.schema.json \
  spec/plugin/performance-contract-v3.json \
  spec/plugin/performance-evidence-v3.schema.json \
  spec/plugin/platform-package-set-v1.schema.json \
  spec/plugin/platform-package-publication-v1.schema.json \
  spec/plugin/process-containment-v1.schema.json \
  spec/plugin/runtime-admission-v1.schema.json \
  spec/plugin/runtime-descriptor-v2.schema.json \
  spec/plugin/runtime-exec-journal-v1.schema.json; do
  test -f "$required"
done

for obsolete in \
  spec/openapi/plugin-platform-v7.yaml \
  spec/plugin/compatibility-manifest-v7.schema.json \
  spec/plugin/contract-registry-v1.json \
  spec/plugin/error-codes-v5.schema.json \
  spec/plugin/ipc-v5.schema.json \
  spec/plugin/performance-contract-v2.json \
  spec/plugin/performance-evidence-v2.schema.json \
  spec/plugin/release-manifest-v4.schema.json \
  spec/plugin/source-policy-v1.schema.json \
  spec/plugin/source-revocations-v1.schema.json \
  scripts/build_redevplugin_release.sh \
  scripts/build_redevplugin_worker_sdk_package.mjs \
  scripts/verify_redevplugin_release_artifacts.sh \
  scripts/verify_redevplugin_release_bundle.mjs \
  scripts/verify_published_release.mjs \
  scripts/test_published_release_verifier.mjs; do
  if [[ -e "$obsolete" ]]; then
    echo "obsolete runtime release surface remains: $obsolete" >&2
    exit 1
  fi
done

node --input-type=module <<'NODE'
import { readFileSync } from "node:fs";

const registry = JSON.parse(readFileSync("spec/plugin/contract-registry-v2.json", "utf8"));
const ids = new Set(registry.artifacts.map(({ id }) => id));
for (const required of [
  "compatibility-manifest-schema",
  "contract-registry-schema",
  "error-codes-schema",
  "rust-ipc-schema",
  "performance-contract",
  "performance-evidence-schema",
  "platform-package-publication-schema",
  "platform-package-set-schema",
  "process-containment-schema",
  "runtime-admission-schema",
  "runtime-descriptor-schema",
  "runtime-exec-journal-schema",
]) {
  if (!ids.has(required)) throw new Error(`active contract registry omitted ${required}`);
}
for (const obsolete of ["release-manifest-schema", "source-policy-schema", "source-revocations-schema"]) {
  if (ids.has(obsolete)) throw new Error(`active contract registry retained ${obsolete}`);
}
NODE

echo "==> generated contract and wire gates"
npm run contracts:check
npm run platform-package-contracts:check
npm run openapi:check
npm run openapi-contract:test
npm run platform-package-contract:test
npm run platform-package-build:test
npm run platform-package-publication:test

echo "==> Go and Rust runtime contract tests"
go test -count=1 ./pkg/contracts ./pkg/protocol ./internal/runtimeclient ./pkg/version
cargo test -p redevplugin-contracts -p redevplugin-ipc -p redevplugin-runtime

echo "==> package-only workflow policy"
release_workflow=.github/workflows/release.yml
grep -Eq 'platform-package-publication-v1\.json' "$release_workflow"
grep -Eq 'platform_package_build\.mjs' "$release_workflow"
grep -Eq 'verify_rust_registry_release\.mjs' "$release_workflow"
grep -Eq 'verify_npm_registry_release\.mjs' "$release_workflow"
grep -Eq 'verify_go_module_readback\.mjs' "$release_workflow"

if grep -Eni 'macos|darwin|cosign|sha256sums|runtime-target|runtime archive|runtime bundle|\.tar\.gz|build_redevplugin_release|verify_published_release|verify_redevplugin_release_artifacts' "$release_workflow"; then
  echo "release workflow retains an OS runtime artifact path" >&2
  exit 1
fi

if [[ $(grep -Ec 'gh release create' "$release_workflow") -ne 1 ]]; then
  echo "release workflow must contain exactly one GitHub Release creation step" >&2
  exit 1
fi
if [[ $(grep -Ec 'dist/publication/platform-package-publication-v1\.json' "$release_workflow") -lt 1 ]]; then
  echo "release workflow does not upload the canonical completion asset" >&2
  exit 1
fi

echo "ReDevPlugin runtime and package publication contracts passed"
