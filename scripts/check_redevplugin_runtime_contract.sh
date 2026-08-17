#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci) shift ;;
    -h|--help)
      echo "Usage: scripts/check_redevplugin_runtime_contract.sh [--ci]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"
export GOWORK=off

for required in \
  VERSION \
  spec/openapi/plugin-platform.yaml \
  spec/platform-release-manifest.schema.json \
  spec/plugin/plugin-api.json \
  spec/plugin/manifest-v9.schema.json \
  spec/plugin/error-codes.schema.json \
  spec/plugin/bridge.schema.json \
  spec/plugin/package-signature-v1.schema.json \
  spec/plugin/release-metadata.schema.json \
  spec/plugin/wasm-abi.json \
  spec/plugin/worker-invocation.schema.json \
  spec/internal/runtime-wire.schema.json; do
  test -f "$required"
done

for obsolete in \
  internal/contracts/active-contracts.json \
  spec/openapi/plugin-platform-v16.yaml \
  spec/openapi/plugin-platform-v17.yaml \
  spec/plugin/compatibility-manifest-v19.schema.json \
  spec/plugin/compatibility-manifest-v20.schema.json \
  spec/plugin/contract-registry-v2.json \
  spec/plugin/contract-registry-v2.schema.json \
  spec/plugin/ipc-v6.schema.json \
  spec/plugin/ipc-v7.schema.json \
  spec/plugin/public-api-v1.json \
  spec/plugin/error-codes-v6.schema.json \
  spec/plugin/error-codes-v8.schema.json \
  spec/plugin/bridge-v7.schema.json \
  spec/plugin/release-metadata-v8.schema.json \
  spec/plugin/runtime-descriptor-v2.schema.json \
  spec/plugin/runtime-descriptor-v3.schema.json \
  spec/plugin/wasm-worker-v2.schema.json \
  spec/plugin/worker-invocation-v3.schema.json \
  spec/plugin/platform-package-set-v3.json \
  spec/plugin/platform-package-set-v3.schema.json \
  spec/plugin/platform-package-publication-v2.schema.json; do
  if [[ -e "$obsolete" ]]; then
    echo "obsolete contract remains: $obsolete" >&2
    exit 1
  fi
done

npm run platform-version:test
npm run platform-release-manifest:test
npm run error-codes:check
npm run ui-contracts:check
npm run openapi:check
npm run openapi-contract:test
go test -count=1 ./pkg/protocol ./pkg/version ./internal/runtimeclient
cargo test -p redevplugin-runtime -p redevplugin-worker-sdk

echo "ReDevPlugin current runtime contracts passed"
