#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

(
  cd "$ROOT_DIR"
  go test ./pkg/protocol ./pkg/httpadapter
  grep -q '"target_classifier_version": { "const": "target-classifier-v1" }' spec/plugin/network-grant-v1.schema.json
  grep -q '"transport": { "enum": \["http", "websocket", "tcp", "udp"\] }' spec/plugin/network-grant-v1.schema.json
  grep -q 'package-signature-v1.schema.json' spec/plugin/package-signature-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.package_signature.v1" }' spec/plugin/package-signature-v1.schema.json
  grep -q '"algorithm": { "enum": \["ed25519"\] }' spec/plugin/package-signature-v1.schema.json
  grep -q '"runtime_execution_lease"' spec/plugin/token-ticket-v1.schema.json
  grep -q '"handle_grant"' spec/plugin/token-ticket-v1.schema.json
  grep -q '"runtime_generation_id",' spec/plugin/token-ticket-v1.schema.json
  grep -q '"handle_id",' spec/plugin/token-ticket-v1.schema.json
  grep -q '"stream_id",' spec/plugin/token-ticket-v1.schema.json
  grep -q '"stream_direction"' spec/plugin/token-ticket-v1.schema.json
  grep -q '"method"' spec/plugin/token-ticket-v1.schema.json
  grep -q '"type": { "const": "redeven.plugin.handshake" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redeven.plugin.call" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redeven.plugin.response" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redeven.plugin.lifecycle" }' spec/plugin/bridge-v1.schema.json
  grep -q '"ui_protocol_version": { "const": "plugin-ui-v1" }' spec/plugin/bridge-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.compatibility.v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"bridge_schema_version": { "const": "bridge-v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"compatibility_schema_version"' spec/plugin/compatibility-manifest-v1.schema.json
  go run ./cmd/redevplugin version | grep -q '"schema_version": "redevplugin.compatibility.v1"'
  go run ./cmd/redevplugin version | grep -q '"id": "compatibility-manifest-schema"'
  grep -q '"hello_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"invoke_worker_result"' spec/plugin/ipc-v1.schema.json
  grep -q '"revoke_epoch_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"host_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"rust_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"wasm_abi_version": { "const": "redeven-wasm-worker-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"plugin_instance_id": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
  grep -q '"package_hash": { "$ref": "#/$defs/sha256" }' spec/plugin/worker-invocation-v1.schema.json
  grep -q '"artifact_sha256": { "$ref": "#/$defs/sha256" }' spec/plugin/worker-invocation-v1.schema.json
  grep -q '"pattern": "^sha256:\[a-f0-9\]{64}$"' spec/plugin/worker-invocation-v1.schema.json
)

if command -v cargo >/dev/null 2>&1; then
  (
    cd "$ROOT_DIR"
    cargo test --workspace
  )
else
  echo "cargo not found; skipping Rust runtime contract check" >&2
fi
