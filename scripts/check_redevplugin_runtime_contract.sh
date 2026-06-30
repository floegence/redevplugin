#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

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
  grep -q '"type": { "const": "redevplugin.bridge.handshake" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redevplugin.bridge.call" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redevplugin.bridge.response" }' spec/plugin/bridge-v1.schema.json
  grep -q '"type": { "const": "redevplugin.bridge.lifecycle" }' spec/plugin/bridge-v1.schema.json
  grep -q '"ui_protocol_version": { "const": "plugin-ui-v1" }' spec/plugin/bridge-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.compatibility.v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"bridge_schema_version": { "const": "bridge-v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"compatibility_schema_version"' spec/plugin/compatibility-manifest-v1.schema.json
  go run ./cmd/redevplugin version | grep -q '"schema_version": "redevplugin.compatibility.v1"'
  go run ./cmd/redevplugin version | grep -q '"id": "compatibility-manifest-schema"'
  grep -q '"hello_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"invoke_worker_result"' spec/plugin/ipc-v1.schema.json
  grep -q '"open_handle_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"open_handle_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"validate_handle_grant_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"validate_handle_grant_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_file_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_file_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"method": { "const": "storage.files" }' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_kv_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_kv_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"method": { "const": "storage.kv" }' spec/plugin/ipc-v1.schema.json
  grep -q '"network_grant_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"network_grant_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"network_execute_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"network_execute_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"network_destination"' spec/plugin/ipc-v1.schema.json
  grep -q '"ttl_ms": { "type": "integer", "minimum": 0 }' spec/plugin/ipc-v1.schema.json
  grep -q 'FRAME_TYPE_STORAGE_FILE' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_STORAGE_FILE_FAILED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct StorageFileRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'storage_file_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_storage_file_response' crates/redevplugin-ipc/src/lib.rs
  grep -q 'FRAME_TYPE_STORAGE_KV' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_STORAGE_KV_FAILED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct StorageKVRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'storage_kv_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_storage_kv_response' crates/redevplugin-ipc/src/lib.rs
  grep -q 'FRAME_TYPE_NETWORK_GRANT' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_NETWORK_GRANT_FAILED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct NetworkGrantRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'network_grant_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_network_grant_response' crates/redevplugin-ipc/src/lib.rs
  grep -q 'FRAME_TYPE_NETWORK_EXECUTE' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_NETWORK_EXECUTE_FAILED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct NetworkExecuteRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'network_execute_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_network_execute_response' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_WASM_WORKER_INVALID' crates/redevplugin-ipc/src/lib.rs
  grep -q 'worker_success_result_json' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_worker_module' crates/redevplugin-wasm-abi/src/lib.rs
  grep -q 'redevplugin-wasm-abi' crates/redevplugin-runtime/Cargo.toml
  grep -q 'wasmi = ' crates/redevplugin-runtime/Cargo.toml
  grep -q 'redevplugin_wasm_abi::validate_worker_module' crates/redevplugin-runtime/src/main.rs
  grep -q 'execute_worker_module' crates/redevplugin-runtime/src/main.rs
  grep -q 'get_typed_func::<(), ()>' crates/redevplugin-runtime/src/main.rs
  grep -q 'files_write_demo' crates/redevplugin-runtime/src/main.rs
  grep -q '"files"' crates/redevplugin-runtime/src/main.rs
  grep -q 'perform_storage_file_request_hostcall' crates/redevplugin-runtime/src/main.rs
  grep -q 'storage_file_frame' crates/redevplugin-runtime/src/main.rs
  grep -q 'kv_put_demo' crates/redevplugin-runtime/src/main.rs
  grep -q '"storage.kv"' crates/redevplugin-runtime/src/main.rs
  grep -q 'perform_storage_kv_request_hostcall' crates/redevplugin-runtime/src/main.rs
  grep -q 'storage_kv_frame' crates/redevplugin-runtime/src/main.rs
  grep -q 'http_request_demo' crates/redevplugin-runtime/src/main.rs
  grep -q '"http_request"' crates/redevplugin-runtime/src/main.rs
  grep -q 'perform_network_http_request_hostcall' crates/redevplugin-runtime/src/main.rs
  grep -q 'network_execute_frame' crates/redevplugin-runtime/src/main.rs
  grep -q 'storageMemoryHostcallWorkerWASMForTest' pkg/host/host_test.go
  grep -q 'networkMemoryHostcallWorkerWASMForTest' pkg/host/host_test.go
  grep -q 'runtime_instance_id' spec/plugin/worker-invocation-v1.schema.json
  grep -q 'runtime_generation_id' spec/plugin/worker-invocation-v1.schema.json
  grep -q '"revoke_epoch_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"host_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"rust_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"wasm_abi_version": { "const": "redevplugin-wasm-worker-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"plugin_instance_id": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
  grep -q '"content_base64": { "type": "string", "contentEncoding": "base64" }' spec/plugin/ipc-v1.schema.json
  grep -q '"handle_grant_token": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
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
