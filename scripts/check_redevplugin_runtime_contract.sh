#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)

if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
  PATH="$HOME/.cargo/bin:$PATH"
fi

usage() {
  cat <<'USAGE'
Usage: scripts/check_redevplugin_runtime_contract.sh [--ci]

Runs the ReDevPlugin runtime contract gate. --ci is accepted as an explicit
no-op so documentation, local runs, and CI can share the same command shape.
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
  go test ./pkg/protocol ./pkg/httpadapter ./pkg/connectivity ./pkg/runtimeclient
  cargo test -p redevplugin-target-classifier
  grep -q '"target_classifier_version": { "const": "target-classifier-v1" }' spec/plugin/network-grant-v1.schema.json
  grep -q '"fixtures":' spec/plugin/target-classifier-v1.json
  grep -q '"ipv4-mapped-private-resolved"' spec/plugin/target-classifier-v1.json
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
  grep -q '"network_grant_schema_version": { "const": "network-grant-v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"compatibility_schema_version"' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"error_codes_schema_version": { "const": "error-codes-v1" }' spec/plugin/compatibility-manifest-v1.schema.json
  grep -q '"title": "ReDevPlugin stable error codes v1"' spec/plugin/error-codes-v1.schema.json
  grep -q '"PLUGIN_JSON_LIMIT_EXCEEDED"' spec/plugin/error-codes-v1.schema.json
  grep -q '"PLUGIN_PLATFORM_REQUEST_FAILED"' spec/plugin/error-codes-v1.schema.json
  grep -q '"UNSUPPORTED_FRAME"' spec/plugin/error-codes-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.release_manifest.v1" }' spec/plugin/release-manifest-v1.schema.json
  grep -q '"runtime_target"' spec/plugin/release-manifest-v1.schema.json
  grep -q '"files"' spec/plugin/release-manifest-v1.schema.json
  grep -q 'audit-release:' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_release_audit.sh' .github/workflows/release.yml
  grep -q 'REDEVPLUGIN_INSTALL_AUDIT_TOOLS: "1"' .github/workflows/release.yml
  grep -q 'release-audit:' .github/workflows/ci.yml
  grep -q 'bash -n scripts/check_redevplugin_release_audit.sh' .github/workflows/ci.yml
  grep -q 'stress-release:' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_stress.sh --release --summary dist/redevplugin-release-stress.json' .github/workflows/release.yml
  grep -q -- '- audit-release' .github/workflows/release.yml
  grep -q -- '- stress-release' .github/workflows/release.yml
  grep -q 'redevplugin-release-stress.json > SHA256SUMS' .github/workflows/release.yml
  grep -q 'id-token: write' .github/workflows/release.yml
  grep -q 'sigstore/cosign-installer' .github/workflows/release.yml
  grep -q 'cosign sign-blob --yes' .github/workflows/release.yml
  grep -q 'redevplugin-release-stress.json SHA256SUMS' .github/workflows/release.yml
  grep -q './scripts/verify_redevplugin_release_artifacts.sh dist/artifacts' .github/workflows/release.yml
  grep -q 'bash -n scripts/verify_redevplugin_release_artifacts.sh' .github/workflows/ci.yml
  grep -Fq 'dist/artifacts/*.tar.gz.sig' .github/workflows/release.yml
  grep -Fq 'dist/artifacts/*.tar.gz.bundle' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json.sig' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json.bundle' .github/workflows/release.yml
  grep -q 'dist/artifacts/SHA256SUMS.sig' .github/workflows/release.yml
  grep -q 'dist/artifacts/SHA256SUMS.bundle' .github/workflows/release.yml
  verify_artifact_fixture=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-release-artifacts.XXXXXX")
  trap 'rm -rf "$verify_artifact_fixture"' EXIT
  printf 'runtime bundle\n' >"$verify_artifact_fixture/redevplugin-v0.0.0-test-linux-amd64.tar.gz"
  cat >"$verify_artifact_fixture/redevplugin-release-stress.json" <<'JSON'
{
  "ok": true,
  "mode": "release",
  "stress_categories": ["go_race","stream_backpressure","connectivity_classifier","runtime_revoke_ack","storage_quota","csp_report_flood","browser_demo","runtime_contract","release_bundle"],
  "stress_evidence": [
    {"category":"stream_backpressure","counters":{"workers":1,"backpressure_denials":1,"core_operation_checks":1}},
    {"category":"connectivity_classifier","counters":{"minted_grants":1,"stale_grant_denials":1,"blocked_resolved_ips":1,"connector_policy_count":1,"http_redirects_not_followed":1,"dns_rebinding_denials":1,"http_proxy_env_ignored":1,"http_connect_denials":1,"alt_svc_headers_dropped":1,"proxy_auth_headers_dropped":1,"udp_round_trips":1,"udp_source_mismatch_dropped":1}},
    {"category":"runtime_revoke_ack","counters":{"attempts":1,"p95_ms":1,"max_ms":1,"threshold_ms":500,"hard_timeout_ms":2000,"closed_actor":1,"closed_socket":1,"closed_stream":1,"closed_storage":1}},
    {"category":"storage_quota","counters":{"writes":1,"quota_denials":1,"imported":1,"usage_bytes":1,"sqlite_quota_denials":2,"sqlite_rollback_checks":1,"sqlite_page_count":1,"sqlite_sidecar_files":4,"sqlite_sidecar_bytes":1,"sqlite_sparse_logical_bytes":1}},
    {"category":"csp_report_flood","counters":{"attempts":2,"accepted_reports":1,"rate_limited_reports":1,"diagnostic_events":1,"audit_events":0,"unique_sandbox_origins":1,"unique_active_fingerprints":1}}
  ],
  "steps": [{"name":"stress_evidence","status":0,"duration_ms":1},{"name":"release_bundle","status":0,"duration_ms":1}]
}
JSON
  (
    cd "$verify_artifact_fixture"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json >SHA256SUMS
    else
      shasum -a 256 redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json | awk '{ print $1 "  " $2 }' >SHA256SUMS
    fi
    for file in redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json SHA256SUMS; do
      : >"${file}.sig"
      : >"${file}.bundle"
    done
  )
  ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign "$verify_artifact_fixture"
  cp "$verify_artifact_fixture/redevplugin-release-stress.json" "$verify_artifact_fixture/redevplugin-release-stress.valid.json"
  sed 's/"p95_ms":1/"p95_ms":501/' "$verify_artifact_fixture/redevplugin-release-stress.valid.json" >"$verify_artifact_fixture/redevplugin-release-stress.json"
  (
    cd "$verify_artifact_fixture"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json >SHA256SUMS
    else
      shasum -a 256 redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json | awk '{ print $1 "  " $2 }' >SHA256SUMS
    fi
  )
  if ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign "$verify_artifact_fixture"; then
    echo "release artifact verifier accepted stress p95 above threshold" >&2
    exit 1
  fi
  cp "$verify_artifact_fixture/redevplugin-release-stress.valid.json" "$verify_artifact_fixture/redevplugin-release-stress.json"
  (
    cd "$verify_artifact_fixture"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json >SHA256SUMS
    else
      shasum -a 256 redevplugin-v0.0.0-test-linux-amd64.tar.gz redevplugin-release-stress.json | awk '{ print $1 "  " $2 }' >SHA256SUMS
    fi
  )
  printf 'unsigned extra tarball\n' >"$verify_artifact_fixture/redevplugin-v0.0.0-extra-linux-amd64.tar.gz"
  if ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign "$verify_artifact_fixture"; then
    echo "release artifact verifier accepted an unchecked tarball" >&2
    exit 1
  fi
  grep -q 'verifyRuntimeHello' scripts/verify_redevplugin_release_bundle.mjs
  grep -q 'verifyNoticeEvidence' scripts/verify_redevplugin_release_bundle.mjs
  go run ./cmd/redevplugin version | grep -q '"schema_version": "redevplugin.compatibility.v1"'
  go run ./cmd/redevplugin version | grep -q '"id": "compatibility-manifest-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "release-manifest-schema"'
  go run ./cmd/redevplugin version | grep -q '"network_grant_schema_version": "network-grant-v1"'
  go run ./cmd/redevplugin version | grep -q '"id": "network-grant-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "error-codes-schema"'
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
  grep -q '"storage_sqlite_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_sqlite_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"method": { "const": "storage.sqlite" }' spec/plugin/ipc-v1.schema.json
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
  grep -q 'FRAME_TYPE_STORAGE_SQLITE' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_STORAGE_SQLITE_FAILED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct StorageSQLiteRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'storage_sqlite_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_storage_sqlite_response' crates/redevplugin-ipc/src/lib.rs
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
  grep -q 'ERR_RUNTIME_CAPABILITY_REVOKED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'RuntimeRevocations' crates/redevplugin-runtime/src/main.rs
  grep -q 'handle_revoke_epoch' crates/redevplugin-runtime/src/main.rs
  grep -q 'worker_invocation_rejects_stale_epoch_before_opening_artifact' crates/redevplugin-runtime/src/main.rs
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
  grep -q 'sqlite_exec_demo' crates/redevplugin-runtime/src/main.rs
  grep -q '"storage.sqlite"' crates/redevplugin-runtime/src/main.rs
  grep -q 'perform_storage_sqlite_request_hostcall' crates/redevplugin-runtime/src/main.rs
  grep -q 'storage_sqlite_frame' crates/redevplugin-runtime/src/main.rs
  grep -q 'http_request_demo' crates/redevplugin-runtime/src/main.rs
  grep -q '"execute"' crates/redevplugin-runtime/src/main.rs
  grep -q '"http_request"' crates/redevplugin-runtime/src/main.rs
  grep -q 'perform_network_execute_request_hostcall' crates/redevplugin-runtime/src/main.rs
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
