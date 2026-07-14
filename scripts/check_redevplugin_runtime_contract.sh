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
  npm run contracts:check
  grep -q '"target_classifier_version": { "const": "target-classifier-v1" }' spec/plugin/network-grant-v1.schema.json
  grep -q '"fixtures":' spec/plugin/target-classifier-v1.json
  grep -q '"ipv4-mapped-private-resolved"' spec/plugin/target-classifier-v1.json
  grep -q '"transport": { "enum": \["http", "websocket", "tcp", "udp"\] }' spec/plugin/network-grant-v1.schema.json
  grep -q 'package-signature-v1.schema.json' spec/plugin/package-signature-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.package_signature.v1" }' spec/plugin/package-signature-v1.schema.json
  grep -q '"algorithm": { "enum": \["ed25519"\] }' spec/plugin/package-signature-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.release_metadata.v2" }' spec/plugin/release-metadata-v2.schema.json
  grep -q '"release_metadata_signature"' spec/plugin/release-metadata-v2.schema.json
  grep -q '"schema_version": { "const": "redevplugin.source_policy.v1" }' spec/plugin/source-policy-v1.schema.json
  grep -q '"unsigned_policy": { "enum": \["dev_only", "review_required", "block"\] }' spec/plugin/source-policy-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.source_revocations.v1" }' spec/plugin/source-revocations-v1.schema.json
  grep -q '"revoked_key_ids"' spec/plugin/source-revocations-v1.schema.json
  grep -q '"runtime_execution_lease"' spec/plugin/token-ticket-v2.schema.json
  grep -q '"handle_grant"' spec/plugin/token-ticket-v2.schema.json
  ! grep -q '"type": { "const": "redevplugin.bridge.handshake" }' spec/plugin/bridge-v2.schema.json
  grep -q '"type": { "const": "redevplugin.bridge.call" }' spec/plugin/bridge-v2.schema.json
  grep -q '"type": { "const": "redevplugin.bridge.cancel" }' spec/plugin/bridge-v2.schema.json
  grep -q '"type": { "const": "redevplugin.ui.render" }' spec/plugin/bridge-v2.schema.json
  grep -q '"x-redevplugin-render-policy"' spec/plugin/bridge-v2.schema.json
  grep -q '"safe_input_types"' spec/plugin/bridge-v2.schema.json
  grep -q 'handshake_transcript_sha256' spec/openapi/plugin-platform-v2.yaml
  grep -q 'previous_plugin_gateway_token' spec/openapi/plugin-platform-v2.yaml
  grep -q '/_redevplugin/api/plugins/surfaces/revoke-scope' spec/openapi/plugin-platform-v2.yaml
  grep -q '/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare' spec/openapi/plugin-platform-v2.yaml
  grep -q '/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read' spec/openapi/plugin-platform-v2.yaml
  grep -q '"schema_version": { "const": "redevplugin.compatibility.v2" }' spec/plugin/compatibility-manifest-v2.schema.json
  grep -q '"bridge_schema_version": { "const": "bridge-v2" }' spec/plugin/compatibility-manifest-v2.schema.json
  grep -q '"release_metadata_schema_version": { "const": "release-metadata-v2" }' spec/plugin/compatibility-manifest-v2.schema.json
  grep -q '"opaque_surface_document_schema_version"' spec/plugin/compatibility-manifest-v2.schema.json
  grep -q '"opaque_surface_transport_schema_version"' spec/plugin/compatibility-manifest-v2.schema.json
  grep -q '"title": "ReDevPlugin stable error codes v1"' spec/plugin/error-codes-v1.schema.json
  grep -q '"PLUGIN_JSON_LIMIT_EXCEEDED"' spec/plugin/error-codes-v1.schema.json
  grep -q '"PLUGIN_PLATFORM_REQUEST_FAILED"' spec/plugin/error-codes-v1.schema.json
  grep -q '"RUNTIME_LEASE_SIGNATURE_INVALID"' spec/plugin/error-codes-v1.schema.json
  grep -q '"UNSUPPORTED_FRAME"' spec/plugin/error-codes-v1.schema.json
  grep -q '"schema_version": { "const": "redevplugin.release_manifest.v2" }' spec/plugin/release-manifest-v2.schema.json
  grep -q '"source_commit"' spec/plugin/release-manifest-v2.schema.json
  grep -q '"npm_package"' spec/plugin/release-manifest-v2.schema.json
  grep -q '"runtime_target"' spec/plugin/release-manifest-v2.schema.json
  grep -q '"files"' spec/plugin/release-manifest-v2.schema.json
  grep -q '"type": { "const": "classic" }' spec/plugin/opaque-surface-document-v1.schema.json
  grep -q '"surface_handle"' spec/plugin/opaque-surface-transport-v1.schema.json
  grep -q '"runtime_control"' spec/plugin/opaque-surface-transport-v1.schema.json
  grep -q '"plugin_bridge"' spec/plugin/opaque-surface-transport-v1.schema.json
  grep -q '"required": \["method", "route"\]' spec/plugin/manifest-v2.schema.json
  grep -q '"required": \["effect", "execution", "request_schema", "response_schema"\]' spec/plugin/manifest-v2.schema.json
  grep -q '{ "required": \["cancel_policy"\] }' spec/plugin/manifest-v2.schema.json
  test ! -e spec/openapi/plugin-platform-v1.yaml
  test ! -e spec/plugin/bridge-v1.schema.json
  test ! -e spec/plugin/compatibility-manifest-v1.schema.json
  test ! -e spec/plugin/manifest-v1.schema.json
  test ! -e spec/plugin/release-manifest-v1.schema.json
  test ! -e spec/plugin/release-metadata-v1.schema.json
  test ! -e spec/plugin/token-ticket-v1.schema.json
  grep -q '^  quality-release:$' .github/workflows/release.yml
  grep -q 'name: Complete Release Quality Gate' .github/workflows/release.yml
  grep -q 'GOWORK=off go test ./...' .github/workflows/release.yml
  grep -q 'GOWORK=off go list ./...' .github/workflows/release.yml
  grep -q 'GOWORK=off golangci-lint run ./...' .github/workflows/release.yml
  grep -q 'TypeScript, unit, demo, and browser checks' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_ui_bridge.sh' .github/workflows/release.yml
  grep -q 'cargo clippy --workspace --all-targets -- -D warnings' .github/workflows/release.yml
  grep -q 'cargo deny check' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_runtime_contract.sh --ci' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_platform.sh --ci' .github/workflows/release.yml
  test "$(grep -c '^      - quality-release$' .github/workflows/release.yml)" -eq 4
  grep -q 'audit-release:' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_release_audit.sh' .github/workflows/release.yml
  grep -q 'REDEVPLUGIN_INSTALL_AUDIT_TOOLS: "1"' .github/workflows/release.yml
  grep -q 'release-audit:' .github/workflows/ci.yml
  grep -q '^permissions:$' .github/workflows/ci.yml
  grep -q 'GOWORK=off golangci-lint run ./...' .github/workflows/ci.yml
  grep -q 'GOWORK=off go list ./...' .github/workflows/ci.yml
  grep -q 'go list ./...' scripts/check_redevplugin_platform.sh
  grep -q 'npm run check' .github/workflows/ci.yml
  grep -q 'Bridge replay and cancellation gate' .github/workflows/ci.yml
  ! grep -Eq 'uses: [^ ]+@v[0-9]+' .github/workflows/ci.yml .github/workflows/stress.yml
  grep -q 'bash -n scripts/check_redevplugin_release_audit.sh' .github/workflows/ci.yml
  grep -q 'stress-release:' .github/workflows/release.yml
  grep -q './scripts/check_redevplugin_stress.sh --release --summary dist/redevplugin-release-stress.json' .github/workflows/release.yml
  grep -q 'package-ui:' .github/workflows/release.yml
  grep -q 'Build immutable npm tarball' .github/workflows/release.yml
  grep -q -- '--npm-package "$npm_package"' .github/workflows/release.yml
  grep -q 'Publish or verify identical npm bytes' .github/workflows/release.yml
  test "$(grep -c 'npm i -g npm@11.18.0' .github/workflows/release.yml)" -eq 2
  grep -q 'git merge-base --is-ancestor' .github/workflows/release.yml
  grep -q './scripts/assert_github_release_absent.sh' .github/workflows/release.yml
  grep -q './scripts/verify_github_release_identity.sh' .github/workflows/release.yml
  grep -q -- '--require-release' .github/workflows/release.yml
  grep -q 'gh release create' .github/workflows/release.yml
  ! grep -q 'softprops/action-gh-release' .github/workflows/release.yml
  grep -q 'fetch-depth: 0' .github/workflows/release.yml
  grep -q 'verify-published-release:' .github/workflows/release.yml
  grep -q 'scripts/verify_published_release.mjs' .github/workflows/release.yml
  grep -q -- '--structural-only' scripts/verify_published_release.mjs
  grep -q 'scripts/verify_go_module_readback.mjs' .github/workflows/release.yml
  grep -q 'redevplugin-a2-acceptance.json' .github/workflows/release.yml
  grep -q 'redevplugin-a2-supported.png' .github/workflows/release.yml
  grep -q 'redevplugin-a2-unsupported.png' .github/workflows/release.yml
  grep -q 'id-token: write' .github/workflows/release.yml
  grep -q 'sigstore/cosign-installer' .github/workflows/release.yml
  test "$(grep -c 'cosign-release: v2.4.3' .github/workflows/release.yml)" -eq 2
  grep -q 'cosign sign-blob --yes' .github/workflows/release.yml
  grep -q './scripts/verify_redevplugin_release_artifacts.sh --tag "$GITHUB_REF_NAME" dist/artifacts' .github/workflows/release.yml
  grep -q 'bash -n scripts/verify_redevplugin_release_artifacts.sh' .github/workflows/ci.yml
  grep -q 'bash -n scripts/assert_github_release_absent.sh' .github/workflows/ci.yml
  grep -q 'bash -n scripts/verify_github_release_identity.sh' .github/workflows/ci.yml
  grep -q 'node --check scripts/verify_published_release.mjs' .github/workflows/ci.yml
  grep -q 'node --check scripts/verify_go_module_readback.mjs' .github/workflows/ci.yml
  grep -q 'node --check scripts/test_published_release_verifier.mjs' .github/workflows/ci.yml
  grep -q 'node --check scripts/verify_npm_registry_release.mjs' .github/workflows/ci.yml
  grep -q 'node --check scripts/test_npm_registry_release_verifier.mjs' .github/workflows/ci.yml
  test "$(grep -c 'scripts/verify_npm_registry_release.mjs' .github/workflows/release.yml)" -eq 2
  node scripts/test_npm_registry_release_verifier.mjs
  grep -Fq 'dist/artifacts/*.tar.gz.sig' .github/workflows/release.yml
  grep -Fq 'dist/artifacts/*.tar.gz.bundle' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json.sig' .github/workflows/release.yml
  grep -q 'dist/artifacts/redevplugin-release-stress.json.bundle' .github/workflows/release.yml
  grep -q 'dist/artifacts/SHA256SUMS.sig' .github/workflows/release.yml
  grep -q 'dist/artifacts/SHA256SUMS.bundle' .github/workflows/release.yml
  verify_artifact_fixture=$(mktemp -d "${TMPDIR:-/tmp}/redevplugin-release-artifacts.XXXXXX")
  stress_valid_fixture=$(mktemp "${TMPDIR:-/tmp}/redevplugin-release-stress-valid.XXXXXX")
  trap 'rm -rf "$verify_artifact_fixture"; rm -f "$stress_valid_fixture"' EXIT
  runtime_fixture_files=(
    redevplugin-v0.0.0-test-x86_64-unknown-linux-gnu.tar.gz
    redevplugin-v0.0.0-test-aarch64-unknown-linux-gnu.tar.gz
    redevplugin-v0.0.0-test-x86_64-apple-darwin.tar.gz
    redevplugin-v0.0.0-test-aarch64-apple-darwin.tar.gz
  )
  for file in "${runtime_fixture_files[@]}"; do
    printf 'runtime bundle %s\n' "$file" >"$verify_artifact_fixture/$file"
  done
  cat >"$verify_artifact_fixture/redevplugin-release-stress.json" <<'JSON'
{
  "ok": true,
  "mode": "release",
  "stress_categories": ["go_race","stream_backpressure","operation_cancel_ownership","connectivity_classifier","runtime_revoke_ack","storage_quota","browser_demo","runtime_contract","release_bundle"],
  "stress_evidence": [
    {"category":"stream_backpressure","counters":{"workers":1,"backpressure_denials":1,"core_operation_checks":1,"stream_close_requests":1,"closed_streams":1,"post_close_append_denials":1,"stream_close_audit_events":1,"stream_close_status_checked":1}},
    {"category":"operation_cancel_ownership","counters":{"operations_registered":2,"cancel_requested_records":2,"durable_requests_without_active_lease":2,"http_accepted_requests":1,"audit_cancel_requested_events":2,"registry_redispatches":0}},
    {"category":"connectivity_classifier","counters":{"minted_grants":1,"stale_grant_denials":1,"blocked_resolved_ips":1,"connector_policy_count":1,"http_redirects_not_followed":1,"dns_rebinding_denials":1,"http_proxy_env_ignored":1,"http_connect_denials":1,"alt_svc_headers_dropped":1,"proxy_auth_headers_dropped":1,"http_stream_round_trips":1,"http_stream_chunks":1,"http_stream_request_denials":1,"http_stream_response_denials":1,"http_stream_cancelled_reads":1,"tcp_database_round_trips":1,"tcp_request_denials":1,"tcp_response_denials":1,"tcp_cancelled_reads":1,"udp_round_trips":1,"udp_source_mismatch_dropped":1,"udp_rate_limit_denials":1,"websocket_round_trips":1,"websocket_request_denials":1,"websocket_response_denials":1,"websocket_cancelled_reads":1}},
    {"category":"runtime_revoke_ack","counters":{"attempts":1,"p95_ms":1,"max_ms":1,"threshold_ms":500,"hard_timeout_ms":2000,"closed_actor":1,"closed_socket":1,"closed_stream":1,"closed_storage":1}},
    {"category":"storage_quota","counters":{"writes":1,"quota_denials":1,"imported":1,"usage_bytes":1,"file_quota_denials":1,"file_usage_files":1,"file_quota_files":1,"sqlite_quota_denials":2,"sqlite_rollback_checks":1,"sqlite_page_count":1,"sqlite_sidecar_files":4,"sqlite_sidecar_bytes":1,"sqlite_sparse_logical_bytes":1}}
  ],
  "steps": [{"name":"stress_evidence","status":0,"duration_ms":1},{"name":"release_bundle","status":0,"duration_ms":1}]
}
JSON
  cat >"$verify_artifact_fixture/redevplugin-a2-acceptance.json" <<'JSON'
{
  "schema_version": "redevplugin.a2_acceptance.v1",
  "evidence_source": "go-host-http-adapter-rust-runtime-chromium",
  "scenarios": [
    {
      "credentialless_scenario": "supported",
      "credentialless": true,
      "sandbox": "allow-scripts",
      "allow": "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'",
      "referrer_policy": "no-referrer",
      "csp": "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'",
      "frame_origin": "null",
      "opaque_origin": true,
      "isolation": {"parent_dom_blocked":true,"parent_cookie_blocked":true,"parent_local_storage_blocked":true,"parent_session_storage_blocked":true,"indexeddb_blocked":true,"cache_storage_blocked":true,"direct_fetch_blocked":true,"service_worker_blocked":true},
      "worker_probe": {"dedicated_worker":true,"fetch_blocked":true,"websocket_blocked":true,"nested_worker_blocked":true,"indexeddb_blocked":true,"cache_storage_blocked":true,"broadcast_channel_blocked":true,"global_postmessage_blocked":true,"navigator_storage_blocked":true,"eval_blocked":true,"function_constructor_blocked":true,"prototype_descriptors_sealed":true,"message_port_prototype_sealed":true,"prototype_fetch_blocked":true,"prototype_indexeddb_blocked":true,"prototype_nested_blob_worker_blocked":true,"all_blocked":true},
      "platform_dynamic_import_gate": true,
      "parent_credentials_absent": true,
      "credential_query_absent": true,
      "direct_worker_network_absent": true,
      "strict_request_allowlist": true,
      "websocket_absent": true,
      "service_worker_absent": true,
      "opening_progress": true,
      "first_paint_before_lazy_asset": true,
      "real_stream_redeemed": true,
      "confirmation_disposal_aborted": true,
      "server_disposed": true,
      "disposed": true
    },
    {
      "credentialless_scenario": "unsupported",
      "credentialless": false,
      "sandbox": "allow-scripts",
      "allow": "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'",
      "referrer_policy": "no-referrer",
      "csp": "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'",
      "frame_origin": "null",
      "opaque_origin": true,
      "isolation": {"parent_dom_blocked":true,"parent_cookie_blocked":true,"parent_local_storage_blocked":true,"parent_session_storage_blocked":true,"indexeddb_blocked":true,"cache_storage_blocked":true,"direct_fetch_blocked":true,"service_worker_blocked":true},
      "worker_probe": {"dedicated_worker":true,"fetch_blocked":true,"websocket_blocked":true,"nested_worker_blocked":true,"indexeddb_blocked":true,"cache_storage_blocked":true,"broadcast_channel_blocked":true,"global_postmessage_blocked":true,"navigator_storage_blocked":true,"eval_blocked":true,"function_constructor_blocked":true,"prototype_descriptors_sealed":true,"message_port_prototype_sealed":true,"prototype_fetch_blocked":true,"prototype_indexeddb_blocked":true,"prototype_nested_blob_worker_blocked":true,"all_blocked":true},
      "platform_dynamic_import_gate": true,
      "parent_credentials_absent": true,
      "credential_query_absent": true,
      "direct_worker_network_absent": true,
      "strict_request_allowlist": true,
      "websocket_absent": true,
      "service_worker_absent": true,
      "opening_progress": true,
      "first_paint_before_lazy_asset": true,
      "real_stream_redeemed": true,
      "confirmation_disposal_aborted": true,
      "server_disposed": true,
      "disposed": true
    }
  ]
}
JSON
  printf '\211PNG\r\n\032\nfixture\n' >"$verify_artifact_fixture/redevplugin-a2-supported.png"
  printf '\211PNG\r\n\032\nfixture\n' >"$verify_artifact_fixture/redevplugin-a2-unsupported.png"
  release_sum_files=(
    "${runtime_fixture_files[@]}"
    redevplugin-release-stress.json
    redevplugin-a2-acceptance.json
    redevplugin-a2-supported.png
    redevplugin-a2-unsupported.png
  )
  refresh_release_fixture_sums() {
    (
      cd "$verify_artifact_fixture"
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${release_sum_files[@]}" >SHA256SUMS
      else
        shasum -a 256 "${release_sum_files[@]}" | awk '{ print $1 "  " $2 }' >SHA256SUMS
      fi
    )
  }
  refresh_release_fixture_sums
  (
    cd "$verify_artifact_fixture"
    for file in "${release_sum_files[@]}" SHA256SUMS; do
      : >"${file}.sig"
      : >"${file}.bundle"
    done
  )
  ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign --tag v0.0.0-test "$verify_artifact_fixture"
  cp "$verify_artifact_fixture/redevplugin-release-stress.json" "$stress_valid_fixture"
  sed 's/"p95_ms":1/"p95_ms":501/' "$stress_valid_fixture" >"$verify_artifact_fixture/redevplugin-release-stress.json"
  refresh_release_fixture_sums
  if ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign --tag v0.0.0-test "$verify_artifact_fixture"; then
    echo "release artifact verifier accepted stress p95 above threshold" >&2
    exit 1
  fi
  cp "$stress_valid_fixture" "$verify_artifact_fixture/redevplugin-release-stress.json"
  refresh_release_fixture_sums
  printf 'unexpected release asset\n' >"$verify_artifact_fixture/unexpected.txt"
  if ./scripts/verify_redevplugin_release_artifacts.sh --skip-cosign --tag v0.0.0-test "$verify_artifact_fixture"; then
    echo "release artifact verifier accepted an unexpected non-tar asset" >&2
    exit 1
  fi
  rm "$verify_artifact_fixture/unexpected.txt"
  grep -q 'name: Publish npm Package' .github/workflows/release.yml
  grep -q '@floegence/redevplugin-ui' .github/workflows/release.yml
  grep -q 'permissions:' .github/workflows/release.yml
  grep -q 'npm publish "$package" --access public --provenance' .github/workflows/release.yml
  grep -q 'registry-url: https://registry.npmjs.org' .github/workflows/release.yml
  grep -q '"repository"' packages/redevplugin-ui/package.json
  grep -q 'git+https://github.com/floegence/redevplugin.git' packages/redevplugin-ui/package.json
  grep -q '"directory": "packages/redevplugin-ui"' packages/redevplugin-ui/package.json
  grep -q '"publishConfig"' packages/redevplugin-ui/package.json
  grep -q '"access": "public"' packages/redevplugin-ui/package.json
  grep -q 'verifyRuntimeHello' scripts/verify_redevplugin_release_bundle.mjs
  grep -q 'verifyExecutableTargets' scripts/verify_redevplugin_release_bundle.mjs
  grep -q 'test_published_release_verifier.mjs' scripts/check_redevplugin_stress.sh
  grep -q 'verifyNoticeEvidence' scripts/verify_redevplugin_release_bundle.mjs
  grep -q 'verifyHostCapabilitySample' scripts/verify_redevplugin_release_bundle.mjs
  go run ./cmd/redevplugin version | grep -q '"schema_version": "redevplugin.compatibility.v2"'
  go run ./cmd/redevplugin version | grep -q '"id": "compatibility-manifest-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "release-manifest-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "release-metadata-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "source-policy-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "source-revocations-schema"'
  go run ./cmd/redevplugin version | grep -q '"network_grant_schema_version": "network-grant-v1"'
  go run ./cmd/redevplugin version | grep -q '"id": "network-grant-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "error-codes-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-contract-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-pin-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-manifest-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-compatibility-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-signature-schema"'
  go run ./cmd/redevplugin version | grep -q '"id": "host-capability-notices-schema"'
  test -f testdata/contracts/ipc/current_hello_ack.json
  test -f testdata/contracts/ipc/invoke_worker_result_ok.json
  test -f testdata/contracts/ipc/host_new_rust_old.json
  test -f testdata/contracts/ipc/host_old_rust_new.json
  test -f testdata/contracts/ipc/wasm_abi_old.json
  test -f testdata/contracts/ipc/wasm_abi_new.json
  test -f testdata/contracts/ipc/unknown_enum.json
  test -f testdata/contracts/ipc/missing_required.json
  test -f testdata/contracts/ipc/replay_frame.json
  test -f testdata/contracts/ipc/runtime_generation_mismatch.json
  grep -q '"hello_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"invoke_worker_result"' spec/plugin/ipc-v1.schema.json
  grep -q '"token_id"' spec/plugin/ipc-v1.schema.json
  grep -q '"issued_at_unix_ms"' spec/plugin/ipc-v1.schema.json
  grep -q '"plugin_id"' spec/plugin/ipc-v1.schema.json
  grep -q '"plugin_version"' spec/plugin/ipc-v1.schema.json
  grep -q '"active_fingerprint"' spec/plugin/ipc-v1.schema.json
  grep -q '"effect": { "enum": \["read", "write", "execute", "delete", "admin"\] }' spec/plugin/ipc-v1.schema.json
  grep -q '"execution": { "enum": \["sync", "operation", "subscription"\] }' spec/plugin/ipc-v1.schema.json
  grep -q '"limits"' spec/plugin/ipc-v1.schema.json
  grep -q '"max_stream_bytes_per_sec"' spec/plugin/ipc-v1.schema.json
  grep -q 'plugin.runtime.lease.issued' pkg/host/host.go
  grep -q '"open_handle_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"open_handle_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"validate_handle_grant_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"validate_handle_grant_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_file_request_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"storage_file_response_payload"' spec/plugin/ipc-v1.schema.json
  grep -q '"usage_files": { "type": "integer", "minimum": 0 }' spec/plugin/ipc-v1.schema.json
  grep -q '"quota_files": { "type": "integer", "minimum": 0 }' spec/plugin/ipc-v1.schema.json
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
  grep -q '"http_stream"' spec/plugin/ipc-v1.schema.json
  grep -q '"stream_id": { "type": "string"' spec/plugin/ipc-v1.schema.json
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
  grep -q 'ERR_NETWORK_STREAM_BACKPRESSURE' crates/redevplugin-ipc/src/lib.rs
  grep -q 'struct NetworkExecuteRequest' crates/redevplugin-ipc/src/lib.rs
  grep -q 'network_execute_frame' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_network_execute_response' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_RUNTIME_CAPABILITY_REVOKED' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_RUNTIME_LEASE_INVALID' crates/redevplugin-ipc/src/lib.rs
  grep -q 'ERR_RUNTIME_LEASE_SIGNATURE_INVALID' crates/redevplugin-ipc/src/lib.rs
  grep -q 'parse_runtime_lease_public_keys' crates/redevplugin-ipc/src/lib.rs
  grep -q 'verify_worker_runtime_lease_signature' crates/redevplugin-ipc/src/lib.rs
  grep -q 'validate_worker_runtime_lease' crates/redevplugin-ipc/src/lib.rs
  grep -q 'worker_invocation_rejects_expired_lease_before_opening_artifact' crates/redevplugin-runtime/src/main.rs
  grep -q 'worker_invocation_rejects_execution_binding_mismatch_before_opening_artifact' crates/redevplugin-runtime/src/main.rs
  grep -q 'runtime_lease_optional_unix_ms' crates/redevplugin-ipc/src/lib.rs
  grep -q 'append_runtime_lease_limits_field' crates/redevplugin-ipc/src/lib.rs
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
  grep -q 'owner_session_hash' spec/plugin/worker-invocation-v1.schema.json
  grep -q 'owner_user_hash' spec/plugin/worker-invocation-v1.schema.json
  grep -q '"revoke_epoch_ack"' spec/plugin/ipc-v1.schema.json
  grep -q '"host_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"rust_ipc_version": { "const": "rust-ipc-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"wasm_abi_version": { "const": "redevplugin-wasm-worker-v1" }' spec/plugin/ipc-v1.schema.json
  grep -q '"runtime_lease_public_keys"' spec/plugin/ipc-v1.schema.json
  grep -q '"plugin_instance_id": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
  grep -q '"target_descriptor_hashes"' spec/plugin/ipc-v1.schema.json
  grep -q '"runtime_instance_id": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
  grep -q '"ipc_channel_id": { "type": "string", "minLength": 1 }' spec/plugin/ipc-v1.schema.json
  grep -q '"signature": { "type": "string", "pattern": "^ed25519:.+" }' spec/plugin/ipc-v1.schema.json
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
