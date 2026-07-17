import assert from "node:assert/strict";
import { test } from "node:test";
import { validateA2Evidence } from "../../scripts/verify_redevplugin_a2_evidence.mjs";

const png = Buffer.from("89504e470d0a1a0a", "hex");

test("A2 release evidence accepts the complete live browser contract", () => {
  assert.doesNotThrow(() => validateA2Evidence({
    report: validReport(),
    supportedScreenshot: png,
    unsupportedScreenshot: png,
  }));
});

test("A2 release evidence rejects the retired partial browser report", () => {
  const report = validReport();
  delete report.evidence_source;
  delete report.scenarios[0].credentialless;
  delete report.scenarios[0].server_disposed;
  assert.throws(
    () => validateA2Evidence({ report, supportedScreenshot: png, unsupportedScreenshot: png }),
    /report schema or scenario count is invalid/,
  );
});

function validReport() {
  return {
    schema_version: "redevplugin.a2_acceptance.v1",
    evidence_source: "go-host-http-adapter-rust-runtime-chromium",
    scenarios: [validScenario("supported"), validScenario("unsupported")],
  };
}

function validScenario(name) {
  return {
    credentialless_scenario: name,
    credentialless: name === "supported",
    sandbox: "allow-scripts",
    allow: "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'",
    referrer_policy: "no-referrer",
    csp: "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'",
    frame_origin: "null",
    opaque_origin: true,
    isolation: {
      parent_dom_blocked: true,
      parent_cookie_blocked: true,
      parent_local_storage_blocked: true,
      parent_session_storage_blocked: true,
      indexeddb_blocked: true,
      cache_storage_blocked: true,
      direct_fetch_blocked: true,
      service_worker_blocked: true,
    },
    worker_probe: {
      dedicated_worker: true,
      fetch_blocked: true,
      websocket_blocked: true,
      nested_worker_blocked: true,
      indexeddb_blocked: true,
      cache_storage_blocked: true,
      broadcast_channel_blocked: true,
      global_postmessage_blocked: true,
      navigator_storage_blocked: true,
      eval_blocked: true,
      function_constructor_blocked: true,
      prototype_descriptors_sealed: true,
      message_port_prototype_sealed: true,
      prototype_fetch_blocked: true,
      prototype_indexeddb_blocked: true,
      prototype_nested_blob_worker_blocked: true,
      all_blocked: true,
    },
    platform_dynamic_import_gate: true,
    parent_credentials_absent: true,
    credential_query_absent: true,
    direct_worker_network_absent: true,
    strict_request_allowlist: true,
    websocket_absent: true,
    service_worker_absent: true,
    opening_progress: true,
    first_paint_before_lazy_asset: true,
    stream_response_loss_recovered: true,
    real_stream_redeemed: true,
    confirmation_disposal_aborted: true,
    server_disposed: true,
    disposed: true,
  };
}
