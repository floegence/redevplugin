#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const expectedCSP = "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'";
const expectedAllow = "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'";
const scenarioKeys = [
  "credentialless_scenario", "credentialless", "sandbox", "allow", "referrer_policy", "csp",
  "frame_origin", "opaque_origin", "isolation", "worker_probe", "platform_dynamic_import_gate",
  "parent_credentials_absent", "credential_query_absent", "direct_worker_network_absent",
  "strict_request_allowlist", "websocket_absent", "service_worker_absent", "opening_progress",
  "first_paint_before_lazy_asset", "real_stream_redeemed", "confirmation_disposal_aborted",
  "server_disposed", "disposed",
];
const isolationKeys = [
  "parent_dom_blocked", "parent_cookie_blocked", "parent_local_storage_blocked",
  "parent_session_storage_blocked", "indexeddb_blocked", "cache_storage_blocked",
  "direct_fetch_blocked", "service_worker_blocked",
];
const workerProbeKeys = [
  "dedicated_worker",
  "fetch_blocked",
  "websocket_blocked",
  "nested_worker_blocked",
  "indexeddb_blocked",
  "cache_storage_blocked",
  "broadcast_channel_blocked",
  "global_postmessage_blocked",
  "navigator_storage_blocked",
  "eval_blocked",
  "function_constructor_blocked",
  "prototype_descriptors_sealed",
  "message_port_prototype_sealed",
  "prototype_fetch_blocked",
  "prototype_indexeddb_blocked",
  "prototype_nested_blob_worker_blocked",
  "all_blocked",
];
const scenarioProofKeys = [
  "opaque_origin", "platform_dynamic_import_gate", "parent_credentials_absent", "credential_query_absent",
  "direct_worker_network_absent", "strict_request_allowlist", "websocket_absent", "service_worker_absent",
  "opening_progress", "first_paint_before_lazy_asset", "real_stream_redeemed",
  "confirmation_disposal_aborted", "server_disposed", "disposed",
];

export function validateA2Evidence({ report, supportedScreenshot, unsupportedScreenshot }) {
  if (!exactKeys(report, ["schema_version", "evidence_source", "scenarios"]) ||
      report.schema_version !== "redevplugin.a2_acceptance.v1" ||
      report.evidence_source !== "go-host-http-adapter-rust-runtime-chromium" ||
      !Array.isArray(report.scenarios) || report.scenarios.length !== 2) {
    throw new Error("report schema or scenario count is invalid");
  }

  const scenarios = new Map(report.scenarios.map((scenario) => [scenario?.credentialless_scenario, scenario]));
  if (scenarios.size !== 2) throw new Error("report schema or scenario count is invalid");
  for (const name of ["supported", "unsupported"]) {
    const scenario = scenarios.get(name);
    if (!exactKeys(scenario, scenarioKeys) || scenario.credentialless !== (name === "supported") ||
        scenario.sandbox !== "allow-scripts" || scenario.allow !== expectedAllow ||
        scenario.referrer_policy !== "no-referrer" || scenario.csp !== expectedCSP || scenario.frame_origin !== "null") {
      throw new Error(`${name} sandbox identity is invalid`);
    }
    requireTrueFields(scenario, scenarioProofKeys, name);
    requireAllTrue(scenario.isolation, isolationKeys, `${name}.isolation`);
    requireAllTrue(scenario.worker_probe, workerProbeKeys, `${name}.worker_probe`);
  }

  requirePNG(supportedScreenshot, "supported screenshot");
  requirePNG(unsupportedScreenshot, "unsupported screenshot");
}

function exactKeys(value, keys) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function requireAllTrue(value, keys, label) {
  if (!exactKeys(value, keys)) throw new Error(`${label} fields are invalid`);
  requireTrueFields(value, keys, label);
}

function requireTrueFields(value, keys, label) {
  for (const key of keys) {
    if (value?.[key] !== true) throw new Error(`${label}.${key} must be true`);
  }
}

function requirePNG(value, label) {
  if (!Buffer.isBuffer(value) || value.length < 8 || value.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") {
    throw new Error(`${label} is not a PNG screenshot`);
  }
}

async function main() {
  const [reportPath, supportedScreenshotPath, unsupportedScreenshotPath] = process.argv.slice(2);
  if (!reportPath || !supportedScreenshotPath || !unsupportedScreenshotPath) {
    throw new Error("usage: verify_redevplugin_a2_evidence.mjs <report.json> <supported.png> <unsupported.png>");
  }
  validateA2Evidence({
    report: JSON.parse(readFileSync(reportPath, "utf8")),
    supportedScreenshot: readFileSync(supportedScreenshotPath),
    unsupportedScreenshot: readFileSync(unsupportedScreenshotPath),
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`invalid A2 acceptance evidence: ${error?.message || error}`);
    process.exit(1);
  });
}
