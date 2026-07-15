import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { chromium } from "playwright";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";

const harness = createBrowserHarnessServer();
const address = await harness.listen(0);
const baseURL = `http://127.0.0.1:${address.port}`;
const browser = await chromium.launch({ headless: true });
const evidenceDir = resolve(process.env.REDEVPLUGIN_A2_EVIDENCE_DIR || "dist/a2-evidence");
const deniedPermissionsPolicy = "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'";

try {
  mkdirSync(evidenceDir, { recursive: true });
  const scenarios = [
    await verifyScenario("supported"),
    await verifyScenario("unsupported"),
  ];
  writeFileSync(join(evidenceDir, "redevplugin-a2-acceptance.json"), JSON.stringify({
    schema_version: "redevplugin.a2_acceptance.v1",
    scenarios,
  }, null, 2) + "\n");
  console.log("opaque browser harness smoke passed");
} finally {
  await browser.close();
  await harness.close();
}

async function verifyScenario(credentiallessScenario) {
  const page = await browser.newPage();
  if (credentiallessScenario === "unsupported") {
    await page.addInitScript(() => {
      Reflect.deleteProperty(HTMLIFrameElement.prototype, "credentialless");
    });
  }
  const requestedURLs = [];
  const consoleLines = [];
  page.on("request", (request) => requestedURLs.push(request.url()));
  page.on("console", (message) => consoleLines.push(message.text()));
  await page.goto(`${baseURL}/testdata/browser-harness/opaque-surface/index.html?credentialless=${credentiallessScenario}`, { waitUntil: "domcontentloaded" });
  try {
    await page.waitForFunction(() => window.__redevpluginHarness?.snapshot().status === "ready", null, { timeout: 30_000 });
  } catch (error) {
    const failure = await page.evaluate(() => ({
      snapshot: window.__redevpluginHarness?.snapshot(),
      status: document.querySelector("#host-status")?.textContent,
      event_log: document.querySelector("#event-log")?.textContent,
    }));
    throw new Error(`${credentiallessScenario} surface did not become ready: ${JSON.stringify({ failure, consoleLines })}`, { cause: error });
  }

  const snapshot = await page.evaluate(() => window.__redevpluginHarness.snapshot());
  assert.equal(snapshot.errors.length, 0, `${credentiallessScenario} surface errors`);
  assert.equal(snapshot.progressEvents.length >= 1, true, `${credentiallessScenario} opening progress`);
  assert.equal(snapshot.progressEvents[0] >= 300, true, `${credentiallessScenario} progress threshold`);

  const iframe = page.locator("#plugin-frame");
  const sandbox = await iframe.getAttribute("sandbox");
  const allow = await iframe.getAttribute("allow");
  const referrerPolicy = await iframe.getAttribute("referrerpolicy");
  const srcdoc = await iframe.getAttribute("srcdoc");
  const csp = normalizeCSP(srcdoc);
  assert.equal(sandbox, "allow-scripts");
  assert.equal(allow, deniedPermissionsPolicy);
  assert.equal(referrerPolicy, "no-referrer");
  assert.equal(sandbox?.includes("allow-same-origin"), false);
  assert.equal(csp, "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'");
  const credentialless = await iframe.evaluate((frame) => "credentialless" in frame ? frame.credentialless : false);
  assert.equal(credentialless, credentiallessScenario === "supported");

  const frame = await waitForPluginFrame(page);
  await frame.waitForSelector("#plugin-status", { timeout: 10_000 });
  await frame.waitForFunction(() => document.querySelector("#plugin-status")?.textContent === "Ready");
  const isolation = await frame.evaluate(async () => {
    const blocked = async (operation) => {
      try {
        await operation();
        return false;
      } catch {
        return true;
      }
    };
    const cannotReadHostSecret = async (operation) => {
      try {
        return !String(await operation()).includes("parent-only");
      } catch {
        return true;
      }
    };
    return {
      origin: location.origin,
      parent_dom_blocked: await blocked(() => Promise.resolve(parent.document.querySelector("#host-status"))),
      parent_cookie_blocked: await cannotReadHostSecret(() => Promise.resolve(document.cookie)),
      parent_local_storage_blocked: await cannotReadHostSecret(() => Promise.resolve(localStorage.getItem("redevplugin_host_harness_secret"))),
      parent_session_storage_blocked: await cannotReadHostSecret(() => Promise.resolve(sessionStorage.getItem("redevplugin_host_harness_secret"))),
      indexeddb_blocked: await blocked(() => new Promise((resolve, reject) => {
        const request = indexedDB.open("redevplugin-opaque-probe");
        request.onsuccess = () => resolve(undefined);
        request.onerror = () => reject(request.error || new Error("indexedDB failed"));
      })),
      cache_storage_blocked: await blocked(() => caches.open("redevplugin-opaque-probe")),
      direct_fetch_blocked: await blocked(() => fetch("/__browser_harness/forbidden-direct-fetch")),
      service_worker_blocked: await blocked(async () => {
        const serviceWorker = navigator.serviceWorker;
        await serviceWorker.register("/__browser_harness/forbidden-sw.js");
      }),
    };
  });
  assert.equal(isolation.origin, "null");
  for (const [name, value] of Object.entries(isolation)) {
    if (name === "origin") continue;
    assert.equal(value, true, `${credentiallessScenario} ${name}`);
  }

  const workerProbe = JSON.parse(await frame.locator("#security-probe").textContent());
  for (const field of [
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
  ]) {
    assert.equal(workerProbe[field], true, `${credentiallessScenario} worker probe ${field}`);
  }
  await waitFor(() => page.workers().length === 1, 5_000, "dedicated worker creation");

  await frame.getByRole("button", { name: "Call host" }).click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes("typed MessagePort"));
  assert.equal((await frame.locator("#plugin-result").textContent()).includes("gateway_token"), false);

  await frame.getByRole("button", { name: "Read stream" }).click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes("opaque log line 2"));
  const streamResult = await frame.locator("#plugin-result").textContent();
  assert.equal(streamResult.includes("stream_ticket"), false);
  assert.equal(streamResult.includes("parent_stream_ticket"), false);
  assert.equal(streamResult.includes('"parent_stream_credential_visible": false'), true);

  await frame.getByRole("button", { name: "Dangerous action" }).click();
  await page.locator("#confirmation-panel").waitFor({ state: "visible" });
  await page.locator("#approve-confirmation").click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes('"confirmed": true'));

  await waitFor(async () => {
    const response = await fetch(`${baseURL}/__browser_harness/diagnostics`);
    const value = await response.json();
    return value.asset_completed_at > 0;
  }, 5_000, "lazy asset completion");
  const diagnostics = await (await fetch(`${baseURL}/__browser_harness/diagnostics`)).json();
  assert.equal(snapshot.openedAt > 0, true);
  assert.equal(snapshot.openedAt < diagnostics.asset_completed_at, true, "first paint must precede delayed lazy asset completion");

  const eventLog = await page.locator("#event-log").textContent();
  const serializedEvidence = JSON.stringify({ requestedURLs, consoleLines, eventLog, diagnostics });
  for (const forbidden of [
    "parent_asset_ticket_",
    "parent_asset_session_",
    "parent_gateway_token_",
    "parent_stream_ticket_",
    "owner_session_hash",
    "session_channel_id_hash",
  ]) {
    assert.equal(serializedEvidence.includes(forbidden), false, `${credentiallessScenario} evidence leaked ${forbidden}`);
  }
  assert.equal(requestedURLs.some((url) => /[?&](ticket|token|asset_session|stream_ticket)=/i.test(url)), false);
  assert.equal(requestedURLs.some((url) => url.includes("worker-network-probe") || url.includes("worker-prototype-fetch")), false);

  await page.screenshot({
    path: join(evidenceDir, `redevplugin-a2-${credentiallessScenario}.png`),
    fullPage: true,
  });

  await page.locator("#dispose-surface").click();
  await page.waitForFunction(() => window.__redevpluginHarness.snapshot().status === "disposed");
  await waitFor(() => page.workers().length === 0, 5_000, "dedicated worker disposal");
  const disposed = await page.evaluate(() => window.__redevpluginHarness.snapshot());
  assert.equal(disposed.iframeSrcdocEmpty, true);
  assert.equal(await iframe.getAttribute("srcdoc"), "");
  await page.close();
  return {
    credentialless_scenario: credentiallessScenario,
    sandbox,
    allow,
    referrer_policy: referrerPolicy,
    csp,
    frame_origin: isolation.origin,
    opaque_origin: isolation.origin === "null",
    isolation: Object.fromEntries(Object.entries(isolation).filter(([name]) => name !== "origin")),
    worker_probe: workerProbe,
    platform_dynamic_import_gate: true,
    parent_credentials_absent: forbiddenEvidenceAbsent(serializedEvidence),
    credential_query_absent: !requestedURLs.some((url) => /[?&](ticket|token|asset_session|stream_ticket)=/i.test(url)),
    direct_worker_network_absent: !requestedURLs.some((url) => url.includes("worker-network-probe") || url.includes("worker-prototype-fetch")),
    disposed: disposed.iframeSrcdocEmpty === true,
  };
}

function normalizeCSP(srcdoc) {
  const content = srcdoc?.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)?.[1];
  if (!content) throw new Error("opaque iframe srcdoc omitted Content-Security-Policy");
  return content.replaceAll("&quot;", '"').replace(/'nonce-[A-Za-z0-9_-]+'/g, "'nonce-<redacted>'");
}

function forbiddenEvidenceAbsent(serializedEvidence) {
  return ![
    "parent_asset_ticket_",
    "parent_asset_session_",
    "parent_gateway_token_",
    "parent_stream_ticket_",
    "owner_session_hash",
    "session_channel_id_hash",
  ].some((forbidden) => serializedEvidence.includes(forbidden));
}

async function waitForPluginFrame(page) {
  await waitFor(() => page.frames().some((frame) => frame.parentFrame() === page.mainFrame() && frame.url() === "about:srcdoc"), 10_000, "opaque iframe");
  return page.frames().find((frame) => frame.parentFrame() === page.mainFrame() && frame.url() === "about:srcdoc");
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for ${label}`);
}
