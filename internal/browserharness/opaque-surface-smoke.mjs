import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { chromium } from "playwright";
import { validateA2Evidence } from "../../scripts/verify_redevplugin_a2_evidence.mjs";
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
  const report = {
    schema_version: "redevplugin.a2_acceptance.v1",
    evidence_source: "go-host-http-adapter-rust-runtime-chromium",
    scenarios,
  };
  const reportPath = join(evidenceDir, "redevplugin-a2-acceptance.json");
  const supportedScreenshotPath = join(evidenceDir, "redevplugin-a2-supported.png");
  const unsupportedScreenshotPath = join(evidenceDir, "redevplugin-a2-unsupported.png");
  writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n");
  validateA2Evidence({
    report,
    supportedScreenshot: readFileSync(supportedScreenshotPath),
    unsupportedScreenshot: readFileSync(unsupportedScreenshotPath),
  });
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
  const requests = [];
  const webSockets = [];
  const consoleLines = [];
  page.on("request", (request) => requests.push({ method: request.method(), url: request.url() }));
  page.on("websocket", (webSocket) => webSockets.push(webSocket.url()));
  page.on("console", (message) => consoleLines.push(message.text()));
  await page.goto(`${baseURL}/testdata/browser-harness/opaque-surface/index.html?credentialless=${credentiallessScenario}`, { waitUntil: "domcontentloaded" });
  const openingFrame = page.locator("#plugin-surface-mount > iframe");
  await openingFrame.waitFor({ state: "attached", timeout: 10_000 });
  const openingPresentation = await openingFrame.evaluate((frame) => {
    const style = getComputedStyle(frame);
    const bounds = frame.getBoundingClientRect();
    return {
      hidden: frame.hidden,
      inert: frame.inert,
      ariaHidden: frame.getAttribute("aria-hidden"),
      display: style.display,
      visibility: style.visibility,
      opacity: style.opacity,
      pointerEvents: style.pointerEvents,
      width: bounds.width,
      height: bounds.height,
      acceptsProgrammaticFocus: (() => {
        frame.focus();
        return document.activeElement === frame;
      })(),
    };
  });
  assert.equal(openingPresentation.hidden, false, `${credentiallessScenario} opening iframe stays renderable for requestAnimationFrame`);
  assert.equal(openingPresentation.inert, true, `${credentiallessScenario} opening iframe is inert`);
  assert.equal(openingPresentation.ariaHidden, "true", `${credentiallessScenario} opening iframe is absent from accessibility`);
  assert.notEqual(openingPresentation.display, "none", `${credentiallessScenario} opening iframe participates in rendering`);
  assert.equal(openingPresentation.visibility, "visible", `${credentiallessScenario} opening iframe remains eligible for animation frames`);
  assert.equal(openingPresentation.opacity, "0", `${credentiallessScenario} opening iframe cannot flash before first commit`);
  assert.equal(openingPresentation.pointerEvents, "none", `${credentiallessScenario} opening iframe rejects pointer input`);
  assert.equal(openingPresentation.width > 0 && openingPresentation.height > 0, true, `${credentiallessScenario} opening iframe retains layout bounds`);
  assert.equal(openingPresentation.acceptsProgrammaticFocus, false, `${credentiallessScenario} opening iframe rejects keyboard focus`);
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
  const readyPresentation = await iframe.evaluate((frame) => ({
    hidden: frame.hidden,
    inert: frame.inert,
    ariaHidden: frame.getAttribute("aria-hidden"),
    visibility: getComputedStyle(frame).visibility,
    opacity: getComputedStyle(frame).opacity,
    pointerEvents: getComputedStyle(frame).pointerEvents,
  }));
  assert.deepEqual(readyPresentation, {
    hidden: false,
    inert: false,
    ariaHidden: "false",
    visibility: "visible",
    opacity: "1",
    pointerEvents: "auto",
  }, `${credentiallessScenario} first paint and worker commit reveal exactly one interactive iframe`);
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

  const canvasWheel = await frame.locator("canvas[data-redevplugin-canvas='wheel-probe']").evaluate((canvas) => {
    const bounds = canvas.getBoundingClientRect();
    const event = new WheelEvent("wheel", {
      bubbles: true,
      cancelable: true,
      composed: true,
      clientX: bounds.left + 32,
      clientY: bounds.top + 24,
      deltaX: -8,
      deltaY: 42,
      deltaMode: WheelEvent.DOM_DELTA_PIXEL,
      ctrlKey: true,
    });
    return { dispatchResult: canvas.dispatchEvent(event), defaultPrevented: event.defaultPrevented };
  });
  assert.deepEqual(canvasWheel, { dispatchResult: false, defaultPrevented: true });
  await frame.waitForFunction(() => document.querySelector("#canvas-wheel")?.textContent?.includes('"deltaY":42'));
  assert.deepEqual(JSON.parse(await frame.locator("#canvas-wheel").textContent()), {
    type: "wheel",
    x: 32,
    y: 24,
    deltaX: -8,
    deltaY: 42,
    deltaMode: 0,
    altKey: false,
    ctrlKey: true,
    metaKey: false,
    shiftKey: false,
  });
  await page.waitForFunction(() => window.__redevpluginHarness.snapshot().interactions.some(
    (event) => event.kind === "wheel" && event.localScroll === true,
  ));

  const originalIframe = await iframe.elementHandle();
  assert.notEqual(originalIframe, null, `${credentiallessScenario} surface iframe exists before lifecycle retention`);
  const hiddenRenderCommitted = page.waitForRequest((request) => (
    request.method() === "POST"
    && request.postData()?.includes("Lifecycle render committed: hidden") === true
  ), { timeout: 2_000 });
  await page.locator("#plugin-surface-mount").evaluate((mount) => {
    mount.style.display = "none";
  });
  await page.getByRole("button", { name: "Hidden" }).click();
  await hiddenRenderCommitted;
  assert.equal((await page.evaluate(() => window.__redevpluginHarness.snapshot())).errors.length, 0, `${credentiallessScenario} hidden lifecycle render errors`);

  const visibleRenderCommitted = page.waitForRequest((request) => (
    request.method() === "POST"
    && request.postData()?.includes("Lifecycle render committed: visible") === true
  ), { timeout: 2_000 });
  await page.locator("#plugin-surface-mount").evaluate((mount) => {
    mount.style.display = "";
  });
  await page.getByRole("button", { name: "Visible" }).click();
  await visibleRenderCommitted;
  await frame.waitForFunction(() => document.querySelector("#plugin-status")?.textContent === "Lifecycle: visible");
  assert.equal(await iframe.evaluate((element, retained) => element === retained, originalIframe), true, `${credentiallessScenario} lifecycle retains the exact iframe`);
  assert.equal((await page.evaluate(() => window.__redevpluginHarness.snapshot())).errors.length, 0, `${credentiallessScenario} visible lifecycle render errors`);

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
    "dynamic_import_blocked",
    "all_blocked",
  ]) {
    assert.equal(workerProbe[field], true, `${credentiallessScenario} worker probe ${field}`);
  }
  await waitFor(() => page.workers().length === 1, 5_000, "dedicated worker creation");

  const documentScroll = await frame.evaluate(() => {
    const previousStyle = document.body.getAttribute("style");
    document.body.style.minHeight = "200vh";
    const scrollingElement = document.scrollingElement;
    document.body.dispatchEvent(new WheelEvent("wheel", { bubbles: true, composed: true, deltaY: 24 }));
    const result = {
      overflowY: scrollingElement ? getComputedStyle(scrollingElement).overflowY : "",
      scrollHeight: scrollingElement?.scrollHeight ?? 0,
      clientHeight: scrollingElement?.clientHeight ?? 0,
    };
    if (previousStyle === null) document.body.removeAttribute("style");
    else document.body.setAttribute("style", previousStyle);
    return result;
  });
  assert.equal(documentScroll.scrollHeight > documentScroll.clientHeight, true, `${credentiallessScenario} document scroll fixture`);
  assert.equal(/^(auto|scroll|overlay)$/.test(documentScroll.overflowY), false, `${credentiallessScenario} document uses default scrolling`);
  await page.waitForFunction(() => window.__redevpluginHarness.snapshot().interactions.some(
    (event) => event.kind === "wheel" && event.localScroll === true,
  ));

  await frame.getByRole("button", { name: "Call host" }).click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes("typed MessagePort"));
  assert.equal((await frame.locator("#plugin-result").textContent()).includes("gateway_token"), false);

  await frame.getByRole("button", { name: "Read execution events" }).click();
  try {
    await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes("opaque log line 2"));
  } catch (error) {
    const diagnostics = await (await fetch(`${baseURL}/__browser_harness/diagnostics`)).json();
    const pluginResult = await frame.locator("#plugin-result").textContent();
    throw new Error(`execution event response recovery failed: ${JSON.stringify({ diagnostics, pluginResult })}`, { cause: error });
  }
  const executionResult = await frame.locator("#plugin-result").textContent();
  const realExecutionEventsRead = executionResult.includes("opaque log line 1") && executionResult.includes("opaque log line 2");
  assert.equal(executionResult.includes("ticket"), false);
  assert.equal(executionResult.includes('"parent_execution_credential_visible": false'), true);

  await frame.getByRole("button", { name: "Dangerous action" }).click();
  try {
    await page.locator("#confirmation-panel").waitFor({ state: "visible" });
  } catch (error) {
    const diagnostics = await (await fetch(`${baseURL}/__browser_harness/diagnostics`)).json();
    const pluginResult = await frame.locator("#plugin-result").textContent();
    throw new Error(`confirmation preparation failed: ${JSON.stringify({ diagnostics, pluginResult })}`, { cause: error });
  }
  await page.locator("#approve-confirmation").click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes('"confirmed": true'));

  await frame.getByRole("button", { name: "Observe execution" }).click();
  await frame.waitForFunction(() => document.querySelector("#plugin-result")?.textContent?.includes('"retry_status": "completed"'));
  const observationResult = await frame.locator("#plugin-result").textContent();
  assert.equal(observationResult.includes('"first_cancelled": true'), true);

  await waitFor(async () => {
    const response = await fetch(`${baseURL}/__browser_harness/diagnostics`);
    const value = await response.json();
    return value.asset_completed_at > 0;
  }, 5_000, "lazy asset completion");
  const diagnostics = await (await fetch(`${baseURL}/__browser_harness/diagnostics`)).json();
  const currentSurfaceID = diagnostics.latest_surface_id;
  assert.equal(snapshot.openedAt > 0, true);
  assert.equal(snapshot.openedAt < diagnostics.asset_completed_at, true, "first paint must precede delayed lazy asset completion");

  await page.screenshot({
    path: join(evidenceDir, `redevplugin-a2-${credentiallessScenario}.png`),
    fullPage: true,
  });

  await frame.getByRole("button", { name: "Dangerous action" }).click();
  await page.locator("#confirmation-panel").waitFor({ state: "visible" });
  await page.evaluate(() => {
    document.querySelector("#plugin-surface-mount").style.display = "none";
    document.querySelector("#send-hidden").click();
    document.querySelector("#dispose-surface").click();
  });
  try {
    await page.waitForFunction(() => window.__redevpluginHarness.snapshot().status === "disposed");
  } catch (error) {
    const failure = await page.evaluate(() => ({
      snapshot: window.__redevpluginHarness.snapshot(),
      status: document.querySelector("#host-status")?.textContent,
      eventLog: document.querySelector("#event-log")?.textContent,
    }));
    throw new Error(`${credentiallessScenario} surface did not dispose: ${JSON.stringify(failure)}`, { cause: error });
  }
  await page.waitForFunction(() => document.querySelector("#event-log")?.textContent?.includes("confirmation-aborted"));
  await waitFor(() => page.workers().length === 0, 5_000, "dedicated worker disposal");
  await new Promise((resolve) => setTimeout(resolve, 250));
  await waitFor(async () => {
    const response = await fetch(`${baseURL}/__browser_harness/diagnostics`);
    const value = await response.json();
    return value.dispose_completed_at > 0;
  }, 5_000, "server surface disposal");
  const disposed = await page.evaluate(() => window.__redevpluginHarness.snapshot());
  const finalDiagnostics = await (await fetch(`${baseURL}/__browser_harness/diagnostics`)).json();
  const eventLog = await page.locator("#event-log").textContent();
  const serializedEvidence = JSON.stringify({ requests, webSockets, consoleLines, eventLog, diagnostics: finalDiagnostics });
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
  const requestedURLs = requests.map((request) => request.url);
  const unexpectedRequests = requests.filter((request) => !requestAllowed(request, credentiallessScenario));
  const strictRequestAllowlist = unexpectedRequests.length === 0;
  assert.deepEqual(unexpectedRequests, [], `${credentiallessScenario} request allowlist`);
  assert.equal(requestedURLs.some((url) => /[?&](ticket|token|asset_session|stream_ticket)=/i.test(url)), false);
  assert.equal(requestedURLs.some((url) => url.includes("worker-network-probe") || url.includes("worker-prototype-fetch")), false);
  assert.deepEqual(webSockets, [], `${credentiallessScenario} websocket creation`);
  assert.deepEqual(page.context().serviceWorkers(), [], `${credentiallessScenario} service worker creation`);
  assert.equal(eventLog.includes("confirmation-aborted"), true);
  assert.equal(finalDiagnostics.dispose_completed_at > 0, true);
  assert.equal(finalDiagnostics.execution_snapshot_cancel_recovered, true);
  assert.equal(disposed.iframeSrcdocEmpty, true);
  assert.equal(await iframe.count(), 0, `${credentiallessScenario} slot removes the disposed iframe`);
  assert.equal(disposed.errors.length, 0, `${credentiallessScenario} disposed surface errors`);
  await page.close();
  return {
    credentialless_scenario: credentiallessScenario,
    credentialless,
    sandbox,
    allow,
    referrer_policy: referrerPolicy,
    csp,
    frame_origin: isolation.origin,
    opaque_origin: isolation.origin === "null",
    isolation: Object.fromEntries(Object.entries(isolation).filter(([name]) => name !== "origin")),
    worker_probe: workerProbe,
    platform_dynamic_import_gate: workerProbe.dynamic_import_blocked === true,
    parent_credentials_absent: forbiddenEvidenceAbsent(serializedEvidence),
    credential_query_absent: !requestedURLs.some((url) => /[?&](ticket|token|asset_session|stream_ticket)=/i.test(url)),
    direct_worker_network_absent: !requestedURLs.some((url) => url.includes("worker-network-probe") || url.includes("worker-prototype-fetch")),
    strict_request_allowlist: strictRequestAllowlist,
    websocket_absent: webSockets.length === 0 && workerProbe.websocket_blocked === true,
    service_worker_absent: page.context().serviceWorkers().length === 0 && isolation.service_worker_blocked === true,
    opening_progress: snapshot.progressEvents.length >= 1 && snapshot.progressEvents[0] >= 300,
    first_paint_before_lazy_asset: snapshot.openedAt > 0 && snapshot.openedAt < diagnostics.asset_completed_at,
    execution_event_response_loss_recovered: finalDiagnostics.execution_event_response_loss_recovered === true,
    real_execution_events_read: realExecutionEventsRead && requests.filter((request) => request.url.includes("/executions/execution_harness_logs/events/query")).length === 3,
    confirmation_disposal_aborted: eventLog.includes("confirmation-aborted"),
    server_disposed: finalDiagnostics.dispose_completed_at > 0,
    disposed: disposed.iframeSrcdocEmpty === true,
  };
}

function requestAllowed(request, credentiallessScenario) {
  if (request.method === "GET" && /^blob:null\/[0-9a-f-]{36}$/.test(request.url)) return true;
  const url = new URL(request.url);
  if (url.origin !== baseURL || url.username || url.password || url.hash) return false;
  const staticRequests = new Map([
    ["/testdata/browser-harness/opaque-surface/index.html", "GET"],
    ["/testdata/browser-harness/opaque-surface/styles.css", "GET"],
    ["/testdata/browser-harness/opaque-surface/host.mjs", "GET"],
    ["/packages/redevplugin-ui/dist/trusted-parent.js", "GET"],
    ["/packages/redevplugin-ui/dist/bridge-capability.js", "GET"],
    ["/packages/redevplugin-ui/dist/contracts.gen.js", "GET"],
    ["/packages/redevplugin-ui/dist/error-codes.gen.js", "GET"],
    ["/packages/redevplugin-ui/dist/errors.js", "GET"],
    ["/packages/redevplugin-ui/dist/platform.js", "GET"],
    ["/packages/redevplugin-ui/dist/surface-scope.js", "GET"],
    ["/packages/redevplugin-ui/dist/surface.js", "GET"],
    ["/packages/redevplugin-ui/dist/ui-patch-validator.js", "GET"],
    ["/packages/redevplugin-ui/dist/ui-reconciler.js", "GET"],
    ["/packages/redevplugin-ui/dist/http.js", "GET"],
    ["/packages/redevplugin-ui/dist/opaque-surface-policy.gen.js", "GET"],
    ["/__browser_harness/diagnostics", "GET"],
    ["/_redevplugin/api/plugins/surfaces/open", "POST"],
    ["/_redevplugin/api/plugins/rpc", "POST"],
    ["/_redevplugin/api/plugins/confirmations/prepare", "POST"],
  ]);
  const expectedMethod = staticRequests.get(url.pathname);
  if (expectedMethod) {
    const expectedSearch = url.pathname.endsWith("/index.html") ? `?credentialless=${credentiallessScenario}` : "";
    return request.method === expectedMethod && url.search === expectedSearch;
  }
  return request.method === "POST" && url.search === "" &&
    (/^\/_redevplugin\/api\/plugins\/surfaces\/surface_browser_[0-9]{4}\/(prepare|bridge-token|assets\/read|dispose)$/.test(url.pathname) ||
      url.pathname === "/_redevplugin/api/plugins/executions/execution_harness_logs/events/query" ||
      url.pathname === "/_redevplugin/api/plugins/executions/execution_harness_1/query");
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
