import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "playwright";
import { isExpectedSandboxConsoleLine } from "./smoke-console-policy.mjs";

const repoRoot = new URL("../..", import.meta.url);
const toolEnv = withUserToolchainPath(process.env);
const hostPort = await getFreePort();
const hostName = "app.redevplugin.localhost";
const hostOrigin = `http://${hostName}:${hostPort}`;
const hostURL = `${hostOrigin}/demo/real/index.html`;
const evidenceDir = resolve(process.env.REDEVPLUGIN_A2_EVIDENCE_DIR || "dist/a2-evidence");
const stateRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-runtime-demo-"));
const binRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-runtime-bin-"));
const deniedPermissionsPolicy = "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'";
const expectedCSP = "default-src 'none'; script-src 'nonce-<redacted>'; style-src 'nonce-<redacted>'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src blob:; child-src blob:; form-action 'none'; base-uri 'none'; object-src 'none'; manifest-src 'none'";
const runtimePath = await buildRuntime();
const cliPath = await buildCLI(binRoot);
const server = spawn(cliPath, ["demo-real-server", stateRoot, runtimePath], {
  cwd: repoRoot,
  env: {
    ...toolEnv,
    GOWORK: "off",
    REAL_DEMO_HOST_PORT: String(hostPort),
    REAL_DEMO_HOST_NAME: hostName,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverOutput = "";
let browser;
server.stdout.on("data", (chunk) => { serverOutput += String(chunk); });
server.stderr.on("data", (chunk) => { serverOutput += String(chunk); });

try {
  await waitForHTTP(hostURL);
  browser = await chromium.launch({ headless: true });
  mkdirSync(evidenceDir, { recursive: true });
  const scenarios = [];
  for (const name of ["supported", "unsupported"]) {
    scenarios.push(await verifyScenario(name));
  }
  writeFileSync(join(evidenceDir, "redevplugin-a2-acceptance.json"), JSON.stringify({
    schema_version: "redevplugin.a2_acceptance.v1",
    evidence_source: "go-host-http-adapter-rust-runtime-chromium",
    scenarios,
  }, null, 2) + "\n");
  console.log("real runtime opaque browser smoke passed");
} finally {
  await browser?.close();
  await stopServer();
  await rm(stateRoot, { recursive: true, force: true });
  await rm(binRoot, { recursive: true, force: true });
}

async function verifyScenario(credentiallessScenario) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 760 } });
  if (credentiallessScenario === "unsupported") {
    await context.addInitScript(() => {
      Reflect.deleteProperty(HTMLIFrameElement.prototype, "credentialless");
    });
  }
  const page = await context.newPage();
  const consoleLines = [];
  const requests = [];
  const webSockets = [];
  const serviceWorkers = [];
  const apiResponseHeaders = [];
  const failedAPIResponses = [];
  let bootstrapResponseBody;

  page.on("request", (request) => {
    requests.push({ method: request.method(), url: request.url(), resourceType: request.resourceType() });
  });
  page.on("response", (response) => {
    if (response.url().endsWith("/demo/real/bootstrap")) bootstrapResponseBody = response.json();
    if (response.url().includes("/_redevplugin/api/plugins/") || response.url().endsWith("/demo/real/bootstrap")) {
      apiResponseHeaders.push(response.allHeaders().then((headers) => ({ url: response.url(), headers })));
    }
    if (response.url().includes("/_redevplugin/api/plugins/") && !response.ok()) {
      failedAPIResponses.push(response.text().then((body) => ({ url: response.url(), status: response.status(), body })));
    }
  });
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") consoleLines.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => consoleLines.push(`pageerror: ${error.message}`));
  page.on("websocket", (socket) => webSockets.push(socket.url()));
  context.on("serviceworker", (worker) => serviceWorkers.push(worker.url()));

  try {
    await page.goto(`${hostURL}?credentialless=${credentiallessScenario}`, { waitUntil: "load" });
    await expectText(page.locator("#host-status"), "ready", 30_000);
    await expectText(page.locator("#handshake-count"), "1");
    await expectText(page.locator("#runtime-ready"), "1");
    await waitFor(() => page.workers().length === 1, 5_000, `${credentiallessScenario} real plugin worker`);

    const snapshot = await page.evaluate(() => window.__redevpluginRealDemo.snapshot());
    assert.equal(snapshot.progressEvents.length >= 1, true, `${credentiallessScenario} opening progress`);
    assert.equal(snapshot.progressEvents[0] >= 300, true, `${credentiallessScenario} progress threshold`);
    assert.equal(snapshot.openedAt > 0, true, `${credentiallessScenario} opened timestamp`);

    const iframe = page.locator("#plugin-frame");
    const sandbox = await iframe.getAttribute("sandbox");
    const allow = await iframe.getAttribute("allow");
    const referrerPolicy = await iframe.getAttribute("referrerpolicy");
    const srcdoc = await iframe.getAttribute("srcdoc");
    const csp = normalizeCSP(srcdoc);
    const credentialless = await iframe.evaluate((frame) => "credentialless" in frame ? frame.credentialless === true : false);
    assert.equal(sandbox, "allow-scripts");
    assert.equal(allow, deniedPermissionsPolicy);
    assert.equal(referrerPolicy, "no-referrer");
    assert.equal(sandbox?.includes("allow-same-origin"), false);
    assert.equal(await iframe.getAttribute("src"), "about:blank");
    assert.equal(csp, expectedCSP);
    assert.equal(credentialless, credentiallessScenario === "supported");

    assert.equal(Boolean(bootstrapResponseBody), true, "bootstrap response was not captured");
    const bootstrapEnvelope = await bootstrapResponseBody;
    const bootstrap = bootstrapEnvelope?.data?.bootstrap;
    const bootstrapCanaries = [
      bootstrap?.asset_ticket,
      bootstrap?.asset_ticket_id,
      bootstrap?.asset_session_nonce,
      bootstrap?.bridge_nonce,
    ].filter((value) => typeof value === "string" && value.length > 0);
    assert.equal(bootstrapCanaries.length, 4, "bootstrap response omitted canary fields");

    const frame = page.frameLocator("#plugin-frame");
    await expectText(frame.locator("#status"), "Ready");
    await expectText(frame.locator("h1"), "Real Runtime Demo Plugin");
    await page.evaluate(() => {
      document.cookie = "real_demo_host_secret=parent-only; SameSite=Strict";
      localStorage.setItem("real_demo_host_secret", "parent-only");
      sessionStorage.setItem("real_demo_host_secret", "parent-only");
    });
    const isolation = await frame.locator("body").evaluate(async () => {
      const blocked = async (operation) => {
        try { await operation(); return false; } catch { return true; }
      };
      const secretBlocked = async (operation) => {
        try { return !String(await operation()).includes("parent-only"); } catch { return true; }
      };
      return {
        origin: location.origin,
        parent_dom_blocked: await blocked(() => Promise.resolve(parent.document.querySelector("#host-status"))),
        parent_cookie_blocked: await secretBlocked(() => Promise.resolve(document.cookie)),
        parent_local_storage_blocked: await secretBlocked(() => Promise.resolve(localStorage.getItem("real_demo_host_secret"))),
        parent_session_storage_blocked: await secretBlocked(() => Promise.resolve(sessionStorage.getItem("real_demo_host_secret"))),
        indexeddb_blocked: await blocked(() => new Promise((resolve, reject) => {
          const request = indexedDB.open("redevplugin-real-opaque-probe");
          request.onsuccess = () => resolve(undefined);
          request.onerror = () => reject(request.error || new Error("indexedDB failed"));
        })),
        cache_storage_blocked: await blocked(() => caches.open("redevplugin-real-opaque-probe")),
        direct_fetch_blocked: await blocked(() => fetch("/demo/real/forbidden-direct-fetch")),
        service_worker_blocked: await blocked(async () => {
          await navigator.serviceWorker.register("/demo/real/forbidden-sw.js");
        }),
      };
    });
    assert.equal(isolation.origin, "null");
    for (const [name, value] of Object.entries(isolation)) {
      if (name !== "origin") assert.equal(value, true, `${credentiallessScenario} ${name}`);
    }

    const workerProbe = JSON.parse(await frame.locator("#security-probe").textContent());
    for (const field of requiredWorkerProbeFields()) {
      assert.equal(workerProbe[field], true, `${credentiallessScenario} worker probe ${field}`);
    }

    await clickButton(frame, "Invoke backend");
    await expectText(frame.locator("#status"), "Backend responded");
    await expectText(frame.locator("#result"), "rust runtime ipc");
    await expectText(frame.locator("#result"), '"worker_id": "backend"');
    await expectText(page.locator("#rpc-count"), "1");

    await clickButton(frame, "Storage + network");
    await expectText(frame.locator("#status"), "Brokered backend responded");
    for (const expected of [
      "storage_file",
      "storage_kv",
      "demo/last_broker_run",
      "storage_sqlite",
      "plugin.sqlite",
      "network_execute",
      "host-network-executor",
      "notes/generated-broker-demo.txt",
      "generated brokered http request",
      '"storage_credential_visible": false',
    ]) await expectText(frame.locator("#result"), expected);
    await expectText(page.locator("#rpc-count"), "2");

    await clickButton(frame, "Plan schedule");
    await expectText(frame.locator("#status"), "Schedule saved");
    await expectText(frame.locator("#schedule-meta"), "Persisted 1 item in plugin.sqlite");
    for (const expected of ["Design plugin rollout", "Focus Room A", "rust runtime storage"]) {
      await expectText(frame.locator("#schedule-list"), expected);
    }
    await expectText(page.locator("#rpc-count"), "3");

    await clickButton(frame, "Network matrix");
    await expectText(frame.locator("#status"), "Network matrix completed");
    for (const expected of [
      "network.matrix",
      "http:hello http",
      "websocket:hello websocket",
      "tcp:hello tcp",
      "udp:hello udp",
      '"gateway_credential_visible": false',
      '"network_credential_visible": false',
    ]) await expectText(frame.locator("#result"), expected);
    await expectText(page.locator("#rpc-count"), "7");

    await clickButton(frame, "Read stream");
    await expectText(frame.locator("#status"), "Runtime stream received");
    await expectText(frame.locator("#result"), "real stream line 1");
    await expectText(frame.locator("#result"), "real stream line 2");
    await expectText(frame.locator("#result"), '"parent_stream_credential_visible": false');
    await expectText(page.locator("#rpc-count"), "8");
    const streamResult = await frame.locator("#result").textContent();
    assert.equal(streamResult.includes("stream_ticket"), false);

    await waitFor(async () => (await readDiagnostics()).asset_completed_at > 0, 5_000, `${credentiallessScenario} lazy asset completion`);
    const paintedDiagnostics = await readDiagnostics();
    assert.equal(snapshot.openedAt < paintedDiagnostics.asset_completed_at, true, `${credentiallessScenario} first paint must precede lazy asset completion`);
    assert.equal(paintedDiagnostics.asset_read_count, 1);

    await clickButton(frame, "Dangerous action");
    await expectText(page.locator("#confirmation-method"), "danger.run");
    await clickButton(page, "Deny");
    await expectText(frame.locator("#status"), "Dangerous action blocked");
    await expectText(frame.locator("#result"), "PLUGIN_CONFIRMATION_REJECTED");
    await expectText(page.locator("#rpc-count"), "9");

    await clickButton(frame, "Dangerous action");
    await expectText(page.locator("#confirmation-method"), "danger.run");
    await clickButton(page, "Approve");
    await expectText(frame.locator("#status"), "Dangerous action confirmed");
    await expectText(frame.locator("#result"), "real http adapter confirmation");
    await expectText(frame.locator("#result"), '"confirmation_credential_visible": false');
    await expectText(page.locator("#rpc-count"), "11");

    assertRequestsAllowed(requests);
    assert.deepEqual(webSockets, [], `${credentiallessScenario} opened a WebSocket`);
    assert.deepEqual(serviceWorkers, [], `${credentiallessScenario} registered a Service Worker`);
    const headers = await Promise.all(apiResponseHeaders);
    assert.equal(headers.length > 0, true);
    for (const entry of headers) {
      assert.equal(entry.headers["cache-control"], "no-store", entry.url);
      assert.equal("access-control-allow-origin" in entry.headers, false, entry.url);
    }

    const pageEvidence = await page.evaluate(() => ({
      url: location.href,
      text: document.body.textContent,
      attributes: Array.from(document.querySelectorAll("*")).flatMap((element) =>
        Array.from(element.attributes, (attribute) => [element.tagName, attribute.name, attribute.value])
      ),
      cookie: document.cookie,
      localStorage: Object.entries(localStorage),
      sessionStorage: Object.entries(sessionStorage),
    }));
    const pluginEvidence = await frame.locator("html").evaluate((root) => ({
      text: root.textContent,
      attributes: Array.from(root.querySelectorAll("*")).flatMap((element) =>
        Array.from(element.attributes, (attribute) => [element.tagName, attribute.name, attribute.value])
      ),
    }));
    const serializedEvidence = JSON.stringify({
      requests,
      consoleLines,
      eventLog: await page.locator("#event-log").textContent(),
      pageEvidence,
      pluginEvidence,
    });
    for (const canary of bootstrapCanaries) {
      assert.equal(serializedEvidence.includes(canary), false, `${credentiallessScenario} bootstrap canary escaped its module closure`);
    }
    for (const forbidden of [
      "asset_ticket=",
      "asset_session=",
      "plugin_gateway_token=",
      "stream_ticket=",
      "owner_session_hash",
      "session_channel_id_hash",
    ]) assert.equal(serializedEvidence.includes(forbidden), false, `${credentiallessScenario} evidence leaked ${forbidden}`);

    await page.screenshot({
      path: join(evidenceDir, `redevplugin-a2-${credentiallessScenario}.png`),
      fullPage: true,
    });

    await clickButton(frame, "Dangerous action");
    await page.locator("#confirmation-panel").waitFor({ state: "visible" });
    await clickButton(page, "Dispose");
    await expectText(page.locator("#host-status"), "disposed");
    await waitFor(() => page.workers().length === 0, 5_000, `${credentiallessScenario} worker disposal`);
    await waitFor(async () => (await readDiagnostics()).dispose_count === 1, 5_000, `${credentiallessScenario} server disposal`);
    const disposed = await page.evaluate(() => window.__redevpluginRealDemo.snapshot());
    const disposedDiagnostics = await readDiagnostics();
    assert.equal(disposed.confirmationAborted, true);
    assert.equal(disposed.confirmationVisible, false);
    assert.equal(disposed.iframeSrcdocEmpty, true);
    assert.equal(await iframe.getAttribute("srcdoc"), "");
    assert.equal(disposedDiagnostics.dispose_completed_at > 0, true);

    const failedResponses = await Promise.all(failedAPIResponses);
    assert.equal(failedResponses.length, 3, `${credentiallessScenario} expected one confirmation challenge per dangerous call`);
    assert.equal(failedResponses.every((entry) => entry.status === 409 && entry.body.includes("PLUGIN_CONFIRMATION_REQUIRED")), true);
    const unexpectedConsoleLines = consoleLines.filter((entry) => !isExpectedSandboxConsoleLine(entry));
    assert.deepEqual(unexpectedConsoleLines, []);

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
      platform_dynamic_import_gate: true,
      parent_credentials_absent: forbiddenEvidenceAbsent(serializedEvidence),
      credential_query_absent: !requests.some((request) => /[?&](ticket|token|asset_session|stream_ticket)=/i.test(request.url)),
      direct_worker_network_absent: !requests.some((request) => request.url.includes("redevplugin.invalid")),
      strict_request_allowlist: true,
      websocket_absent: webSockets.length === 0,
      service_worker_absent: serviceWorkers.length === 0,
      opening_progress: snapshot.progressEvents.length >= 1 && snapshot.progressEvents[0] >= 300,
      first_paint_before_lazy_asset: snapshot.openedAt < paintedDiagnostics.asset_completed_at,
      real_stream_redeemed: streamResult.includes("real stream line 1") && streamResult.includes("real stream line 2"),
      confirmation_disposal_aborted: disposed.confirmationAborted === true && disposed.confirmationVisible === false,
      server_disposed: disposedDiagnostics.dispose_count === 1,
      disposed: disposed.iframeSrcdocEmpty === true,
    };
  } catch (error) {
    let browserState = {};
    let pluginState = {};
    try {
      browserState = await page.evaluate(() => ({
        status: document.querySelector("#host-status")?.textContent,
        event_log: document.querySelector("#event-log")?.textContent,
        snapshot: window.__redevpluginRealDemo?.snapshot(),
      }));
    } catch {}
    try {
      const pluginFrame = page.frames().find((frame) => frame.parentFrame() === page.mainFrame() && frame.url() === "about:srcdoc");
      pluginState = await pluginFrame?.evaluate(() => ({
        status: document.querySelector("#status")?.textContent,
        result: document.querySelector("#result")?.textContent,
        security_probe: document.querySelector("#security-probe")?.textContent,
      })) ?? {};
    } catch {}
    const failedResponses = await Promise.all(failedAPIResponses);
    throw new Error(`real runtime ${credentiallessScenario} smoke failed: ${JSON.stringify({ browserState, pluginState, requests, failedResponses, consoleLines, webSockets, serviceWorkers, serverOutput })}`, { cause: error });
  } finally {
    await context.close();
  }
}

function requiredWorkerProbeFields() {
  return [
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
}

function assertRequestsAllowed(requests) {
  for (const request of requests) {
    const url = new URL(request.url);
    if (url.protocol === "blob:") {
      assert.equal(request.resourceType === "script" || request.resourceType === "other", true, `unexpected blob request type: ${JSON.stringify(request)}`);
      continue;
    }
    assert.equal(url.origin, hostOrigin, `unexpected outbound request origin: ${request.url}`);
    const allowed = url.pathname === "/demo/real/index.html" ||
      url.pathname === "/demo/real/bootstrap" ||
      url.pathname === "/demo/real/broker-grants" ||
      url.pathname === "/demo/real/diagnostics" ||
      url.pathname === "/favicon.ico" ||
      url.pathname.startsWith("/packages/redevplugin-ui/dist/") ||
      url.pathname.startsWith("/_redevplugin/api/plugins/");
    assert.equal(allowed, true, `unexpected request path: ${request.method} ${url.pathname}`);
  }
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

async function readDiagnostics() {
  const response = await fetch(`${hostOrigin}/demo/real/diagnostics`);
  if (!response.ok) throw new Error(`diagnostics returned HTTP ${response.status}`);
  return response.json();
}

async function buildRuntime() {
  const command = spawn("cargo", ["build", "-p", "redevplugin-runtime"], {
    cwd: repoRoot,
    env: { ...toolEnv, CARGO_TERM_COLOR: "never" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  command.stdout.on("data", (chunk) => { output += String(chunk); });
  command.stderr.on("data", (chunk) => { output += String(chunk); });
  const [code] = await once(command, "exit");
  if (code !== 0) throw new Error(`cargo build -p redevplugin-runtime failed with code ${code}\n${output}`);
  return new URL("../../target/debug/redevplugin-runtime", import.meta.url).pathname;
}

async function buildCLI(outDir) {
  const filename = join(outDir, process.platform === "win32" ? "redevplugin.exe" : "redevplugin");
  const command = spawn("go", ["build", "-o", filename, "./cmd/redevplugin"], {
    cwd: repoRoot,
    env: { ...toolEnv, GOWORK: "off" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  command.stdout.on("data", (chunk) => { output += String(chunk); });
  command.stderr.on("data", (chunk) => { output += String(chunk); });
  const [code] = await once(command, "exit");
  if (code !== 0) throw new Error(`go build ./cmd/redevplugin failed with code ${code}\n${output}`);
  return filename;
}

async function stopServer() {
  if (server.exitCode != null) return;
  server.kill("SIGTERM");
  const result = await Promise.race([once(server, "exit").then(() => "exit"), delay(1_000).then(() => "timeout")]);
  if (result === "timeout") {
    server.kill("SIGKILL");
    await Promise.race([once(server, "exit"), delay(1_000)]);
  }
}

async function expectText(locator, expected, timeoutMs = 7_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      last = (await locator.textContent()) ?? "";
      if (last.includes(expected)) return;
    } catch {
      // The opaque frame may still be replacing its critical document.
    }
    await delay(50);
  }
  throw new Error(`expected text ${JSON.stringify(expected)} but last saw ${JSON.stringify(last)}`);
}

async function clickButton(scope, name) {
  const button = scope.getByRole("button", { name, exact: true });
  await button.waitFor({ state: "visible", timeout: 7_000 });
  assert.equal(await button.getAttribute("disabled"), null, `${name} button should be enabled`);
  await button.click({ timeout: 7_000 });
}

async function waitForHTTP(url, timeoutMs = 12_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server.exitCode != null) throw new Error(`real demo server exited early with code ${server.exitCode}\n${serverOutput}`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(50);
  }
  throw new Error(`real demo server was not ready: ${lastError?.message ?? "unknown error"}\n${serverOutput}`);
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(25);
  }
  throw new Error(`timed out waiting for ${label}`);
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      probe.close(() => address && typeof address === "object" ? resolve(address.port) : reject(new Error("no TCP port allocated")));
    });
  });
}

function withUserToolchainPath(env) {
  const home = env.HOME;
  if (!home) return { ...env };
  const cargoBin = join(home, ".cargo", "bin");
  const pathValue = env.PATH ? `${cargoBin}:${env.PATH}` : cargoBin;
  return { ...env, PATH: pathValue };
}
