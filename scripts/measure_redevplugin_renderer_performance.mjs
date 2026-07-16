#!/usr/bin/env node

import { appendFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { chromium } from "playwright";

const options = parseArgs(process.argv.slice(2));
const reconciler = await import(pathToFileURL(resolve("packages/redevplugin-ui/dist/ui-reconciler.js")));
const element = (key, children = []) => ({ type: "element", key, tag: "div", children });
const children = Array.from({ length: 1000 }, (_, index) => element(`item-${index}`));
const current = reconciler.validatePluginUITree(element("root", children));
const next = reconciler.validatePluginUITree(element("root", [...children].reverse()));
const operations = reconciler.reconcilePluginUITrees(current, next);
if (operations.length !== 999 || operations.some((operation) => operation.type !== "move_child")) {
  throw new Error("renderer fixture did not produce the minimal keyed reversal");
}
const workerContent = await buildPerformanceWorkerSource(current, next);
const hostHarness = await buildHostHarnessSource(workerContent);
const server = createServer((request, response) => {
  if (request.url === "/harness.js") {
    response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
    response.end(hostHarness);
    return;
  }
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  response.end('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ReDevPlugin Renderer Performance</title></head><body><main id="surface-root"></main><script src="/harness.js"></script></body></html>');
});
await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});
const address = server.address();
if (!address || typeof address === "string") throw new Error("renderer performance server did not bind a TCP port");
const harnessURL = `http://127.0.0.1:${address.port}/`;

const browser = await chromium.launch({ headless: true });
const durations = [];
const longTasks = [];
try {
  for (let iteration = 0; iteration < 10; iteration += 1) {
    const result = await runScenario(browser, harnessURL);
    durations.push(result.duration_ms);
    longTasks.push(...result.long_tasks);
  }
} finally {
  await browser.close();
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
}
const p95 = percentile(durations, 95);
const maxLongTask = longTasks.length === 0 ? 0 : Math.max(...longTasks);
if (p95 > 50) throw new Error(`Chromium keyed reversal p95 ${p95.toFixed(3)}ms exceeds 50ms`);
if (longTasks.length > 0 || maxLongTask > 50) throw new Error(`Chromium renderer produced ${longTasks.length} long tasks; max ${maxLongTask.toFixed(3)}ms`);
appendFileSync(options.output, `${JSON.stringify({
  id: "ui.chromium-renderer",
  gate: options.gate,
  status: "pass",
  sample_count: durations.length,
  metrics: [
    { name: "reverse_patch_p95", unit: "milliseconds", observed: p95, limit: 50, comparator: "lte" },
    { name: "long_tasks", unit: "long_tasks", observed: longTasks.length, limit: 0, comparator: "eq" },
    { name: "max_long_task", unit: "milliseconds", observed: maxLongTask, limit: 50, comparator: "lte" },
  ],
})}\n`, { mode: 0o600 });

async function runScenario(browser, harnessURL) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  try {
    await page.goto(harnessURL, { waitUntil: "load" });
    await page.waitForFunction(() =>
      (globalThis.__redevpluginMounted === true && globalThis.__redevpluginWorkerReady === true) ||
      typeof globalThis.__redevpluginError === "string",
    );
    const openingState = await page.evaluate(() => ({
      mounted: globalThis.__redevpluginMounted === true,
      workerReady: globalThis.__redevpluginWorkerReady === true,
      error: globalThis.__redevpluginError,
      calls: globalThis.__redevpluginCalls,
    }));
    if (openingState.error || !openingState.mounted || !openingState.workerReady) {
      throw new Error(`renderer opening failed: ${JSON.stringify(openingState)}; console=${consoleErrors.join(" | ")}`);
    }
    const frame = await waitForSurfaceFrame(page);
    await frame.waitForLoadState("load");
    await frame.evaluate(() => {
      globalThis.__redevpluginLongTasks = [];
      if (PerformanceObserver.supportedEntryTypes.includes("longtask")) {
        const observer = new PerformanceObserver((list) => {
          globalThis.__redevpluginLongTasks.push(...list.getEntries().map((entry) => entry.duration));
        });
        observer.observe({ type: "longtask", buffered: true });
        globalThis.__redevpluginLongTaskObserver = observer;
      }
    });
    await frame.evaluate(() => {
      globalThis.__redevpluginLongTasks.length = 0;
    });
    await page.evaluate(() => globalThis.__redevpluginTriggerVisible());
    await page.waitForFunction(() => typeof globalThis.__redevpluginReport?.duration_ms === "number");
    const report = await page.evaluate(() => globalThis.__redevpluginReport);
    await page.waitForTimeout(50);
    const observedLongTasks = await frame.evaluate(() => [...globalThis.__redevpluginLongTasks]);
    const firstKey = await frame.locator("[data-redevplugin-key]").first().getAttribute("data-redevplugin-key");
    if (firstKey !== "root") throw new Error(`renderer root key mismatch: ${firstKey}`);
    if (consoleErrors.length > 0) throw new Error(`renderer console errors: ${consoleErrors.join(" | ")}`);
    return { duration_ms: Number(report.duration_ms), long_tasks: observedLongTasks };
  } finally {
    await page.close();
  }
}

async function buildHostHarnessSource(workerContent) {
  const result = await build({
    stdin: {
      contents: `
import { PluginSurfaceHost, createReDevPluginSurfaceTransport } from "./packages/redevplugin-ui/src/surface.ts";
const digest = (character) => "sha256:" + character.repeat(64);
const workerContent = ${JSON.stringify(workerContent)};
const now = Date.now();
const preparation = {
  asset_session: "asset_session_performance_1",
  asset_session_id: "asset_session_id_performance_1",
  asset_session_nonce: "asset_session_nonce_performance_1",
  entry_path: "ui/index.html",
  entry_sha256: digest("1"),
  plugin_state_version: 1,
  revoke_epoch: 1,
  issued_at: new Date(now).toISOString(),
  expires_at: new Date(now + 600000).toISOString(),
  document: {
    schema_version: "redevplugin.opaque_surface_document.v3",
    entry_path: "ui/index.html",
    entry_sha256: digest("1"),
    title: "Renderer Performance",
    language: "en",
    direction: "ltr",
    body_html: "<main></main>",
    styles: [],
    worker: { path: "ui/performance.js", sha256: digest("2"), type: "classic", content: workerContent },
    assets: [],
    critical_bytes: workerContent.length,
  },
};
const gateway = {
  plugin_gateway_token: "gateway_performance_secret",
  plugin_gateway_token_id: "gateway_performance_1",
  asset_session: "asset_session_performance_1",
  asset_session_id: "asset_session_id_performance_1",
  issued_at: new Date(now).toISOString(),
  expires_at: new Date(now + 600000).toISOString(),
};
const fetchLike = async (input, init) => {
  const path = new URL(input, location.origin).pathname;
  const body = init.body ? JSON.parse(init.body) : {};
  (globalThis.__redevpluginCalls ||= []).push({ path, method: body.method });
  let data = {};
  if (path.endsWith("/prepare")) data = preparation;
  else if (path.endsWith("/bridge-token")) data = gateway;
  else if (path === "/_redevplugin/api/plugins/rpc") {
    if (body.method === "performance.ready") globalThis.__redevpluginWorkerReady = true;
    if (body.method === "performance.report") globalThis.__redevpluginReport = body.params;
  } else if (path.endsWith("/dispose")) data = {};
  else throw new Error("unexpected performance harness request: " + path);
  return { ok: true, status: 200, json: async () => ({ ok: true, data }) };
};
const host = PluginSurfaceHost.create({
  bootstrap: {
    pluginId: "com.example.performance",
    pluginInstanceId: "plugini_performance_1",
    pluginVersion: "1.0.0",
    surfaceId: "performance.view",
    surfaceInstanceId: "surface_performance_1",
    activeFingerprint: digest("a"),
    bridgeNonce: "bridge_nonce_performance_1",
    entryPath: "ui/index.html",
    entrySHA256: digest("1"),
    assetTicket: "asset_ticket_performance_secret",
    assetSessionNonce: "asset_session_nonce_performance_1",
    pluginStateVersion: 1,
    revokeEpoch: 1,
    runtimeGenerationId: "runtime_generation_performance_1",
  },
  bridgeChannelId: "bridge_performance_1",
  hostTransport: createReDevPluginSurfaceTransport({ fetch: fetchLike, apiBaseURL: location.origin }),
  loadTimeoutMs: 5000,
  requestTimeoutMs: 5000,
  onError: (error) => { globalThis.__redevpluginError = error.message; },
});
document.querySelector("#surface-root").append(host.element);
globalThis.__redevpluginTriggerVisible = () => host.sendLifecycle({ type: "visible" });
void host.open().then(() => { globalThis.__redevpluginMounted = true; }, (error) => { globalThis.__redevpluginError = error.message; });
`,
      resolveDir: resolve("."),
      sourcefile: "redevplugin-renderer-performance-host.ts",
      loader: "ts",
    },
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    legalComments: "none",
    write: false,
    logLevel: "silent",
  });
  if (result.outputFiles.length !== 1) throw new Error("renderer performance host bundle is missing");
  return result.outputFiles[0].text;
}

async function buildPerformanceWorkerSource(currentTree, nextTree) {
  const result = await build({
    stdin: {
      contents: `
import { PluginBridgeClient } from "./packages/redevplugin-ui/src/surface.ts";
const client = new PluginBridgeClient({ timeoutMs: 5000 });
let resolveVisible;
const visible = new Promise((resolve) => { resolveVisible = resolve; });
client.onLifecycle((event) => {
  if (event.type === "visible") resolveVisible();
});
void (async () => {
  await client.ready();
  await client.render(${JSON.stringify(currentTree)});
  void client.call("performance.ready", {}).catch(() => undefined);
  await visible;
  const startedAt = performance.now();
  await client.render(${JSON.stringify(nextTree)});
  void client.call("performance.report", { duration_ms: performance.now() - startedAt }).catch(() => undefined);
})();
`,
      resolveDir: resolve("."),
      sourcefile: "redevplugin-renderer-performance-worker.ts",
      loader: "ts",
    },
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    legalComments: "none",
    write: false,
    logLevel: "silent",
  });
  if (result.outputFiles.length !== 1) throw new Error("renderer performance worker bundle is missing");
  return result.outputFiles[0].text;
}

async function waitForSurfaceFrame(page) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
    if (frame && await frame.title().catch(() => "")) return frame;
    await page.waitForTimeout(10);
  }
  throw new Error("opaque renderer frame did not load");
}

function percentile(values, target) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.max(0, Math.ceil(ordered.length * target / 100) - 1)] ?? Infinity;
}

function parseArgs(args) {
  let output = "";
  let gate = "full";
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--output") output = args[++index] ?? "";
    else if (args[index] === "--gate") gate = args[++index] ?? "";
    else throw new Error(`unknown argument: ${args[index]}`);
  }
  if (!output) throw new Error("--output is required");
  if (!["weekly", "full", "release"].includes(gate)) throw new Error(`invalid renderer gate: ${gate}`);
  return { output, gate };
}
