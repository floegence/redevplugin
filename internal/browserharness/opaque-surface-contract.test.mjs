import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";
import { isExpectedSandboxConsoleLine } from "./smoke-console-policy.mjs";

test("browser harness exposes one same-origin opaque surface transport", async (t) => {
  const harness = createBrowserHarnessServer({ prepareDelayMs: 1, assetDelayMs: 1 });
  const address = await harness.listen(0);
  t.after(() => harness.close());
  const baseURL = `http://127.0.0.1:${address.port}`;

  const openResponse = await fetch(`${baseURL}/_redevplugin/api/plugins/surfaces/open`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ plugin_instance_id: "plugin_browser_harness_1", surface_id: "dev.redevplugin.opaque-browser.view" }),
  });
  assert.equal(openResponse.status, 200);
  assert.equal(openResponse.headers.get("cache-control"), "no-store");
  assert.equal(openResponse.headers.has("access-control-allow-origin"), false);
  const opened = (await openResponse.json()).data;
  assert.equal(opened.entry_path, "ui/index.html");
  assert.match(opened.entry_sha256, /^sha256:[0-9a-f]{64}$/);

  const prepareResponse = await fetch(`${baseURL}/_redevplugin/api/plugins/surfaces/${opened.surface_instance_id}/prepare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset_ticket: opened.asset_ticket }),
  });
  const prepared = (await prepareResponse.json()).data;
  assert.equal(prepared.document.schema_version, "redevplugin.opaque_surface_document.v2");
  assert.equal(prepared.document.worker.type, "classic");
  assert.equal(prepared.document.assets.length, 1);
  assert.deepEqual(prepared.document.assets[0].logical_ids, ["harness.lazy-image"]);
  assert.equal(Buffer.byteLength(JSON.stringify(prepared.document)) > 256 * 1024, true);
  assert.equal(JSON.stringify(prepared.document).includes(opened.asset_ticket), false);

  const assetResponse = await fetch(`${baseURL}/_redevplugin/api/plugins/surfaces/${opened.surface_instance_id}/assets/read`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      asset_session: prepared.asset_session,
      asset_session_id: prepared.asset_session_id,
      binding_id: prepared.document.assets[0].binding_id,
    }),
  });
  assert.equal(assetResponse.status, 200);
  assert.equal(assetResponse.url.includes("asset_session"), false);
  assert.equal(assetResponse.url.includes("ticket"), false);
  const assetEnvelope = await assetResponse.json();
  assert.equal(assetEnvelope.data.content_base64.length > 256 * 1024, true);
});

test("browser host delegates sandbox construction to PluginSurfaceHost", async () => {
  const html = await readFile(new URL("../../testdata/browser-harness/opaque-surface/index.html", import.meta.url), "utf8");
  assert.match(html, /id="plugin-surface-mount"/);
  assert.doesNotMatch(html, /<iframe/);
  assert.doesNotMatch(html, /allow-same-origin/);
  assert.doesNotMatch(html, /plugin_origin|parent_origin|sandbox_origin/);

  const host = await readFile(new URL("../../testdata/browser-harness/opaque-surface/host.mjs", import.meta.url), "utf8");
  for (const expected of [
    "PluginSurfaceHost",
    "PluginSurfaceHost.create",
    "createReDevPluginSurfaceTransport",
    "surfaceHost.element",
    "surfaceHost.open()",
    "surfaceHost.close()",
    "credentiallessScenario",
  ]) {
    assert.match(host, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const forbidden of [
    "iframeOrigin",
    "parentOrigin",
    "plugin_origin",
    "allow-same-origin",
    "window.postMessage",
    "asset_ticket=",
    "stream_ticket=",
    "new PluginSurfaceHost",
    "frameForScenario",
  ]) {
    assert.equal(host.includes(forbidden), false, `host script retained ${forbidden}`);
  }
});

test("the trusted worker wrapper owns the direct dynamic-import gate", async () => {
  const probe = await readFile(new URL("../../testdata/browser-harness/opaque-surface/worker-security-probe.ts", import.meta.url), "utf8");
  assert.doesNotMatch(probe, /\bimport\s*\(/);
  assert.doesNotMatch(probe, /AsyncFunction|new Function/);

  const surface = await readFile(new URL("../../packages/redevplugin-ui/src/surface.ts", import.meta.url), "utf8");
  assert.match(surface, /await import\(specifier\)/);
  assert.match(surface, /Dynamic import escaped the ReDevPlugin worker sandbox/);

  const worker = await readFile(new URL("../../testdata/browser-harness/opaque-surface/plugin-worker.ts", import.meta.url), "utf8");
  assert.match(worker, /runWorkerSecurityProbe/);
  assert.match(worker, /\.\/worker-security-probe\.js/);
});

test("browser smoke accepts only known sandbox console evidence", () => {
  assert.equal(isExpectedSandboxConsoleLine("warning: Unrecognized feature: 'bluetooth'."), true);
  assert.equal(isExpectedSandboxConsoleLine("warning: Unrecognized feature: 'camera'."), false);
  assert.equal(isExpectedSandboxConsoleLine("error: violates the following Content Security Policy directive"), true);
  assert.equal(isExpectedSandboxConsoleLine("error: unexpected plugin failure"), false);
});
