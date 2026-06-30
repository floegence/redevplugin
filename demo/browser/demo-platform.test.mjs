import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createDemoPlatformFetch, demoBootstrap } from "./demo-platform.mjs";

test("demo platform mints bridge token and handles rpc calls", async () => {
  const platform = createDemoPlatformFetch();
  const tokenResponse = await platform.fetch(`/_redeven_proxy/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: { surface_instance_id: demoBootstrap.surfaceInstanceId } }),
  });
  assert.equal(tokenResponse.status, 200);
  assert.equal((await tokenResponse.json()).data.plugin_gateway_token, "gateway_token_parent_only_demo");

  const echoResponse = await platform.fetch("/_redeven_proxy/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      method: "demo.echo",
      params: { message: "ok" },
    }),
  });
  assert.deepEqual((await echoResponse.json()).data.data.echoed, "ok");
});

test("demo platform requires confirmation before cache deletion", async () => {
  const platform = createDemoPlatformFetch();
  await platform.fetch(`/_redeven_proxy/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });
  const denied = await platform.fetch("/_redeven_proxy/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      method: "demo.cache.delete",
      params: { path: "workspace/cache/index.sqlite" },
    }),
  });
  const deniedBody = await denied.json();
  assert.equal(deniedBody.ok, false);
  assert.equal(deniedBody.error_code, "PLUGIN_CONFIRMATION_REQUIRED");

  const confirmation = await platform.fetch("/_redeven_proxy/api/plugins/confirm", {
    method: "POST",
    headers: {},
    body: JSON.stringify({ method: "demo.cache.delete" }),
  });
  const token = (await confirmation.json()).data.confirmation_token;
  const approved = await platform.fetch("/_redeven_proxy/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      confirmation_token: token,
      method: "demo.cache.delete",
      params: { path: "workspace/cache/index.sqlite" },
    }),
  });
  assert.equal((await approved.json()).data.data.deleted, true);
});

test("demo host embeds a sandboxed iframe", async () => {
  const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
  assert.match(html, /sandbox="allow-scripts allow-same-origin"/);
  assert.match(html, /src="about:blank"/);

  const hostScript = await readFile(new URL("./host.mjs", import.meta.url), "utf8");
  assert.match(hostScript, /plugin_origin/);
  assert.match(hostScript, /iframeOrigin: pluginURL\.origin/);

  const pluginScript = await readFile(new URL("./plugin.mjs", import.meta.url), "utf8");
  assert.match(pluginScript, /parent_origin/);
  assert.match(pluginScript, /parentOrigin/);
});
