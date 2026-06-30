import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createDemoPlatformFetch, createMemoryPersistence, demoBootstrap } from "./demo-platform.mjs";

test("demo platform mints bridge token and handles rpc calls", async () => {
  const platform = createDemoPlatformFetch();
  const tokenResponse = await platform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: { surface_instance_id: demoBootstrap.surfaceInstanceId } }),
  });
  assert.equal(tokenResponse.status, 200);
  assert.equal((await tokenResponse.json()).data.plugin_gateway_token, "gateway_token_parent_only_demo");

  const echoResponse = await platform.fetch("/_redevplugin/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      method: "demo.echo",
      params: { message: "ok" },
    }),
  });
  assert.deepEqual((await echoResponse.json()).data.data.echoed, "ok");

  const streamResponse = await platform.fetch("/_redevplugin/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      method: "demo.logs.tail",
      params: { source: "demo" },
    }),
  });
  const streamBody = await streamResponse.json();
  assert.equal(streamBody.data.stream_id, "demo_stream_logs");
  assert.match(streamBody.data.stream_ticket, /^demo_stream_ticket_/);
});

test("demo platform requires confirmation before cache deletion", async () => {
  const platform = createDemoPlatformFetch();
  await platform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });
  const denied = await platform.fetch("/_redevplugin/api/plugins/rpc", {
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

  const confirmation = await platform.fetch("/_redevplugin/api/plugins/confirm", {
    method: "POST",
    headers: {},
    body: JSON.stringify({ method: "demo.cache.delete" }),
  });
  const token = (await confirmation.json()).data.confirmation_token;
  const approved = await platform.fetch("/_redevplugin/api/plugins/rpc", {
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
  assert.match(html, /demo-picker/);
  assert.match(html, /platform-client-status/);

  const hostScript = await readFile(new URL("./host.mjs", import.meta.url), "utf8");
  assert.match(hostScript, /PluginPlatformClient/);
  assert.match(hostScript, /plugin_origin/);
  assert.match(hostScript, /iframeOrigin: pluginURL\.origin/);
  assert.match(hostScript, /Bouncer game/);
  assert.match(hostScript, /Schedule planner/);
  assert.match(hostScript, /Weather console/);

  const pluginScript = await readFile(new URL("./plugin.mjs", import.meta.url), "utf8");
  assert.match(pluginScript, /parent_origin/);
  assert.match(pluginScript, /parentOrigin/);
});

test("demo platform exposes host management settings endpoints", async () => {
  const platform = createDemoPlatformFetch();
  const schemaResponse = await platform.fetch("/_redevplugin/api/plugins/plugini_demo_1/settings/schema", {
    method: "GET",
    headers: {},
  });
  const schema = await schemaResponse.json();
  assert.equal(schema.data.plugin_instance_id, "plugini_demo_1");
  assert.equal(schema.data.fields[0].key, "accent_mode");

  const patchedResponse = await platform.fetch("/_redevplugin/api/plugins/plugini_demo_1/settings", {
    method: "PATCH",
    headers: {},
    body: JSON.stringify({ values: { accent_mode: "indigo", telemetry_enabled: true } }),
  });
  const patched = await patchedResponse.json();
  assert.equal(patched.data.values.accent_mode, "indigo");
  assert.equal(patched.data.values.telemetry_enabled, true);

  const currentResponse = await platform.fetch("/_redevplugin/api/plugins/plugini_demo_1/settings", {
    method: "GET",
    headers: {},
  });
  const current = await currentResponse.json();
  assert.equal(current.data.settings_revision, 2);
  assert.equal(current.data.values.accent_mode, "indigo");
});

test("rich demo plugins exercise game, storage, and network methods", async () => {
  const platform = createDemoPlatformFetch();
  await platform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });

  const score = await rpc(platform, "game.score.save", { score: 42 });
  assert.equal(score.data.data.best_score, 42);
  assert.equal(score.data.data.leaderboard.length, 3);
  assert.equal(score.data.data.achievements.includes("score-sprinter"), false);
  const snapshot = await rpc(platform, "game.snapshot.save", { score: 52, level: 2, energy: 88 });
  assert.equal(snapshot.data.data.storage_key, "game/snapshots");
  assert.equal(snapshot.data.data.snapshots[0].score, 52);
  const loadedSnapshot = await rpc(platform, "game.snapshot.load", {});
  assert.equal(loadedSnapshot.data.data.snapshot.level, 2);

  const brokeredWorker = await rpc(platform, "worker.brokerDemo", { note: "generated plugin broker smoke" });
  assert.equal(brokeredWorker.data.data.method, "worker.brokerDemo");
  assert.equal(brokeredWorker.data.data.storage_file.executor, "host storage broker");
  assert.equal(brokeredWorker.data.data.storage_file.path, "notes/generated-broker-demo.txt");
  assert.equal(brokeredWorker.data.data.network_execute.executor, "host-network-executor");
  assert.equal(brokeredWorker.data.data.network_execute.transport, "http");

  const initial = await rpc(platform, "schedule.items.list", {});
  assert.equal(initial.data.data.items.length, 3);
  assert.equal(initial.data.data.storage.engine, "sqlite-demo");
  assert.equal(initial.data.data.timeline.length, 3);
  const added = await rpc(platform, "schedule.item.add", {
    title: "Write browser demo",
    date: "2026-06-30",
    time: "16:30",
    tag: "qa",
  });
  assert.equal(added.data.data.persisted, true);
  assert.equal(added.data.data.items.length, 4);
  assert.equal(added.data.data.storage.revision, 2);
  assert.equal(added.data.data.journal[0].action, "add");
  const seeded = await rpc(platform, "schedule.items.seedWeek", { view: { status: "all" } });
  assert.equal(seeded.data.data.added, 5);
  assert.equal(seeded.data.data.storage.records, 9);
  assert.equal(seeded.data.data.journal[0].action, "seed_week");
  const archived = await rpc(platform, "schedule.items.archiveDone", { view: { status: "all" } });
  assert.equal(archived.data.data.archived, 1);
  assert.equal(archived.data.data.storage.records, 8);
  assert.equal(archived.data.data.journal[0].action, "archive_done");

  const saved = await rpc(platform, "weather.location.save", { location: "Shanghai" });
  assert.equal(saved.data.data.location, "Shanghai");
  const weather = await rpc(platform, "weather.fetch", { location: "Shanghai" });
  assert.equal(weather.data.data.current.condition, "Warm evening haze");
  assert.equal(weather.data.data.network.transport, "http");
  assert.equal(weather.data.data.network.response_status, 200);
  assert.equal(weather.data.data.network.upstream_mode, "in-memory fixture");
  assert.equal(JSON.parse(weather.data.data.raw_response_body).location, "Shanghai");
  assert.equal(weather.data.data.parser.format, "json");
  assert.equal(weather.data.data.hourly.length, 4);
  assert.equal(weather.data.data.air_quality.category, "good");
  assert.equal(weather.data.data.alerts.length, 0);
  assert.equal(weather.data.data.network_history.length, 1);

  for (const filename of [
    "./plugins/bouncer.html",
    "./plugins/bouncer.mjs",
    "./plugins/schedule.html",
    "./plugins/schedule.mjs",
    "./plugins/weather.html",
    "./plugins/weather.mjs",
  ]) {
    const source = await readFile(new URL(filename, import.meta.url), "utf8");
    assert.match(source, /PluginBridgeClient|plugin-status|game-canvas|schedule-form|weather-form/);
  }
});

test("weather demo can fetch raw data through a host HTTP network broker", async () => {
  const requestedURLs = [];
  const platform = createDemoPlatformFetch({
    networkBaseURL: "http://127.0.0.1:43000",
    networkFetch: async (url, init) => {
      requestedURLs.push({ url, headers: init.headers });
      return {
        status: 200,
        headers: new Map([
          ["content-type", "application/json; charset=utf-8"],
          ["x-demo-weather-fetch", "miss"],
        ]),
        async text() {
          return JSON.stringify({
            location: "Tokyo",
            current: {
              temperature_c: 28,
              condition: "Humid cloud breaks",
              wind_kph: 12,
              humidity_percent: 74,
              pressure_hpa: 1008,
              uv_index: 6,
            },
            hourly: [{ hour: "09:00", temperature_c: 26, condition: "Humid cloud breaks", wind_kph: 12 }],
            forecast: [{ day: "D+0", high_c: 30, low_c: 24, condition: "Humid cloud breaks", precipitation_percent: 42 }],
          });
        },
      };
    },
  });
  await platform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });

  const weather = await rpc(platform, "weather.fetch", { location: "Tokyo" });

  assert.equal(requestedURLs.length, 1);
  assert.match(requestedURLs[0].url, /^http:\/\/127\.0\.0\.1:43000\/demo\/weather-api\/v1\/forecast\?/);
  assert.equal(requestedURLs[0].headers["x-redevplugin-connector"], "weather_api");
  assert.equal(weather.data.data.current.condition, "Humid cloud breaks");
  assert.equal(weather.data.data.network.upstream_mode, "host http fetch");
  assert.match(weather.data.data.network.broker_endpoint, /\/demo\/weather-api\/v1\/forecast/);
  assert.equal(weather.data.data.network.response_headers["content-type"], "application/json; charset=utf-8");
  assert.equal(JSON.parse(weather.data.data.raw_response_body).location, "Tokyo");
});

test("demo platform persists plugin storage through host persistence adapter", async () => {
  const persistence = createMemoryPersistence();
  const firstPlatform = createDemoPlatformFetch({ persistence });
  await firstPlatform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });

  const added = await rpc(firstPlatform, "schedule.item.add", {
    title: "Persist across host reload",
    date: "2026-07-02",
    time: "12:20",
    tag: "storage",
    duration_minutes: 35,
  });
  assert.equal(added.data.data.persisted, true);
  assert.equal(added.data.data.source, "host storage broker");

  const secondPlatform = createDemoPlatformFetch({ persistence });
  await secondPlatform.fetch(`/_redevplugin/api/plugins/surfaces/${demoBootstrap.surfaceInstanceId}/bridge-token`, {
    method: "POST",
    headers: {},
    body: JSON.stringify({ handshake: {} }),
  });
  const reloaded = await rpc(secondPlatform, "schedule.items.list", { query: "persist across" });
  assert.equal(reloaded.data.data.items.length, 1);
  assert.equal(reloaded.data.data.items[0].title, "Persist across host reload");
  assert.equal(reloaded.data.data.source, "host storage broker");
});

test("generated browser demo uses complete dev lifecycle and cleanup", async () => {
  const launcher = await readFile(new URL("./generated-demo.mjs", import.meta.url), "utf8");
  for (const expected of [
    "\"scaffold\"",
    "\"package\"",
    "\"dev-install\"",
    "\"dev-enable\"",
    "\"dev-open\"",
    "\"dev-disable\"",
    "\"dev-uninstall\"",
    "\"--delete-data\"",
  ]) {
    assert.match(launcher, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(launcher, /EXTRA_PLUGIN_ROOT/);
  assert.match(launcher, /plugin_path", "\/generated-plugin\/ui\/index\.html"/);
  assert.match(launcher, /Press Ctrl\+C to disable, uninstall, delete plugin data/);
});

async function rpc(platform, method, params) {
  const response = await platform.fetch("/_redevplugin/api/plugins/rpc", {
    method: "POST",
    headers: {},
    body: JSON.stringify({
      plugin_gateway_token: "gateway_token_parent_only_demo",
      method,
      params,
    }),
  });
  return response.json();
}

test("real runtime demo launcher starts real host and cleans temporary state", async () => {
  const packageConfig = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.match(packageConfig.scripts["demo:browser:real"], /node demo\/browser\/real-demo\.mjs/);

  const launcher = await readFile(new URL("./real-demo.mjs", import.meta.url), "utf8");
  for (const expected of [
    "\"demo-real-server\"",
    "\"redevplugin-runtime\"",
    "\"go\", [\"build\", \"-o\", filename, \"./cmd/redevplugin\"]",
    "app.redevplugin.localhost",
    "plg-real.redevplugin.localhost",
    "Sandbox origin:",
    "Press Ctrl+C to stop the demo server and delete the temporary demo state.",
  ]) {
    assert.match(launcher, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(launcher, /mkdtemp\(join\(tmpdir\(\), "redevplugin-real-demo-"\)\)/);
  assert.match(launcher, /mkdtemp\(join\(tmpdir\(\), "redevplugin-real-demo-bin-"\)\)/);
  assert.match(launcher, /rm\(stateRoot, \{ recursive: true, force: true \}\)/);
  assert.match(launcher, /rm\(binRoot, \{ recursive: true, force: true \}\)/);
});
