import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PluginBridgeError,
  PluginPlatformClient,
  PluginSurfaceHost,
  PluginSurfaceReloadLimiter,
  createReDevPluginSurfaceTransport,
  createPluginSurfaceScope,
  type FetchInitLike,
  type FetchLike,
  type FetchResponseLike,
  type MessageChannelLike,
  type MessageEventLike,
  type MessagePortLike,
  type PluginSurfaceHostOptions,
} from "../src/trusted-parent.js";
import { PluginBridgeClient } from "../src/plugin.js";
import { createOpaquePluginBootstrapHTML, decodePluginStreamText } from "../src/surface.js";
import { PluginLocalImportClient } from "../src/local-import.js";

class FakePort implements MessagePortLike {
  peer?: FakePort;
  sent: unknown[] = [];
  postError?: Error;
  #listeners = new Set<(event: MessageEventLike) => void>();
  closed = false;

  postMessage(message: unknown): void {
    if (this.postError) throw this.postError;
    if (this.closed) throw new Error("port is closed");
    this.sent.push(message);
    queueMicrotask(() => this.peer?.emit(message));
  }

  addEventListener(_type: "message", listener: (event: MessageEventLike) => void): void {
    this.#listeners.add(listener);
  }

  removeEventListener(_type: "message", listener: (event: MessageEventLike) => void): void {
    this.#listeners.delete(listener);
  }

  start(): void {}

  close(): void {
    this.closed = true;
    this.#listeners.clear();
  }

  emit(data: unknown): void {
    for (const listener of this.#listeners) listener({ origin: "null", data });
  }
}

function fakeChannel(): { port1: FakePort; port2: FakePort } {
  const port1 = new FakePort();
  const port2 = new FakePort();
  port1.peer = port2;
  port2.peer = port1;
  return { port1, port2 };
}

class FakeFrame {
  srcdoc = "";
  credentialless = false;
  attributes = new Map<string, string>();
  transferred: Array<{ message: unknown; targetOrigin: string; ports: MessagePortLike[] }> = [];
  autoAcknowledge = true;
  #listeners = new Set<() => void>();
  contentWindow = {
    postMessage: (message: unknown, targetOrigin: string, ports?: MessagePortLike[]) => {
      this.transferred.push({ message, targetOrigin, ports: ports ?? [] });
      if (this.autoAcknowledge && isSurfacePortEnvelope(message) && ports?.[0]) {
        queueMicrotask(() => ports[0]?.postMessage({
          type: "redevplugin.surface.port_ack",
          frame_generation_id: message.frame_generation_id,
        }));
      }
    },
  };

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  addEventListener(_type: "load", listener: () => void): void {
    this.#listeners.add(listener);
  }

  removeEventListener(_type: "load", listener: () => void): void {
    this.#listeners.delete(listener);
  }

  load(): void {
    for (const listener of this.#listeners) listener();
  }
}

class FakeFrameWithoutCredentialless {
  srcdoc = "";
  attributes = new Map<string, string>();
  transferred: Array<{ message: unknown; targetOrigin: string; ports: MessagePortLike[] }> = [];
  autoAcknowledge = true;
  #listeners = new Set<() => void>();
  contentWindow = {
    postMessage: (message: unknown, targetOrigin: string, ports?: MessagePortLike[]) => {
      this.transferred.push({ message, targetOrigin, ports: ports ?? [] });
      if (this.autoAcknowledge && isSurfacePortEnvelope(message) && ports?.[0]) {
        queueMicrotask(() => ports[0]?.postMessage({
          type: "redevplugin.surface.port_ack",
          frame_generation_id: message.frame_generation_id,
        }));
      }
    },
  };
  setAttribute(name: string, value: string): void { this.attributes.set(name, value); }
  addEventListener(_type: "load", listener: () => void): void { this.#listeners.add(listener); }
  removeEventListener(_type: "load", listener: () => void): void { this.#listeners.delete(listener); }
  load(): void { for (const listener of this.#listeners) listener(); }
}

function createSurfaceHost(
  frame: FakeFrame | FakeFrameWithoutCredentialless,
  options: PluginSurfaceHostOptions & { testMessageChannel?: MessageChannelLike },
): PluginSurfaceHost {
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const previousMessageChannel = Object.getOwnPropertyDescriptor(globalThis, "MessageChannel");
  const { testMessageChannel, ...hostOptions } = options;
  let createdFrames = 0;
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      createElement(tagName: string) {
        assert.equal(tagName, "iframe");
        createdFrames += 1;
        return frame;
      },
    },
  });
  if (testMessageChannel) {
    const channel = testMessageChannel;
    Object.defineProperty(globalThis, "MessageChannel", {
      configurable: true,
      value: class {
        readonly port1 = channel.port1;
        readonly port2 = channel.port2;
      },
    });
  }
  try {
    const host = PluginSurfaceHost.create(hostOptions);
    assert.equal(host.element, frame);
    assert.equal(createdFrames, 1);
    assert.equal(frame.attributes.get("src"), "about:blank");
    assert.equal(frame.attributes.get("sandbox"), "allow-scripts");
    assert.equal(frame.attributes.get("allow"), deniedPermissionsPolicy);
    assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
    return host;
  } finally {
    if (previousDocument) {
      Object.defineProperty(globalThis, "document", previousDocument);
    } else {
      Reflect.deleteProperty(globalThis, "document");
    }
    if (previousMessageChannel) {
      Object.defineProperty(globalThis, "MessageChannel", previousMessageChannel);
    } else {
      Reflect.deleteProperty(globalThis, "MessageChannel");
    }
  }
}

function isSurfacePortEnvelope(value: unknown): value is { type: "redevplugin.surface.port"; frame_generation_id: string } {
  return value !== null && typeof value === "object" &&
    (value as { type?: unknown }).type === "redevplugin.surface.port" &&
    typeof (value as { frame_generation_id?: unknown }).frame_generation_id === "string";
}

class FakeFetch {
  calls: Array<{ input: string; init: FetchInitLike }> = [];
  responses: Array<
    | { status: number; body: unknown }
    | ((input: string, init: FetchInitLike) => Promise<FetchResponseLike>)
  > = [];

  fetch: FetchLike = async (input, init) => {
    this.calls.push({ input, init });
    const next = this.responses.shift();
    if (!next) throw new Error(`missing fake response for ${input}`);
    if (typeof next === "function") return next(input, init);
    return {
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      json: async () => next.body,
    } satisfies FetchResponseLike;
  };

  push(data: unknown, status = 200): void {
    this.responses.push({ status, body: status >= 200 && status < 300 ? { ok: true, data } : data });
  }

  pushHandler(handler: (input: string, init: FetchInitLike) => Promise<FetchResponseLike>): void {
    this.responses.push(handler);
  }
}

const digest = (value: string): string => `sha256:${value.repeat(64)}`;
const deniedPermissionsPolicy = "accelerometer 'none'; autoplay 'none'; bluetooth 'none'; camera 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; encrypted-media 'none'; fullscreen 'none'; gamepad 'none'; geolocation 'none'; gyroscope 'none'; hid 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; screen-wake-lock 'none'; serial 'none'; usb 'none'; xr-spatial-tracking 'none'";

const hostBootstrap = {
  pluginId: "com.example.plugin",
  pluginInstanceId: "plugin_instance_1",
  pluginVersion: "1.0.0",
  surfaceId: "example.view",
  surfaceInstanceId: "surface_1",
  activeFingerprint: digest("a"),
  bridgeNonce: "bridge_nonce_1",
  entryPath: "ui/index.html",
  entrySHA256: digest("b"),
  assetTicket: "asset_ticket_secret",
  assetSessionNonce: "asset_session_nonce_1",
  pluginStateVersion: 7,
  revokeEpoch: 3,
  runtimeGenerationId: "runtime_gen_1",
};

test("surface host construction cannot bypass the SDK factory", () => {
  const UnsafeSurfaceHost = PluginSurfaceHost as unknown as new () => PluginSurfaceHost;
  assert.throws(
    () => new UnsafeSurfaceHost(),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

function preparation() {
  return {
    asset_session: "asset_session_secret",
    asset_session_id: "asset_session_id_1",
    asset_session_nonce: "asset_session_nonce_1",
    entry_path: "ui/index.html",
    entry_sha256: digest("b"),
    plugin_state_version: 7,
    revoke_epoch: 3,
    issued_at: "2026-07-12T00:00:00Z",
    expires_at: "2026-07-12T00:10:00Z",
    document: {
      schema_version: "redevplugin.opaque_surface_document.v1",
      entry_path: "ui/index.html",
      entry_sha256: digest("b"),
      title: "Plugin",
      language: "en",
      direction: "ltr",
      body_html: '<main><button data-redevplugin-action="refresh">Refresh</button><img data-redevplugin-asset-binding="asset_12345678" data-redevplugin-asset-attr="src" alt="Status"></main>',
      styles: [{ path: "ui/app.css", sha256: digest("c"), content: ":root{color:#111}" }],
      worker: { path: "ui/app.js", sha256: digest("d"), type: "classic", content: "const client = new globalThis.PluginBridgeClient(); void client.ready();" },
      assets: [{ binding_id: "asset_12345678", path: "ui/status.png", sha256: digest("e"), size: 8, content_type: "image/png" }],
      critical_bytes: 512,
    },
  };
}

function gatewayLease(overrides: Record<string, unknown> = {}) {
  const issuedAt = new Date();
  return {
    plugin_gateway_token: "gateway_secret",
    plugin_gateway_token_id: "gateway_token_1",
    asset_session: "asset_session_rotated_1",
    asset_session_id: "asset_session_id_rotated_1",
    issued_at: issuedAt.toISOString(),
    expires_at: new Date(issuedAt.getTime() + 10 * 60_000).toISOString(),
    ...overrides,
  };
}

test("opaque bootstrap runs only the trusted renderer and creates a hardened worker", () => {
  const html = createOpaquePluginBootstrapHTML({ scriptNonce: "nonce_test" });
  for (const directive of [
    "default-src 'none'",
    "script-src 'nonce-nonce_test'",
    "style-src 'nonce-nonce_test'",
    "connect-src 'none'",
    "worker-src blob:",
    "form-action 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ]) {
    assert.equal(html.includes(directive), true, `missing CSP directive ${directive}`);
  }
  assert.equal(html.includes("allow-same-origin"), false);
  assert.equal(html.includes("new Worker(url, { name: \"redevplugin-surface\" })"), true);
  assert.equal(html.includes("type: \"module\""), false);
  assert.equal(html.includes("claim() { if (__rpClaimed) return undefined"), true);
  assert.equal(html.includes("event.ports.length !== 2"), true);
  assert.equal(html.includes("__rpControlPort"), true);
  assert.equal(html.includes('port_roles.join(",") !== "runtime_control,plugin_bridge"'), true);
  assert.equal(html.includes("indexedDB:undefined"), true);
  assert.equal(html.includes("WebSocket:undefined"), true);
  assert.equal(html.includes("__rpSealChain"), true);
  assert.equal(html.includes("Object.getOwnPropertyDescriptor"), true);
  assert.equal(html.includes("sendBeacon:undefined"), true);
  assert.equal(html.includes("__rpControlPost"), true);
  assert.equal(html.includes("__rpSealMessagePortMethod"), true);
  assert.equal(html.includes("maxConcurrentAssetReads = 4"), true);
  assert.equal(html.includes("plugin asset response did not match the prepared document"), true);
  assert.equal(html.includes("plugin asset response failed renderer validation"), true);
  assert.equal(html.includes("message.content_type !== asset.content_type"), true);
  assert.equal(html.includes('crypto.subtle.digest("SHA-256"'), true);
  assert.equal(html.includes("plugin asset bytes failed SHA-256 verification"), true);
  assert.equal(html.includes("surfaceDocument.worker.content"), true);
  assert.equal(html.includes(hostBootstrap.pluginId), false);
  assert.equal(html.includes(hostBootstrap.bridgeNonce), false);
  assert.equal(html.includes(hostBootstrap.assetTicket), false);
  const script = html.match(/<script nonce="nonce_test">([\s\S]*)<\/script>/)?.[1];
  assert.equal(typeof script, "string");
  assert.equal(typeof new Function(script!), "function");
});

test("surface host rejects zero-valued revision bindings", () => {
  for (const invalid of [
    { ...hostBootstrap, pluginStateVersion: 0 },
    { ...hostBootstrap, revokeEpoch: 0 },
  ]) {
    assert.throws(
      () => createSurfaceHost(new FakeFrame(), {
        bootstrap: invalid,
        hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
      }),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
  }
});

test("surface host rejects unknown fields in the closed preparation document", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const invalid = preparation();
  (invalid.document as unknown as Record<string, unknown>).asset_ticket = "must-not-enter-iframe";
  fetch.push(invalid);
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  const opening = host.open();
  frame.load();
  await assert.rejects(
    opening,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.equal(frame.srcdoc, "");
});

test("surface host rejects caller-crafted transports", () => {
  assert.throws(
    () => createSurfaceHost(new FakeFrame(), {
      bootstrap: hostBootstrap,
      hostTransport: {} as never,
    }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

test("surface transport accepts only safe same-origin API bases before any fetch", () => {
  const fetch = new FakeFetch();
  withLocationOrigin("https://host.example", () => {
    for (const apiBaseURL of [
      "https://attacker.example",
      "https://user@host.example",
      "https://host.example/base?token=1",
      "https://host.example/base#fragment",
      "/../escape",
      "/%2e%2e/escape",
      "//attacker.example/base",
      "/base\\escape",
    ]) {
      assert.throws(
        () => createReDevPluginSurfaceTransport({ fetch: fetch.fetch, apiBaseURL }),
        (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
        apiBaseURL,
      );
    }

    createReDevPluginSurfaceTransport({ fetch: fetch.fetch });
    createReDevPluginSurfaceTransport({ fetch: fetch.fetch, apiBaseURL: "/plugin-api/" });
    createReDevPluginSurfaceTransport({ fetch: fetch.fetch, apiBaseURL: "https://host.example/plugin-api/" });
  });
  assert.equal(fetch.calls.length, 0);
});

test("plugin bridge client exposes only a public handle and its private port", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });

  const ready = client.ready();
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await ready;

  const callPromise = client.call<{ pong: true }>("echo.ping", { value: 1 });
  assert.deepEqual(pluginPort.sent[0], {
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "echo.ping", params: { value: 1 } },
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_1", ok: true, data: { pong: true } });
  assert.deepEqual(await callPromise, { pong: true });

  const renderPromise = client.render({ type: "element", tag: "main", children: ["Ready"] });
  assert.deepEqual(pluginPort.sent[1], {
    type: "redevplugin.ui.render",
    id: "render_2",
    tree: { type: "element", tag: "main", children: ["Ready"] },
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await renderPromise;

  const streamPromise = client.readStream("stream_12345678");
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "stream_3",
    ok: true,
    data: [{ stream_id: "stream_1", sequence: 1, kind: "data", data: "b2s=", at: "2026-07-12T00:00:00Z" }],
  });
  const events = await streamPromise;
  assert.equal(decodePluginStreamText(events[0]!), "ok");
  client.dispose();
  assert.equal(pluginPort.closed, true);
});

test("plugin bridge client rejects non-JSON structured-clone payloads before posting", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 10 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  for (const params of [
    { value: new ArrayBuffer(1024) },
    { value: new Map([["unexpected", true]]) },
  ]) {
    const sentBefore = pluginPort.sent.length;
    assert.throws(
      () => {
        void client.call("echo.invalid", params as never).catch(() => undefined);
      },
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
    );
    assert.equal(pluginPort.sent.length, sentBefore);
  }
  client.dispose();
});

test("plugin bridge client rejects non-canonical render trees before posting", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 10 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const sentBefore = pluginPort.sent.length;
  assert.throws(
    () => {
      void client.render({ type: "element", tag: "main", children: [undefined] } as never);
    },
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  assert.equal(pluginPort.sent.length, sentBefore);
  client.dispose();
});

test("plugin bridge client clears pending requests when postMessage fails synchronously", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  pluginPort.postError = new Error("post failed");
  for (let index = 0; index < 256; index += 1) {
    await assert.rejects(
      client.call("echo.closed"),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
    );
  }

  pluginPort.postError = undefined;
  const recovered = client.call("echo.recovered");
  assert.deepEqual(pluginPort.sent.at(-1), {
    type: "redevplugin.bridge.call",
    request: { id: "rpc_257", method: "echo.recovered" },
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_257", ok: true, data: { ok: true } });
  assert.deepEqual(await recovered, { ok: true });
  client.dispose();
});

test("plugin bridge timeout sends one cancel and rejects replayed late responses", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 10 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const call = client.call("echo.slow", { value: 1 });
  await assert.rejects(
    call,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_TIMEOUT",
  );
  assert.deepEqual(pluginPort.sent[1], { type: "redevplugin.bridge.cancel", id: "rpc_1" });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_1", ok: true, data: { late: true } });

  const next = client.call("echo.fast");
  assert.deepEqual(pluginPort.sent[2], {
    type: "redevplugin.bridge.call",
    request: { id: "rpc_2", method: "echo.fast" },
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_2", ok: true, data: { ok: true } });
  assert.deepEqual(await next, { ok: true });
  client.dispose();
});

test("surface host transfers one secret-free wildcard port and waits for paint, worker, and token", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  let settled = false;
  const opening = host.open().then(() => { settled = true; });
  frame.load();
  await waitFor(() => frame.transferred.length === 1 && fetch.calls.length === 2);
  assert.equal(settled, false);
  assert.equal(frame.attributes.get("sandbox"), "allow-scripts");
  assert.equal(frame.attributes.get("allow"), deniedPermissionsPolicy);
  assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
  assert.equal(frame.credentialless, true);
  assert.equal(frame.transferred[0]?.targetOrigin, "*");
  assert.equal(frame.transferred[0]?.ports.length, 1);
  assert.deepEqual(Object.keys(frame.transferred[0]?.message as Record<string, unknown>).sort(), [
    "frame_generation_id",
    "type",
    "ui_protocol_version",
  ]);
  assert.equal(JSON.stringify(frame.transferred[0]?.message).includes("nonce"), false);
  assert.equal(JSON.stringify(frame.transferred[0]?.message).includes("plugin"), true);
  assert.equal(frame.srcdoc.includes("asset_ticket_secret"), false);
  assert.equal(frame.srcdoc.includes("plugin_instance_1"), false);

  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  assert.equal(settled, false);
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;
  assert.equal(settled, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/prepare");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  assert.equal(JSON.stringify(frame.transferred.map((entry) => entry.message)).includes("gateway_secret"), false);

  fetch.push({});
  await host.close();
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
	assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  assert.equal(channel.port1.closed, true);
  assert.equal(frame.srcdoc, "");
});

test("surface host mints no bridge token before the transferred port acknowledges its frame generation", async () => {
  const frame = new FakeFrame();
  frame.autoAcknowledge = false;
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1 && fetch.calls.length >= 1);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(fetch.calls.length, 1);
  channel.port2.postMessage({ type: "redevplugin.surface.port_ack", frame_generation_id: host.frameGenerationId });
  await waitFor(() => fetch.calls.length === 2);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;
  host.dispose();
});

test("surface host dispose sends a keepalive revocation before local teardown", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({});
  host.dispose();
  await waitFor(() => fetch.calls.length === 3);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(fetch.calls[2]?.init.method, "POST");
  assert.equal(fetch.calls[2]?.init.keepalive, true);
	assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  assert.equal(channel.port1.closed, true);
  assert.equal(frame.srcdoc, "");
});

test("post-ready renderer failure revokes the surface and blocks later RPC", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const errors: PluginBridgeError[] = [];
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onError: (error) => errors.push(error),
  });

  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({});
  channel.port2.postMessage({ type: "redevplugin.surface.error", error: "worker crashed" });
  await waitFor(() => fetch.calls.length === 3 && channel.port1.closed);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(fetch.calls[2]?.init.keepalive, true);
  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.message, "worker crashed");

  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_after_crash", method: "echo.ping", params: {} },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(fetch.calls.length, 3);
  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("trusted parent never forwards non-JSON structured-clone RPC params", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_non_json", method: "echo.invalid", params: { value: new Map([["unexpected", true]]) } },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(fetch.calls.some((call) => call.input.endsWith("/rpc")), false);
  host.dispose();
});

test("trusted parent strips stream tickets and redeems a single-use handle with POST", async () => {
  const frame = new FakeFrameWithoutCredentialless();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({
    data: { started: true },
    stream_id: "stream_private_1",
    stream_ticket: "stream_ticket_secret",
    stream_ticket_id: "stream_ticket_id_private",
    stream_expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "logs.tail", params: { container_id: "web" } },
  });
  await waitFor(() => fetch.calls.length === 3);
  const response = [...channel.port1.sent].reverse().find((value) =>
    (value as { type?: string; id?: string }).type === "redevplugin.bridge.response" &&
    (value as { id?: string }).id === "rpc_1"
  ) as { ok: true; data: { stream_handle: string }; type: string; id: string };
  assert.equal(response.ok, true);
  assert.equal(/^stream_/.test(response.data.stream_handle), true);
  assert.equal(JSON.stringify(response).includes("stream_ticket_secret"), false);
  assert.equal(JSON.stringify(response).includes("stream_private_1"), false);

  fetch.push({ events: [{ stream_id: "stream_private_1", sequence: 1, kind: "data", data: "bG9nCg==", at: "2026-07-12T00:00:00Z" }] });
  channel.port2.postMessage({ type: "redevplugin.bridge.stream.read", id: "stream_2", stream_handle: response.data.stream_handle });
  await waitFor(() => fetch.calls.length === 4);
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/streams/read");
  assert.equal(fetch.calls[3]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {
    stream_id: "stream_private_1",
    stream_ticket: "stream_ticket_secret",
  });
  assert.equal(fetch.calls[3]?.input.includes("ticket"), false);

  channel.port2.postMessage({ type: "redevplugin.bridge.stream.read", id: "stream_3", stream_handle: response.data.stream_handle });
  await waitFor(() => channel.port1.sent.some((value) =>
    (value as { id?: string; error_code?: string }).id === "stream_3" &&
    (value as { error_code?: string }).error_code === "PLUGIN_STREAM_TICKET_INVALID"
  ));
  assert.equal(fetch.calls.length, 4);
  host.dispose();
});

test("trusted parent rejects mismatched and out-of-order stream events", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({
    stream_id: "stream_private_1",
    stream_ticket: "stream_ticket_secret",
    stream_ticket_id: "stream_ticket_id_private",
    stream_expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  channel.port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "logs.tail" } });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_1"));
  const call = [...channel.port1.sent].reverse().find((value) => (value as { id?: string }).id === "rpc_1") as {
    data: { stream_handle: string };
  };

  fetch.push({
    events: [
      { stream_id: "stream_private_1", sequence: 2, kind: "data", data: "Yg==", at: "2026-07-12T00:00:01Z" },
      { stream_id: "stream_other", sequence: 1, kind: "data", data: "YQ==", at: "2026-07-12T00:00:00Z" },
    ],
  });
  channel.port2.postMessage({ type: "redevplugin.bridge.stream.read", id: "stream_2", stream_handle: call.data.stream_handle });
  await waitFor(() => channel.port1.sent.some((value) =>
    (value as { id?: string; error_code?: string }).id === "stream_2" &&
    (value as { error_code?: string }).error_code === "PLUGIN_CONTRACT_MISMATCH"
  ));
  host.dispose();
});

test("trusted parent rejects expired stream tickets without retaining a handle", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({
    stream_id: "stream_expired_1",
    stream_ticket: "stream_ticket_expired",
    stream_ticket_id: "stream_ticket_id_expired",
    stream_expires_at: new Date(Date.now() - 1_000).toISOString(),
  });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "logs.tail" },
  });
  await waitFor(() => channel.port1.sent.some((value) =>
    (value as { id?: string; error_code?: string }).id === "rpc_1" &&
    (value as { error_code?: string }).error_code === "PLUGIN_STREAM_TICKET_INVALID"
  ));
  assert.equal(JSON.stringify(channel.port1.sent).includes("stream_ticket_expired"), false);
  host.dispose();
});

test("trusted parent bounds retained stream handles per surface", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  for (let index = 1; index <= 129; index += 1) {
    fetch.push({
      stream_id: `stream_bounded_${index}`,
      stream_ticket: `stream_ticket_bounded_${index}`,
      stream_ticket_id: `stream_ticket_id_bounded_${index}`,
      stream_expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    channel.port2.postMessage({
      type: "redevplugin.bridge.call",
      request: { id: `rpc_${index}`, method: "logs.tail" },
    });
    await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === `rpc_${index}`));
  }
  const last = [...channel.port1.sent].reverse().find((value) => (value as { id?: string }).id === "rpc_129") as {
    ok: boolean;
    error_code?: string;
  };
  assert.equal(last.ok, false);
  assert.equal(last.error_code, "PLUGIN_JSON_LIMIT_EXCEEDED");
  host.dispose();
});

test("surface disposal aborts an unresolved confirmation handler", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  let confirmationAborted = false;
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    confirm(intent) {
      return new Promise((resolve) => {
        intent.signal.addEventListener("abort", () => {
          confirmationAborted = true;
          resolve({ confirmed: false });
        }, { once: true });
      });
    },
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" }, 409);
  fetch.push({
    confirmation_id: "confirmation_1",
    confirmation_token_id: "confirmation_token_1",
    request_hash: digest("1"),
    plan_hash: digest("2"),
  });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "danger.run", params: { target: "database" } },
  });
  await waitFor(() => fetch.calls.length === 4);
  host.dispose();
  await waitFor(() => confirmationAborted);
  assert.equal(channel.port1.closed, true);
});

test("trusted renderer asset reads stay on the private parent POST route", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({ path: "ui/status.png", sha256: digest("e"), content_type: "image/png", content_base64: "iVBORw0KGgo=" });
  channel.port2.postMessage({
    type: "redevplugin.surface.asset.read",
    request_id: "asset_request_1",
    binding_id: "asset_12345678",
    path: "ui/status.png",
    sha256: digest("e"),
  });
  await waitFor(() => fetch.calls.length === 3);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/assets/read");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {
    asset_session: "asset_session_rotated_1",
    asset_session_id: "asset_session_id_rotated_1",
    binding_id: "asset_12345678",
  });
  assert.equal(fetch.calls[2]?.input.includes("asset_session"), false);
  host.dispose();
});

test("trusted parent fails the surface when a lazy asset MIME type changes", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const errors: PluginBridgeError[] = [];
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onError(error) {
      errors.push(error);
    },
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({
    path: "ui/status.png",
    sha256: digest("e"),
    content_type: "application/octet-stream",
    content_base64: "iVBORw0KGgo=",
  });
  fetch.push({});
  channel.port2.postMessage({
    type: "redevplugin.surface.asset.read",
    request_id: "asset_request_1",
    binding_id: "asset_12345678",
    path: "ui/status.png",
    sha256: digest("e"),
  });

  await waitFor(() => errors.length === 1);
  assert.equal(errors[0]?.errorCode, "PLUGIN_CONTRACT_MISMATCH");
  assert.equal(frame.srcdoc, "");
  await waitFor(() => fetch.calls.length === 4);
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
});

test("surface host applies the initial lease before renderer initialization", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  let releaseLease!: () => void;
  fetch.pushHandler(async () => {
    await new Promise<void>((resolve) => {
      releaseLease = resolve;
    });
    return {
      ok: true,
      status: 200,
      json: async () => ({ ok: true, data: gatewayLease() }),
    };
  });
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  const opening = host.open();
  frame.load();
  await waitFor(() => fetch.calls.length === 2);
  assert.equal(channel.port1.sent.some((message) =>
    (message as { type?: string }).type === "redevplugin.surface.initialize"
  ), false);

  releaseLease();
  await waitFor(() => channel.port1.sent.some((message) =>
    (message as { type?: string }).type === "redevplugin.surface.initialize"
  ));
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;
  host.dispose();
});

test("surface host reports opening progress after 300ms", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const progress: number[] = [];
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onOpeningProgress: (value) => progress.push(value.elapsedMs),
  });
  const opening = host.open();
  frame.load();
  await new Promise((resolve) => setTimeout(resolve, 320));
  assert.equal(progress.length, 1);
  assert.equal(progress[0]! >= 300, true);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;
  host.dispose();
});

test("surface opening deadline revokes server state, tears down locally, and remains retryable", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const reloadLimiter = new PluginSurfaceReloadLimiter();
  const delayedEnvelope = async (data: unknown): Promise<FetchResponseLike> => {
    await new Promise((resolve) => setTimeout(resolve, 18));
    return { ok: true, status: 200, json: async () => ({ ok: true, data }) };
  };
  fetch.pushHandler(async () => delayedEnvelope(preparation()));
  fetch.pushHandler(async () => delayedEnvelope(gatewayLease()));
  fetch.push({ disposed: true });
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    loadTimeoutMs: 30,
    requestTimeoutMs: 100,
    reloadLimiter,
  });

  const opening = host.open();
  frame.load();
  const lateRendererSignals = setTimeout(() => {
    try {
      channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
      channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
    } catch {
      // The expected deadline closes the transferred channel first.
    }
  }, 50);
  await assert.rejects(
    opening,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_TIMEOUT",
  );
  clearTimeout(lateRendererSignals);
  assert.equal(fetch.calls.at(-1)?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.deepEqual(JSON.parse(fetch.calls.at(-1)?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  assert.equal(frame.srcdoc, "");
  assert.equal(channel.port1.closed, true);
  assert.deepEqual(reloadLimiter.state, {
    reloads: 1,
    remaining: 1,
    windowStartedAtMs: reloadLimiter.state.windowStartedAtMs,
    nextRetryAtMs: undefined,
  });

  const retryFrame = new FakeFrame();
  const retryFetch = new FakeFetch();
  const retryChannel = fakeChannel();
  retryFetch.push(preparation());
  retryFetch.push(gatewayLease());
  const retryHost = createSurfaceHost(retryFrame, {
    bootstrap: hostBootstrap,
    testMessageChannel: retryChannel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: retryFetch.fetch }),
    loadTimeoutMs: 100,
    reloadLimiter,
  });
  const retryOpening = retryHost.open();
  retryFrame.load();
  await waitFor(() => retryFrame.transferred.length === 1);
  retryChannel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  retryChannel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await retryOpening;
  assert.deepEqual(reloadLimiter.state, { reloads: 0, remaining: 2, windowStartedAtMs: undefined, nextRetryAtMs: undefined });
  retryHost.dispose();
});

test("plugin bridge rejects malformed handles and disposed calls", async () => {
  const { port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678" });
  assert.throws(() => client.readStream("stream"), (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST");
  client.dispose();
  assert.throws(() => client.call("echo.ping"), (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED");
});

test("surface host revokes a server session when disposed before open", async () => {
  const fetch = new FakeFetch();
  fetch.push({});
  const host = createSurfaceHost(new FakeFrame(), {
    bootstrap: hostBootstrap,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  host.dispose();
  await waitFor(() => fetch.calls.length === 1);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(fetch.calls[0]?.init.keepalive, true);
	assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
});

test("surface scope revoke immediately tears down every local host in the session", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push({ revoked_surface_count: 1 });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  assert.deepEqual(await client.revokeSurfaceScope(), { revoked_surface_count: 1 });
  assert.equal(frame.srcdoc, "");
  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  assert.equal(fetch.calls.length, 1);
});

test("plugin disable immediately tears down matching local surface hosts", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push({
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    plugin_id: hostBootstrap.pluginId,
    version: hostBootstrap.pluginVersion,
    active_fingerprint: hostBootstrap.activeFingerprint,
    trust_state: "verified",
    trust_assessment: { trust_state: "verified", verified_hashes: { package_sha256: digest("1"), manifest_sha256: digest("2"), entries_sha256: digest("3") } },
    enable_state: "disabled",
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.disablePlugin({ plugin_instance_id: hostBootstrap.pluginInstanceId, plugin_state_version: 7 });
  assert.equal(frame.srcdoc, "");
  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

const lifecyclePluginRecord = {
  plugin_instance_id: hostBootstrap.pluginInstanceId,
  plugin_id: hostBootstrap.pluginId,
  version: hostBootstrap.pluginVersion,
  active_fingerprint: hostBootstrap.activeFingerprint,
  trust_state: "verified",
  trust_assessment: {
    trust_state: "verified",
    verified_hashes: {
      package_sha256: digest("1"),
      manifest_sha256: digest("2"),
      entries_sha256: digest("3"),
    },
  },
  enable_state: "disabled",
};

const releaseRef = {
  source_id: "official",
  release_metadata_ref: "plugins/com.example/com.example.plugin/1.1.0/release.json",
  release_metadata_sha256: digest("4"),
  publisher_id: "com.example",
  plugin_id: hostBootstrap.pluginId,
  version: "1.1.0",
  expected_hashes: {
    package_sha256: digest("5"),
    manifest_sha256: digest("6"),
    entries_sha256: digest("7"),
  },
};

for (const lifecycle of [
  {
    name: "release update",
    run: (client: PluginPlatformClient) => client.updateReleaseRef({
      plugin_instance_id: hostBootstrap.pluginInstanceId,
      release_ref: releaseRef,
      plugin_state_version: 7,
    }),
  },
  {
    name: "downgrade",
    run: (client: PluginPlatformClient) => client.downgradePlugin({
      plugin_instance_id: hostBootstrap.pluginInstanceId,
      version: "0.9.0",
      plugin_state_version: 7,
    }),
  },
  {
    name: "uninstall",
    run: (client: PluginPlatformClient) => client.uninstallPlugin({
      plugin_instance_id: hostBootstrap.pluginInstanceId,
      plugin_state_version: 7,
      delete_data: true,
    }),
  },
] as const) {
  test(`plugin ${lifecycle.name} tears down matching local surface hosts after success`, async () => {
    const frame = new FakeFrame();
    const scope = createPluginSurfaceScope();
    const host = createSurfaceHost(frame, {
      bootstrap: hostBootstrap,
      surfaceScope: scope,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
    });
    const fetch = new FakeFetch();
    fetch.push(lifecyclePluginRecord);
    const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

    await lifecycle.run(client);

    assert.throws(
      () => host.sendLifecycle({ type: "hidden" }),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
    );
  });
}

test("failed plugin mutation tears down the matching local surface host", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error_code: "PLUGIN_STATE_VERSION_MISMATCH", error: "stale state" }, 409);
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await assert.rejects(() => client.disablePlugin({
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    plugin_state_version: 6,
  }));

  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("runtime stop tears down the complete local surface scope", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push({ stopped: true });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.stopRuntime();

  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("local package update tears down matching local surface hosts after success", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push(lifecyclePluginRecord);
  const client = new PluginLocalImportClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.updateLocalPackage({
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    package_base64: "cGtn",
    plugin_state_version: 7,
  });

  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("surface close bounds a non-responsive revocation transport", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  fetch.pushHandler(async () => new Promise<FetchResponseLike>(() => undefined));
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    requestTimeoutMs: 10,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  const result = await Promise.race([
    host.close().then(() => "resolved", () => "rejected"),
    new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 100)),
  ]);
  assert.equal(result === "hung", false);
  assert.equal(frame.srcdoc, "");
});

test("throwing error observers cannot block surface revocation", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onError: () => { throw new Error("observer failure"); },
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({});
  channel.port2.postMessage({ type: "redevplugin.surface.error", error: "worker crashed" });
  await waitFor(() => fetch.calls.length === 3 && channel.port1.closed);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
});

test("plugin cancellation aborts the matching parent request", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  let requestAborted = false;
  fetch.pushHandler(async (_input, init) => new Promise<FetchResponseLike>((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => {
      requestAborted = true;
      reject(new DOMException("aborted", "AbortError"));
    }, { once: true });
  }));
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  channel.port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "echo.slow" } });
  await waitFor(() => fetch.calls.length === 3);
  channel.port2.postMessage({ type: "redevplugin.bridge.cancel", id: "rpc_1" });
  await waitFor(() => requestAborted);
  assert.equal(channel.port1.sent.some((message) => (message as { id?: string }).id === "rpc_1"), false);
  host.dispose();
});

test("surface lease renews gateway and asset credentials before expiry", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const issuedAt = new Date();
  fetch.push(preparation());
  fetch.push(gatewayLease({
    issued_at: issuedAt.toISOString(),
    expires_at: new Date(issuedAt.getTime() + 80).toISOString(),
  }));
  fetch.push(gatewayLease({
    plugin_gateway_token: "gateway_secret_2",
    plugin_gateway_token_id: "gateway_token_2",
    asset_session: "asset_session_rotated_2",
    asset_session_id: "asset_session_id_rotated_2",
  }));
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    leaseRenewalLeadMs: 20,
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;
  await waitFor(() => fetch.calls.length === 3);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  assert.equal(JSON.parse(fetch.calls[2]?.init.body ?? "").previous_plugin_gateway_token, "gateway_secret");

  fetch.push({ data: { ok: true } });
  channel.port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "echo.fast" } });
  await waitFor(() => fetch.calls.length === 4);
  assert.equal(JSON.parse(fetch.calls[3]?.init.body ?? "").plugin_gateway_token, "gateway_secret_2");

  fetch.push({ path: "ui/status.png", sha256: digest("e"), content_type: "image/png", content_base64: "iVBORw0KGgo=" });
  channel.port2.postMessage({
    type: "redevplugin.surface.asset.read",
    request_id: "asset_request_1",
    binding_id: "asset_12345678",
    path: "ui/status.png",
    sha256: digest("e"),
  });
  await waitFor(() => fetch.calls.length === 5);
  const assetBody = JSON.parse(fetch.calls[4]?.init.body ?? "");
  assert.equal(assetBody.asset_session, "asset_session_rotated_2");
  assert.equal(assetBody.asset_session_id, "asset_session_id_rotated_2");
  assert.equal(assetBody.binding_id, "asset_12345678");
  host.dispose();
});

test("unexpected iframe reload fails closed and records the shared reload budget", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const errors: PluginBridgeError[] = [];
  const reloadLimiter = new PluginSurfaceReloadLimiter();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    reloadLimiter,
    onError: (error) => errors.push(error),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({});
  frame.load();
  await waitFor(() => fetch.calls.length === 3 && channel.port1.closed);
  assert.equal(reloadLimiter.state.reloads, 1);
  assert.equal(errors[0]?.errorCode, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
});

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not met");
}

function withLocationOrigin<T>(origin: string, run: () => T): T {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", { configurable: true, value: { origin } });
  try {
    return run();
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "location", descriptor);
    else delete (globalThis as { location?: unknown }).location;
  }
}
