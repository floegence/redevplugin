import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PluginBridgeError,
  PluginPlatformClient,
  PluginTransportError,
  PluginSurfaceReloadLimiter,
  PluginSurfaceSlot,
  createReDevPluginSurfaceTransport,
  createPluginSurfaceScope,
  trustedParentBridgeHandshakeTranscriptSHA256,
  type FetchInitLike,
  type FetchLike,
  type FetchResponseLike,
  type MessageChannelLike,
  type MessageEventLike,
  type MessagePortLike,
  type PluginSurfaceInteractionEvent,
  type PluginWebOriginPreparation,
} from "../src/trusted-parent.js";
import { PluginBridgeClient, callCapabilitySync } from "../src/plugin.js";
import {
  createPreparedPluginSurfaceHost,
  openPreparedPluginSurfaceInSlot,
  type PluginSurfaceHostOptions,
  type PluginSurfaceHostBootstrap,
  type PreparedPluginSurfaceHost,
} from "../src/surface.js";
import { PluginLocalImportClient } from "../src/local-import.js";
import { disposePluginSurfaceScope, invalidatePluginSurfaceScope, registerPluginSurface } from "../src/surface-scope.js";


for (const withoutSubtleCrypto of [false, true]) test(`trusted-parent handshake transcript has one stable current vector (without SubtleCrypto: ${withoutSubtleCrypto})`, async () => {
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  if (withoutSubtleCrypto) Object.defineProperty(globalThis, "crypto", { configurable: true, value: { getRandomValues: crypto.getRandomValues.bind(crypto) } });
  try {
    const got = await trustedParentBridgeHandshakeTranscriptSHA256({
      type: "redevplugin.bridge.handshake",
      plugin_id: "com.example.plugin",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      active_fingerprint: "sha256:abc",
      bridge_nonce: "nonce_1",
      asset_session_nonce: "asset_nonce_1",
      management_revision: 7,
      revoke_epoch: 3,
    }, "bridge_channel_1");
    assert.equal(got, "sha256:761226eb620c1a1277cb83b129f9e800ce1f1df243a04e7b6f5ad4952e65bcba");
  } finally {
    if (cryptoDescriptor) Object.defineProperty(globalThis, "crypto", cryptoDescriptor);
  }
});

const windowMessages = new Set<(event: MessageEvent) => void>();
Object.defineProperty(globalThis, "location", { configurable: true, value: { origin: "https://host.example" } });
globalThis.addEventListener = ((_type: string, listener: (event: MessageEvent) => void) => { windowMessages.add(listener); }) as typeof globalThis.addEventListener;
globalThis.removeEventListener = ((_type: string, listener: (event: MessageEvent) => void) => { windowMessages.delete(listener); }) as typeof globalThis.removeEventListener;
function entryReady(frame: FakeFrame | FakeFrameWithoutCredentialless): void {
  if (!frame.src.startsWith("https://web.example/")) return;
  for (const listener of windowMessages) listener({ source: frame.contentWindow, origin: "https://web.example", data: { type: "redevplugin.surface.entry_ready", entry_path: "/index.html", document_id: frame.documentID } } as unknown as MessageEvent);
}

class FakePort implements MessagePortLike {
  peer?: FakePort;
  sent: unknown[] = [];
  postError?: Error;
  #listeners = new Set<(event: MessageEventLike) => void>();
  closed = false;
  autoAppReady = false;
  frameGeneration = "";
  applicationReady(): void { if (this.autoAppReady) this.completeApplication(); }
  completeApplication(): void { this.postMessage({ type: "redevplugin.surface.app_ready", frame_generation_id: this.frameGeneration }); }

  postMessage(message: unknown, _transfer?: readonly unknown[]): void {
    if (this.postError) throw this.postError;
    if (this.closed) throw new Error("port is closed");
    if (!isMessageType(message, "redevplugin.bridge.client_ready")) this.sent.push(message);
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
  port2.autoAppReady = true;
  return { port1, port2 };
}

function isMessageType(value: unknown, type: string): boolean {
  return value !== null && typeof value === "object" && (value as { type?: unknown }).type === type;
}

class FakeFrame {
  documentID = "document_12345678";
  srcdoc = "";
  #source = "about:blank";
  #loaded = false;
  get src(): string { return this.#source; }
  set src(value: string) { this.#source = value; if (this.#loaded) queueMicrotask(() => entryReady(this)); }
  credentialless = false;
  hidden = false;
  inert = false;
  style = { visibility: "", opacity: "", pointerEvents: "" };
  removed = false;
  attributes = new Map<string, string>();
  transferred: Array<{ message: unknown; targetOrigin: string; ports: MessagePortLike[] }> = [];
  autoAcknowledge = true;
  #listeners = new Set<() => void>();
  contentWindow = {
    postMessage: (message: unknown, targetOrigin: string, ports?: MessagePortLike[]) => {
      this.transferred.push({ message, targetOrigin, ports: ports ?? [] });
      if (isSurfacePortEnvelope(message) && ports?.[0] instanceof FakePort) { ports[0].frameGeneration = message.frame_generation_id; if (ports[0].peer) ports[0].peer.frameGeneration = message.frame_generation_id; }
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
    this.#loaded = true; entryReady(this);
    for (const listener of this.#listeners) listener();
  }

  remove(): void {
    this.removed = true;
  }
}

class FakeStage {
  dataset: Record<string, string> = {};
  children: FakeFrame[] = [];

  append(...frames: FakeFrame[]): void {
    this.children.push(...frames);
  }
}

class FakeFrameWithoutCredentialless {
  documentID = "document_12345678";
  srcdoc = "";
  #source = "about:blank";
  #loaded = false;
  get src(): string { return this.#source; }
  set src(value: string) { this.#source = value; if (this.#loaded) queueMicrotask(() => entryReady(this)); }
  attributes = new Map<string, string>();
  transferred: Array<{ message: unknown; targetOrigin: string; ports: MessagePortLike[] }> = [];
  autoAcknowledge = true;
  #listeners = new Set<() => void>();
  contentWindow = {
    postMessage: (message: unknown, targetOrigin: string, ports?: MessagePortLike[]) => {
      this.transferred.push({ message, targetOrigin, ports: ports ?? [] });
      if (isSurfacePortEnvelope(message) && ports?.[0] instanceof FakePort) { ports[0].frameGeneration = message.frame_generation_id; if (ports[0].peer) ports[0].peer.frameGeneration = message.frame_generation_id; }
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
  load(): void { this.#loaded = true; entryReady(this); for (const listener of this.#listeners) listener(); }
}

function createSurfaceHost(
  frame: FakeFrame | FakeFrameWithoutCredentialless,
  options: PluginSurfaceHostOptions & { testMessageChannel?: MessageChannelLike },
): PreparedPluginSurfaceHost {
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
    const host = createPreparedPluginSurfaceHost(hostOptions);
    assert.equal(host.element, frame);
    assert.equal(createdFrames, 1);
    assert.equal(frame.attributes.get("src"), "about:blank");
    assert.equal(frame.attributes.get("sandbox"), "allow-scripts allow-forms");
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
  calls: Array<{ input: string; init: Omit<FetchInitLike, "body"> & { body?: any } }> = [];
  responses: Array<
    | { status: number; body: unknown }
    | ((input: string, init: FetchInitLike) => Promise<FetchResponseLike>)
  > = [];

  fetch: FetchLike = async (input, init) => {
    this.calls.push({ input, init });
    const next = this.responses.shift();
    if (!next && input.endsWith("/dispose")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ ok: true, data: surfaceRevocation() }),
      } satisfies FetchResponseLike;
    }
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
  managementRevision: 7,
  revokeEpoch: 3,
  runtimeGenerationId: "runtime_gen_1",
} satisfies PluginSurfaceHostBootstrap;

function sessionScopeRevokeResult() {
  return {
    state: "complete",
    fenced: true,
    complete: true,
    counts: {
      surfaces: 1,
      asset_tickets: 0,
      asset_sessions: 0,
      plugin_gateway_tokens: 0,
      confirmation_tokens: 0,
      handle_grants: 0,
      confirmations: 0,
      executions: 0,
      active_network_requests: 0,
      sockets: 0,
      network_streams: 0,
      storage_hostcalls: 0,
    },
  };
}

function platformSurfaceBootstrap(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    plugin_id: hostBootstrap.pluginId,
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    plugin_version: hostBootstrap.pluginVersion,
    surface_id: hostBootstrap.surfaceId,
    surface_instance_id: hostBootstrap.surfaceInstanceId,
    active_fingerprint: hostBootstrap.activeFingerprint,
    bridge_nonce: hostBootstrap.bridgeNonce,
    entry_path: hostBootstrap.entryPath,
    entry_sha256: hostBootstrap.entrySHA256,
    asset_ticket: hostBootstrap.assetTicket,
    asset_session_nonce: hostBootstrap.assetSessionNonce,
    management_revision: hostBootstrap.managementRevision,
    revoke_epoch: hostBootstrap.revokeEpoch,
    runtime_generation_id: hostBootstrap.runtimeGenerationId,
    ...overrides,
  };
}

function preparation() {
  return {
    asset_session: "asset_session_secret",
    asset_session_id: "asset_session_id_1",
    asset_session_nonce: "asset_session_nonce_1",
    entry_path: "ui/index.html",
    entry_sha256: digest("b"),
    management_revision: 7,
    revoke_epoch: 3,
    issued_at: "2026-07-12T00:00:00Z",
    expires_at: "2026-07-12T00:10:00Z",
    document: {
      schema_version: "redevplugin.web_surface.v1",
      origin: "https://web.example",
      parent_origin: globalThis.location.origin,
      bootstrap_url: "https://web.example/_redevplugin_web/bootstrap#" + "a".repeat(64),
      entry_url: "https://web.example/index.html",
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

function surfaceRevocation(overrides: Record<string, unknown> = {}) {
  return {
    disposed: true,
    state: "closed",
    previous_state: "active",
    revoked: true,
    ...overrides,
  };
}

test("surface host rejects zero-valued revision bindings", () => {
  for (const invalid of [
    { ...hostBootstrap, managementRevision: 0 },
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
  fetch.push(surfaceRevocation());
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
  assert.equal(fetch.calls.length, 2);
  assert.equal(frame.src, "about:blank");
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
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_1",
    ok: true,
    data: { pong: true },
    future_trace: "trace_1",
  });
  assert.deepEqual(await callPromise, { pong: true });

  const businessErrorPromise = client.call("documents.get", { document_id: "missing" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_2",
    ok: false,
    error_code: "PLUGIN_CAPABILITY_ERROR",
    error: "host capability request failed",
    error_details: {
      capability_id: "example.capability.documents",
      capability_version: "1.0.0",
      detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      business_error_code: "DOCUMENT_NOT_FOUND",
      business_error_details: { document_id: "missing" },
    },
    future_trace: "trace_2",
  });
  await assert.rejects(businessErrorPromise, (error: unknown) =>
    error instanceof PluginBridgeError &&
    error.errorCode === "PLUGIN_CAPABILITY_ERROR" &&
    (error.details as { business_error_code?: string })?.business_error_code === "DOCUMENT_NOT_FOUND"
  );
  const unknownMutationPromise = client.call("memos.delete", { id: "memo_1" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_3",
    ok: false,
    error_code: "PLUGIN_RUNTIME_UNAVAILABLE",
    error: "response lost",
    mutation_outcome: "unknown",
  });
  await assert.rejects(unknownMutationPromise, (error: unknown) =>
    error instanceof PluginBridgeError &&
    error.errorCode === "PLUGIN_RUNTIME_UNAVAILABLE" &&
    error.mutationOutcome === "unknown"
  );
  client.dispose();
  assert.equal(pluginPort.closed, true);
});

test("plugin bridge client retains and fences host appearance and locale context", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678" });
  const context = {
    schema_version: "redevplugin.surface_context.v1",
    revision: 1,
    appearance: {
      color_scheme: "dark",
      colors: {
        canvas: "#101010", surface: "#181818", surface_elevated: "#202020", text: "#ffffff", text_muted: "#aaaaaa", border: "#444444",
        accent: "#66aaff", accent_text: "#000000", success: "#44cc88", warning: "#ffcc44", danger: "#ff6677", focus: "#88bbff",
      },
    },
    locale: { language_tag: "zh-CN", direction: "ltr" },
  } as const;
  const seen: unknown[] = [];
  client.onContext(() => {
    throw new Error("observer failure");
  });
  client.onContext((value) => seen.push(value));
  rendererPort.postMessage({ type: "redevplugin.bridge.context", context });
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  assert.deepEqual(client.context(), context);
  assert.equal(Object.isFrozen(client.context()), true);
  assert.equal(Object.isFrozen(client.context()?.appearance.colors), true);
  assert.deepEqual(seen, [context]);
  rendererPort.postMessage({ type: "redevplugin.bridge.context", context: { ...context, revision: 1, locale: { language_tag: "en-US", direction: "ltr" } } });
  assert.equal(seen.length, 1);
  const next = { ...context, revision: 2, locale: { language_tag: "en-US", direction: "ltr" } };
  rendererPort.postMessage({ type: "redevplugin.bridge.context", context: next });
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  assert.deepEqual(client.context(), next);
  assert.equal(seen.length, 2);
  client.dispose();
});


test("plugin bridge classifies cancellation before and after mutation dispatch", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });

  const preDispatch = new AbortController();
  preDispatch.abort("cancel before dispatch");
  await assert.rejects(
    client.call("documents.archive", { document_id: "doc-1" }, { signal: preDispatch.signal }),
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_CANCELLED" &&
      error.mutationOutcome === "not_committed",
  );
  assert.deepEqual(pluginPort.sent, []);

  const postDispatch = new AbortController();
  const call = client.call("documents.archive", { document_id: "doc-1" }, { signal: postDispatch.signal });
  await waitFor(() => pluginPort.sent.length === 1);
  postDispatch.abort("cancel after dispatch");
  await assert.rejects(
    call,
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_CANCELLED" &&
      error.mutationOutcome === "unknown",
  );
  assert.deepEqual(pluginPort.sent[1], { type: "redevplugin.bridge.cancel", id: "rpc_2" });

  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_2", ok: true, data: { ignored: true } });
  const next = client.call("documents.get", { document_id: "doc-1" });
  await waitFor(() => pluginPort.sent.length === 3);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_3", ok: true, data: { ok: true } });
  assert.deepEqual(await next, { ok: true });
  client.dispose();
});

test("plugin bridge preserves committed mutation outcomes from the host", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });

  const call = client.call("documents.archive", { document_id: "doc-1" });
  await waitFor(() => pluginPort.sent.length === 1);
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_1",
    ok: false,
    error_code: "PLUGIN_ADAPTER_FAILURE",
    error: "host mutation committed before the adapter failed",
    mutation_outcome: "committed",
  });

  await assert.rejects(call, (error: unknown) =>
    error instanceof PluginBridgeError &&
    error.errorCode === "PLUGIN_ADAPTER_FAILURE" &&
    error.mutationOutcome === "committed"
  );
  client.dispose();
});

test("generated read capability cancellation never reports an unknown mutation outcome", async () => {
  const { port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  const controller = new AbortController();
  const read = callCapabilitySync(
    client,
    {
      method: "documents.get",
      effect: "read",
      execution: "sync",
      requestSchema: { type: "object", additionalProperties: false },
      responseSchema: { type: "object", additionalProperties: false },
    },
    {},
    { signal: controller.signal },
  );
  await waitFor(() => pluginPort.sent.length === 1);
  controller.abort();
  await assert.rejects(
    read,
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_CANCELLED" &&
      error.mutationOutcome === undefined,
  );
  client.dispose();
});


test("plugin bridge acknowledges quiesce only after async lifecycle observers settle", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  let releasePersistence!: () => void;
  const persistence = new Promise<void>((resolve) => {
    releasePersistence = resolve;
  });
  let disposalStarted = false;
  client.onLifecycle(async (event) => {
    if (event.type !== "dispose") return;
    disposalStarted = true;
    await persistence;
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  rendererPort.postMessage({
    type: "redevplugin.bridge.lifecycle",
    event: { type: "dispose" },
    quiesce_id: "quiesce_12345678",
  });
  await waitFor(() => disposalStarted);
  assert.equal(pluginPort.sent.some((message) =>
    (message as { type?: string }).type === "redevplugin.bridge.lifecycle_ack"
  ), false);

  releasePersistence();
  await waitFor(() => pluginPort.sent.some((message) =>
    (message as { type?: string }).type === "redevplugin.bridge.lifecycle_ack"
  ));
  assert.deepEqual(pluginPort.sent.at(-1), {
    type: "redevplugin.bridge.lifecycle_ack",
    quiesce_id: "quiesce_12345678",
  });
  assert.equal(pluginPort.closed, false);
  assert.throws(
    () => client.call("echo.after-quiesce"),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "dispose" } });
  await waitFor(() => pluginPort.closed);
});

test("plugin bridge exports one bounded file as transferred bytes", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const source = new Uint8Array([137, 80, 78, 71]);
  const exporting = client.exportFile({
    fileName: "diagram.png",
    mediaType: "image/png",
    bytes: source,
  });
  assert.equal(source.byteLength, 4);
  const request = pluginPort.sent[0] as {
    type: string;
    id: string;
    file_name: string;
    media_type: string;
    content: ArrayBuffer;
  };
  assert.equal(request.type, "redevplugin.ui.file.export");
  assert.equal(request.id, "file_1");
  assert.equal(request.file_name, "diagram.png");
  assert.equal(request.media_type, "image/png");
  assert.deepEqual([...new Uint8Array(request.content)], [...source]);
  assert.equal(request.content === source.buffer, false);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "file_1", ok: true });
  await exporting;

  for (const invalid of [
    { fileName: "../diagram.png", mediaType: "image/png", bytes: source },
    { fileName: "diagram.exe", mediaType: "application/octet-stream", bytes: source },
    { fileName: "diagram.png", mediaType: "image/png", bytes: new Uint8Array() },
  ]) {
    assert.throws(
      () => client.exportFile(invalid as Parameters<PluginBridgeClient["exportFile"]>[0]),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
    );
  }
  client.dispose();
});

test("plugin bridge client rejects malformed capability errors immediately", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1_000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const callPromise = client.call("documents.get", { document_id: "missing" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_1",
    ok: false,
    error_code: "PLUGIN_CAPABILITY_ERROR",
    error: "host capability request failed",
    error_details: {
      business_error_code: "DOCUMENT_NOT_FOUND",
      business_error_details: { document_id: "missing" },
    },
  });

  await assert.rejects(callPromise, (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH"
  );

  const oversizedVersionPromise = client.call("documents.get", { document_id: "missing" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_2",
    ok: false,
    error_code: "PLUGIN_CAPABILITY_ERROR",
    error: "host capability request failed",
    error_details: {
      capability_id: "example.capability.documents",
      capability_version: `1.2.3-${"a".repeat(4096)}`,
      detail_schema_sha256: "a".repeat(64),
      business_error_code: "DOCUMENT_NOT_FOUND",
    },
  });
  await assert.rejects(oversizedVersionPromise, (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH"
  );

  const unknownErrorPromise = client.call("documents.get", { document_id: "missing" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_3",
    ok: false,
    error_code: "PLUGIN_UNKNOWN_ERROR",
    error: "unknown host error",
  });
  await assert.rejects(unknownErrorPromise, (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH"
  );
  client.dispose();
});

test("plugin bridge client rejects non-JSON structured-clone payloads before posting", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 10 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  for (const params of [
    { value: new ArrayBuffer(1024) },
    { value: new Map([["unexpected", true]]) },
    JSON.parse('{"__proto__":"unsafe"}'),
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

test("plugin bridge client clears pending requests when postMessage fails synchronously", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  pluginPort.postError = new Error("post failed");
  for (let index = 0; index < 256; index += 1) {
    await assert.rejects(
      client.call("echo.closed"),
      (error: unknown) => error instanceof PluginBridgeError &&
        error.errorCode === "PLUGIN_BRIDGE_DISPOSED" &&
        error.mutationOutcome === "not_committed",
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
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_TIMEOUT" &&
      error.mutationOutcome === "unknown",
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

test("surface host transfers one secret-free origin-bound port and waits for application and token", async () => {
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
  assert.equal(frame.attributes.get("sandbox"), "allow-scripts allow-same-origin allow-forms");
  assert.equal(frame.attributes.get("allow"), deniedPermissionsPolicy);
  assert.equal(frame.attributes.get("referrerpolicy"), "no-referrer");
  assert.equal(frame.credentialless, false);
  assert.equal(frame.transferred[0]?.targetOrigin, "https://web.example");
  assert.equal(frame.transferred[0]?.ports.length, 1);
  assert.deepEqual(Object.keys(frame.transferred[0]?.message as Record<string, unknown>).sort(), [
    "document_id",
    "frame_generation_id",
    "type",
  ]);
  assert.equal(JSON.stringify(frame.transferred[0]?.message).includes("nonce"), false);
  assert.equal(JSON.stringify(frame.transferred[0]?.message).includes("plugin"), true);
  assert.equal(frame.srcdoc.includes("asset_ticket_secret"), false);
  assert.equal(frame.srcdoc.includes("plugin_instance_1"), false);

  assert.equal(settled, false);
  channel.port2.applicationReady();
  await opening;
  assert.equal(settled, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/prepare");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  assert.equal(JSON.stringify(frame.transferred.map((entry) => entry.message)).includes("gateway_secret"), false);

  fetch.push(surfaceRevocation());
  const closing = host.close();
  const concurrentClosing = host.close();
  assert.equal(concurrentClosing, closing);
  await waitFor(() => channel.port1.sent.some((message) =>
    (message as { type?: string; quiesce_id?: string }).type === "redevplugin.bridge.lifecycle" &&
    typeof (message as { quiesce_id?: string }).quiesce_id === "string"
  ));
  const quiesce = channel.port1.sent.find((message) =>
    (message as { type?: string; quiesce_id?: string }).type === "redevplugin.bridge.lifecycle" &&
    typeof (message as { quiesce_id?: string }).quiesce_id === "string"
  ) as { quiesce_id: string };
  assert.equal(quiesce.quiesce_id.startsWith("quiesce_"), true);
  assert.equal(fetch.calls.length, 2);
  channel.port2.postMessage({ type: "redevplugin.surface.quiesce_ack", quiesce_id: quiesce.quiesce_id });
  await Promise.all([closing, concurrentClosing]);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  assert.equal(channel.port1.closed, true);
  assert.equal(frame.src, "about:blank");
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
  channel.port2.applicationReady();
  await opening;
  host.dispose();
});

test("surface host exposes no iframe before the application becomes ready", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  channel.port2.autoAppReady = false;
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  let settled = false;
  const opening = host.open().then(() => { settled = true; });
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await waitFor(() => channel.port1.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.lifecycle") &&
    (message as { event?: { type?: string } }).event?.type === "ready"
  ));
  assert.equal(settled, false);
  channel.port2.completeApplication();
  await opening;
  host.dispose();
});

test("opening renderer failure remains authoritative through surface disposal", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  channel.port2.autoAppReady = false;
  const errors: PluginBridgeError[] = [];
  fetch.push(preparation());
  fetch.push(gatewayLease());
  fetch.push(surfaceRevocation());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onError: (error) => errors.push(error),
  });

  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await waitFor(() => channel.port1.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.lifecycle") &&
    (message as { event?: { type?: string } }).event?.type === "ready"
  ));
  channel.port2.postMessage({ type: "redevplugin.surface.error", error: "renderer rejected weather input" });

  await assert.rejects(
    opening,
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_HANDSHAKE_FAILED" &&
      error.message === "renderer rejected weather input",
  );
  await waitFor(() => fetch.calls.length === 3 && channel.port1.closed);
  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.errorCode, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
  assert.equal(errors[0]?.message, "renderer rejected weather input");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
});

test("platform client fails closed when absolute surface transport base has no browser origin", () => {
  const previousLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  Reflect.deleteProperty(globalThis, "location");
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/plugin-api/",
    fetch: new FakeFetch().fetch,
  });
  try {
    assert.throws(
      () => client.openSurfaceInSlot({} as PluginSurfaceSlot, {
        plugin_instance_id: "plugin_instance_1",
        surface_id: "example.view",
        surface_instance_id: "surface_1",
        expected_management_revision: 7,
      }),
      /same-origin/,
    );
  } finally {
    if (previousLocation) Object.defineProperty(globalThis, "location", previousLocation);
  }
});

test("platform client opens a surface in a slot with one SDK-owned same-origin transport", async () => {
  const frame = new FakeFrame();
  const channel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([frame], [channel]);
  const fetch = new FakeFetch();
  fetch.push(platformSurfaceBootstrap());
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const controller = new AbortController();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const surfaceTransport = withLocationOrigin("https://host.example", () => createReDevPluginSurfaceTransport({
    apiBaseURL: "https://host.example/plugin-api/",
    fetch: fetch.fetch,
  }));
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/plugin-api/",
    fetch: fetch.fetch,
    surfaceTransport,
  });

  try {
    const opening = withLocationOrigin("https://host.example", () => client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }, { signal: controller.signal, bridgeChannelId: "bridge_12345678" }));
    await waitFor(() => stage.children.length === 1);
    frame.load();
    await waitFor(() => frame.transferred.length === 1);
    channel.port2.applicationReady();
    const host = await opening;

    assert.equal(host.surfaceInstanceId, "surface_1");
    assert.equal(fetch.calls[0]?.input, "https://host.example/plugin-api/_redevplugin/api/plugins/surfaces/open");
    assert.equal(fetch.calls[0]?.init.signal, undefined, "dispatch cancellation must preserve the bootstrap needed for revocation");
    assert.equal(fetch.calls[1]?.input, "https://host.example/plugin-api/_redevplugin/api/plugins/surfaces/surface_1/prepare");
    assert.equal(fetch.calls[2]?.input, "https://host.example/plugin-api/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  } finally {
    fetch.push(surfaceRevocation());
    await slot.dispose();
    restoreDOM();
  }
});

test("platform surface opening aborts before dispatch without fetch or iframe creation", async () => {
  const fetch = new FakeFetch();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const controller = new AbortController();
  controller.abort("closed before dispatch");
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }, { signal: controller.signal }),
    (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "not_committed",
  );
  assert.deepEqual(fetch.calls, []);
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("platform surface opening rejects an empty canonical plugin instance before dispatch", async () => {
  const fetch = new FakeFetch();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.openSurfaceInSlot(slot, {
      plugin_instance_id: "   ",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  assert.deepEqual(fetch.calls, []);
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("platform surface opening uses one canonical plugin instance for dispatch and scope teardown", async () => {
  const fetch = new FakeFetch();
  let resolveOpen!: (response: FetchResponseLike) => void;
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveOpen = resolve; }));
  fetch.push(surfaceRevocation());
  const scope = createPluginSurfaceScope();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });
  const opening = client.openSurfaceInSlot(slot, {
    plugin_instance_id: "  plugin_instance_1  ",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    expected_management_revision: 7,
  });
  await waitFor(() => fetch.calls.length === 1);

  const teardown = disposePluginSurfaceScope(scope, "plugin_instance_1");
  resolveOpen({ ok: true, status: 200, json: async () => ({ ok: true, data: platformSurfaceBootstrap() }) });
  await teardown;
  await assert.rejects(
    opening,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    expected_management_revision: 7,
  });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("platform surface opening on a disposed slot never dispatches", async () => {
  const fetch = new FakeFetch();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  await slot.dispose();
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  assert.throws(
    () => client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  assert.deepEqual(fetch.calls, []);
});

test("platform surface opening waits for bootstrap and revocation after dispatch abort", async () => {
  const frame = new FakeFrame();
  const channel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([frame], [channel]);
  const fetch = new FakeFetch();
  let resolveOpen!: (response: FetchResponseLike) => void;
  let resolveRevoke!: (response: FetchResponseLike) => void;
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveOpen = resolve; }));
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveRevoke = resolve; }));
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const controller = new AbortController();
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  try {
    let settled = false;
    const opening = client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }, { signal: controller.signal }).finally(() => { settled = true; });
    await waitFor(() => fetch.calls.length === 1);
    controller.abort("closed after dispatch");
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(settled, false);
    assert.equal(fetch.calls[0]?.init.signal, undefined);

    resolveOpen({ ok: true, status: 200, json: async () => ({ ok: true, data: platformSurfaceBootstrap() }) });
    await waitFor(() => fetch.calls.length === 2);
    assert.equal(settled, false);
    assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
    assert.equal(stage.children.length, 0);

    resolveRevoke({ ok: true, status: 200, json: async () => ({ ok: true, data: surfaceRevocation() }) });
    await assert.rejects(
      opening,
      (error: unknown) => error instanceof PluginTransportError && error.mutationOutcome === "unknown",
    );
    assert.equal(frame.transferred.length, 0);
  } finally {
    await slot.dispose();
    restoreDOM();
  }
});

test("surface slot dispose waits for a pending server opening lease to revoke", async () => {
  const fetch = new FakeFetch();
  let resolveOpen!: (response: FetchResponseLike) => void;
  let resolveRevoke!: (response: FetchResponseLike) => void;
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveOpen = resolve; }));
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveRevoke = resolve; }));
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });
  const opening = client.openSurfaceInSlot(slot, {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    expected_management_revision: 7,
  });
  await waitFor(() => fetch.calls.length === 1);

  let disposed = false;
  const disposal = slot.dispose().finally(() => { disposed = true; });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(disposed, false);
  resolveOpen({ ok: true, status: 200, json: async () => ({ ok: true, data: platformSurfaceBootstrap() }) });
  await waitFor(() => fetch.calls.length === 2);
  assert.equal(disposed, false);
  resolveRevoke({ ok: true, status: 200, json: async () => ({ ok: true, data: surfaceRevocation() }) });
  await disposal;
  await assert.rejects(
    opening,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("surface scope teardown waits for every registration before reporting failure", async () => {
  const scope = createPluginSurfaceScope();
  const failure = new Error("first teardown failed");
  let releaseSecond!: () => void;
  const second = new Promise<void>((resolve) => { releaseSecond = resolve; });
  registerPluginSurface(scope, "plugin_instance_1", () => { throw failure; }, () => undefined);
  registerPluginSurface(scope, "plugin_instance_2", async () => { await second; }, () => undefined);

  let settled = false;
  const teardown = disposePluginSurfaceScope(scope).finally(() => { settled = true; });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(settled, false);
  releaseSecond();
  await assert.rejects(teardown, (error: unknown) => error === failure);
});

test("surface scope invalidation is local-only, durable for later registrations, and independent from disposal", async () => {
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  let invalidated = 0;
  registerPluginSurface(
    scope,
    "plugin_instance_1",
    () => { disposed += 1; },
    () => { invalidated += 1; },
  );

  await invalidatePluginSurfaceScope(scope);
  registerPluginSurface(
    scope,
    "plugin_instance_2",
    () => { disposed += 1; },
    () => { invalidated += 1; },
  );
  await Promise.resolve();
  await disposePluginSurfaceScope(scope);

  assert.equal(invalidated, 2);
  assert.equal(disposed, 0);
});

test("surface scope canonicalizes plugin instance identifiers at registration and teardown", async () => {
  const scope = createPluginSurfaceScope();
  let disposed = 0;
  registerPluginSurface(scope, "  plugin_instance_1  ", () => { disposed += 1; }, () => undefined);

  await disposePluginSurfaceScope(scope, " plugin_instance_1 ");

  assert.equal(disposed, 1);
});

test("surface scope rejects empty canonical plugin instance identifiers", async () => {
  const scope = createPluginSurfaceScope();

  assert.throws(
    () => registerPluginSurface(scope, "   ", () => undefined, () => undefined),
    (error: unknown) => error instanceof TypeError && error.message === "Plugin instance identifier must be a non-empty string",
  );
  await assert.rejects(
    disposePluginSurfaceScope(scope, "   "),
    (error: unknown) => error instanceof TypeError && error.message === "Plugin instance identifier must be a non-empty string",
  );
});

test("platform surface opening revokes exactly once when host construction fails", async () => {
  const fetch = new FakeFetch();
  fetch.push(platformSurfaceBootstrap({ management_revision: 0 }));
  fetch.push(surfaceRevocation());
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("platform surface opening revokes a bootstrap with a mismatched plugin identity", async () => {
  const fetch = new FakeFetch();
  fetch.push(platformSurfaceBootstrap({ plugin_instance_id: "plugin_instance_other" }));
  fetch.push(surfaceRevocation());
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("surface slot waits for retired surface revocation before opening the next iframe", async () => {
  const firstFrame = new FakeFrame();
  const secondFrame = new FakeFrame();
  const firstChannel = fakeChannel();
  const secondChannel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([firstFrame, secondFrame], [firstChannel, secondChannel]);
  const firstFetch = new FakeFetch();
  const secondFetch = new FakeFetch();
  firstFetch.push(preparation());
  firstFetch.push(gatewayLease());
  secondFetch.push(preparation());
  secondFetch.push(gatewayLease());
  const stage = new FakeStage();
  const states: string[] = [];
  const slot = PluginSurfaceSlot.create({
    stage: stage as unknown as HTMLElement,
    onStateChange: (state) => states.push(state),
  });

  try {
    const firstOpening = openPreparedPluginSurfaceInSlot(slot, {
      bootstrap: hostBootstrap,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: firstFetch.fetch }),
    });
    await waitFor(() => stage.children.length === 1);
    assert.equal(firstFrame.hidden, false, "opening iframe must remain renderable for its animation frames");
    assert.equal(firstFrame.inert, true);
    assert.equal(firstFrame.attributes.get("aria-hidden"), "true");
    assert.equal(firstFrame.style.visibility, "", "opening iframe must remain eligible for animation frames");
    assert.equal(firstFrame.style.opacity, "0", "opening iframe must not flash before first commit");
    assert.equal(firstFrame.style.pointerEvents, "none");
    firstFrame.load();
    await waitFor(() => firstFrame.transferred.length === 1);
    firstChannel.port2.applicationReady();
    await firstOpening;
    assert.equal(firstFrame.hidden, false);
    assert.equal(firstFrame.inert, false);
    assert.equal(firstFrame.attributes.get("aria-hidden"), "false");
    assert.equal(firstFrame.style.visibility, "");
    assert.equal(firstFrame.style.opacity, "");
    assert.equal(firstFrame.style.pointerEvents, "");

    firstFetch.push(surfaceRevocation());
    const secondOpening = openPreparedPluginSurfaceInSlot(slot, {
      bootstrap: {
        ...hostBootstrap,
        surfaceInstanceId: "surface_2",
        bridgeNonce: "bridge_nonce_2",
      },
      hostTransport: createReDevPluginSurfaceTransport({ fetch: secondFetch.fetch }),
    });
    await waitFor(() => firstFrame.hidden && firstFrame.inert);
    assert.equal(stage.children.length, 1);
    assert.equal(firstFrame.hidden, true);
    assert.equal(firstFrame.inert, true);
    assert.equal(firstFrame.attributes.get("aria-hidden"), "true");
    assert.equal(firstFrame.style.visibility, "");
    assert.equal(firstFrame.style.opacity, "");
    assert.equal(firstFrame.style.pointerEvents, "none");

    const firstQuiesce = await waitForQuiesce(firstChannel.port1);
    firstChannel.port2.postMessage({
      type: "redevplugin.surface.quiesce_ack",
      quiesce_id: firstQuiesce,
    });
    await waitFor(() => firstFrame.removed);
    await waitFor(() => stage.children.at(-1) === secondFrame);
    assert.equal(firstFrame === secondFrame, false);

    secondFrame.load();
    await waitFor(() => secondFrame.transferred.length === 1);
    secondChannel.port2.applicationReady();
    await secondOpening;
    assert.equal(secondFrame.hidden, false);
    assert.equal(secondFrame.inert, false);
    assert.equal(secondFrame.attributes.get("aria-hidden"), "false");
    assert.equal(secondFrame.style.visibility, "");
    assert.equal(secondFrame.style.pointerEvents, "");

    secondFetch.push(surfaceRevocation());
    const closing = slot.close();
    const secondQuiesce = await waitForQuiesce(secondChannel.port1);
    secondChannel.port2.postMessage({
      type: "redevplugin.surface.quiesce_ack",
      quiesce_id: secondQuiesce,
    });
    await closing;
    assert.equal(secondFrame.removed, true);
    assert.deepEqual(states, ["empty", "opening", "ready", "opening", "ready", "empty"]);
  } finally {
    await slot.dispose();
    restoreDOM();
  }
});

test("surface lifecycle observers cannot interrupt opening or revocation", async () => {
  const frame = new FakeFrame();
  const channel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([frame], [channel]);
  const fetch = new FakeFetch();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  fetch.push(surfaceRevocation());
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({
    stage: stage as unknown as HTMLElement,
    onStateChange: () => { throw new Error("state observer failed"); },
    onSurfaceClosed: () => { throw new Error("close observer failed"); },
  });

  try {
    const opening = openPreparedPluginSurfaceInSlot(slot, {
      bootstrap: hostBootstrap,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
      onOpeningProgress: () => { throw new Error("progress observer failed"); },
    });
    await waitFor(() => stage.children.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 320));
    frame.load();
    await waitFor(() => frame.transferred.length === 1);
    channel.port2.applicationReady();
    await opening;

    const closing = slot.close();
    const quiesce = await waitForQuiesce(channel.port1);
    channel.port2.postMessage({ type: "redevplugin.surface.quiesce_ack", quiesce_id: quiesce });
    const result = await closing;
    assert.equal(result?.quiesce.outcome, "acknowledged");
    assert.equal(frame.removed, true);
    assert.equal(stage.dataset.redevpluginSurfaceState, "empty");
    assert.equal(fetch.calls.at(-1)?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  } finally {
    await slot.dispose();
    restoreDOM();
  }
});

test("surface slot fails closed, revokes the queued lease, and reconciles an unknown cleanup result", async () => {
  const firstFrame = new FakeFrame();
  const replacementFrame = new FakeFrame();
  const firstChannel = fakeChannel();
  const replacementChannel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([firstFrame, replacementFrame], [firstChannel, replacementChannel]);
  const firstFetch = new FakeFetch();
  firstFetch.push(preparation());
  firstFetch.push(gatewayLease());
  firstFetch.push({
    ok: false,
    error: {
      code: "PLUGIN_RUNTIME_UNAVAILABLE",
      message: "surface cleanup failed",
      details: {},
      mutation_outcome: "unknown",
    },
  }, 503);
  const secondFetch = new FakeFetch();
  secondFetch.push(platformSurfaceBootstrap({ surface_instance_id: "surface_2", bridge_nonce: "bridge_nonce_2" }));
  secondFetch.push(surfaceRevocation());
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });

  try {
    const firstOpening = openPreparedPluginSurfaceInSlot(slot, {
      bootstrap: hostBootstrap,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: firstFetch.fetch }),
    });
    await waitFor(() => stage.children.length === 1);
    firstFrame.load();
    await waitFor(() => firstFrame.transferred.length === 1);
    firstChannel.port2.applicationReady();
    await firstOpening;

    const client = new PluginPlatformClient({ fetch: secondFetch.fetch });
    const secondOpening = client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_2",
      expected_management_revision: 7,
    });
    const quiesce = await waitForQuiesce(firstChannel.port1);
    firstChannel.port2.postMessage({ type: "redevplugin.surface.quiesce_ack", quiesce_id: quiesce });
    await assert.rejects(
      secondOpening,
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_RUNTIME_UNAVAILABLE",
    );
    assert.equal(secondFetch.calls.length, 2, "queued server surface must be revoked after prior cleanup failure");
    assert.equal(secondFetch.calls[1]?.input, "/_redevplugin/api/plugins/surfaces/surface_2/dispose");
    assert.equal(stage.children.length, 1, "no replacement iframe may be created after cleanup failure");

    firstFetch.push({ disposed: true, state: "closed", previous_state: "closed", revoked: false });
    const reconciled = await slot.close();
    if (!reconciled?.revocation) throw new Error("expected reconciled surface revocation");
    assert.equal(reconciled.revocation.state, "closed");
    assert.equal(firstFetch.calls.filter((call) => call.input.endsWith("/dispose")).length, 2);
    for (const call of firstFetch.calls.filter((candidate) => candidate.input.endsWith("/dispose"))) {
      assert.equal(call.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
      assert.deepEqual(JSON.parse(call.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
    }

    const replacementFetch = new FakeFetch();
    replacementFetch.push(preparation());
    replacementFetch.push(gatewayLease());
    const replacementOpening = openPreparedPluginSurfaceInSlot(slot, {
      bootstrap: { ...hostBootstrap, surfaceInstanceId: "surface_3", bridgeNonce: "bridge_nonce_3" },
      hostTransport: createReDevPluginSurfaceTransport({ fetch: replacementFetch.fetch }),
    });
    await waitFor(() => stage.children.at(-1) === replacementFrame);
    replacementFrame.load();
    await waitFor(() => replacementFrame.transferred.length === 1);
    replacementChannel.port2.applicationReady();
    await replacementOpening;
    assert.equal(replacementFrame.hidden, false);

    replacementFetch.push(surfaceRevocation());
    const replacementClosing = slot.close();
    const replacementQuiesce = await waitForQuiesce(replacementChannel.port1);
    replacementChannel.port2.postMessage({
      type: "redevplugin.surface.quiesce_ack",
      quiesce_id: replacementQuiesce,
    });
    await replacementClosing;
  } finally {
    await slot.dispose();
    restoreDOM();
  }
});

test("surface slot keeps only the latest unresolved opening and exposes its error", async () => {
  const stage = new FakeStage();
  const errors: Array<PluginBridgeError | undefined> = [];
  const slot = PluginSurfaceSlot.create({
    stage: stage as unknown as HTMLElement,
    onStateChange: (state, error) => {
      if (state === "error") errors.push(error);
    },
  });
  let resolveFirst!: (options: PluginSurfaceHostOptions) => void;
  const firstOptions = new Promise<PluginSurfaceHostOptions>((resolve) => {
    resolveFirst = resolve;
  });
  const firstOpening = openPreparedPluginSurfaceInSlot(slot, firstOptions);
  const latestError = new Error("surface options failed");
  const latestOpening = openPreparedPluginSurfaceInSlot(slot, Promise.reject(latestError));

  resolveFirst({} as PluginSurfaceHostOptions);
  await assert.rejects(
    firstOpening,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  await assert.rejects(latestOpening, (error: unknown) => error === latestError);
  assert.equal(stage.dataset.redevpluginSurfaceState, "error");
  assert.equal(errors[0]?.errorCode, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
  assert.equal(stage.children.length, 0);
  await slot.dispose();
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
  channel.port2.applicationReady();
  await opening;

  fetch.push(surfaceRevocation());
  host.dispose();
  await waitFor(() => fetch.calls.length === 3);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(fetch.calls[2]?.init.method, "POST");
  assert.equal(fetch.calls[2]?.init.keepalive, true);
	assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  assert.equal(channel.port1.closed, true);
  assert.equal(frame.src, "about:blank");
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
  channel.port2.applicationReady();
  await opening;

  fetch.push(surfaceRevocation());
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
  channel.port2.applicationReady();
  await opening;

  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_non_json", method: "echo.invalid", params: { value: new Map([["unexpected", true]]) } },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(fetch.calls.some((call) => call.input.endsWith("/rpc")), false);
  host.dispose();
});

test("trusted parent accepts only current port-bound interaction ownership signals and bounds floods", async () => {
  const frame = new FakeFrameWithoutCredentialless();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const wrongChannel = fakeChannel();
  const interactions: PluginSurfaceInteractionEvent[] = [];
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onInteraction: (event) => interactions.push(event),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  const message = (sequence: number, overrides: Record<string, unknown> = {}) => ({
    type: "redevplugin.surface.interaction",
    frame_generation_id: host.frameGenerationId,
    surface_handle: host.surfaceHandle,
    sequence,
    kind: "activation",
    target_key: null,
    action: null,
    local_scroll: false,
    selection_active: false,
    ...overrides,
  });
  wrongChannel.port2.postMessage(message(1));
  channel.port2.postMessage(message(1, { unexpected: true }));
  channel.port2.postMessage(message(1, { frame_generation_id: "frame_stale123" }));
  channel.port2.postMessage(message(1));
  channel.port2.postMessage(message(1));
  channel.port2.postMessage(message(2, { surface_handle: "surface_stale123" }));
  channel.port2.postMessage(message(2, { kind: "wheel", local_scroll: true }));
  channel.port2.postMessage(message(3, { frame_generation_id: "frame_stale123" }));
  channel.port2.postMessage(message(4, { kind: "action", action: ":open" }));
  for (let sequence = 5; sequence <= 142; sequence += 1) channel.port2.postMessage(message(sequence));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(interactions[0]?.sequence, 1);
  assert.deepEqual(interactions[1], { kind: "wheel", sequence: 2, localScroll: true, selectionActive: false });
  assert.deepEqual(interactions[2], { kind: "action", sequence: 4, action: ":open", localScroll: false, selectionActive: false });
  assert.equal(interactions.length, 120);

  await new Promise((resolve) => setTimeout(resolve, 1010));
  channel.port2.postMessage(message(143));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(interactions.at(-1)?.sequence, 143);
  assert.equal(interactions.length, 121);

  fetch.push({ disposed: true, state: "closed", previous_state: "active", revoked: true });
  await host.dispose();
  channel.port2.postMessage(message(144));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(interactions.length, 121);
});

test("trusted parent asks the host to authorize every file export", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const exports: Array<{ fileName: string; mediaType: string; bytes: number[] }> = [];
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onFileExport: async ({ fileName, mediaType, bytes }) => {
      if (exports.length) throw new PluginBridgeError("PLUGIN_ACTION_DENIED", "The user declined the export");
      exports.push({ fileName, mediaType, bytes: [...bytes] });
    },
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  channel.port2.postMessage({
    type: "redevplugin.surface.interaction",
    frame_generation_id: host.frameGenerationId,
    surface_handle: host.surfaceHandle,
    sequence: 1,
    kind: "action",
    target_key: "export-png",
    action: "export-png",
    local_scroll: false,
    selection_active: false,
  });
  channel.port2.postMessage({
    type: "redevplugin.surface.file.export",
    frame_generation_id: host.frameGenerationId,
    surface_handle: host.surfaceHandle,
    id: "file_1",
    file_name: "map.png",
    media_type: "image/png",
    content: new Uint8Array([1, 2, 3]).buffer,
  });
  await waitFor(() => channel.port1.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.response") && (message as { id?: string }).id === "file_1"
  ));
  assert.deepEqual(exports, [{ fileName: "map.png", mediaType: "image/png", bytes: [1, 2, 3] }]);
  assert.deepEqual(channel.port1.sent.at(-1), { type: "redevplugin.bridge.response", id: "file_1", ok: true });

  channel.port2.postMessage({
    type: "redevplugin.surface.file.export",
    frame_generation_id: host.frameGenerationId,
    surface_handle: host.surfaceHandle,
    id: "file_2",
    file_name: "map.png",
    media_type: "image/png",
    content: new Uint8Array([4]).buffer,
  });
  await waitFor(() => channel.port1.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.response") && (message as { id?: string }).id === "file_2"
  ));
  assert.equal(exports.length, 1);
  assert.equal((channel.port1.sent.at(-1) as { error_code?: string }).error_code, "PLUGIN_ACTION_DENIED");

  fetch.push({ disposed: true, state: "closed", previous_state: "active", revoked: true });
  await host.dispose();
});


test("trusted parent routes current execution cancellation, snapshot, and events", async () => {
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
  channel.port2.applicationReady();
  await opening;

  const execution = {
    execution_id: "execution_12345678",
    plugin_instance_id: "plugin_instance_1",
    kind: "subscription",
    cursor: 1,
    status: "running",
    cancelable: true,
    created_at: "2026-08-13T00:00:00Z",
    updated_at: "2026-08-13T00:00:01Z",
  } as const;
  fetch.push(execution);
  fetch.push(execution);
  fetch.push({
    execution_id: execution.execution_id,
    events: [{
      execution_id: execution.execution_id,
      sequence: 1,
      kind: "data",
      payload: { event_type: "LogsEvent", data: "e30=" },
      future_metadata: { source: "runtime" },
    }],
    cursor: 1,
    future_trace: "trace_1",
  });
  channel.port2.postMessage({ type: "redevplugin.bridge.execution.cancel", id: "execution_1", execution_id: execution.execution_id, reason: "user canceled" });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "execution_1"));
  channel.port2.postMessage({ type: "redevplugin.bridge.execution.query", id: "execution_2", execution_id: execution.execution_id });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "execution_2"));
  channel.port2.postMessage({ type: "redevplugin.bridge.execution.events", id: "execution_3", execution_id: execution.execution_id, after_cursor: 0 });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "execution_3"));

  assert.deepEqual(fetch.calls.slice(2).map((call) => ({
    input: call.input,
    body: JSON.parse(call.init.body ?? "{}"),
  })), [
    { input: "/_redevplugin/api/plugins/executions/execution_12345678/cancel", body: { reason: "user canceled" } },
    { input: "/_redevplugin/api/plugins/executions/execution_12345678/query", body: {} },
    { input: "/_redevplugin/api/plugins/executions/execution_12345678/events/query", body: { after_cursor: 0 } },
  ]);
  const eventsResponse = channel.port1.sent.find((value) => (value as { id?: string }).id === "execution_3") as { ok: boolean; data: { cursor: number } };
  assert.equal(eventsResponse.ok, true);
  assert.equal(eventsResponse.data.cursor, 1);
  host.dispose();
});

test("execution event reader rejects unknown event kinds", async () => {
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
  channel.port2.applicationReady();
  await opening;

  fetch.push({
    execution_id: "execution_12345678",
    events: [{ execution_id: "execution_12345678", sequence: 1, kind: "future_kind" }],
    cursor: 1,
  });
  channel.port2.postMessage({
    type: "redevplugin.bridge.execution.events",
    id: "execution_1",
    execution_id: "execution_12345678",
    after_cursor: 0,
  });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "execution_1"));

  const response = channel.port1.sent.find((value) => (value as { id?: string }).id === "execution_1") as {
    ok: boolean;
    error_code?: string;
  };
  assert.equal(response.ok, false);
  assert.equal(response.error_code, "PLUGIN_CONTRACT_MISMATCH");
  host.dispose();
});

test("confirmation rejection waits for lease renewal before capturing the gateway token", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const issuedAt = new Date();
  let resolveDecision: ((decision: boolean) => void) | undefined;
  let markRenewalStarted: (() => void) | undefined;
  const renewalStarted = new Promise<void>((resolve) => {
    markRenewalStarted = resolve;
  });
  fetch.push(preparation());
  fetch.push(gatewayLease({
    issued_at: issuedAt.toISOString(),
    expires_at: new Date(issuedAt.getTime() + 1_000).toISOString(),
  }));
  fetch.push({ ok: false, error: { code: "PLUGIN_CONFIRMATION_REQUIRED", message: "confirmation required", details: {}, mutation_outcome: "not_committed" } }, 409);
  fetch.push({
    confirmation_id: "confirmation_renewal_1",
    confirmation_token_id: "confirmation_token_renewal_1",
    request_hash: digest("1"),
    plan_hash: digest("2"),
  });
  fetch.pushHandler(async () => {
    markRenewalStarted!();
    await new Promise((resolve) => setTimeout(resolve, 20));
    return {
      ok: true,
      status: 200,
      json: async () => ({ ok: true, data: gatewayLease({
        plugin_gateway_token: "gateway_secret_2",
        plugin_gateway_token_id: "gateway_token_2",
        asset_session: "asset_session_rotated_2",
        asset_session_id: "asset_session_id_rotated_2",
      }) }),
    };
  });
  fetch.push({ rejected: true });
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    leaseRenewalLeadMs: 500,
    confirm: () => new Promise<boolean>((resolve) => {
      resolveDecision = resolve;
    }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "danger.run", params: { target: "database" } },
  });
  await waitFor(() => resolveDecision !== undefined);
  await renewalStarted;
  resolveDecision!(false);
  await waitFor(() => fetch.calls.length === 6);
  assert.equal(JSON.parse(fetch.calls[5]?.init.body ?? "").plugin_gateway_token, "gateway_secret_2");
  host.dispose();
});

test("trusted parent forwards validated capability error details without credentials", async () => {
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
  channel.port2.applicationReady();
  await opening;

  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_CAPABILITY_ERROR",
      message: "host capability request failed",
      details: {
        capability_id: "example.capability.documents",
        capability_version: "1.0.0",
        detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        business_error_code: "DOCUMENT_NOT_FOUND",
        business_error_details: { document_id: "doc-missing" },
      },
      mutation_outcome: "not_committed",
    },
  }, 422);
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "documents.get", params: { document_id: "doc-missing" } },
  });
  await waitFor(() => fetch.calls.length === 3);
  const response = [...channel.port1.sent].reverse().find((value) =>
    (value as { id?: string }).id === "rpc_1"
  ) as { error_code?: string; error_details?: Record<string, unknown>; mutation_outcome?: string };
  assert.equal(response.error_code, "PLUGIN_CAPABILITY_ERROR");
  assert.deepEqual(response.error_details, {
    capability_id: "example.capability.documents",
    capability_version: "1.0.0",
    detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    business_error_code: "DOCUMENT_NOT_FOUND",
    business_error_details: { document_id: "doc-missing" },
  });
  assert.equal(JSON.stringify(response).includes("gateway"), false);
  host.dispose();
});

test("trusted parent converts oversized capability error details into a bounded bridge error", async () => {
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
  channel.port2.applicationReady();
  await opening;

  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_CAPABILITY_ERROR",
      message: "host capability request failed",
      details: {
        capability_id: "example.capability.documents",
        capability_version: "1.0.0",
        detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        business_error_code: "DOCUMENT_NOT_FOUND",
        business_error_details: { payload: "x".repeat((1024 * 1024)) },
      },
      mutation_outcome: "not_committed",
    },
  }, 422);
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_103", method: "documents.get", params: { document_id: "doc-missing" } },
  });
  await waitFor(() => channel.port1.sent.some((value) =>
    (value as { id?: string }).id === "rpc_103"
  ));
  const response = [...channel.port1.sent].reverse().find((value) =>
    (value as { id?: string }).id === "rpc_103"
  ) as { error_code?: string; error_details?: Record<string, unknown>; mutation_outcome?: string };
  host.dispose();
  assert.equal(response.error_code, "PLUGIN_JSON_LIMIT_EXCEEDED");
  assert.equal(response.error_details, undefined);
  assert.equal(response.mutation_outcome, "not_committed");
  assert.equal(new TextEncoder().encode(JSON.stringify(response)).byteLength <= (1024 * 1024), true);
});

test("trusted parent marks a lost RPC response as an unknown mutation outcome", async () => {
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
  channel.port2.applicationReady();
  await opening;

  let backendCommitted = false;
  fetch.pushHandler(async () => {
    backendCommitted = true;
    throw new Error("response connection closed");
  });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "memos.delete", params: { id: "memo_1" } },
  });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_1"));
  const response = channel.port1.sent.find((value) => (value as { id?: string }).id === "rpc_1") as {
    ok?: boolean;
    error_code?: string;
    mutation_outcome?: string;
  };
  assert.equal(backendCommitted, true);
  assert.equal(response.ok, false);
  assert.equal(response.error_code, "PLUGIN_PERMISSION_DENIED");
  assert.equal(response.mutation_outcome, "unknown");
  host.dispose();
});

test("trusted parent marks an RPC transport timeout as an unknown mutation outcome", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    bridgeChannelId: "bridge_12345678",
    requestTimeoutMs: 10,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  fetch.pushHandler(async () => new Promise<FetchResponseLike>(() => undefined));
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "memos.delete", params: { id: "memo_1" } },
  });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_1"));
  const response = channel.port1.sent.find((value) => (value as { id?: string }).id === "rpc_1") as {
    ok?: boolean;
    error_code?: string;
    mutation_outcome?: string;
  };
  assert.equal(response.ok, false);
  assert.equal(response.error_code, "PLUGIN_BRIDGE_TIMEOUT");
  assert.equal(response.mutation_outcome, "unknown");
  host.dispose();
});

test("trusted parent converts oversized RPC responses into a bounded bridge error", async () => {
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
  channel.port2.applicationReady();
  await opening;

  fetch.push({ data: { payload: "x".repeat((1024 * 1024) - 32 * 1024) } });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_101", method: "payload.read", params: {} },
  });
  await waitFor(() => fetch.calls.length === 3);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(
    channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_101"),
    true,
    JSON.stringify(channel.port1.sent),
  );
  const accepted = channel.port1.sent.find((value) => (value as { id?: string }).id === "rpc_101") as { ok?: boolean };
  assert.equal(accepted.ok, true);

  fetch.push({ data: { payload: "x".repeat((1024 * 1024) + 32 * 1024) } });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_102", method: "payload.read", params: {} },
  });
  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_102"));
  const rejected = channel.port1.sent.find((value) => (value as { id?: string }).id === "rpc_102") as {
    ok?: boolean;
    error_code?: string;
  };
  assert.equal(rejected.ok, false);
  assert.equal(rejected.error_code, "PLUGIN_JSON_LIMIT_EXCEEDED");
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
  channel.port2.applicationReady();
  await opening;

  fetch.push({ ok: false, error: { code: "PLUGIN_CONFIRMATION_REQUIRED", message: "confirmation required", details: {}, mutation_outcome: "not_committed" } }, 409);
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

test("surface confirmation rejection is recorded before the plugin receives its terminal error", async () => {
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
    confirm: () => false,
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  fetch.push({ ok: false, error: { code: "PLUGIN_CONFIRMATION_REQUIRED", message: "confirmation required", details: {}, mutation_outcome: "not_committed" } }, 409);
  fetch.push({
    confirmation_id: "confirmation_1",
    confirmation_token_id: "confirmation_token_1",
    request_hash: digest("1"),
    plan_hash: digest("2"),
  });
  fetch.push({ rejected: true });
  channel.port2.postMessage({
    type: "redevplugin.bridge.call",
    request: { id: "rpc_1", method: "danger.run", params: { target: "database" } },
  });

  await waitFor(() => channel.port1.sent.some((value) => (value as { id?: string }).id === "rpc_1"));
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/confirmations/prepare");
  assert.equal(fetch.calls[3]?.init.method, "POST");
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/confirmations/reject");
  assert.deepEqual(JSON.parse(fetch.calls[4]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    bridge_channel_id: "bridge_12345678",
    plugin_gateway_token: "gateway_secret",
    confirmation_id: "confirmation_1",
  });
  assert.deepEqual(channel.port1.sent.at(-1), {
    type: "redevplugin.bridge.response",
    id: "rpc_1",
    ok: false,
    error_code: "PLUGIN_CONFIRMATION_REJECTED",
    error: "Plugin method confirmation was rejected",
  });
  host.dispose();
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
  channel.port2.applicationReady();
  await opening;
  host.dispose();
});

test("surface host applies and updates context without replacing the iframe", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const initialContext = {
    schema_version: "redevplugin.surface_context.v1",
    revision: 1,
    appearance: {
      color_scheme: "dark",
      colors: {
        canvas: "#101010", surface: "#181818", surface_elevated: "#202020", text: "#ffffff", text_muted: "#aaaaaa", border: "#444444",
        accent: "#66aaff", accent_text: "#000000", success: "#44cc88", warning: "#ffcc44", danger: "#ff6677", focus: "#88bbff",
      },
    },
    locale: { language_tag: "zh-CN", direction: "ltr" },
  } as const;
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceContext: initialContext,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });
  const originalElement = host.element;

  const opening = host.open();
  frame.load();
  await waitFor(() => channel.port1.sent.some((message) => isMessageType(message, "redevplugin.surface.initialize")));
  const originalSource = frame.srcdoc;
  const initialize = channel.port1.sent.find((message) => isMessageType(message, "redevplugin.surface.initialize")) as {
    context?: unknown;
  };
  assert.deepEqual(initialize.context, initialContext, "initial context must cross the private port before renderer readiness");

  const openingContext = { ...initialContext, revision: 2, locale: { language_tag: "en-US", direction: "ltr" as const } };
  host.updateContext(openingContext);
  assert.deepEqual(channel.port1.sent.at(-1), {
    type: "redevplugin.surface.context",
    frame_generation_id: host.frameGenerationId,
    surface_handle: host.surfaceHandle,
    context: openingContext,
  });
  assert.throws(() => host.updateContext(openingContext), (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST"
  );
  assert.equal(host.element, originalElement);
  assert.equal(frame.srcdoc, originalSource);
  assert.equal(frame.transferred.length, 1);

  channel.port2.applicationReady();
  await opening;
  const readyContext = { ...openingContext, revision: 3 };
  host.updateContext(readyContext);
  assert.deepEqual((channel.port1.sent.at(-1) as { context?: unknown }).context, readyContext);
  assert.equal(host.element, originalElement);
  assert.equal(frame.transferred.length, 1);
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
  void opening.catch(() => undefined);
  try {
    frame.load();
    await new Promise((resolve) => setTimeout(resolve, 320));
    assert.equal(progress.length, 1);
    assert.equal(progress[0]! >= 300, true);
    channel.port2.applicationReady();
    await opening;
  } finally {
    host.dispose();
  }
});

for (const milestone of ["prepare", "origin", "entry_ready", "port_ack", "token", "app_ready"] as const) {
  test("opening deadline identifies and tears down stalled " + milestone, async () => {
    const frame = new FakeFrame();
    const fetch = new FakeFetch();
    const channel = fakeChannel();
    const limiter = new PluginSurfaceReloadLimiter();
    const pending = () => new Promise<FetchResponseLike>(() => undefined);
    if (milestone === "prepare") fetch.pushHandler(pending);
    else fetch.push(preparation());
    if (milestone === "token") fetch.pushHandler(pending);
    else if (milestone === "app_ready") fetch.push(gatewayLease());
    if (milestone === "port_ack") frame.autoAcknowledge = false;
    const host = createSurfaceHost(frame, {
      bootstrap: hostBootstrap, testMessageChannel: channel,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
      loadTimeoutMs: 35, requestTimeoutMs: 100, reloadLimiter: limiter,
      prepareWebOrigin: milestone === "origin" ? () => new Promise<void>(() => undefined) : undefined,
    });
    const opening = host.open();
    if (milestone !== "entry_ready") frame.load();
    await assert.rejects(opening, (error: unknown) => {
      if (!(error instanceof PluginBridgeError)) return false;
      assert.equal(error.errorCode, "PLUGIN_BRIDGE_TIMEOUT");
      const details = error.details as { pendingMilestones: string[]; elapsedMs: number; stageElapsedMs: number };
      assert.deepEqual(details.pendingMilestones, [milestone]);
      assert.equal(details.elapsedMs >= 0 && details.stageElapsedMs >= 0, true);
      assert.equal(JSON.stringify(details).includes("secret"), false);
      return true;
    });
    assert.equal(frame.src, "about:blank");
    assert.equal(limiter.state.reloads, 1);
    assert.equal(fetch.calls.at(-1)?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
    if (["port_ack", "token", "app_ready"].includes(milestone)) assert.equal(channel.port1.closed, true);
    if (milestone === "prepare" || milestone === "token") assert.equal(fetch.calls.find(call => call.input.endsWith("/" + (milestone === "prepare" ? "prepare" : "bridge-token")))?.init.signal?.aborted, true);
  });
}

test("surface opening deadline revokes server state, tears down locally, and remains retryable", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  const reloadLimiter = new PluginSurfaceReloadLimiter();
  fetch.push(preparation());
  fetch.pushHandler(async () => {
    await new Promise((resolve) => setTimeout(resolve, 60));
    return { ok: true, status: 200, json: async () => ({ ok: true, data: gatewayLease() }) };
  });
  fetch.push({ disposed: true, state: "closed", previous_state: "active", revoked: true });
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
      channel.port2.applicationReady();
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
  assert.equal(frame.src, "about:blank");
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
  retryChannel.port2.applicationReady();
  await retryOpening;
  assert.deepEqual(reloadLimiter.state, { reloads: 0, remaining: 2, windowStartedAtMs: undefined, nextRetryAtMs: undefined });
  retryHost.dispose();
});

test("plugin bridge rejects malformed handles and disposed calls", async () => {
  const { port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678" });
  assert.throws(() => client.executionEvents("execution", 0), (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST");
  client.dispose();
  assert.throws(() => client.call("echo.ping"), (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED");
});

test("surface host revokes a server session when disposed before open", async () => {
  const fetch = new FakeFetch();
  fetch.push(surfaceRevocation());
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

test("surface host retries reconciliation after a lost close response with the same identity", async () => {
  const fetch = new FakeFetch();
  fetch.pushHandler(async () => { throw new Error("response lost"); });
  fetch.push(surfaceRevocation({ previous_state: "closed", revoked: false }));
  const host = createSurfaceHost(new FakeFrame(), {
    bootstrap: hostBootstrap,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
  });

  await assert.rejects(
    host.close(),
    (error: unknown) => error instanceof PluginBridgeError &&
      error.errorCode === "PLUGIN_BRIDGE_DISPOSED" && error.mutationOutcome === "unknown",
  );
  const result = await host.close();
  if (!result.revocation) throw new Error("expected reconciled surface revocation");
  assert.equal(result.revocation.state, "closed");
  assert.equal(fetch.calls.length, 2);
  for (const call of fetch.calls) {
    assert.equal(call.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
    assert.deepEqual(JSON.parse(call.init.body ?? ""), { bridge_nonce: "bridge_nonce_1" });
  }
});

test("session scope revoke locally invalidates active hosts without per-surface HTTP", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const surfaceFetch = new FakeFetch();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: surfaceFetch.fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push(sessionScopeRevokeResult());
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  assert.equal((await client.revokeSessionScope()).state, "complete");
  assert.equal(frame.src, "about:blank");
  assert.equal(frame.removed, true);
  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  assert.equal(fetch.calls.length, 1);
  assert.equal(surfaceFetch.calls.length, 0);
});

test("session scope revoke cancels an opening slot locally without follow-up HTTP", async () => {
  const fetch = new FakeFetch();
  let resolveOpen!: (response: FetchResponseLike) => void;
  fetch.pushHandler(async () => new Promise<FetchResponseLike>((resolve) => { resolveOpen = resolve; }));
  fetch.push(sessionScopeRevokeResult());
  const scope = createPluginSurfaceScope();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });
  const opening = client.openSurfaceInSlot(slot, {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    expected_management_revision: 7,
  });
  await waitFor(() => fetch.calls.length === 1);

  await client.revokeSessionScope();
  assert.equal(stage.dataset.redevpluginSurfaceState, "empty");
  resolveOpen({ ok: true, status: 200, json: async () => ({ ok: true, data: platformSurfaceBootstrap() }) });

  await assert.rejects(opening, (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED"
  );
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/surfaces/open");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/session/revoke-scope");
  assert.equal(stage.children.length, 0);
  await slot.dispose();
});

test("an invalidated session scope rejects later surface openings before dispatch", async () => {
  const fetch = new FakeFetch();
  fetch.push(sessionScopeRevokeResult());
  const scope = createPluginSurfaceScope();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.revokeSessionScope();
  await assert.rejects(client.openSurfaceInSlot(slot, {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.view",
    surface_instance_id: "surface_1",
    expected_management_revision: 7,
  }), (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED");

  assert.equal(fetch.calls.length, 1);
  assert.equal(stage.children.length, 0);
  assert.equal(stage.dataset.redevpluginSurfaceState, "empty");
  await slot.dispose();
});

test("session scope revoke invalidates a ready slot and closes its local channel without follow-up HTTP", async () => {
  const frame = new FakeFrame();
  const channel = fakeChannel();
  const restoreDOM = installSurfaceSlotDOM([frame], [channel]);
  const fetch = new FakeFetch();
  fetch.push(platformSurfaceBootstrap());
  fetch.push(preparation());
  fetch.push(gatewayLease());
  fetch.push(sessionScopeRevokeResult());
  const scope = createPluginSurfaceScope();
  const stage = new FakeStage();
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  try {
    const opening = client.openSurfaceInSlot(slot, {
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.view",
      surface_instance_id: "surface_1",
      expected_management_revision: 7,
    });
    await waitFor(() => stage.children.length === 1);
    frame.load();
    await waitFor(() => frame.transferred.length === 1);
    channel.port2.applicationReady();
    await opening;

    await client.revokeSessionScope();

    assert.equal(frame.src, "about:blank");
    assert.equal(frame.removed, true);
    assert.equal(channel.port1.closed, true);
    assert.equal(stage.dataset.redevpluginSurfaceState, "empty");
    assert.equal(fetch.calls.length, 4);
    assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/session/revoke-scope");
  } finally {
    await slot.dispose();
    restoreDOM();
  }
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
    enable_state: "disabled_by_user",
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await client.disablePlugin({ plugin_instance_id: hostBootstrap.pluginInstanceId, expected_management_revision: 7 });
  assert.equal(frame.src, "about:blank");
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
  enable_state: "disabled_by_user",
};

const releaseRef = {
  source_id: "official",
  channel: "stable",
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
      expected_management_revision: 7,
    }),
  },
  {
    name: "downgrade",
    run: (client: PluginPlatformClient) => client.downgradePlugin({
      plugin_instance_id: hostBootstrap.pluginInstanceId,
      version: "0.9.0",
      expected_management_revision: 7,
    }),
  },
  {
    name: "uninstall",
    run: (client: PluginPlatformClient) => client.uninstallPlugin({
      plugin_instance_id: hostBootstrap.pluginInstanceId,
      expected_management_revision: 7,
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

test("not-committed plugin mutation keeps the matching local surface host", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.push({
    ok: false,
    error: {
      code: "PLUGIN_MANAGEMENT_REVISION_MISMATCH",
      message: "stale state",
      details: {
        plugin_instance_id: hostBootstrap.pluginInstanceId,
        expected_management_revision: 6,
        actual_management_revision: 7,
      },
      mutation_outcome: "not_committed",
    },
  }, 409);
  const client = new PluginPlatformClient({ fetch: fetch.fetch, surfaceScope: scope });

  await assert.rejects(() => client.disablePlugin({
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    expected_management_revision: 6,
  }));

  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED",
  );
  host.dispose();
});

test("unknown plugin mutation outcome closes the surface and notifies the shell", async () => {
  const frame = new FakeFrame();
  const scope = createPluginSurfaceScope();
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    surfaceScope: scope,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: new FakeFetch().fetch }),
  });
  const fetch = new FakeFetch();
  fetch.pushHandler(async () => {
    throw new Error("connection closed");
  });
  const unknown: Array<string | undefined> = [];
  const client = new PluginPlatformClient({
    fetch: fetch.fetch,
    surfaceScope: scope,
    onMutationOutcomeUnknown: (pluginInstanceId) => unknown.push(pluginInstanceId),
  });

  await assert.rejects(() => client.disablePlugin({
    plugin_instance_id: hostBootstrap.pluginInstanceId,
    expected_management_revision: 7,
  }));

  assert.deepEqual(unknown, [hostBootstrap.pluginInstanceId]);
  assert.throws(
    () => host.sendLifecycle({ type: "hidden" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
});

test("runtime stop preserves host-owned UI-only surface scope", async () => {
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
		(error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED",
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

	await client.updateLocalPackage(hostBootstrap.pluginInstanceId, 7, new Blob(["pkg"]));

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
  assert.equal(frame.src, "about:blank");
});

test("surface close bounds a non-responsive plugin quiesce", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation());
  fetch.push(gatewayLease());
  const errors: PluginBridgeError[] = [];
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap,
    requestTimeoutMs: 10,
    testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    onError: (error) => errors.push(error),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  fetch.push(surfaceRevocation());
  const result = await Promise.race([
    host.close(),
    new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 100)),
  ]);
  assert.equal(result === "hung", false);
  assert.equal(typeof result === "string" ? result : result.quiesce.outcome, "timed_out");
  assert.equal(errors[0]?.errorCode, "PLUGIN_SURFACE_QUIESCE_TIMEOUT");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/dispose");
  assert.equal(frame.src, "about:blank");
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
  channel.port2.applicationReady();
  await opening;

  fetch.push(surfaceRevocation());
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
  channel.port2.applicationReady();
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
  channel.port2.applicationReady();
  await opening;
  await waitFor(() => fetch.calls.length === 3);
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  assert.equal(JSON.parse(fetch.calls[2]?.init.body ?? "").previous_plugin_gateway_token, "gateway_secret");

  fetch.push({ data: { ok: true } });
  channel.port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "echo.fast" } });
  await waitFor(() => fetch.calls.length === 4);
  assert.equal(JSON.parse(fetch.calls[3]?.init.body ?? "").plugin_gateway_token, "gateway_secret_2");

  assert.equal(JSON.stringify(channel.port1.sent).includes("asset_session_rotated_2"), false);
  assert.equal(JSON.stringify(channel.port1.sent).includes("gateway_secret_2"), false);
  await host.dispose();
});

test("a document that fails to reconnect revokes its surface after the bounded deadline", async () => {
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
    loadTimeoutMs: 30,
    onError: (error) => errors.push(error),
  });
  const opening = host.open();
  frame.load();
  await waitFor(() => frame.transferred.length === 1);
  channel.port2.applicationReady();
  await opening;

  channel.port2.postMessage({ type: "redevplugin.surface.navigation", frame_generation_id: "frame_stale_generation" });
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(channel.port1.closed, false);
  fetch.push(surfaceRevocation());
  channel.port2.postMessage({ type: "redevplugin.surface.navigation", frame_generation_id: host.frameGenerationId });
  await waitFor(() => fetch.calls.length === 3 && channel.port1.closed);
  assert.equal(reloadLimiter.state.reloads, 0);
  assert.equal(errors[0]?.errorCode, "PLUGIN_BRIDGE_TIMEOUT");
});

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not met");
}

async function waitForQuiesce(port: FakePort): Promise<string> {
  await waitFor(() => port.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.lifecycle") &&
    typeof (message as { quiesce_id?: unknown }).quiesce_id === "string"
  ));
  const message = port.sent.find((candidate) =>
    isMessageType(candidate, "redevplugin.bridge.lifecycle") &&
    typeof (candidate as { quiesce_id?: unknown }).quiesce_id === "string"
  ) as { quiesce_id: string };
  return message.quiesce_id;
}

function installSurfaceSlotDOM(frames: FakeFrame[], channels: Array<{ port1: FakePort; port2: FakePort }>): () => void {
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const previousMessageChannel = Object.getOwnPropertyDescriptor(globalThis, "MessageChannel");
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      createElement(tagName: string) {
        assert.equal(tagName, "iframe");
        const frame = frames.shift();
        if (!frame) throw new Error("unexpected iframe creation");
        return frame;
      },
    },
  });
  Object.defineProperty(globalThis, "MessageChannel", {
    configurable: true,
    value: class implements MessageChannelLike {
      readonly port1: FakePort;
      readonly port2: FakePort;

      constructor() {
        const channel = channels.shift();
        if (!channel) throw new Error("unexpected MessageChannel creation");
        this.port1 = channel.port1;
        this.port2 = channel.port2;
      }
    },
  });
  return () => {
    if (previousDocument) Object.defineProperty(globalThis, "document", previousDocument);
    else Reflect.deleteProperty(globalThis, "document");
    if (previousMessageChannel) Object.defineProperty(globalThis, "MessageChannel", previousMessageChannel);
    else Reflect.deleteProperty(globalThis, "MessageChannel");
  };
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


test("user close keeps unsaved work live and permits a later successful save", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel();
  fetch.push(preparation()); fetch.push(gatewayLease());
  const reasons: string[] = [];
  const host = createSurfaceHost(frame, { bootstrap: hostBootstrap, hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }), testMessageChannel: channel, confirmClose: ({ reason }) => { reasons.push(reason); return false; } });
  const opening = host.open(); frame.load(); await waitFor(() => channel.port1.sent.some(m => isMessageType(m, "redevplugin.surface.initialize"))); channel.port2.applicationReady(); await opening;
  const client = new PluginBridgeClient({ port: channel.port2, surfaceHandle: host.surfaceHandle });
  let saved = false;
  client.onBeforeClose(() => saved);
  assert.equal(await host.requestClose(), undefined);
  assert.deepEqual(reasons, ["unsaved"]);
  assert.equal(fetch.calls.length, 2);
  assert.equal(channel.port1.closed, false);
  saved = true; fetch.push(surfaceRevocation());
  const closing = host.requestClose();
  assert.equal(host.requestClose(), closing);
  const result = await closing;
  assert.equal(result?.revocation?.state, "closed");
  assert.equal(frame.src, "about:blank");
  client.dispose();
});

test("an unresponsive close cannot block forced session revocation", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel();
  fetch.push(preparation()); fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, { bootstrap: hostBootstrap, hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }), testMessageChannel: channel, requestTimeoutMs: 30 });
  const opening = host.open(); frame.load(); await waitFor(() => channel.port1.sent.some(m => isMessageType(m, "redevplugin.surface.initialize"))); channel.port2.applicationReady(); await opening;
  assert.equal(await host.requestClose(), undefined);
  assert.equal(channel.port1.closed, false);
  const asking = host.requestClose();
  fetch.push(surfaceRevocation());
  await host.dispose();
  await asking;
  assert.equal(channel.port1.closed, true);
  assert.equal(fetch.calls.filter(call => call.input.endsWith("/dispose")).length, 1);
});

test("native navigation binds a fresh port and ignores old request completions", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch();
  const channels = [fakeChannel(), fakeChannel()]; let index = 0;
  const host = createSurfaceHost(frame, { bootstrap: hostBootstrap,
    testMessageChannel: { get port1() { return channels[index].port1; }, get port2() { return channels[index++].port2; } },
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }) });
  fetch.push(preparation()); fetch.push(gatewayLease());
  const opening = host.open(); frame.load(); await waitFor(() => frame.transferred.length === 1); channels[0].port2.applicationReady(); await opening;
  const oldGeneration = host.frameGenerationId;
  let completeOld!: (response: FetchResponseLike) => void;
  fetch.pushHandler(() => new Promise(resolve => { completeOld = resolve; }));
  channels[0].port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "notes.read" } });
  await waitFor(() => fetch.calls.length === 3);
  channels[0].port2.postMessage({ type: "redevplugin.surface.navigation", frame_generation_id: oldGeneration });
  await waitFor(() => channels[0].port1.closed);
  assert.equal(host.frameGenerationId === oldGeneration, false);
  fetch.push(gatewayLease({ plugin_gateway_token: "gateway_next" }));
  frame.documentID = "document_87654321";
  frame.load(); await waitFor(() => frame.transferred.length === 2); channels[1].port2.applicationReady();
  await waitFor(() => channels[1].port1.sent.some(m => isMessageType(m, "redevplugin.bridge.lifecycle")));
  completeOld({ ok: true, status: 200, json: async () => ({ ok: true, data: { data: { stale: true } } }) });
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(channels[1].port1.sent.some(m => isMessageType(m, "redevplugin.bridge.response")), false);
  fetch.push({ data: { fresh: true } });
  channels[1].port2.postMessage({ type: "redevplugin.bridge.call", request: { id: "rpc_1", method: "notes.read" } });
  await waitFor(() => channels[1].port1.sent.some(m => isMessageType(m, "redevplugin.bridge.response")));
  const response = channels[1].port1.sent.find(m => isMessageType(m, "redevplugin.bridge.response")) as { data: unknown };
  assert.deepEqual(response.data, { data: { fresh: true } });
  await host.dispose();
});

test("document navigation cancels its pending close confirmation", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel();
  fetch.push(preparation()); fetch.push(gatewayLease());
  let confirmationSignal: AbortSignal | undefined;
  const host = createSurfaceHost(frame, { bootstrap: hostBootstrap, testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }), loadTimeoutMs: 1000,
    confirmClose: ({ signal }) => { confirmationSignal = signal; return new Promise<boolean>(() => undefined); } });
  const opening = host.open(); frame.load(); await waitFor(() => frame.transferred.length === 1); channel.port2.applicationReady(); await opening;
  const client = new PluginBridgeClient({ port: channel.port2, surfaceHandle: host.surfaceHandle });
  client.onBeforeClose(() => false);
  const asking = host.requestClose();
  await waitFor(() => confirmationSignal !== undefined);
  channel.port2.postMessage({ type: "redevplugin.surface.navigation", frame_generation_id: host.frameGenerationId });
  await waitFor(() => channel.port1.closed);
  try {
    assert.equal(confirmationSignal?.aborted, true);
    assert.equal(await asking, undefined);
    assert.equal(fetch.calls.filter(call => call.input.endsWith("/dispose")).length, 0);
  } finally { await host.dispose(); client.dispose(); }
});

test("slot disposal bypasses a pending user close confirmation", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel(), stage = new FakeStage();
  const restore = installSurfaceSlotDOM([frame], [channel]);
  const slot = PluginSurfaceSlot.create({ stage: stage as unknown as HTMLElement });
  let confirmationSignal: AbortSignal | undefined;
  try {
    fetch.push(preparation()); fetch.push(gatewayLease());
    const opening = openPreparedPluginSurfaceInSlot(slot, { bootstrap: hostBootstrap,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }), requestTimeoutMs: 30,
      confirmClose: ({ signal }) => { confirmationSignal = signal; return new Promise<boolean>(() => undefined); } });
    frame.load(); await waitFor(() => frame.transferred.length === 1); channel.port2.applicationReady(); const host = await opening;
    const client = new PluginBridgeClient({ port: channel.port2, surfaceHandle: (host as PreparedPluginSurfaceHost).surfaceHandle });
    client.onBeforeClose(() => false);
    const asking = slot.requestClose(); await waitFor(() => confirmationSignal !== undefined);
    fetch.push(surfaceRevocation());
    const disposing = slot.dispose();
    try {
      await waitFor(() => fetch.calls.some(call => call.input.endsWith("/dispose")));
      await disposing; await asking;
      assert.equal(confirmationSignal?.aborted, true);
      assert.equal(frame.removed, true);
      assert.equal(stage.dataset.redevpluginSurfaceState, "disposed");
    } finally { await host.dispose(); client.dispose(); }
  } finally { await slot.dispose(); restore(); }
});

test("duplicate document readiness cannot replace the live bridge", async () => {
  const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel();
  fetch.push(preparation()); fetch.push(gatewayLease());
  const host = createSurfaceHost(frame, { bootstrap: hostBootstrap, testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }), loadTimeoutMs: 30 });
  const opening = host.open(); frame.load(); await waitFor(() => frame.transferred.length === 1); channel.port2.applicationReady(); await opening;
  const generation = host.frameGenerationId;
  try {
    entryReady(frame);
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(host.frameGenerationId, generation);
    assert.equal(channel.port1.closed, false);
    assert.equal(frame.transferred.length, 1);
  } finally { await host.dispose(); }
});


test("host origin preparation completes before any child navigation", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  fetch.push(preparation()); fetch.push(gatewayLease());
  let entered = false;
  let complete!: () => void;
  let captured: PluginWebOriginPreparation | undefined;
  const host = createSurfaceHost(frame, {
    bootstrap: hostBootstrap, testMessageChannel: channel,
    hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
    prepareWebOrigin: async (request) => {
      entered = true; captured = request;
      await new Promise<void>(resolve => { complete = resolve; });
    },
  });
  const opening = host.open();
  frame.load();
  try {
    await waitFor(() => entered || frame.src !== "about:blank");
    assert.equal(entered, true, "origin adapter must run before navigation");
    assert.equal(frame.src, "about:blank");
    assert.equal(frame.transferred.length, 0);
    assert.equal(fetch.calls.length, 1);
    assert.deepEqual(Object.keys(captured as object).sort(), ["origin", "parentOrigin", "pluginInstanceId", "signal", "surfaceInstanceId"]);
    assert.equal(Object.isFrozen(captured), true);
    assert.equal(captured?.origin, preparation().document.origin);
    assert.equal(captured?.parentOrigin, "https://host.example");
    assert.equal(captured?.pluginInstanceId, hostBootstrap.pluginInstanceId);
    assert.equal(captured?.surfaceInstanceId, hostBootstrap.surfaceInstanceId);
    assert.equal(captured?.signal.aborted, false);
    complete();
    await waitFor(() => frame.transferred.length === 1 && fetch.calls.length === 2);
    channel.port2.applicationReady();
    await opening;
  } finally { await host.dispose(); await opening.catch(() => undefined); }
});

for (const outcome of ["reject", "throw", "timeout", "dispose", "invalidate"] as const) {
  test("origin preparation cannot navigate after " + outcome, async () => {
    const frame = new FakeFrame(), fetch = new FakeFetch(), channel = fakeChannel();
    const scope = createPluginSurfaceScope();
    fetch.push(preparation());
    let request: PluginWebOriginPreparation | undefined;
    let complete!: () => void;
    const host = createSurfaceHost(frame, {
      bootstrap: hostBootstrap, testMessageChannel: channel, surfaceScope: scope,
      hostTransport: createReDevPluginSurfaceTransport({ fetch: fetch.fetch }),
      loadTimeoutMs: outcome === "timeout" ? 35 : 1000, requestTimeoutMs: 100,
      prepareWebOrigin: value => {
        request = value;
        if (outcome === "throw") throw new Error("route unavailable");
        if (outcome === "reject") return Promise.reject(new Error("route unavailable"));
        return new Promise<void>(resolve => { complete = resolve; });
      },
    });
    const opening = host.open();
    const rejected = assert.rejects(opening, (error: unknown) => {
      if (!(error instanceof PluginBridgeError)) return false;
      assert.equal(error.errorCode, outcome === "timeout" ? "PLUGIN_BRIDGE_TIMEOUT" : outcome === "dispose" || outcome === "invalidate" ? "PLUGIN_BRIDGE_DISPOSED" : "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
      return true;
    });
    frame.load();
    await waitFor(() => request !== undefined);
    if (outcome === "dispose") await host.dispose();
    if (outcome === "invalidate") invalidatePluginSurfaceScope(scope);
    await rejected;
    assert.equal(request?.signal.aborted, true);
    complete?.();
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(frame.src, "about:blank");
    assert.equal(frame.transferred.length, 0);
    assert.equal(fetch.calls.filter(call => call.input.endsWith("/bridge-token")).length, 0);
    assert.equal(fetch.calls.filter(call => call.input.endsWith("/dispose")).length, 1);
    await host.dispose();
  });
}
