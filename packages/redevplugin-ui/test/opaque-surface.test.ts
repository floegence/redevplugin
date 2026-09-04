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
} from "../src/trusted-parent.js";
import { PluginBridgeClient, callCapabilitySync } from "../src/plugin.js";
import {
  createOpaquePluginBootstrapHTML,
  createPreparedPluginSurfaceHost,
  openPreparedPluginSurfaceInSlot,
  type PluginSurfaceHostOptions,
  type PluginSurfaceHostBootstrap,
  type PreparedPluginSurfaceHost,
} from "../src/surface.js";
import { PluginLocalImportClient } from "../src/local-import.js";
import { opaqueSurfaceRenderLimits } from "../src/opaque-surface-policy.gen.js";
import { disposePluginSurfaceScope, invalidatePluginSurfaceScope, registerPluginSurface } from "../src/surface-scope.js";
import { validatePluginUITree, type PluginUIElementVNode, type PluginUITextVNode } from "../src/ui-reconciler.js";

const uiText = (key: string, text: string): PluginUITextVNode => ({ type: "text", key, text });

test("trusted-parent handshake transcript has one stable current vector", async () => {
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
});

test("opaque bootstrap has no independent UI protocol compatibility axis", () => {
  const html = createOpaquePluginBootstrapHTML({ scriptNonce: "nonce_test" });
  assert.equal(html.includes("plugin-ui-v"), false);
  assert.equal(html.includes("ui_protocol_version"), false);
});

class FakePort implements MessagePortLike {
  peer?: FakePort;
  sent: unknown[] = [];
  postError?: Error;
  #listeners = new Set<(event: MessageEventLike) => void>();
  closed = false;
  autoFirstCommit = false;

  postMessage(message: unknown, _transfer?: readonly unknown[]): void {
    if (this.postError) throw this.postError;
    if (this.closed) throw new Error("port is closed");
    this.sent.push(message);
    queueMicrotask(() => this.peer?.emit(message));
    if (this.autoFirstCommit && isMessageType(message, "redevplugin.surface.worker_ready")) {
      queueMicrotask(() => this.peer?.emit({ type: "redevplugin.surface.first_commit" }));
    }
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
  port2.autoFirstCommit = true;
  return { port1, port2 };
}

function isMessageType(value: unknown, type: string): boolean {
  return value !== null && typeof value === "object" && (value as { type?: unknown }).type === type;
}

class FakeFrame {
  srcdoc = "";
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
      schema_version: "redevplugin.opaque_surface_document.v3",
      entry_path: "ui/index.html",
      entry_sha256: digest("b"),
      title: "Plugin",
      language: "en",
      direction: "ltr",
      body_html: '<main><button data-redevplugin-action="refresh">Refresh</button><img data-redevplugin-asset-binding="asset_12345678" data-redevplugin-asset-attr="src" alt="Status"></main>',
      styles: [{ path: "ui/app.css", sha256: digest("c"), content: ":root{color:#111}" }],
      worker: { path: "ui/app.js", sha256: digest("d"), type: "classic", content: "const client = new globalThis.PluginBridgeClient(); void client.ready();" },
      assets: [{ binding_id: "asset_12345678", logical_ids: ["status-image"], path: "ui/status.png", sha256: digest("e"), size: 8, content_type: "image/png" }],
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

function surfaceRevocation(overrides: Record<string, unknown> = {}) {
  return {
    disposed: true,
    state: "closed",
    previous_state: "active",
    revoked: true,
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
  assert.equal(html.includes("fetch:__rpBlocked"), true);
  assert.equal(html.includes("WebSocket:undefined"), true);
  assert.equal(html.includes('__rpAddEventListener("securitypolicyviolation"'), false);
  assert.equal(html.includes("data:text/javascript"), false);
  assert.equal(html.includes("Dynamic import sandbox verification timed out"), false);
  assert.equal(html.includes("Dynamic import escaped the ReDevPlugin worker sandbox"), false);
  assert.equal(html.includes("__rpSealChain"), true);
  assert.equal(html.includes("Object.getOwnPropertyDescriptor"), true);
  assert.equal(html.includes("sendBeacon:undefined"), true);
  assert.equal(html.includes("/_redevplugin/api/"), false);
  assert.equal(html.includes("__rpControlPost"), true);
  assert.equal(html.includes("__rpSealMessagePortMethod"), true);
  assert.equal(html.includes("maxConcurrentAssetReads = 4"), true);
  assert.equal(html.includes("maxMessageBytes = 524288"), true);
  assert.equal(html.includes("maxPatchOperations = 1024"), true);
  assert.equal(html.includes("state.nodes > 32768 || depth > 64"), true);
  assert.equal(html.includes("plugin asset response did not match the prepared document"), true);
  assert.equal(html.includes("plugin asset response failed renderer validation"), true);
  assert.equal(html.includes("message.content_type !== asset.content_type"), true);
  assert.equal(html.includes('crypto.subtle.digest("SHA-256"'), true);
  assert.equal(html.includes("plugin asset bytes failed SHA-256 verification"), true);
  assert.equal(html.includes("transferControlToOffscreen"), true);
  assert.equal(html.includes("new ResizeObserver"), true);
  assert.equal(html.includes("redevplugin.ui.canvas.input"), true);
  assert.equal(html.includes("maxCanvasCount = 4"), true);
  assert.equal(html.includes("maxCanvasDimension = 4096"), true);
  assert.equal(html.includes("maxCanvasTotalPixels = 16777216"), true);
  assert.equal(html.includes("maxImageCount = 32"), true);
  assert.equal(html.includes("maxImageDimension = 4096"), true);
  assert.equal(html.includes("maxImageTotalPixels = 33554432"), true);
  assert.equal(html.includes("detectRasterImageType"), true);
  assert.equal(html.includes("readImageDimensions"), true);
  assert.equal(html.includes("decoded image assets exceed the renderer pixel budget"), true);
  assert.equal(html.includes("OffscreenCanvas:undefined"), true);
  assert.equal(html.includes("plugin canvas resize exceeds the worker pixel budget"), true);
  assert.equal(html.includes("redevplugin.worker.ping"), true);
  assert.equal(html.includes("redevplugin.worker.pong"), true);
  assert.equal(html.includes("plugin worker heartbeat timed out"), true);
  assert.equal(html.includes('event.type === "pointermove"'), true);
  assert.equal(html.includes("createImageBitmap"), true);
  assert.equal(html.includes("logical_ids"), true);
  assert.equal(html.includes('element.tagName === "FORM" && event.type !== "submit"'), true);
  assert.equal(html.includes('const submitButton = origin ? origin.closest("button") : null'), true);
  assert.equal(html.includes('sendWorker(actionPayload(event, element, "submit"))'), true);
  assert.equal(html.includes("captureRenderState"), true);
  assert.equal(html.includes("restoreRenderState"), true);
  assert.equal(html.includes("buildWorkerSubtree"), true);
  assert.equal(html.includes("uiGraph"), true);
  assert.equal(html.includes('["type", "key", "text"]'), true);
  assert.equal(html.includes('["type", "target_key", "parent_key", "before_key"]'), true);
  assert.equal(html.includes("graphParentChainContains"), true);
  assert.equal(html.includes("child_index"), false);
  assert.equal(html.includes("from_index"), false);
  assert.equal(html.includes("to_index"), false);
  assert.equal(html.split("const renderState = captureRenderState();").length - 1, 2);
  assert.equal(html.split("restoreRenderState(renderState);").length - 1, 2);
  assert.equal(html.includes("setSelectionRange"), true);
  assert.equal(html.includes('querySelector("[data-redevplugin-renderer-autofocus]")'), true);
  assert.equal(html.includes('querySelector("[autofocus]")'), false);
  assert.equal(html.includes('lower.startsWith("aria-") ? String(attributeValue)'), true);
  assert.equal(html.includes('[role="dialog"][aria-modal="true"]'), true);
  assert.equal(html.includes("focusableModalElements"), true);
  assert.equal(html.includes("redevplugin.ui.canvas.accessibility"), true);
  assert.equal(html.includes('event.key !== "Escape"'), true);
  assert.equal(html.includes("data-redevplugin-escape-action"), true);
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
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_1",
    ok: true,
    data: { pong: true },
    future_trace: "trace_1",
  });
  assert.deepEqual(await callPromise, { pong: true });

  const readyTree: PluginUIElementVNode = { type: "element", key: "root", tag: "main", children: [uiText("ready-text", "Ready")] };
  const renderPromise = client.render(readyTree);
  assert.deepEqual(pluginPort.sent[1], {
    type: "redevplugin.ui.mount",
    id: "render_2",
    revision: 1,
    tree: validatePluginUITree(readyTree),
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await renderPromise;


  const businessErrorPromise = client.call("documents.get", { document_id: "missing" });
  rendererPort.postMessage({
    type: "redevplugin.bridge.response",
    id: "rpc_3",
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
    id: "rpc_4",
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
  const actions: string[] = [];
  client.onAction("close-dialog", (event) => actions.push(event.event));
  rendererPort.postMessage({
    type: "redevplugin.ui.action",
    action: "close-dialog",
    event: "escape",
    target_key: "dialog",
    edit_revision: 0,
    is_composing: false,
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(actions, ["escape"]);
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

test("plugin bridge completes lifecycle render and persistence work before quiesce acknowledgement", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();
  const initialRender = client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "Unsaved")] });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_1", ok: true });
  await initialRender;

  client.onLifecycle(async (event) => {
    if (event.type !== "dispose") return;
    await client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "Saving")] });
    await client.call("memos.save", { title: "Quiesced memo" });
    await client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "Saved")] });
  });
  rendererPort.postMessage({
    type: "redevplugin.bridge.lifecycle",
    event: { type: "dispose" },
    quiesce_id: "quiesce_12345678",
  });

  await waitFor(() => pluginPort.sent.some((message) => (message as { id?: string }).id === "render_2"));
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await waitFor(() => pluginPort.sent.some((message) => (message as { request?: { id?: string } }).request?.id === "rpc_3"));
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "rpc_3", ok: true, data: { saved: true } });
  await waitFor(() => pluginPort.sent.some((message) => (message as { id?: string }).id === "render_4"));
  assert.equal(pluginPort.sent.some((message) => isMessageType(message, "redevplugin.bridge.lifecycle_ack")), false);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_4", ok: true });
  await waitFor(() => pluginPort.sent.some((message) => isMessageType(message, "redevplugin.bridge.lifecycle_ack")));
  assert.deepEqual(pluginPort.sent.at(-1), {
    type: "redevplugin.bridge.lifecycle_ack",
    quiesce_id: "quiesce_12345678",
  });
  assert.throws(
    () => client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "Too late")] }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED",
  );
  client.dispose();
});

test("plugin bridge transfers one canvas and verified image assets by logical identifier", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const canvas = { width: 960, height: 540, getContext() { return null; } } as unknown as OffscreenCanvas;
  const opening = client.openCanvas("playfield");
  assert.deepEqual(pluginPort.sent[0], {
    type: "redevplugin.ui.canvas.open",
    id: "canvas_1",
    canvas_id: "playfield",
  });
  rendererPort.postMessage({
    type: "redevplugin.ui.canvas.ready",
    id: "canvas_1",
    canvas_id: "playfield",
    canvas,
    css_width: 960,
    css_height: 540,
    device_pixel_ratio: 2,
  });
  assert.deepEqual(await opening, {
    canvas,
    canvasId: "playfield",
    cssWidth: 960,
    cssHeight: 540,
    devicePixelRatio: 2,
  });

  const updatingAccessibility = client.updateCanvasAccessibility("playfield", {
    label: "Sky Strike. Running. Score 120. Three lives. 60 FPS.",
    description: "Use arrow keys to fly and Space to fire.",
  });
  assert.deepEqual(pluginPort.sent[1], {
    type: "redevplugin.ui.canvas.accessibility",
    id: "canvas_2",
    canvas_id: "playfield",
    label: "Sky Strike. Running. Score 120. Three lives. 60 FPS.",
    description: "Use arrow keys to fly and Space to fire.",
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "canvas_2", ok: true });
  await updatingAccessibility;

  const image = { width: 64, height: 64, close() {} } as unknown as ImageBitmap;
  const loading = client.loadImageAsset("player-ship");
  assert.deepEqual(pluginPort.sent[2], {
    type: "redevplugin.ui.asset.image.open",
    id: "asset_3",
    asset_id: "player-ship",
  });
  rendererPort.postMessage({
    type: "redevplugin.ui.asset.image.ready",
    id: "asset_3",
    asset_id: "player-ship",
    image,
    width: 64,
    height: 64,
  });
  assert.equal(await loading, image);

  client.dispose();
});

test("plugin bridge normalizes canvas focus, resize, keyboard, pointer, and wheel input", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();
  const events: unknown[] = [];
  const unsubscribe = client.onCanvasInput("playfield", (event) => events.push(event));

  for (const event of [
    { type: "focus" },
    { type: "resize", css_width: 800, css_height: 450, device_pixel_ratio: 2 },
    { type: "key", event: "keydown", code: "ArrowLeft", key: "ArrowLeft", repeat: false, alt_key: false, ctrl_key: false, meta_key: false, shift_key: false },
    { type: "pointer", event: "pointermove", pointer_id: 1, pointer_type: "mouse", buttons: 1, button: -1, x: 120.5, y: 82.25, pressure: 0.5 },
    { type: "wheel", x: 240.5, y: 160.25, delta_x: -12, delta_y: 48, delta_mode: 0, alt_key: false, ctrl_key: true, meta_key: false, shift_key: false },
  ]) {
    rendererPort.postMessage({ type: "redevplugin.ui.canvas.input", canvas_id: "playfield", event });
  }
  rendererPort.postMessage({
    type: "redevplugin.ui.canvas.input",
    canvas_id: "playfield",
    event: { type: "pointer", event: "pointermove", pointer_id: -1, x: Number.NaN, y: 0 },
  });
  rendererPort.postMessage({
    type: "redevplugin.ui.canvas.input",
    canvas_id: "playfield",
    event: { type: "wheel", x: 0, y: 0, delta_x: 0, delta_y: Number.NaN, delta_mode: 0, alt_key: false, ctrl_key: false, meta_key: false, shift_key: false },
  });
  await Promise.resolve();

  assert.equal(events.length, 5);
  assert.deepEqual(events[2], {
    type: "key",
    event: "keydown",
    code: "ArrowLeft",
    key: "ArrowLeft",
    repeat: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
  });
  assert.deepEqual(events[3], {
    type: "pointer",
    event: "pointermove",
    pointerId: 1,
    pointerType: "mouse",
    buttons: 1,
    button: -1,
    x: 120.5,
    y: 82.25,
    pressure: 0.5,
  });
  assert.deepEqual(events[4], {
    type: "wheel",
    x: 240.5,
    y: 160.25,
    deltaX: -12,
    deltaY: 48,
    deltaMode: 0,
    altKey: false,
    ctrlKey: true,
    metaKey: false,
    shiftKey: false,
  });
  unsubscribe();
  client.dispose();
});

test("plugin bridge installs exact surface keyboard bindings and normalizes keyboard input", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const installing = client.setKeyboardBindings([{
    id: "commit-node-title",
    event: "keydown",
    code: "Enter",
    repeat: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    targetKey: "node-title-editor",
    targetKind: "editable",
  }]);
  assert.deepEqual(pluginPort.sent[0], {
    type: "redevplugin.ui.keyboard.bindings",
    id: "keyboard_1",
    bindings: [{
      binding_id: "commit-node-title",
      event: "keydown",
      code: "Enter",
      repeat: false,
      alt_key: false,
      ctrl_key: false,
      meta_key: false,
      shift_key: false,
      target_key: "node-title-editor",
      target_kind: "editable",
    }],
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "keyboard_1", ok: true });
  await installing;

  const events: unknown[] = [];
  const unsubscribe = client.onKeyboardInput((event) => events.push(event));
  for (const event of [
    {
      event: "keydown", code: "Enter", key: "Enter", repeat: false,
      alt_key: false, ctrl_key: false, meta_key: false, shift_key: false,
      is_composing: false, target_key: "node-title-editor", target_kind: "editable",
      default_prevented: true, binding_id: "commit-node-title",
    },
    {
      event: "keyup", code: "Enter", key: "Enter", repeat: false,
      alt_key: false, ctrl_key: false, meta_key: false, shift_key: false,
      is_composing: false, target_key: "node-title-editor", target_kind: "editable",
      default_prevented: false, binding_id: null,
    },
  ]) rendererPort.postMessage({ type: "redevplugin.ui.keyboard.input", event });
  rendererPort.postMessage({
    type: "redevplugin.ui.keyboard.input",
    event: {
      event: "keydown", code: "Enter", key: "Enter", repeat: false,
      alt_key: false, ctrl_key: false, meta_key: false, shift_key: false,
      is_composing: false, target_key: "missing key", target_kind: "editable",
      default_prevented: true, binding_id: "commit-node-title",
    },
  });
  await Promise.resolve();

  assert.deepEqual(events, [{
    event: "keydown",
    code: "Enter",
    key: "Enter",
    repeat: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    isComposing: false,
    targetKey: "node-title-editor",
    targetKind: "editable",
    defaultPrevented: true,
    bindingId: "commit-node-title",
  }, {
    event: "keyup",
    code: "Enter",
    key: "Enter",
    repeat: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    isComposing: false,
    targetKey: "node-title-editor",
    targetKind: "editable",
    defaultPrevented: false,
    bindingId: null,
  }]);

  unsubscribe();
  rendererPort.postMessage({
    type: "redevplugin.ui.keyboard.input",
    event: {
      event: "keydown", code: "KeyA", key: "a", repeat: false,
      alt_key: false, ctrl_key: false, meta_key: false, shift_key: false,
      is_composing: false, target_key: null, target_kind: "surface",
      default_prevented: false, binding_id: null,
    },
  });
  await Promise.resolve();
  assert.equal(events.length, 2);
  client.dispose();
});

test("surface keyboard bindings reject ambiguous and malformed declarations", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();
  const binding = {
    id: "commit-node-title",
    event: "keydown" as const,
    code: "Enter",
    repeat: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    targetKey: "node-title-editor",
    targetKind: "editable" as const,
  };
  assert.throws(() => client.setKeyboardBindings([binding, { ...binding, id: "other" }]),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST");
  assert.throws(() => client.setKeyboardBindings([{ ...binding, code: "x".repeat(65) }]),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST");
  client.dispose();
});

test("opaque bootstrap forwards canvas wheel input and suppresses ancestor scrolling", () => {
  const html = createOpaquePluginBootstrapHTML({ scriptNonce: "nonce_canvas_wheel" });
  assert.equal(/const handleWheel = \(event\) =>/u.test(html), true);
  assert.equal(/listen\("wheel", handleWheel\)/u.test(html), true);
  assert.equal(/event\.preventDefault\(\)/u.test(html), true);
  assert.equal(/delta_mode: \[0, 1, 2\]\.includes\(event\.deltaMode\) \? event\.deltaMode : 0/u.test(html), true);
});

test("opaque bootstrap captures complete surface keyboard input and applies bindings synchronously", () => {
  const html = createOpaquePluginBootstrapHTML({ scriptNonce: "nonce_keyboard_input" });
  assert.equal(/redevplugin\.ui\.keyboard\.bindings/u.test(html), true);
  assert.equal(/redevplugin\.ui\.keyboard\.input/u.test(html), true);
  assert.equal(/for \(const eventType of \["keydown", "keyup"\]\)/u.test(html), true);
  assert.equal(/event\.isComposing/u.test(html), true);
  assert.equal(/binding_id/u.test(html), true);
  assert.equal(/default_prevented/u.test(html), true);
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

test("plugin bridge client rejects non-canonical render trees before posting", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 10 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const sentBefore = pluginPort.sent.length;
  assert.throws(
    () => {
      void client.render({ type: "element", key: "root", tag: "main", children: [undefined] } as never);
    },
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_UI_PROTOCOL_VIOLATION",
  );
  assert.equal(pluginPort.sent.length, sentBefore);
  client.dispose();
});

test("plugin bridge sends UI trees up to the renderer node limit without RPC JSON truncation", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const children = Array.from({ length: 1000 }, (_, index) => ({
    type: "element" as const,
    key: `item-${index}`,
    tag: "div" as const,
    children: [],
  }));
  const mounted = client.render({ type: "element", key: "root", tag: "main", children });
  assert.equal((pluginPort.sent[0] as { tree?: { children?: unknown[] } }).tree?.children?.length, 1000);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_1", ok: true });
  await mounted;

  const reversed = client.render({ type: "element", key: "root", tag: "main", children: [...children].reverse() });
  await waitFor(() => pluginPort.sent.length === 2);
  const patch = pluginPort.sent[1] as { operations?: Array<{ type?: string }> };
  assert.equal(patch.operations?.length, 999);
  assert.equal(patch.operations?.every((operation) => operation.type === "move_child"), true);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await reversed;
  client.dispose();
});

test("plugin bridge commits a 1000-child reversal with maximum-length public keys as one patch", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const children = Array.from({ length: 1000 }, (_, index) => ({
    type: "element" as const,
    key: `item-${String(index).padStart(4, "0")}${"x".repeat(119)}`,
    tag: "div" as const,
  }));
  const mounted = client.render({ type: "element", key: "root", tag: "main", children });
  assert.equal(
    new TextEncoder().encode(JSON.stringify(pluginPort.sent[0])).byteLength <= opaqueSurfaceRenderLimits.max_message_bytes,
    true,
  );
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_1", ok: true });
  await mounted;

  const reversed = client.render({ type: "element", key: "root", tag: "main", children: [...children].reverse() });
  void reversed.catch(() => undefined);
  await waitFor(() => pluginPort.sent.length === 2);
  const patch = pluginPort.sent[1] as { operations?: Array<{ type?: string }> };
  assert.equal(patch.operations?.length, 999);
  assert.equal(patch.operations?.every((operation) => operation.type === "move_child"), true);
  assert.equal(
    new TextEncoder().encode(JSON.stringify(patch)).byteLength <= opaqueSurfaceRenderLimits.max_message_bytes,
    true,
  );
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await reversed;
  client.dispose();
});

test("plugin bridge keeps one UI commit in flight and coalesces to the latest tree", async () => {
  const { port1: rendererPort, port2: pluginPort } = fakeChannel();
  const client = new PluginBridgeClient({ port: pluginPort, surfaceHandle: "surface_12345678", timeoutMs: 1000 });
  rendererPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  await client.ready();

  const first = client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "A")] });
  const second = client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "B")] });
  const latest = client.render({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "C")] });
  assert.equal(pluginPort.sent.length, 1);
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_1", ok: true });
  await first;
  await waitFor(() => pluginPort.sent.length === 2);
  const latestTree = validatePluginUITree({ type: "element", key: "root", tag: "main", children: [uiText("root-text", "C")] });
  const latestTextKey = latestTree.children?.[0]?.key;
  assert.deepEqual(pluginPort.sent[1], {
    type: "redevplugin.ui.patch",
    id: "render_2",
    base_revision: 1,
    revision: 2,
    operations: [{ type: "set_text", target_key: latestTextKey, text: "C" }],
  });
  rendererPort.postMessage({ type: "redevplugin.bridge.response", id: "render_2", ok: true });
  await Promise.all([second, latest]);
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

test("surface host exposes no iframe before the first worker UI commit", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  channel.port2.autoFirstCommit = false;
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await waitFor(() => channel.port1.sent.some((message) =>
    isMessageType(message, "redevplugin.bridge.lifecycle") &&
    (message as { event?: { type?: string } }).event?.type === "ready"
  ));
  assert.equal(settled, false);
  channel.port2.postMessage({ type: "redevplugin.surface.first_commit" });
  await opening;
  host.dispose();
});

test("opening renderer failure remains authoritative through surface disposal", async () => {
  const frame = new FakeFrame();
  const fetch = new FakeFetch();
  const channel = fakeChannel();
  channel.port2.autoFirstCommit = false;
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    firstChannel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    firstChannel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    secondChannel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    secondChannel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    firstChannel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    firstChannel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    replacementChannel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    replacementChannel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push(surfaceRevocation());
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
        business_error_details: { payload: "x".repeat(opaqueSurfaceRenderLimits.max_message_bytes) },
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
  assert.equal(new TextEncoder().encode(JSON.stringify(response)).byteLength <= opaqueSurfaceRenderLimits.max_message_bytes, true);
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
  await opening;

  fetch.push({ data: { payload: "x".repeat(opaqueSurfaceRenderLimits.max_message_bytes - 32 * 1024) } });
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

  fetch.push({ data: { payload: "x".repeat(opaqueSurfaceRenderLimits.max_message_bytes + 32 * 1024) } });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
  fetch.push(surfaceRevocation());
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
  assert.deepEqual(initialize.context, initialContext, "initial context must cross the private port before first paint");

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

  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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
    channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
    await opening;
  } finally {
    host.dispose();
  }
});

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
  assert.equal(frame.srcdoc, "");
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
    channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
    channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
    await opening;

    await client.revokeSessionScope();

    assert.equal(frame.srcdoc, "");
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
  assert.equal(frame.srcdoc, "");
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
  channel.port2.postMessage({ type: "redevplugin.surface.first_paint" });
  channel.port2.postMessage({ type: "redevplugin.surface.worker_ready" });
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

  fetch.push(surfaceRevocation());
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
