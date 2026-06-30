import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodePluginStreamText,
  PluginBridgeClient,
  PluginBridgeError,
  PluginPlatformClient,
  PluginSurfaceHost,
  readPluginStream,
  type FetchInitLike,
  type FetchResponseLike,
  type MessageEventLike,
  type StreamFetchInitLike,
  type StreamFetchResponseLike,
  type WindowLike,
} from "../src/index.js";

class FakeWindow implements WindowLike {
  readonly sent: Array<{ message: unknown; targetOrigin: string }> = [];
  #listeners = new Set<(event: MessageEventLike) => void>();

  postMessage(message: unknown, targetOrigin: string): void {
    this.sent.push({ message, targetOrigin });
  }

  addEventListener(type: "message", listener: (event: MessageEventLike) => void): void {
    assert.equal(type, "message");
    this.#listeners.add(listener);
  }

  removeEventListener(type: "message", listener: (event: MessageEventLike) => void): void {
    assert.equal(type, "message");
    this.#listeners.delete(listener);
  }

  emit(origin: string, data: unknown, source?: WindowLike | null): void {
    for (const listener of this.#listeners) {
      listener({ origin, data, source });
    }
  }
}

type FetchCall = {
  input: string;
  init: FetchInitLike;
};

class FakeFetch {
  readonly calls: FetchCall[] = [];
  #responses: unknown[] = [];

  push(response: unknown): void {
    this.#responses.push(response);
  }

  fetch = async (input: string, init: FetchInitLike): Promise<FetchResponseLike> => {
    this.calls.push({ input, init });
    const body = this.#responses.shift();
    return {
      ok: true,
      status: 200,
      json: async () => body,
    };
  };
}

type StreamFetchCall = {
  input: string;
  init?: StreamFetchInitLike;
};

class FakeStreamFetch {
  readonly calls: StreamFetchCall[] = [];
  #responses: Array<{ ok: boolean; status: number; body: string }> = [];

  push(body: string, status = 200): void {
    this.#responses.push({ ok: status >= 200 && status < 300, status, body });
  }

  fetch = async (input: string, init?: StreamFetchInitLike): Promise<StreamFetchResponseLike> => {
    this.calls.push({ input, init });
    const response = this.#responses.shift() ?? { ok: false, status: 500, body: "missing fake stream response" };
    return {
      ok: response.ok,
      status: response.status,
      text: async () => response.body,
    };
  };
}

const bootstrap = {
  pluginId: "com.example.plugin",
  surfaceId: "example.activity",
  surfaceInstanceId: "surface_1",
  activeFingerprint: "sha256:abc",
  bridgeNonce: "nonce_1",
  parentOrigin: "https://host.example",
};

const hostBootstrap = {
  pluginId: "com.example.plugin",
  pluginInstanceId: "plugin_instance_1",
  surfaceId: "example.activity",
  surfaceInstanceId: "surface_1",
  activeFingerprint: "sha256:abc",
  bridgeNonce: "nonce_1",
  ownerSessionHash: "owner_session_hash",
  ownerUserHash: "owner_user_hash",
  sessionChannelIdHash: "session_channel_hash",
};

const handshake = {
  type: "redevplugin.bridge.handshake",
  plugin_id: "com.example.plugin",
  surface_id: "example.activity",
  surface_instance_id: "surface_1",
  active_fingerprint: "sha256:abc",
  bridge_nonce: "nonce_1",
  ui_protocol_version: "plugin-ui-v1",
} as const;

test("handshake posts exact-origin message", () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver });

  client.handshake();

  assert.equal(target.sent.length, 1);
  assert.equal(target.sent[0]?.targetOrigin, "https://host.example");
  assert.deepEqual(target.sent[0]?.message, {
    type: "redevplugin.bridge.handshake",
    plugin_id: "com.example.plugin",
    surface_id: "example.activity",
    surface_instance_id: "surface_1",
    active_fingerprint: "sha256:abc",
    bridge_nonce: "nonce_1",
    ui_protocol_version: "plugin-ui-v1",
  });
  client.dispose();
});

test("call resolves only matching exact-origin response", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 100 });

  const pending = client.call<{ ok: boolean }>("worker.echo", { message: "hello" });
  assert.equal(target.sent.length, 1);
  assert.equal(target.sent[0]?.targetOrigin, "https://host.example");
  assert.deepEqual(target.sent[0]?.message, {
    type: "redevplugin.bridge.call",
    request: { id: "1", method: "worker.echo", params: { message: "hello" } },
  });

  receiver.emit("https://evil.example", { type: "redevplugin.bridge.response", id: "1", ok: true, data: { ok: false } });
  receiver.emit("https://host.example", { type: "redevplugin.bridge.response", id: "other", ok: true, data: { ok: false } });
  receiver.emit("https://host.example", { type: "redevplugin.bridge.response", id: "1", ok: true, data: { ok: true } });

  assert.deepEqual(await pending, { ok: true });
  client.dispose();
});

test("call rejects runtime bridge errors", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 100 });

  const pending = client.call("worker.echo");
  receiver.emit("https://host.example", {
    type: "redevplugin.bridge.response",
    id: "1",
    ok: false,
    error_code: "PLUGIN_RUNTIME_UNAVAILABLE",
    error: "runtime is not ready",
  });

  await assert.rejects(pending, (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_RUNTIME_UNAVAILABLE");
  client.dispose();
});

test("call times out when no response arrives", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 1 });

  await assert.rejects(client.call("worker.echo"), (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_BRIDGE_TIMEOUT");
  client.dispose();
});

test("lifecycle subscription accepts only parent origin", () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver });
  const events: string[] = [];

  const unsubscribe = client.onLifecycle((event) => {
    events.push(event.type);
  });
  receiver.emit("https://evil.example", { type: "redevplugin.bridge.lifecycle", event: { type: "visible" } });
  receiver.emit("https://host.example", { type: "redevplugin.bridge.lifecycle", event: { type: "visible" } });
  unsubscribe();
  receiver.emit("https://host.example", { type: "redevplugin.bridge.lifecycle", event: { type: "hidden" } });

  assert.deepEqual(events, ["visible"]);
  client.dispose();
});

test("dispose rejects pending calls and removes listener", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 1000 });
  const pending = client.call("worker.echo");

  client.dispose();
  receiver.emit("https://host.example", { type: "redevplugin.bridge.response", id: "1", ok: true, data: true });

  await assert.rejects(pending, (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_BRIDGE_DISPOSED");
  assert.throws(() => client.handshake(), PluginBridgeError);
});

test("surface host mints parent-only gateway token after matching handshake", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      plugin_gateway_token: "gateway_secret",
      plugin_gateway_token_id: "gateway_token_1",
    },
  });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
    apiBaseURL: "https://host.example/",
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();

  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/surfaces/surface_1/bridge-token");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {
    bridge_channel_id: "bridge_channel_1",
    handshake,
  });
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], "owner_session_hash");
  assert.deepEqual(iframe.sent, [
    {
      targetOrigin: "https://plugin.example",
      message: { type: "redevplugin.bridge.lifecycle", event: { type: "ready" } },
    },
  ]);
  host.dispose();
});

test("surface host calls rpc with gateway token without exposing it to iframe", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  fetch.push({ ok: true, data: { data: { pong: true }, operation_id: "op_1" } });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_1", method: "echo.ping", params: { message: "hello" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/rpc");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_instance_id: "surface_1",
    session_channel_id_hash: "session_channel_hash",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    bridge_channel_id: "bridge_channel_1",
    plugin_gateway_token: "gateway_secret",
    method: "echo.ping",
    params: { message: "hello" },
  });
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_1",
      ok: true,
      data: { data: { pong: true }, operation_id: "op_1" },
    },
  });
  assert.equal(JSON.stringify(iframe.sent).includes("gateway_secret"), false);
  host.dispose();
});

test("surface host rejects calls before handshake and invalid params", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
  });

  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_before_handshake", method: "echo.ping", params: {} },
  }, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_from_other_window", method: "echo.ping", params: {} },
  }, new FakeWindow());
  await tick();

  assert.equal(fetch.calls.length, 0);
  assert.deepEqual(iframe.sent, [
    {
      targetOrigin: "https://plugin.example",
      message: {
        type: "redevplugin.bridge.response",
        id: "call_before_handshake",
        ok: false,
        error_code: "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED",
        error: "Plugin bridge call arrived before a successful handshake",
      },
    },
  ]);

  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_bad_params", method: "echo.ping", params: ["not", "object"] },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 1);
  assert.deepEqual(iframe.sent[2], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_bad_params",
      ok: false,
      error_code: "PLUGIN_INVALID_REQUEST",
      error: "Plugin bridge call params must be a JSON object when present",
    },
  });
  host.dispose();
});

test("surface host reports mismatched handshake without minting token", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  const errors: PluginBridgeError[] = [];
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
    onError: (err) => errors.push(err),
  });

  parent.emit("https://evil.example", handshake, iframe);
  parent.emit("https://plugin.example", { ...handshake, bridge_nonce: "wrong" }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 0);
  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.errorCode, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
  assert.deepEqual(iframe.sent, []);
  host.dispose();
});

test("surface host maps rpc envelope errors into bridge responses", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  fetch.push({ ok: false, error_code: "PLUGIN_PERMISSION_DENIED", error: "denied" });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_denied", method: "echo.ping", params: {} },
  }, iframe);
  await tick();

  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_denied",
      ok: false,
      error_code: "PLUGIN_PERMISSION_DENIED",
      error: "denied",
    },
  });
  host.dispose();
});

test("surface host owns dangerous confirmation token and retries confirmed rpc", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  const confirmations: unknown[] = [];
  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" });
  fetch.push({
    ok: true,
    data: {
      confirmation_token: "confirmation_secret",
      confirmation_token_id: "confirmation_token_1",
      request_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  });
  fetch.push({ ok: true, data: { data: { done: true } } });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
    confirm: (intent) => {
      confirmations.push(intent);
      return { confirmed: true };
    },
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_danger", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 4);
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/rpc");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/confirm");
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/rpc");
  assert.deepEqual(confirmations, [{
    requestId: "call_danger",
    method: "danger.run",
    params: { target: "db" },
    requestHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    confirmationTokenId: "confirmation_token_1",
  }]);
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_instance_id: "surface_1",
    session_channel_id_hash: "session_channel_hash",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    bridge_channel_id: "bridge_channel_1",
    plugin_gateway_token: "gateway_secret",
    method: "danger.run",
    params: { target: "db" },
  });
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_instance_id: "surface_1",
    session_channel_id_hash: "session_channel_hash",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    bridge_channel_id: "bridge_channel_1",
    plugin_gateway_token: "gateway_secret",
    confirmation_token: "confirmation_secret",
    method: "danger.run",
    params: { target: "db" },
  });
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_danger",
      ok: true,
      data: { data: { done: true } },
    },
  });
  assert.equal(JSON.stringify(iframe.sent).includes("confirmation_secret"), false);
  host.dispose();
});

test("surface host rejects dangerous call when confirmation callback declines", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" });
  fetch.push({
    ok: true,
    data: {
      confirmation_token: "confirmation_secret",
      confirmation_token_id: "confirmation_token_1",
      request_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
  });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
    confirm: () => false,
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_declined", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 3);
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_declined",
      ok: false,
      error_code: "PLUGIN_CONFIRMATION_REJECTED",
      error: "Plugin method confirmation was rejected",
    },
  });
  host.dispose();
});

test("surface host keeps dangerous call fail-closed without confirmation callback", async () => {
  const parent = new FakeWindow();
  const iframe = new FakeWindow();
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_gateway_token: "gateway_secret", plugin_gateway_token_id: "gateway_token_1" } });
  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" });
  const host = new PluginSurfaceHost({
    bootstrap: hostBootstrap,
    iframeOrigin: "https://plugin.example",
    iframeWindow: iframe,
    parentWindow: parent,
    bridgeChannelId: "bridge_channel_1",
    fetch: fetch.fetch,
  });

  parent.emit("https://plugin.example", handshake, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redevplugin.bridge.call",
    request: { id: "call_no_confirm_handler", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 2);
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redevplugin.bridge.response",
      id: "call_no_confirm_handler",
      ok: false,
      error_code: "PLUGIN_CONFIRMATION_REQUIRED",
      error: "confirmation required",
    },
  });
  host.dispose();
});

test("readPluginStream drains ndjson events with a single-use ticket", async () => {
  const fetch = new FakeStreamFetch();
  fetch.push([
    JSON.stringify({
      stream_id: "stream/a b",
      sequence: 1,
      kind: "data",
      data: "bGluZSAxCg==",
      at: "2026-06-30T00:00:00Z",
    }),
    JSON.stringify({
      stream_id: "stream/a b",
      sequence: 2,
      kind: "done",
      at: "2026-06-30T00:00:01Z",
    }),
    "",
  ].join("\n"));

  const events = await readPluginStream({
    streamId: "stream/a b",
    streamTicket: "ticket+1/=",
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
  });

  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/stream/stream%2Fa%20b?ticket=ticket%2B1%2F%3D");
  assert.equal(fetch.calls[0]?.init?.method, "GET");
  assert.equal(fetch.calls[0]?.init?.credentials, "same-origin");
  assert.equal(events.length, 2);
  assert.equal(events[0]?.sequence, 1);
  assert.equal(decodePluginStreamText(events[0]!), "line 1\n");
});

test("readPluginStream accepts method results returned by bridge calls", async () => {
  const fetch = new FakeStreamFetch();
  fetch.push(`${JSON.stringify({
    stream_id: "stream_result_1",
    sequence: 1,
    kind: "data",
    data: "b2s=",
    at: "2026-06-30T00:00:00Z",
  })}\n`);

  const events = await readPluginStream({
    result: {
      data: { started: true },
      stream_id: "stream_result_1",
      stream_ticket: "stream_ticket_1",
    },
    fetch: fetch.fetch,
  });

  assert.equal(fetch.calls[0]?.input, "/_redevplugin/stream/stream_result_1?ticket=stream_ticket_1");
  assert.equal(decodePluginStreamText(events[0]!), "ok");
});

test("readPluginStream maps missing ticket and endpoint errors", async () => {
  await assert.rejects(
    readPluginStream({ streamId: "stream_missing_ticket" }),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_INVALID_REQUEST",
  );

  const fetch = new FakeStreamFetch();
  fetch.push(JSON.stringify({ ok: false, error_code: "PLUGIN_PERMISSION_DENIED", error: "stream ticket is required" }), 403);

  await assert.rejects(
    readPluginStream({ streamId: "stream_denied", streamTicket: "bad", fetch: fetch.fetch }),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_PERMISSION_DENIED" && err.message === "stream ticket is required",
  );
});

test("platform client reads compatibility manifest through host API", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      schema_version: "redevplugin.compatibility.v1",
      matrix: {
        redevplugin_go_version: "0.0.0-dev",
        redevplugin_ui_version: "0.0.0-dev",
        redevplugin_runtime_version: "0.0.0-dev",
        plugin_host_protocol_version: "plugin-host-v1",
        rust_ipc_version: "rust-ipc-v1",
        wasm_abi_version: "redevplugin-wasm-worker-v1",
        manifest_schema_version: "manifest-v1",
        package_signature_schema_version: "package-signature-v1",
        token_ticket_schema_version: "token-ticket-v1",
        bridge_schema_version: "bridge-v1",
        target_classifier_version: "target-classifier-v1",
        plugin_platform_openapi_version: "plugin-platform-v1",
        compatibility_schema_version: "compatibility-manifest-v1",
        worker_invocation_schema_version: "worker-invocation-v1",
      },
      contracts: [
        {
          id: "plugin-platform-openapi",
          path: "spec/openapi/plugin-platform-v1.yaml",
          version: "plugin-platform-v1",
          sha256: "sha256-openapi",
        },
        {
          id: "rust-ipc-schema",
          path: "spec/plugin/ipc-v1.schema.json",
          version: "rust-ipc-v1",
          sha256: "sha256-ipc",
        },
      ],
    },
  });
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
    ownerSessionHashHeader: "owner_session_hash",
  });

  const compatibility = await client.getCompatibility();

  assert.equal(compatibility.schema_version, "redevplugin.compatibility.v1");
  assert.equal(compatibility.matrix.plugin_platform_openapi_version, "plugin-platform-v1");
  assert.deepEqual(compatibility.contracts.map((contract) => contract.id), ["plugin-platform-openapi", "rust-ipc-schema"]);
  assert.equal(compatibility.contracts[0]?.sha256, "sha256-openapi");
  assert.equal(fetch.calls.length, 1);
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/platform/compatibility");
  assert.equal(fetch.calls[0]?.init.method, "GET");
  assert.equal(fetch.calls[0]?.init.body, undefined);
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], undefined);
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], "owner_session_hash");
});

test("platform client reads and patches plugin settings through host API", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      schema_version: 1,
      fields: [{ key: "default_engine", type: "select", label: "Default engine", scope: "user", options: ["docker", "podman"] }],
      settings_revision: 7,
    },
  });
  fetch.push({
    ok: true,
    data: {
      plugin_instance_id: "plugin_instance_1",
      schema_version: 1,
      settings_revision: 8,
      values: { default_engine: "podman" },
      updated_at: "2026-06-30T00:00:00Z",
    },
  });
  const client = new PluginPlatformClient({
    apiBaseURL: "https://host.example/",
    fetch: fetch.fetch,
    ownerSessionHashHeader: "owner_session_hash",
  });

  const schema = await client.getSettingsSchema("plugin instance/1");
  const patched = await client.patchSettings("plugin instance/1", { default_engine: "podman" });

  assert.equal(schema.fields[0]?.key, "default_engine");
  assert.equal(patched.values.default_engine, "podman");
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings/schema");
  assert.equal(fetch.calls[0]?.init.method, "GET");
  assert.equal(fetch.calls[0]?.init.headers["Accept"], "application/json");
  assert.equal(fetch.calls[0]?.init.headers["Content-Type"], undefined);
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], "owner_session_hash");
  assert.equal(fetch.calls[1]?.input, "https://host.example/_redevplugin/api/plugins/plugin%20instance%2F1/settings");
  assert.equal(fetch.calls[1]?.init.method, "PATCH");
  assert.equal(fetch.calls[1]?.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { values: { default_engine: "podman" } });
});

test("platform client manages plugin lifecycle and surface opening routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.1.0", active_fingerprint: "sha256:b", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "enabled" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled", disabled_reason: "admin" } });
  fetch.push({
    ok: true,
    data: {
      plugin_id: "com.example.plugin",
      plugin_instance_id: "plugin_instance_1",
      surface_id: "example.activity",
      surface_instance_id: "surface_1",
      active_fingerprint: "sha256:a",
      asset_ticket: "asset_ticket_1",
      asset_ticket_id: "asset_ticket_id_1",
      bridge_nonce: "bridge_nonce_1",
      issued_at: "2026-06-30T00:00:00Z",
      expires_at: "2026-06-30T00:05:00Z",
    },
  });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", plugin_id: "com.example.plugin", version: "1.0.0", active_fingerprint: "sha256:a", trust_state: "verified", enable_state: "disabled", retained_data_state: "deleted" } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const installed = await client.installPlugin({ package_base64: "cGtn", trust_state: "verified", plugin_instance_id: "plugin_instance_1" });
  const updated = await client.updatePlugin({ plugin_instance_id: "plugin_instance_1", package_base64: "cGtnMg", trust_state: "verified" });
  const downgraded = await client.downgradePlugin({ plugin_instance_id: "plugin_instance_1", version: "1.0.0" });
  const enabled = await client.enablePlugin("plugin_instance_1");
  const disabled = await client.disablePlugin({ plugin_instance_id: "plugin_instance_1", reason: "admin" });
  const surface = await client.openSurface({
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.activity",
    surface_instance_id: "surface_1",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    session_channel_id_hash: "channel_hash",
    sandbox_origin: "https://plg.example",
  });
  const uninstalled = await client.uninstallPlugin({ plugin_instance_id: "plugin_instance_1", delete_data: true });

  assert.equal(installed.enable_state, "disabled");
  assert.equal(updated.version, "1.1.0");
  assert.equal(downgraded.version, "1.0.0");
  assert.equal(enabled.enable_state, "enabled");
  assert.equal(disabled.disabled_reason, "admin");
  assert.equal(surface.asset_ticket, "asset_ticket_1");
  assert.equal(uninstalled.retained_data_state, "deleted");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/install");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { package_base64: "cGtn", trust_state: "verified", plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/update");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", package_base64: "cGtnMg", trust_state: "verified" });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/downgrade");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", version: "1.0.0" });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/enable");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/disable");
  assert.deepEqual(JSON.parse(fetch.calls[4]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", reason: "admin" });
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/surfaces/open");
  assert.deepEqual(JSON.parse(fetch.calls[5]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    surface_id: "example.activity",
    surface_instance_id: "surface_1",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    session_channel_id_hash: "channel_hash",
    sandbox_origin: "https://plg.example",
  });
  assert.equal(fetch.calls[6]?.input, "/_redevplugin/api/plugins/uninstall");
  assert.deepEqual(JSON.parse(fetch.calls[6]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1", delete_data: true });
});

test("platform client manages runtime lifecycle routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { runtime_instance_id: "runtime_1", runtime_generation_id: "gen_1", runtime_version: "0.0.0-dev", rust_ipc_version: "rust-ipc-v1", wasm_abi_version: "redevplugin-wasm-worker-v1", ready: true } });
  fetch.push({ ok: true, data: { runtime_instance_id: "runtime_1", runtime_generation_id: "gen_1", ready: true } });
  fetch.push({ ok: true, data: { stopped: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const started = await client.startRuntime({ target: { os: "darwin", arch: "arm64" } });
  const health = await client.runtimeHealth();
  const stopped = await client.stopRuntime();

  assert.equal(started.ready, true);
  assert.equal(health.runtime_generation_id, "gen_1");
  assert.equal(stopped.stopped, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/runtime/start");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), { target: { os: "darwin", arch: "arm64" } });
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/runtime/health");
  assert.equal(fetch.calls[1]?.init.method, "GET");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/runtime/stop");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), {});
});

test("platform client covers operation and data lifecycle routes", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      operations: [{
        operation_id: "op 1",
        plugin_instance_id: "plugin_instance_1",
        method: "worker.long",
        execution: "operation",
        status: "running",
        created_at: "2026-06-30T00:00:00Z",
        updated_at: "2026-06-30T00:00:00Z",
      }],
    },
  });
  fetch.push({
    ok: true,
    data: {
      operation_id: "op 1",
      plugin_instance_id: "plugin_instance_1",
      method: "worker.long",
      execution: "operation",
      status: "cancel_requested",
      created_at: "2026-06-30T00:00:00Z",
      updated_at: "2026-06-30T00:00:02Z",
    },
  });
  fetch.push({ ok: true, data: { archive_ref: "archive/plugin_instance_1.zip" } });
  fetch.push({ ok: true, data: { imported: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const operations = await client.listOperations("plugin_instance_1");
  const canceled = await client.cancelOperation("op 1", "user canceled");
  const exported = await client.exportData({ plugin_instance_id: "plugin_instance_1" });
  const imported = await client.importData({ plugin_instance_id: "plugin_instance_1", archive_ref: exported.archive_ref, delete_existing: true });

  assert.equal(operations.operations?.[0]?.status, "running");
  assert.equal(canceled.status, "cancel_requested");
  assert.equal(exported.archive_ref, "archive/plugin_instance_1.zip");
  assert.equal(imported.imported, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/operations?plugin_instance_id=plugin_instance_1");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/operations/op%201/cancel");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), { reason: "user canceled" });
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/data/export");
  assert.deepEqual(JSON.parse(fetch.calls[2]?.init.body ?? ""), { plugin_instance_id: "plugin_instance_1" });
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/data/import");
  assert.deepEqual(JSON.parse(fetch.calls[3]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    archive_ref: "archive/plugin_instance_1.zip",
    delete_existing: true,
  });
});

test("platform client lists and invokes host-mediated intents", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      intents: [{
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        publisher_id: "example",
        display_name: "Intent plugin",
        version: "1.0.0",
        active_fingerprint: "sha256:intent",
        intent_id: "example.echo",
        method: "echo.ping",
        effect: "read",
        execution: "sync",
        payload_schema: { type: "object" },
      }],
    },
  });
  fetch.push({ ok: true, data: { data: { ok: true } } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch, ownerSessionHashHeader: "owner_session_hash" });

  const listed = await client.listIntents({ intent_id: "example.echo", plugin_instance_id: "plugin_instance_1" });
  const result = await client.invokeIntent<{ ok: boolean }>({
    plugin_instance_id: "plugin_instance_1",
    intent_id: "example.echo",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    session_channel_id_hash: "channel_hash",
    params: { message: "hello" },
  });

  assert.equal(listed.intents?.[0]?.method, "echo.ping");
  assert.equal(result.data?.ok, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/intents?intent_id=example.echo&plugin_instance_id=plugin_instance_1");
  assert.equal(fetch.calls[0]?.init.method, "GET");
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], "owner_session_hash");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/intents/invoke");
  assert.equal(fetch.calls[1]?.init.method, "POST");
  assert.deepEqual(JSON.parse(fetch.calls[1]?.init.body ?? ""), {
    plugin_instance_id: "plugin_instance_1",
    intent_id: "example.echo",
    owner_session_hash: "owner_session_hash",
    owner_user_hash: "owner_user_hash",
    session_channel_id_hash: "channel_hash",
    params: { message: "hello" },
  });
});

test("platform client maps dangerous intent confirmation requirement", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "plugin method confirmation required" });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.invokeIntent({ plugin_instance_id: "plugin_instance_1", intent_id: "example.danger", params: { target: "db" } }),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_CONFIRMATION_REQUIRED" && err.message === "plugin method confirmation required",
  );
});

test("platform client manages permissions and secret refs without exposing local contracts", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: true, data: { permissions: [{ plugin_instance_id: "plugin_instance_1", permission_id: "network.http" }] } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", granted_by: "admin" } });
  fetch.push({ ok: true, data: { plugin_instance_id: "plugin_instance_1", permission_id: "network.http", revoked_by: "admin" } });
  fetch.push({ ok: true, data: { bound: true } });
  fetch.push({ ok: true, data: { passed: true } });
  fetch.push({ ok: true, data: { deleted: true } });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const grants = await client.listPermissions("plugin_instance_1", true);
  const grant = await client.grantPermission({ plugin_instance_id: "plugin_instance_1", permission_id: "network.http", granted_by: "admin" });
  const revoke = await client.revokePermission({ plugin_instance_id: "plugin_instance_1", permission_id: "network.http", revoked_by: "admin", reason: "rotation" });
  const bound = await client.bindSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const tested = await client.testSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });
  const deleted = await client.deleteSecret({ plugin_instance_id: "plugin_instance_1", secret_ref: "api_token", scope: "user" });

  assert.equal(grants.permissions?.[0]?.permission_id, "network.http");
  assert.equal(grant.granted_by, "admin");
  assert.equal(revoke.revoked_by, "admin");
  assert.equal(bound.bound, true);
  assert.equal(tested.passed, true);
  assert.equal(deleted.deleted, true);
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/permissions?plugin_instance_id=plugin_instance_1&active_only=true");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/permissions/grant");
  assert.equal(fetch.calls[2]?.input, "/_redevplugin/api/plugins/permissions/revoke");
  assert.equal(fetch.calls[3]?.input, "/_redevplugin/api/plugins/secrets/bind");
  assert.equal(fetch.calls[4]?.input, "/_redevplugin/api/plugins/secrets/test");
  assert.equal(fetch.calls[5]?.input, "/_redevplugin/api/plugins/secrets/delete");
});

test("platform client reads host audit and diagnostic events", async () => {
  const fetch = new FakeFetch();
  fetch.push({
    ok: true,
    data: {
      audit_events: [{
        type: "plugin.intent.invoked",
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        occurred_at: "2026-06-30T00:00:00Z",
        details: { intent_id: "example.echo" },
      }],
    },
  });
  fetch.push({
    ok: true,
    data: {
      diagnostic_events: [{
        type: "plugin.csp.violation",
        severity: "warning",
        plugin_id: "com.example.intent",
        plugin_instance_id: "plugin_instance_1",
        surface_instance_id: "surface_1",
        occurred_at: "2026-06-30T00:00:01Z",
        details: { effective_directive: "script-src" },
      }],
    },
  });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  const audit = await client.listAuditEvents({ plugin_instance_id: "plugin_instance_1", type: "plugin.intent.invoked", limit: 5 });
  const diagnostics = await client.listDiagnosticEvents({ plugin_id: "com.example.intent", severity: "warning", limit: 10 });

  assert.equal(audit.audit_events?.[0]?.details?.intent_id, "example.echo");
  assert.equal(diagnostics.diagnostic_events?.[0]?.details?.effective_directive, "script-src");
  assert.equal(fetch.calls[0]?.input, "/_redevplugin/api/plugins/audit?plugin_instance_id=plugin_instance_1&type=plugin.intent.invoked&limit=5");
  assert.equal(fetch.calls[1]?.input, "/_redevplugin/api/plugins/diagnostics?plugin_id=com.example.intent&severity=warning&limit=10");
});

test("platform client maps management envelope errors", async () => {
  const fetch = new FakeFetch();
  fetch.push({ ok: false, error_code: "PLUGIN_INVALID_REQUEST", error: "plugin settings are not declared" });
  const client = new PluginPlatformClient({ fetch: fetch.fetch });

  await assert.rejects(
    client.getSettings("plugin_instance_missing"),
    (err) => err instanceof PluginBridgeError && err.errorCode === "PLUGIN_INVALID_REQUEST" && err.message === "plugin settings are not declared",
  );
});

async function tick(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
