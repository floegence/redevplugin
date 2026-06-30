import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PluginBridgeClient,
  PluginBridgeError,
  PluginSurfaceHost,
  type FetchInitLike,
  type FetchResponseLike,
  type MessageEventLike,
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
  type: "redeven.plugin.handshake",
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
    type: "redeven.plugin.handshake",
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
    type: "redeven.plugin.call",
    request: { id: "1", method: "worker.echo", params: { message: "hello" } },
  });

  receiver.emit("https://evil.example", { type: "redeven.plugin.response", id: "1", ok: true, data: { ok: false } });
  receiver.emit("https://host.example", { type: "redeven.plugin.response", id: "other", ok: true, data: { ok: false } });
  receiver.emit("https://host.example", { type: "redeven.plugin.response", id: "1", ok: true, data: { ok: true } });

  assert.deepEqual(await pending, { ok: true });
  client.dispose();
});

test("call rejects runtime bridge errors", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 100 });

  const pending = client.call("worker.echo");
  receiver.emit("https://host.example", {
    type: "redeven.plugin.response",
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
  receiver.emit("https://evil.example", { type: "redeven.plugin.lifecycle", event: { type: "visible" } });
  receiver.emit("https://host.example", { type: "redeven.plugin.lifecycle", event: { type: "visible" } });
  unsubscribe();
  receiver.emit("https://host.example", { type: "redeven.plugin.lifecycle", event: { type: "hidden" } });

  assert.deepEqual(events, ["visible"]);
  client.dispose();
});

test("dispose rejects pending calls and removes listener", async () => {
  const target = new FakeWindow();
  const receiver = new FakeWindow();
  const client = new PluginBridgeClient(bootstrap, { target, receiver, timeoutMs: 1000 });
  const pending = client.call("worker.echo");

  client.dispose();
  receiver.emit("https://host.example", { type: "redeven.plugin.response", id: "1", ok: true, data: true });

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
  assert.equal(fetch.calls[0]?.input, "https://host.example/_redeven_proxy/api/plugins/surfaces/surface_1/bridge-token");
  assert.deepEqual(JSON.parse(fetch.calls[0]?.init.body ?? ""), {
    bridge_channel_id: "bridge_channel_1",
    handshake,
  });
  assert.equal(fetch.calls[0]?.init.headers["X-ReDevPlugin-Owner-Session-Hash"], "owner_session_hash");
  assert.deepEqual(iframe.sent, [
    {
      targetOrigin: "https://plugin.example",
      message: { type: "redeven.plugin.lifecycle", event: { type: "ready" } },
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
    type: "redeven.plugin.call",
    request: { id: "call_1", method: "echo.ping", params: { message: "hello" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1]?.input, "/_redeven_proxy/api/plugins/rpc");
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
      type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_before_handshake", method: "echo.ping", params: {} },
  }, iframe);
  await tick();
  parent.emit("https://plugin.example", {
    type: "redeven.plugin.call",
    request: { id: "call_from_other_window", method: "echo.ping", params: {} },
  }, new FakeWindow());
  await tick();

  assert.equal(fetch.calls.length, 0);
  assert.deepEqual(iframe.sent, [
    {
      targetOrigin: "https://plugin.example",
      message: {
        type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_bad_params", method: "echo.ping", params: ["not", "object"] },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 1);
  assert.deepEqual(iframe.sent[2], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_denied", method: "echo.ping", params: {} },
  }, iframe);
  await tick();

  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_danger", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 4);
  assert.equal(fetch.calls[1]?.input, "/_redeven_proxy/api/plugins/rpc");
  assert.equal(fetch.calls[2]?.input, "/_redeven_proxy/api/plugins/confirm");
  assert.equal(fetch.calls[3]?.input, "/_redeven_proxy/api/plugins/rpc");
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
      type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_declined", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 3);
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redeven.plugin.response",
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
    type: "redeven.plugin.call",
    request: { id: "call_no_confirm_handler", method: "danger.run", params: { target: "db" } },
  }, iframe);
  await tick();

  assert.equal(fetch.calls.length, 2);
  assert.deepEqual(iframe.sent[1], {
    targetOrigin: "https://plugin.example",
    message: {
      type: "redeven.plugin.response",
      id: "call_no_confirm_handler",
      ok: false,
      error_code: "PLUGIN_CONFIRMATION_REQUIRED",
      error: "confirmation required",
    },
  });
  host.dispose();
});

async function tick(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
