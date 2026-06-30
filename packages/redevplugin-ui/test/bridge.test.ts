import assert from "node:assert/strict";
import { test } from "node:test";
import { PluginBridgeClient, PluginBridgeError, type MessageEventLike, type WindowLike } from "../src/index.js";

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

  emit(origin: string, data: unknown): void {
    for (const listener of this.#listeners) {
      listener({ origin, data });
    }
  }
}

const bootstrap = {
  pluginId: "com.example.plugin",
  surfaceId: "example.activity",
  surfaceInstanceId: "surface_1",
  activeFingerprint: "sha256:abc",
  bridgeNonce: "nonce_1",
  parentOrigin: "https://host.example",
};

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
