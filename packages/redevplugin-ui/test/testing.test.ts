import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginTestHarness, createPluginTestContext, createPluginTestClock } from "../src/testing.js";
import { PluginBridgeError } from "../src/errors.js";

test("author fixtures use the real bridge and reject missing responses on disposal", async () => {
  const fixture = createPluginTestHarness();
  const client = new fixture.BridgeClient();
  await client.ready();
  const called = client.call("notes.load", { id: "one" });
  await Promise.resolve();
  assert.equal(fixture.calls[0].method, "notes.load");
  fixture.calls[0].resolve({ data: { title: "One" } });
  assert.deepEqual(await called, { data: { title: "One" } });
  const pending = client.call("notes.save", {});
  fixture.dispose();
  await assert.rejects(pending, error => error instanceof PluginBridgeError);
});

test("fixture cancellation rejects late responses and context changes use the production contract", async () => {
  const fixture = createPluginTestHarness(); const client = new fixture.BridgeClient();
  await client.ready();
  let language = "";
  client.onContext(context => { language = context.locale.language_tag; });
  fixture.context(createPluginTestContext("zh-CN", 2));
  assert.equal(language, "zh-CN");
  const controller = new AbortController();
  const pending = client.call("notes.read", {}, { signal: controller.signal });
  await Promise.resolve();
  const rejected = assert.rejects(pending, error => error instanceof PluginBridgeError);
  controller.abort(); await rejected; await Promise.resolve();
  assert.equal(fixture.calls[0].cancelled, true);
  fixture.calls[0].resolve({ unexpected: true });
  fixture.dispose();
  assert.throws(() => new fixture.BridgeClient(), /exactly one/u);
});

test("fixture clock drives production request deadlines without real waiting", async () => {
  const time = createPluginTestClock(100);
  const fixture = createPluginTestHarness({ clock: time.clock });
  const client = new fixture.BridgeClient({ timeoutMs: 5000 });
  await client.ready();
  const pending = client.call("notes.save", {});
  const rejected = assert.rejects(pending, error => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_TIMEOUT" && error.mutationOutcome === "unknown");
  await time.advanceBy(4999);
  assert.equal(fixture.calls[0].cancelled, false);
  await time.advanceBy(1); await rejected;
  assert.equal(fixture.calls[0].cancelled, true);
  assert.equal(time.pending, 0);
  fixture.dispose(); time.dispose();
});

test("fixture clock orders equal deadlines and cancels completed calls", async () => {
  const time = createPluginTestClock(); const order: number[] = [];
  const cancel = time.clock.schedule(() => order.push(0), 10); cancel();
  time.clock.schedule(() => { order.push(1); time.clock.schedule(() => order.push(3), 0); }, 10);
  time.clock.schedule(() => order.push(2), 10);
  await time.advanceBy(10); assert.deepEqual(order, [1, 2, 3]);
  const fixture = createPluginTestHarness({ clock: time.clock }); const client = new fixture.BridgeClient();
  await client.ready(); const pending = client.call("notes.read", {}); await Promise.resolve();
  fixture.calls[0].resolve({ data: "saved" }); await pending;
  assert.equal(time.pending, 0); fixture.dispose();
  await assert.rejects(time.advanceBy(-1));
});
