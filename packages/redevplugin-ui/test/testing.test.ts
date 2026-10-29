import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginTestHarness, createPluginTestContext } from "../src/testing.js";
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
  await client.render({ type: "element", key: "root", tag: "main", children: [{ type: "text", key: "label", text: "One" }] });
  assert.equal(fixture.tree?.children?.[0].type, "text");
  let selected = "";
  client.onAction("select-note", event => { selected = event.value ?? ""; });
  fixture.action("select-note", { value: "two" });
  await Promise.resolve();
  assert.equal(selected, "two");
  const pending = client.call("notes.save", {});
  fixture.dispose();
  await assert.rejects(pending, error => error instanceof PluginBridgeError);
});

test("fixture rendering retains the production VNode validator", async () => {
  const fixture = createPluginTestHarness(); const client = new fixture.BridgeClient();
  await client.ready();
  await assert.rejects(async () => client.render({ type: "element", key: "root", tag: "main", attributes: { style: "color:red" } }));
  fixture.dispose();
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
