import assert from "node:assert/strict";
import { test } from "node:test";
import { createAgentClient, defineAgentProfile } from "../src/agent-conversation.js";
import { createPluginTestHarness } from "../src/testing.js";
import { PluginBridgeError } from "../src/plugin.js";

test("binding and opening never launch work; uncertain sends retain their original request identity", async () => {
  const snapshot = { conversation_id: "conversation-1", key: "main", title: "Assistant", archived: false, revision: 1, state: "idle" };
  const fixture = createPluginTestHarness({ call(method, input) {
    switch (method) {
      case "agent.conversation.bind": return { data: { binding_id: "binding-1", revision: 1, client_protocol: "test.agent.v1", available: true, unavailable_reasons: [] } };
      case "agent.conversation.open": return { data: snapshot };
      case "agent.conversation.send": throw new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "Original outcome unknown");
      case "agent.conversation.receipt": return { data: { request_id: input!.request_id, conversation_id: "conversation-1", turn_id: "turn-1", state: "accepted" } };
      default: throw new Error("Unexpected call " + method);
    }
  } });
  try {
    const bridge = new fixture.BridgeClient();
    const client = createAgentClient(bridge, { capabilityBinding: "agent" });
    const profile = defineAgentProfile({ id: "helper", instructions: "Help with this object", methods: ["document.read"] });
    const agent = await client.bindAgent({ objectKey: "object-1", profile });
    const conversation = await agent.conversations.open({ key: "main" });
    assert.deepEqual(fixture.calls.map(call => call.method), ["agent.conversation.bind", "agent.conversation.open"]);
    await assert.rejects(conversation.send({ requestId: "retained-request", text: "Do the work" }));
    const receipt = await conversation.receipt("retained-request");
    assert.equal(receipt.state, "accepted");
    assert.equal(fixture.calls.filter(call => call.method === "agent.conversation.send").length, 1);
    assert.deepEqual(fixture.calls[2]!.input, { binding_id: "binding-1", conversation_id: "conversation-1", request_id: "retained-request", text: "Do the work" });
    const copied = conversation.snapshot;
    (copied as { conversation_id: string }).conversation_id = "unrelated";
    assert.equal(conversation.id, "conversation-1");
  } finally { fixture.dispose(); }
});

test("conversation revisions are not silently retried or refreshed after a conflict", async () => {
  let updates = 0;
  const fixture = createPluginTestHarness({ call(method) {
    if (method === "agent.conversation.bind") return { data: { binding_id: "binding-1", revision: 1, client_protocol: "test.agent.v1", available: true, unavailable_reasons: [] } };
    if (method === "agent.conversation.open") return { data: { conversation_id: "conversation-1", key: "main", title: "Original", archived: false, revision: 3, state: "idle" } };
    if (method === "agent.conversation.update") { updates++; throw new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "Revision conflict"); }
    throw new Error("Unexpected retry " + method);
  } });
  try {
    const agent = await createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "agent" }).bindAgent({ objectKey: "object-1", profile: { id: "helper", instructions: "", methods: [] } });
    const conversation = await agent.conversations.open({ key: "main" });
    await assert.rejects(conversation.update({ title: "Changed" }));
    assert.equal(updates, 1);
    assert.equal(conversation.snapshot.title, "Original");
    assert.equal(fixture.calls[2]!.input!.revision, 3);
  } finally { fixture.dispose(); }
});
