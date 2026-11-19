import assert from "node:assert/strict";
import { test } from "node:test";
import { createAgentClient, createFlowerClient, defineAgentProfile, isConversationClosed } from "../src/agent-conversation.js";
import { createPluginTestHarness } from "../src/testing.js";
import { PluginBridgeError } from "../src/plugin.js";

test("an authorized library thread supports browsing, window updates and request recovery without resending",async()=>{
  const item={id:"message",role:"user",order:1,preview:"hello"};
  const fixture=createPluginTestHarness({call(method,input){switch(method){
    case "agent.conversation.role.open":return {data:{binding_id:"binding",revision:1,available:true,client_protocol:"test",unavailable_reasons:[]}};
    case "agent.conversation.threads":return {data:{items:[{id:"thread",title:"Catalog"}]}};
    case "agent.conversation.locate":return {data:{id:"thread",title:"Catalog",origin:"host"}};
    case "agent.conversation.library.messages":return {data:{items:[item]}};
    case "agent.conversation.library.body":return {data:{text:"hello"}};
    case "agent.conversation.library.window":return {data:{cursor:"view",view:{state:"idle",items:[item]}}};
    case "agent.conversation.library.attachment":return {data:{data:"AAEC"}};
    case "agent.conversation.library.send":return {data:{request_id:input!.request_id,conversation_id:"thread",state:"accepted",turn_id:"turn"}};
    case "agent.conversation.library.result":return {data:{state:"completed",text:""}};
    case "agent.conversation.library.cancel_send":return {data:{}};
    case "agent.conversation.pick":throw new PluginBridgeError("PLUGIN_CONFIRMATION_REJECTED","Dismissed",{review:"dismissed"});
    default:throw new Error(method);
  }}});
  try {const flower=await createFlowerClient(new fixture.BridgeClient(),{capabilityBinding:"agent",role:"assistant"});
    const {items}=await flower.threads.list();const chat=await flower.threads.open(items[0]!.id);
    assert.equal((await chat.history()).items[0]!.id,"message");assert.equal((await chat.body("message")).text,"hello");assert.deepEqual((await chat.attachment("message",0)).bytes,new Uint8Array([0,1,2]));
    for await(const view of chat.watch()){assert.equal(view.items[0]!.preview,"hello");break;}
    const sent=await chat.send("hello",{requestId:"saved"});assert.deepEqual(await chat.findSend(sent.requestId).result(),{status:"completed",text:""});await sent.cancel();await chat.close();
    assert.equal(fixture.calls.filter(c=>c.method==="agent.conversation.library.send").length,1);assert.equal(await flower.threads.pick(),null);
  }finally{fixture.dispose();}
});

test("a send handle settles and cancels only the original request across reconnect", async () => {
  let pages = 0;
  const fixture = createPluginTestHarness({ call(method, input) {
    switch (method) {
      case "agent.conversation.role.open": return { data: { binding_id: "agent", revision: 1, available: true, client_protocol: "test", unavailable_reasons: [] } };
      case "agent.conversation.open": return { data: { conversation_id: "chat", key: "main", title: "", lifetime: "temporary", archived: false, revision: 1, state: "idle" } };
      case "agent.conversation.send": return { data: { conversation_id: "chat", request_id: input!.request_id, turn_id: "", state: "accepted" } };
      case "agent.conversation.result":
        if (input!.request_id === "b") return { data: { state: "completed", text: "" } };
        assert.equal(input!.request_id, "a");
        if (++pages === 1) return { data: { state: "accepted" } };
        return { data: input!.cursor ? { state: "completed", text: " two" } : { state: "completed", text: "one", next_cursor: "next" } };
      case "agent.conversation.events.read": return { data: { events: [{ kind: "snapshot", cursor: "current", conversation_id: "chat" }] } };
      case "agent.conversation.cancel_send": assert.deepEqual(input, { binding_id: "agent", conversation_id: "chat", request_id: "a" }); return { data: {} };
      default: throw new Error("Unexpected method: " + method);
    }
  } });
  try {
    const agent = await createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "agent" }).openAgent("analyst");
    const chat = await agent.conversations.open({ key: "main", lifetime: "temporary" });
    const first = await chat.send("first", { requestId: "a" });
    const second = await chat.send("second", { requestId: "b" });
    assert.deepEqual(await second.result(), { status: "completed", text: "" });
    assert.deepEqual(await chat.findSend(first.requestId).result(), { status: "completed", text: "one two" });
    await first.cancel();
    assert.equal(fixture.calls.filter(call => call.method === "agent.conversation.send").length, 2);
  } finally { fixture.dispose(); }
});

test("temporary observation advances the cursor and respects remote closure", async () => {
  let reads = 0;
  const fixture = createPluginTestHarness({ call(method, input) {
    if (method === "agent.conversation.role.open") return { data: { binding_id: "board", revision: 1, available: true, client_protocol: "test", unavailable_reasons: [] } };
    if (method === "agent.conversation.open") return { data: { conversation_id: "game", key: "game", lifetime: "temporary", title: "Game", archived: false, revision: 1, state: "idle" } };
    assert.equal(method, "agent.conversation.events.read");
    assert.equal(input!.after, reads === 0 ? undefined : "1");
    reads++;
    return { data: { events: [{ conversation_id: "game", cursor: String(reads), kind: reads === 1 ? "snapshot" : "closed" }] } };
  } });
  try {
    const agent = await createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "flower" }).openAgent("opponent");
    const game = await agent.conversations.open({ key: "game", lifetime: "temporary" });
    const kinds = [];
    for await (const event of game.observe()) kinds.push(event.kind);
    assert.deepEqual(kinds, ["snapshot", "closed"]);
    await assert.rejects(() => game.send({ requestId: "late", text: "A1" }), isConversationClosed);
    assert.equal(reads, 2);
  } finally { fixture.dispose(); }
});

test("temporary sessions close by identity; closing a saved handle never deletes history", async () => {
  let generation = 1;
  const fixture = createPluginTestHarness({ call(method, input) {
    if (method === "agent.conversation.role.open") return { data: { binding_id: "board", revision: 1, available: true, client_protocol: "test", unavailable_reasons: [] } };
    if (method === "agent.conversation.open") return { data: { conversation_id: `game-${generation}`, key: input!.key, lifetime: input!.lifetime ?? "persistent", title: "Game", archived: false, revision: 1, state: "idle" } };
    assert.equal(method, "agent.conversation.close");
    assert.equal(input!.conversation_id, `game-${generation++}`);
    return { data: {} };
  } });
  try {
    const agent = await createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "flower" }).openAgent("opponent");
    const open = () => agent.conversations.open({ key: "board", lifetime: "temporary" });
    const first = await open();
    assert.equal(fixture.calls.at(-1)!.input!.lifetime, "temporary");
    await first.close(); await first.close();
    await assert.rejects(() => first.send({ requestId: "stale", text: "late move" }));
    assert.equal((await open()).id === first.id, false);
    const saved = await agent.conversations.open({ key: "saved" });
    await saved.close();
    assert.equal(fixture.calls.filter(call => call.method === "agent.conversation.close").length, 1);
  } finally { fixture.dispose(); }
});

test("opening a packaged role and asking for temporary text never opens a saved conversation", async () => {
  const fixture = createPluginTestHarness({ call(method, input) {
    if (method === "agent.conversation.role.open") {
      assert.deepEqual(input, { role_id: "opponent" });
      return { data: { binding_id: "board", revision: 4, available: true, client_protocol: "test.v1", unavailable_reasons: [] } };
    }
    assert.equal(method, "agent.conversation.client.execute");
    assert.deepEqual(input, { binding_id: "board", protocol: "test.v1", operation: "temporary.reply", input_json: '{"text":"next move"}' });
    return { data: { output_json: '{"text":"D4"}' } };
  } });
  try {
    const agent = await createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "flower" }).openAgent("opponent");
    assert.deepEqual(await agent.temporary.reply({ text: "next move" }), { text: "D4" });
    assert.equal(fixture.calls.length, 2);
  } finally { fixture.dispose(); }
});

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

test("configuration proposals retain conversation ownership without granting authority", async () => {
  const fixture = createPluginTestHarness({ call(method, input) {
    if (method === "agent.conversation.bind") return { data: { binding_id: input!.object_key, revision: 1, client_protocol: "test.agent.v1", available: true, unavailable_reasons: [] } };
    if (method === "agent.conversation.open") return { data: { conversation_id: "conversation-1", key: "main", title: "Original", archived: false, revision: 1, state: "idle" } };
    if (method === "agent.conversation.configure") return { data: { revision: 2, available: true, unavailable_reasons: [] } };
    throw new Error("Unexpected call " + method);
  } });
  try {
    const client = createAgentClient(new fixture.BridgeClient(), { capabilityBinding: "agent" });
    const profile = { id: "helper", instructions: "", methods: [] };
    const agent = await client.bindAgent({ objectKey: "object-1", profile });
    const conversation = await agent.conversations.open({ key: "main" });
    const other = await client.bindAgent({ objectKey: "object-2", profile });
    await assert.rejects(other.configure({ area: "permissions", conversation }), error => error instanceof Error && error.message.includes("another Agent"));
    assert.equal(fixture.calls.filter(call => call.method === "agent.conversation.configure").length, 0);
    await agent.configure({ area: "permissions", conversation, proposal: { mode: "approval_required" } });
    assert.deepEqual(fixture.calls.at(-1)!.input, { binding_id: "object-1", area: "permissions", slot: "", conversation_id: "conversation-1", proposal_json: '{"mode":"approval_required"}' });
  } finally { fixture.dispose(); }
});
