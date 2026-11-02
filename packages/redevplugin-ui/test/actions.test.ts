import assert from "node:assert/strict";
import { test } from "node:test";
import { callPluginActionSync, callPluginActionOperation, observePluginActionEvents } from "../src/actions.js";
import type { PluginBridgeClient } from "../src/surface.js";

test("action observation resumes a cursor without dispatching or canceling work", async () => {
  let calls = 0;
  let cursor = 0;
  const bridge = {
    call: async () => { calls++; return { data: { accepted: true }, execution_id: "execution_author_test" }; },
    executionEvents: async (_id: string, after: number) => {
      cursor = after;
      return { execution_id: "execution_author_test", events: [{ execution_id: "execution_author_test", sequence: after + 1, kind: "progress" }], cursor: after + 1 };
    },
  } as unknown as PluginBridgeClient;
  const task = await callPluginActionOperation(bridge, { method: "work.start", execution: "operation", cancelable: false }, {});
  assert.equal(calls, 1);
  assert.equal("cancel" in task, false);
  const observation = observePluginActionEvents(bridge, task.execution_id, 9);
  assert.equal((await observation.read()).cursor, 10);
  assert.equal(cursor, 9);
  assert.equal(calls, 1);
  await observation.read();
  assert.equal(cursor, 10);
});

test("sync actions unwrap data and never replay failed writes", async () => {
  let calls = 0;
  const bridge = { call: async () => { calls++; return { data: { value: 4 } }; } } as unknown as PluginBridgeClient;
  assert.deepEqual(await callPluginActionSync(bridge, { method: "draft.read", execution: "sync", cancelable: false }, {}), { value: 4 });
  assert.equal(calls, 1);
});

test("event observation rejects cross-execution events without advancing its cursor", async () => {
  const cursors: number[] = [];
  const bridge = { executionEvents: async (_id: string, after: number) => {
    cursors.push(after);
    return { execution_id: "execution_author_test", cursor: 6, events: [{ execution_id: "execution_other_test", sequence: 6, kind: "data" }] };
  } } as unknown as PluginBridgeClient;
  const observation = observePluginActionEvents(bridge, "execution_author_test", 5);
  await assert.rejects(observation.read());
  await assert.rejects(observation.read());
  assert.deepEqual(cursors, [5, 5]);
});
