import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  callCapabilityOperation,
  callCapabilityStream,
  callCapabilitySync,
  isCapabilityBusinessError,
  PluginBridgeError,
  type PluginBridgeClient,
} from "../src/plugin.js";
import type { PluginExecutionEventList } from "../src/surface.js";
import type { PluginExecutionSnapshot } from "../src/surface.js";

const requestSchema = {
  type: "object",
  additionalProperties: false,
  required: ["document_id"],
  properties: {
    document_id: { type: "string", minLength: 1 },
  },
} as const;

const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["accepted"],
  properties: {
    accepted: { type: "boolean" },
  },
} as const;

const eventTypeName = "DocumentsWatchEvent";
const eventSchema = {
  type: "object",
  additionalProperties: false,
  required: ["line"],
  properties: { line: { type: "string" } },
} as const;

type CapabilityEffect = "read" | "write" | "execute" | "delete" | "admin";

function syncContract(
  method: string,
  request: Readonly<Record<string, unknown>> = requestSchema,
  response: Readonly<Record<string, unknown>> = responseSchema,
  effect: CapabilityEffect = "read",
) {
  return { method, effect, execution: "sync" as const, requestSchema: request, responseSchema: response };
}

function operationContract<Cancelable extends boolean = true>(
  method: string,
  cancelable: Cancelable = true as Cancelable,
  effect: CapabilityEffect = "write",
) {
  return { method, effect, execution: "operation" as const, cancelable, requestSchema, responseSchema };
}

function streamContract(method: string, effect: CapabilityEffect = "read") {
  return {
    method,
    effect,
    execution: "subscription" as const,
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
  };
}

const encodeEvent = (event: unknown) => btoa(JSON.stringify(event));
const dataEvent = (executionID: string, sequence: number, data: unknown, typeName = eventTypeName) => ({
  execution_id: executionID,
  sequence,
  kind: "data" as const,
  payload: { event_type: typeName, data: encodeEvent(data) },
});
const terminalEvent = (executionID: string, sequence: number, status: "completed" | "canceled" | "failed" | "orphaned") => ({
  execution_id: executionID,
  sequence,
  kind: "terminal" as const,
  payload: { status },
});

test("generated capability helpers validate sync request and response payloads", async () => {
  const bridge = fakeBridge({ data: { accepted: true } });
  const result = await callCapabilitySync(
    bridge.client,
    syncContract("documents.get"),
    { document_id: "doc-1" },
  );
  assert.deepEqual(result, { accepted: true });
  assert.deepEqual(bridge.calls, [{ method: "documents.get", params: { document_id: "doc-1" } }]);

  await assert.rejects(
    callCapabilitySync(
      bridge.client,
      syncContract("documents.get"),
      { document_id: "", extra: true } as never,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  assert.equal(bridge.calls.length, 1);

  const invalidResponse = fakeBridge({ data: { accepted: true, unexpected: true } });
  await assert.rejects(
    callCapabilitySync(
      invalidResponse.client,
      syncContract("documents.get"),
      { document_id: "doc-1" },
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

test("generated capability helpers expose one host-owned execution identity", async () => {
  const operationBridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_opaque_1" });
  const operation = await callCapabilityOperation<{ document_id: string }, { accepted: boolean }>(
    operationBridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
  );
  assert.equal(operation.data.accepted, true);
  assert.equal(operation.execution_id, "execution_opaque_1");
  assert.equal(typeof operation.cancel, "function");

  const streamBridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_opaque_2" });
  const stream = await callCapabilityStream<{ document_id: string }, { accepted: boolean }, { line: string }>(
    streamBridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );
  assert.equal(stream.data.accepted, true);
  assert.equal(stream.execution_id, "execution_opaque_2");
  assert.equal("stream_handle" in stream, false);
  assert.equal(typeof stream.read, "function");
  assert.equal(typeof stream.cancel, "function");
  assert.equal(typeof stream[Symbol.asyncIterator], "function");

  await stream.cancel("user canceled");
  assert.deepEqual(streamBridge.cancellations, [{ executionID: "execution_opaque_2", reason: "user canceled" }]);

  await assert.rejects(
    callCapabilityOperation(
      fakeBridge({ data: { accepted: true } }).client,
      operationContract("documents.archive"),
      { document_id: "doc-1" },
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

test("capability calls and returned handle cancellation forward only per-call abort signals", async () => {
  const controller = new AbortController();
  const operationBridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_signal_1" });
  const operation = await callCapabilityOperation(
    operationBridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
    { signal: controller.signal },
  );
  assert.deepEqual(operationBridge.callOptions, [{ signal: controller.signal }]);

  const cancelController = new AbortController();
  await operation.cancel("user_cancelled", { signal: cancelController.signal });
  assert.deepEqual(operationBridge.cancellationOptions, [{ signal: cancelController.signal }]);

  const streamBridge = fakeBridge({
    data: { accepted: true },
    execution_id: "execution_signal_2",
  });
  const stream = await callCapabilityStream(
    streamBridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
    { signal: controller.signal },
  );
  assert.deepEqual(streamBridge.callOptions, [{ signal: controller.signal }]);
  await stream.cancel(undefined, { signal: cancelController.signal });
  assert.deepEqual(streamBridge.cancellationOptions, [{ signal: cancelController.signal }]);
});

test("operation handles expose snapshot and wait without implicit cancellation", async () => {
  const createdAt = "2026-07-26T00:00:00Z";
  const bridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_observe_1" },
    undefined,
    [
      {
        execution_id: "execution_observe_1",
        plugin_instance_id: "plugini_1",
        kind: "operation",
        cursor: 0,
        status: "running",
        cancelable: true,
        created_at: createdAt,
        updated_at: createdAt,
      },
      {
        execution_id: "execution_observe_1",
        plugin_instance_id: "plugini_1",
        kind: "operation",
        cursor: 0,
        status: "completed",
        cancelable: true,
        created_at: createdAt,
        updated_at: "2026-07-26T00:00:01Z",
        terminal_at: "2026-07-26T00:00:01Z",
      },
    ],
  );
  const operation = await callCapabilityOperation(
    bridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
  );
  assert.equal((await operation.snapshot()).status, "running");
  const terminal = await operation.wait({ pollIntervalMs: 1 });
  assert.equal(terminal.status, "completed");
  assert.equal(terminal.snapshot.terminal_at, "2026-07-26T00:00:01Z");
  assert.deepEqual(bridge.observations, ["execution_observe_1", "execution_observe_1"]);
  assert.deepEqual(bridge.cancellations, []);
});

test("operation wait propagates unknown snapshot errors without retrying", async () => {
  const bridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_observe_error" });
  const retiredErrorCode = ["PLUGIN", "OPERATION", "RATE", "LIMITED"].join("_");
  const snapshotError = new PluginBridgeError(retiredErrorCode as never, "execution snapshot failed");
  let snapshotCalls = 0;
  bridge.client.executionSnapshot = async () => {
    snapshotCalls += 1;
    throw snapshotError;
  };
  const operation = await callCapabilityOperation(
    bridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
  );

  await assert.rejects(operation.wait({ timeoutMs: 1_000, pollIntervalMs: 500 }), (error: unknown) => error === snapshotError);
  assert.equal(snapshotCalls, 1);
});

test("aborting operation wait stops local observation without canceling the operation", async () => {
  const bridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_observe_abort" },
    undefined,
    [{
      execution_id: "execution_observe_abort",
      plugin_instance_id: "plugini_1",
      kind: "operation",
      cursor: 0,
      status: "running",
      cancelable: true,
      created_at: "2026-07-26T00:00:00Z",
      updated_at: "2026-07-26T00:00:00Z",
    }],
  );
  const operation = await callCapabilityOperation(
    bridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
  );
  const controller = new AbortController();
  const waiting = operation.wait({ signal: controller.signal, pollIntervalMs: 500 });
  setTimeout(() => controller.abort(), 0);
  await assert.rejects(waiting, (error: unknown) =>
    error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_CANCELLED"
  );
  assert.deepEqual(bridge.cancellations, []);
});

test("operation wait deadline aborts an in-flight snapshot without canceling the operation", async () => {
  const bridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_observe_timeout" });
  let snapshotSignal: AbortSignal | undefined;
  bridge.client.executionSnapshot = (_executionID, options = {}) => new Promise((_resolve, reject) => {
    snapshotSignal = options.signal;
    options.signal?.addEventListener("abort", () => {
      reject(new PluginBridgeError("PLUGIN_BRIDGE_CANCELLED", "snapshot cancelled"));
    }, { once: true });
  });
  const operation = await callCapabilityOperation(
    bridge.client,
    operationContract("documents.archive"),
    { document_id: "doc-1" },
  );
  await assert.rejects(
    operation.wait({ timeoutMs: 1_000, pollIntervalMs: 500 }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_TIMEOUT",
  );
  assert.equal(snapshotSignal?.aborted, true);
  assert.deepEqual(bridge.cancellations, []);
});

test("capability helpers reject malformed result envelopes with stable errors", async () => {
  for (const result of [null, true, "invalid", [], { data: { accepted: true }, unexpected: true }]) {
    await assert.rejects(
      callCapabilitySync(
        fakeBridge(result).client,
        syncContract("documents.get"),
        { document_id: "doc-1" },
      ),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
  }

  for (const result of [
    { data: { accepted: true }, execution_id: "wrong.handle" },
    { data: { accepted: true }, execution_id: "execution_opaque_1", stream_handle: "wrong.handle" },
  ]) {
    const invocation = "stream_handle" in result
      ? callCapabilityStream(fakeBridge(result).client, streamContract("documents.invalid"), { document_id: "doc-1" })
      : callCapabilityOperation(fakeBridge(result).client, operationContract("documents.invalid"), { document_id: "doc-1" });
    await assert.rejects(
      invocation,
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
  }
});

test("capability helpers cancel live handles when response validation fails", async () => {
  const operationBridge = fakeBridge({ data: { unexpected: true }, execution_id: "execution_opaque_1" });
  await assert.rejects(
    callCapabilityOperation(
      operationBridge.client,
      operationContract("documents.archive"),
      { document_id: "doc-1" },
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(operationBridge.cancellations, [{ executionID: "execution_opaque_1", reason: "response_contract_mismatch" }]);

  const streamBridge = fakeBridge({
    data: { unexpected: true },
    execution_id: "execution_opaque_2",
  });
  await assert.rejects(
    callCapabilityStream(
      streamBridge.client,
      streamContract("documents.watch"),
      { document_id: "doc-1" },
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(streamBridge.cancellations, [{ executionID: "execution_opaque_2", reason: "response_contract_mismatch" }]);
});

test("subscription helpers keep reading events produced after dispatch", async () => {
  const bridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_opaque_2" },
    [
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return {
          execution_id: "execution_opaque_2",
          events: [dataEvent("execution_opaque_2", 1, { line: "one" })],
          cursor: 1,
        };
      },
      async () => ({
        execution_id: "execution_opaque_2",
        events: [dataEvent("execution_opaque_2", 2, { line: "two" }), terminalEvent("execution_opaque_2", 3, "completed")],
        cursor: 3,
      }),
    ],
  );
  const stream = await callCapabilityStream<{ document_id: string }, { accepted: boolean }, { line: string }>(
    bridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );
  const text: string[] = [];
  for await (const event of stream) text.push(event.data.line);
  assert.deepEqual(text, ["one", "two"]);
  assert.equal(bridge.streamReads, 2);
});

test("subscription helpers reject event type and schema mismatches", async () => {
  for (const event of [
    { sequence: 1, kind: "OtherEvent", data: encodeEvent({ line: "one" }), at: "2026-07-13T08:00:00Z" },
    { sequence: 1, kind: eventTypeName, data: encodeEvent({ unexpected: true }), at: "2026-07-13T08:00:00Z" },
    { sequence: 1, kind: eventTypeName, data: btoa("not json"), at: "2026-07-13T08:00:00Z" },
  ]) {
    const bridge = fakeBridge(
      { data: { accepted: true }, execution_id: "execution_event_invalid" },
      [async () => ({ execution_id: "execution_event_invalid", events: [
        { execution_id: "execution_event_invalid", sequence: 1, kind: "data", payload: { event_type: event.kind === "OtherEvent" ? "OtherEvent" : eventTypeName, data: event.data } },
      ], cursor: 1 })],
    );
    const stream = await callCapabilityStream(
      bridge.client,
      streamContract("documents.watch"),
      { document_id: "doc-1" },
    );
    await assert.rejects(
      stream[Symbol.asyncIterator]().next(),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
    assert.deepEqual(bridge.cancellations, [{ executionID: "execution_event_invalid", reason: "stream_contract_mismatch" }]);
  }
});

test("subscription read cancels the host operation when an event violates the published contract", async () => {
  const bridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_direct_read_invalid" },
    [async () => ({
      execution_id: "execution_direct_read_invalid",
      events: [dataEvent("execution_direct_read_invalid", 1, { line: "one" }, "OtherEvent")],
      cursor: 1,
    })],
  );
  const stream = await callCapabilityStream(
    bridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );

  await assert.rejects(
    stream.read(),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(bridge.cancellations, [{ executionID: "execution_direct_read_invalid", reason: "stream_contract_mismatch" }]);
});

test("subscription read abort stays per-call and leaves the stream reusable", async () => {
  const controller = new AbortController();
  let receivedSignal: AbortSignal | undefined;
  let streamReads = 0;
  const cancellations: string[] = [];
  const bridge = {
    call: async () => ({
      data: { accepted: true },
      execution_id: "execution_signal_1",
    }),
    executionEvents: async (_executionID: string, _cursor: number, options?: { signal?: AbortSignal }) => {
      streamReads += 1;
      if (streamReads === 1) {
        receivedSignal = options?.signal;
        return new Promise<never>((_resolve, reject) => {
          options?.signal?.addEventListener("abort", () => {
            reject(new PluginBridgeError("PLUGIN_STREAM_CANCELLED", "Plugin stream read was aborted"));
          }, { once: true });
        });
      }
      return { execution_id: "execution_signal_1", events: [terminalEvent("execution_signal_1", 1, "completed")], cursor: 1 } as const;
    },
    cancelExecution: async (_executionID: string, reason?: string) => {
      if (reason) cancellations.push(reason);
    },
  } as unknown as PluginBridgeClient;
  const stream = await callCapabilityStream(
    bridge,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );

  const read = stream.read({ signal: controller.signal });
  controller.abort();
  await assert.rejects(
    read,
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_STREAM_CANCELLED",
  );
  const next = await stream.read();

  assert.equal(receivedSignal, controller.signal);
  assert.deepEqual(next, { events: [], done: true, cursor: 1 });
  assert.deepEqual(cancellations, []);
});

test("non-cancelable operation helpers do not expose or dispatch cancellation", async () => {
  const bridge = fakeBridge({ data: { accepted: true }, execution_id: "execution_non_cancelable" });
  const operation = await callCapabilityOperation(
    bridge.client,
    operationContract("documents.archive", false),
    { document_id: "doc-1" },
  );

  assert.equal("cancel" in operation, false);
  assert.deepEqual(bridge.cancellations, []);
});

test("subscription helpers reject failed terminal states and cancel early iterator return", async () => {
  const failedBridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_failed_1" },
    [async () => ({ execution_id: "execution_failed_1", events: [terminalEvent("execution_failed_1", 1, "failed")], cursor: 1 })],
  );
  const failed = await callCapabilityStream(
    failedBridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );
  await assert.rejects(
    async () => {
      for await (const event of failed) {
        throw new Error(`failed stream yielded event ${event.kind}`);
      }
    },
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_STREAM_FAILED",
  );
  assert.deepEqual(failedBridge.cancellations, []);

  const earlyBridge = fakeBridge(
    { data: { accepted: true }, execution_id: "execution_early_1" },
    [async () => ({
      execution_id: "execution_early_1",
      events: [dataEvent("execution_early_1", 1, { line: "one" })],
      cursor: 1,
    })],
  );
  const early = await callCapabilityStream(
    earlyBridge.client,
    streamContract("documents.watch"),
    { document_id: "doc-1" },
  );
  const iterator = early[Symbol.asyncIterator]();
  assert.equal((await iterator.next()).done, false);
  await iterator.return?.();
  assert.deepEqual(earlyBridge.cancellations, [{ executionID: "execution_early_1", reason: "stream_iterator_closed" }]);
});

test("generated capability helpers enforce exact oneOf matches", async () => {
  const unionSchema = {
    oneOf: [
      {
        type: "object",
        additionalProperties: false,
        required: ["id"],
        properties: { id: { type: "string", minLength: 1 } },
      },
      {
        type: "object",
        additionalProperties: false,
        required: ["id"],
        properties: {
          id: { type: "string", minLength: 1 },
          kind: { const: "archive", type: "string" },
        },
      },
    ],
  } as const;
  const bridge = fakeBridge({ data: { accepted: true } });
  await callCapabilitySync(bridge.client, syncContract("documents.resolve", unionSchema, responseSchema), { id: "doc-1", kind: "archive" });
  await assert.rejects(
    callCapabilitySync(bridge.client, syncContract("documents.resolve", unionSchema, responseSchema), { id: "doc-1" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  await assert.rejects(
    callCapabilitySync(bridge.client, syncContract("documents.resolve", unionSchema, responseSchema), { slug: "doc-1" }),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
});

test("generated capability helpers treat missing object properties as an empty closed object", async () => {
  const emptyObjectSchema = {
    type: "object",
    additionalProperties: false,
  } as const;
  const valid = await callCapabilitySync(
    fakeBridge({ data: {} }).client,
    syncContract("documents.empty", emptyObjectSchema, emptyObjectSchema),
    {},
  );
  assert.deepEqual(valid, {});
  await assert.rejects(
    callCapabilitySync(
      fakeBridge({ data: {} }).client,
      syncContract("documents.empty", emptyObjectSchema, emptyObjectSchema),
      { unexpected: true } as never,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
});

test("generated capability helpers validate every published string format", async () => {
  const formatSchema = {
    type: "object",
    additionalProperties: false,
    required: ["date_time", "uuid", "hostname", "ipv4", "ipv6"],
    properties: {
      date_time: { type: "string", format: "date-time" },
      uuid: { type: "string", format: "uuid" },
      hostname: { type: "string", format: "hostname" },
      ipv4: { type: "string", format: "ipv4" },
      ipv6: { type: "string", format: "ipv6" },
    },
  } as const;
  const valid = {
    date_time: "2026-07-13T08:09:10Z",
    uuid: "123e4567-e89b-42d3-a456-426614174000",
    hostname: "plugin-host.example.test",
    ipv4: "192.0.2.10",
    ipv6: "2001:db8::10",
  };
  assert.deepEqual(
    await callCapabilitySync(fakeBridge({ data: valid }).client, syncContract("documents.formats", formatSchema, formatSchema), valid),
    valid,
  );

  const invalidValues = {
    date_time: "2026-07-13 08:09:10",
    uuid: "not-a-uuid",
    hostname: "-invalid.example",
    ipv4: "999.0.2.10",
    ipv6: "2001:db8:::10",
  } as const;
  for (const [field, value] of Object.entries(invalidValues)) {
    await assert.rejects(
      callCapabilitySync(
        fakeBridge({ data: valid }).client,
        syncContract("documents.formats", formatSchema, formatSchema),
        { ...valid, [field]: value },
      ),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
    );
  }
});

const restrictedSchemaFixture = JSON.parse(readFileSync(
  new URL("../../../../testdata/host-capability/restricted-schema-conformance-v1.json", import.meta.url),
  "utf8",
)) as {
  schema_version: string;
  cases: Array<{ name: string; schema: Record<string, unknown>; value: unknown; valid: boolean }>;
};
assert.equal(restrictedSchemaFixture.schema_version, "redevplugin.restricted_schema_conformance.v1");

for (const testCase of restrictedSchemaFixture.cases) {
  test(`plugin-side restricted schema conformance: ${testCase.name}`, async () => {
    const wrappedSchema = {
      type: "object",
      additionalProperties: false,
      required: ["value"],
      properties: { value: testCase.schema },
    } as const;
    const invocation = callCapabilitySync(
      fakeBridge({ data: { value: testCase.value } }).client,
      syncContract("documents.conformance", wrappedSchema, wrappedSchema),
      { value: testCase.value },
    );
    if (testCase.valid) {
      assert.deepEqual(await invocation, { value: testCase.value });
    } else {
      await assert.rejects(
        invocation,
        (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
      );
    }
  });
}

test("generated capability helpers validate typed business error details", () => {
  const schemas = {
    DOCUMENT_NOT_FOUND: {
      detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      schema: {
        type: "object",
        additionalProperties: false,
        required: ["document_id"],
        properties: { document_id: { type: "string", minLength: 1 } },
      },
    },
    DOCUMENT_LOCKED: {
      detail_schema_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      schema: null,
    },
  } as const;
  const valid = new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "Host capability request failed", undefined, {
    capability_id: "example.capability.documents",
    capability_version: "1.0.0",
    detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    business_error_code: "DOCUMENT_NOT_FOUND",
    business_error_details: { document_id: "doc-1" },
  });
  assert.equal(isCapabilityBusinessError(valid, "example.capability.documents", "1.0.0", schemas), true);
  assert.equal(isCapabilityBusinessError(new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "failed", undefined, {
    capability_id: "example.capability.documents",
    capability_version: "1.0.0",
    detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    business_error_code: "DOCUMENT_NOT_FOUND",
    business_error_details: { document_id: "doc-1", unexpected: true },
  }), "example.capability.documents", "1.0.0", schemas), false);
  assert.equal(isCapabilityBusinessError(new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "failed", undefined, {
    capability_id: "example.capability.documents",
    capability_version: "1.0.0",
    detail_schema_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    business_error_code: "DOCUMENT_LOCKED",
  }), "example.capability.documents", "1.0.0", schemas), true);
  assert.equal(isCapabilityBusinessError(new PluginBridgeError("PLUGIN_CAPABILITY_ERROR", "failed", undefined, {
    capability_id: "other.capability",
    capability_version: "1.0.0",
    detail_schema_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    business_error_code: "DOCUMENT_NOT_FOUND",
    business_error_details: { document_id: "doc-1" },
  }), "example.capability.documents", "1.0.0", schemas), false);
  assert.equal(isCapabilityBusinessError(new PluginBridgeError("PLUGIN_PERMISSION_DENIED", "failed"), "example.capability.documents", "1.0.0", schemas), false);
});

function fakeBridge(
  result: unknown,
  streamResults?: Array<() => Promise<unknown>>,
  executionSnapshots?: PluginExecutionSnapshot[],
): {
  client: PluginBridgeClient;
  calls: Array<{ method: string; params: unknown }>;
  callOptions: Array<{ signal?: AbortSignal } | undefined>;
  cancellations: Array<{ executionID: string; reason?: string }>;
  cancellationOptions: Array<{ signal?: AbortSignal } | undefined>;
  streamReads: number;
  observations: string[];
} {
  const calls: Array<{ method: string; params: unknown }> = [];
  const callOptions: Array<{ signal?: AbortSignal } | undefined> = [];
  const cancellations: Array<{ executionID: string; reason?: string }> = [];
  const cancellationOptions: Array<{ signal?: AbortSignal } | undefined> = [];
  const observations: string[] = [];
  const state = {
    calls,
    callOptions,
    cancellations,
    cancellationOptions,
    observations,
    streamReads: 0,
    client: {
      call: async (method: string, params?: unknown, options?: { signal?: AbortSignal }) => {
        calls.push({ method, params });
        callOptions.push(options ? { signal: options.signal } : undefined);
        return result;
      },
      cancelExecution: async (executionID: string, reason?: string, options?: { signal?: AbortSignal }) => {
        cancellations.push({ executionID, reason });
        cancellationOptions.push(options ? { signal: options.signal } : undefined);
      },
      executionSnapshot: async (executionID: string) => {
        observations.push(executionID);
        const snapshot = executionSnapshots?.shift();
        if (!snapshot) throw new Error("unexpected operation snapshot");
        return snapshot;
      },
      executionEvents: async (executionID: string, _cursor: number) => {
        const read = streamResults?.[state.streamReads];
        state.streamReads += 1;
        if (!read) throw new Error("unexpected stream read");
        const result = await read() as PluginExecutionEventList;
        if (result.execution_id !== executionID) throw new Error("execution identity mismatch");
        return result;
      },
    } as unknown as PluginBridgeClient,
  };
  return state;
}
