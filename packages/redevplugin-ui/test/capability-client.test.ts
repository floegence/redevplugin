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
import type { PluginStreamReadResult } from "../src/surface.js";

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

const encodeEvent = (event: unknown) => btoa(JSON.stringify(event));

test("generated capability helpers validate sync request and response payloads", async () => {
  const bridge = fakeBridge({ data: { accepted: true } });
  const result = await callCapabilitySync(
    bridge.client,
    "documents.get",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
  );
  assert.deepEqual(result, { accepted: true });
  assert.deepEqual(bridge.calls, [{ method: "documents.get", params: { document_id: "doc-1" } }]);

  await assert.rejects(
    callCapabilitySync(
      bridge.client,
      "documents.get",
      { document_id: "", extra: true } as never,
      requestSchema,
      responseSchema,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  assert.equal(bridge.calls.length, 1);

  const invalidResponse = fakeBridge({ data: { accepted: true, unexpected: true } });
  await assert.rejects(
    callCapabilitySync(
      invalidResponse.client,
      "documents.get",
      { document_id: "doc-1" },
      requestSchema,
      responseSchema,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

test("generated capability helpers preserve host-owned operation and stream handles", async () => {
  const operationBridge = fakeBridge({ data: { accepted: true }, operation_id: "operation_opaque_1" });
  const operation = await callCapabilityOperation<{ document_id: string }, { accepted: boolean }>(
    operationBridge.client,
    "documents.archive",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
  );
  assert.equal(operation.data.accepted, true);
  assert.equal(operation.operation_id, "operation_opaque_1");
  assert.equal(typeof operation.cancel, "function");

  const streamBridge = fakeBridge({ data: { accepted: true }, operation_id: "operation_opaque_2", stream_handle: "stream_opaque_1" });
  const stream = await callCapabilityStream<{ document_id: string }, { accepted: boolean }, { line: string }>(
    streamBridge.client,
    "documents.watch",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
  );
  assert.equal(stream.data.accepted, true);
  assert.equal(stream.operation_id, "operation_opaque_2");
  assert.equal(stream.stream_handle, "stream_opaque_1");
  assert.equal(typeof stream.read, "function");
  assert.equal(typeof stream.cancel, "function");
  assert.equal(typeof stream[Symbol.asyncIterator], "function");

  await stream.cancel("user canceled");
  assert.deepEqual(streamBridge.cancellations, [{ operationID: "operation_opaque_2", reason: "user canceled" }]);

  await assert.rejects(
    callCapabilityOperation(
      fakeBridge({ data: { accepted: true } }).client,
      "documents.archive",
      { document_id: "doc-1" },
      requestSchema,
      responseSchema,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
});

test("capability helpers reject malformed result envelopes with stable errors", async () => {
  for (const result of [null, true, "invalid", [], { data: { accepted: true }, unexpected: true }]) {
    await assert.rejects(
      callCapabilitySync(
        fakeBridge(result).client,
        "documents.get",
        { document_id: "doc-1" },
        requestSchema,
        responseSchema,
      ),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
  }

  for (const result of [
    { data: { accepted: true }, operation_id: "wrong.handle" },
    { data: { accepted: true }, operation_id: "operation_opaque_1", stream_handle: "wrong.handle" },
  ]) {
    const invocation = "stream_handle" in result
      ? callCapabilityStream(fakeBridge(result).client, "documents.invalid", { document_id: "doc-1" }, requestSchema, responseSchema, eventTypeName, eventSchema)
      : callCapabilityOperation(fakeBridge(result).client, "documents.invalid", { document_id: "doc-1" }, requestSchema, responseSchema);
    await assert.rejects(
      invocation,
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
  }
});

test("capability helpers cancel live handles when response validation fails", async () => {
  const operationBridge = fakeBridge({ data: { unexpected: true }, operation_id: "operation_opaque_1" });
  await assert.rejects(
    callCapabilityOperation(
      operationBridge.client,
      "documents.archive",
      { document_id: "doc-1" },
      requestSchema,
      responseSchema,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(operationBridge.cancellations, [{ operationID: "operation_opaque_1", reason: "response_contract_mismatch" }]);

  const streamBridge = fakeBridge({
    data: { unexpected: true },
    operation_id: "operation_opaque_2",
    stream_handle: "stream_opaque_1",
  });
  await assert.rejects(
    callCapabilityStream(
      streamBridge.client,
      "documents.watch",
      { document_id: "doc-1" },
      requestSchema,
      responseSchema,
      eventTypeName,
      eventSchema,
    ),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(streamBridge.cancellations, [{ operationID: "operation_opaque_2", reason: "response_contract_mismatch" }]);
});

test("subscription helpers keep reading events produced after dispatch", async () => {
  const bridge = fakeBridge(
    { data: { accepted: true }, operation_id: "operation_opaque_2", stream_handle: "stream_opaque_1" },
    [
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return {
          events: [{ sequence: 1, kind: eventTypeName, data: encodeEvent({ line: "one" }), at: "2026-07-13T08:00:00Z" }],
          done: false,
          retry_after_ms: 0,
        };
      },
      async () => ({
        events: [{ sequence: 2, kind: eventTypeName, data: encodeEvent({ line: "two" }), at: "2026-07-13T08:00:01Z" }],
        done: true,
        terminal_status: "closed",
        retry_after_ms: 0,
      }),
    ],
  );
  const stream = await callCapabilityStream<{ document_id: string }, { accepted: boolean }, { line: string }>(
    bridge.client,
    "documents.watch",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
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
      { data: { accepted: true }, operation_id: "operation_event_invalid", stream_handle: "stream_event_invalid" },
      [async () => ({ events: [event], done: false, retry_after_ms: 0 })],
    );
    const stream = await callCapabilityStream(
      bridge.client,
      "documents.watch",
      { document_id: "doc-1" },
      requestSchema,
      responseSchema,
      eventTypeName,
      eventSchema,
    );
    await assert.rejects(
      stream[Symbol.asyncIterator]().next(),
      (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
    );
    assert.deepEqual(bridge.cancellations, [{ operationID: "operation_event_invalid", reason: "stream_contract_mismatch" }]);
  }
});

test("subscription read cancels the host operation when an event violates the published contract", async () => {
  const bridge = fakeBridge(
    { data: { accepted: true }, operation_id: "operation_direct_read_invalid", stream_handle: "stream_direct_read_invalid" },
    [async () => ({
      events: [{ sequence: 1, kind: "OtherEvent", data: encodeEvent({ line: "one" }), at: "2026-07-13T08:00:00Z" }],
      done: false,
      retry_after_ms: 0,
    })],
  );
  const stream = await callCapabilityStream(
    bridge.client,
    "documents.watch",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
  );

  await assert.rejects(
    stream.read(),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONTRACT_MISMATCH",
  );
  assert.deepEqual(bridge.cancellations, [{ operationID: "operation_direct_read_invalid", reason: "stream_contract_mismatch" }]);
});

test("non-cancelable operation helpers do not expose or dispatch cancellation", async () => {
  const bridge = fakeBridge({ data: { accepted: true }, operation_id: "operation_non_cancelable" });
  const operation = await callCapabilityOperation(
    bridge.client,
    "documents.archive",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    false,
  );

  assert.equal("cancel" in operation, false);
  assert.deepEqual(bridge.cancellations, []);
});

test("subscription helpers reject failed terminal states and cancel early iterator return", async () => {
  const failedBridge = fakeBridge(
    { data: { accepted: true }, operation_id: "operation_failed_1", stream_handle: "stream_failed_1" },
    [async () => ({ events: [], done: true, terminal_status: "failed", retry_after_ms: 0 })],
  );
  const failed = await callCapabilityStream(
    failedBridge.client,
    "documents.watch",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
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
    { data: { accepted: true }, operation_id: "operation_early_1", stream_handle: "stream_early_1" },
    [async () => ({
      events: [{ sequence: 1, kind: eventTypeName, data: encodeEvent({ line: "one" }), at: "2026-07-13T08:00:00Z" }],
      done: false,
      retry_after_ms: 0,
    })],
  );
  const early = await callCapabilityStream(
    earlyBridge.client,
    "documents.watch",
    { document_id: "doc-1" },
    requestSchema,
    responseSchema,
    eventTypeName,
    eventSchema,
  );
  const iterator = early[Symbol.asyncIterator]();
  assert.equal((await iterator.next()).done, false);
  await iterator.return?.();
  assert.deepEqual(earlyBridge.cancellations, [{ operationID: "operation_early_1", reason: "stream_iterator_closed" }]);
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
  await callCapabilitySync(bridge.client, "documents.resolve", { id: "doc-1", kind: "archive" }, unionSchema, responseSchema);
  await assert.rejects(
    callCapabilitySync(bridge.client, "documents.resolve", { id: "doc-1" }, unionSchema, responseSchema),
    (error: unknown) => error instanceof PluginBridgeError && error.errorCode === "PLUGIN_INVALID_REQUEST",
  );
  await assert.rejects(
    callCapabilitySync(bridge.client, "documents.resolve", { slug: "doc-1" }, unionSchema, responseSchema),
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
    "documents.empty",
    {},
    emptyObjectSchema,
    emptyObjectSchema,
  );
  assert.deepEqual(valid, {});
  await assert.rejects(
    callCapabilitySync(
      fakeBridge({ data: {} }).client,
      "documents.empty",
      { unexpected: true } as never,
      emptyObjectSchema,
      emptyObjectSchema,
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
  assert.deepEqual(await callCapabilitySync(fakeBridge({ data: valid }).client, "documents.formats", valid, formatSchema, formatSchema), valid);

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
        "documents.formats",
        { ...valid, [field]: value },
        formatSchema,
        formatSchema,
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
      "documents.conformance",
      { value: testCase.value },
      wrappedSchema,
      wrappedSchema,
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
  streamResults?: Array<() => Promise<PluginStreamReadResult>>,
): {
  client: PluginBridgeClient;
  calls: Array<{ method: string; params: unknown }>;
  cancellations: Array<{ operationID: string; reason?: string }>;
  streamReads: number;
} {
  const calls: Array<{ method: string; params: unknown }> = [];
  const cancellations: Array<{ operationID: string; reason?: string }> = [];
  const state = {
    calls,
    cancellations,
    streamReads: 0,
    client: {
      call: async (method: string, params?: unknown) => {
        calls.push({ method, params });
        return result;
      },
      cancelOperation: async (operationID: string, reason?: string) => {
        cancellations.push({ operationID, reason });
      },
      readStream: async () => {
        const read = streamResults?.[state.streamReads];
        state.streamReads += 1;
        if (!read) throw new Error("unexpected stream read");
        return read();
      },
    } as unknown as PluginBridgeClient,
  };
  return state;
}
