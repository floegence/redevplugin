import assert from "node:assert/strict";
import { test } from "node:test";
import { PluginFilesClient, validFileIORequest, isPluginFileResource, isPluginFileResourceReview } from "../src/files.js";
import { PluginBridgeError, pluginMutationOutcome } from "../src/errors.js";

const uri = "redevfs://selected-" + "a".repeat(64) + "/";
const id = "9223372036854775807";

test("stat accepts the Host canonical Unicode URI without broadening identity", async () => {
  const canonical = uri + "%C3%A9.txt";
  const client = new PluginFilesClient(async () => ({ value: { uri: canonical, kind: "file", size: "1", mode: 384, modified_unix_ms: 1 } }));
  assert.equal((await client.stat(uri + "e%CC%81.txt")).uri, canonical);
  await assert.rejects(client.stat(uri + "other.txt"));
});

test("file evidence rejects recursive files and oversized names", () => {
  const resource = { resource_id: "selected-" + "a".repeat(64), uri, name: "file.txt", kind: "file", recursive: false, writable: false, revision: 1, expires_at: "2026-10-30T00:00:00Z", status: "active" };
  const review = { review_id: "a".repeat(64), plugin_instance_id: "plugini_example", name: "file.txt", kind: "file", recursive: false, writable: false, review_expires_at: "2026-10-29T00:05:00Z", resource_expires_at: resource.expires_at };
  assert.equal(isPluginFileResource(resource), true);
  assert.equal(isPluginFileResourceReview(review), true);
  for (const patch of [{ recursive: true }, { name: "a".repeat(256) }]) {
    assert.equal(isPluginFileResource({ ...resource, ...patch }), false);
    assert.equal(isPluginFileResourceReview({ ...review, ...patch }), false);
  }
});

test("file requests reject mismatched fields and preserve full precision", () => {
  assert.equal(validFileIORequest({ operation: "read", arguments: { handle: id, length: 1 } }), true);
  for (const request of [
    { operation: "read", arguments: { handle: id, length: 1, writable: true } },
    { operation: "read", arguments: { handle: "9223372036854775808", length: 1 } },
    { operation: "read", arguments: { handle: id, length: 65537 } },
    { operation: "select", arguments: { kind: "file", recursive: true } },
    { operation: "write", arguments: { handle: id, data: "AA" } },
    { operation: "seek", arguments: { handle: id, offset: "-9223372036854775809" } },
    { operation: "fs.stat", arguments: { uri: uri + "../outside" } },
  ]) assert.equal(validFileIORequest(request), false);
});

test("file handles preserve 63-bit identity and empty EOF data", async () => {
  const client = new PluginFilesClient(async request => {
    if (request.operation === "fs.open") return { handle: id };
    assert.equal("handle" in request.arguments && request.arguments.handle, id);
    if (request.operation === "read") return { data: "", count: 0, eof: true };
    if (request.operation === "seek") return { offset: "9007199254740993" };
    return {};
  });
  const file = await client.open(uri);
  assert.deepEqual(await file.read(), { bytes: new Uint8Array(), eof: true });
  assert.equal(await file.seek(9007199254740993n), 9007199254740993n);
  await file.close();
  await assert.rejects(file.read());
});

test("multi-chunk write reports prior bytes and never replays an uncertain chunk", async () => {
  let calls = 0;
  const client = new PluginFilesClient(async request => {
    if (request.operation === "fs.open") return { handle: id };
    calls++;
    if (calls === 1) return { count: 65536 };
    throw new PluginBridgeError("PLUGIN_PERMISSION_DENIED", "revoked", undefined, undefined, "not_committed");
  });
  const file = await client.open(uri, { write: true });
  await assert.rejects(file.write(new Uint8Array(65537)), error => {
    assert.equal(pluginMutationOutcome(error), "unknown");
    assert.equal((error as { bytesWritten: number }).bytesWritten, 65536);
    return true;
  });
  assert.equal(calls, 2);
});

test("directory EOF does not close the auto-closed handle twice", async () => {
  let closeCalls = 0;
  const client = new PluginFilesClient(async request => {
    if (request.operation === "fs.read_dir.open") return { handle: id };
    if (request.operation === "read_dir.next") return { value: { entries: [], eof: true } };
    closeCalls++;
    throw new PluginBridgeError("PLUGIN_FILE_OPERATION_FAILED", "closed");
  });
  const entries = [];
  for await (const entry of client.entries(uri)) entries.push(entry);
  assert.deepEqual(entries, []);
  assert.equal(closeCalls, 0);
});
