#!/usr/bin/env node

import assert from "node:assert/strict";
import test from "node:test";

import {
  isTransientGoModuleReadbackFailure,
  retryGoModuleReadback,
  validateModuleIdentity,
} from "./verify_go_module_readback.mjs";

test("Go module readback retries transient network and registry failures", async () => {
  let attempts = 0;
  const messages = [];
  const result = await retryGoModuleReadback({
    label: "proxy readback",
    retryDelaysMs: [0, 0, 0],
    logger: (message) => messages.push(message),
    attemptDownload: () => {
      attempts += 1;
      if (attempts === 1) throw new Error("read tcp: connection reset by peer");
      if (attempts === 2) throw new Error("sum.golang.org returned HTTP 500 Internal Server Error");
      return { Sum: "h1:verified=" };
    },
  });
  assert.deepEqual(result, { Sum: "h1:verified=" });
  assert.equal(attempts, 3);
  assert.equal(messages.length, 2);
  assert.equal(isTransientGoModuleReadbackFailure(new Error("spawnSync go ETIMEDOUT")), true);
  assert.equal(isTransientGoModuleReadbackFailure(new Error("RPC failed; HTTP/2 stream was not closed cleanly")), true);
});

test("Go proxy propagation delay is retryable only for the proxy readback", async () => {
  let attempts = 0;
  const result = await retryGoModuleReadback({
    label: "proxy readback",
    allowPropagationDelay: true,
    retryDelaysMs: [0, 0],
    logger: () => undefined,
    attemptDownload: () => {
      attempts += 1;
      if (attempts === 1) throw new Error("proxy.golang.org returned 404 Not Found");
      return "published";
    },
  });
  assert.equal(result, "published");
  assert.equal(attempts, 2);

  attempts = 0;
  await assert.rejects(() => retryGoModuleReadback({
    label: "direct readback",
    retryDelaysMs: [0, 0, 0],
    logger: () => undefined,
    attemptDownload: () => {
      attempts += 1;
      throw new Error("invalid version: unknown revision v9.8.7");
    },
  }), /unknown revision/);
  assert.equal(attempts, 1);
});

test("Go module readback exhausts a closed retry budget", async () => {
  let attempts = 0;
  await assert.rejects(() => retryGoModuleReadback({
    label: "SumDB readback",
    retryDelaysMs: [0, 0, 0],
    logger: () => undefined,
    attemptDownload: () => {
      attempts += 1;
      throw new Error("sum.golang.org: 503 Service Unavailable");
    },
  }), /remained unavailable after 3 bounded attempts/);
  assert.equal(attempts, 3);
});

test("immutable module and checksum failures are terminal", async () => {
  assert.equal(isTransientGoModuleReadbackFailure(new Error("checksum mismatch\nSECURITY ERROR")), false);
  assert.equal(isTransientGoModuleReadbackFailure(new Error("module declares its path as example.invalid/wrong")), false);
  let attempts = 0;
  await assert.rejects(() => retryGoModuleReadback({
    label: "immutable readback",
    retryDelaysMs: [0, 0, 0],
    logger: () => undefined,
    attemptDownload: () => {
      attempts += 1;
      throw new Error("checksum mismatch\nSECURITY ERROR");
    },
  }), /checksum mismatch/);
  assert.equal(attempts, 1);
  assert.throws(() => validateModuleIdentity({
    Path: "example.invalid/wrong",
    Version: "v9.8.7",
    Sum: "h1:valid=",
    GoModSum: "h1:valid=",
  }, "direct", "v9.8.7"), /module identity mismatch/);
  assert.throws(() => validateModuleIdentity({
    Path: "github.com/floegence/redevplugin",
    Version: "v9.8.7",
    Sum: "tampered",
    GoModSum: "h1:valid=",
  }, "proxy", "v9.8.7"), /Sum is invalid/);
});
