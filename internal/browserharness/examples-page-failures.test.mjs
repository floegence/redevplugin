import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { observePageFailures } from "./examples-page-failures.mjs";

const applicationBaseURL = "https://host.example";
const rpcURL = `${applicationBaseURL}/_redevplugin/api/plugins/rpc`;

test("expected RPC transport failure is correlated by method and URL", async () => {
  const page = new EventEmitter();
  const observer = observePageFailures(page, applicationBaseURL);
  await observer.abortRPCResponse(routeThatFails(page, rpcURL, "memos.publish"), "publish-response-lost", "memos.publish");

  const summary = await observer.assertClean();

  assert.deepEqual(summary.observedRPCTransportFaultLabels, ["publish-response-lost"]);
  assert.equal(summary.expectedTransportFailureConsoleCount, 1);
});

test("unrelated application request failure cannot consume an expected RPC allowance", async () => {
  const page = new EventEmitter();
  const observer = observePageFailures(page, applicationBaseURL);
  await observer.abortRPCResponse(routeThatFails(page, rpcURL, "memos.publish"), "publish-response-lost", "memos.publish");
  const assetURL = `${applicationBaseURL}/assets/missing.js`;
  page.emit("requestfailed", failedRequest(assetURL, undefined, "net::ERR_CONNECTION_FAILED"));
  page.emit("console", consoleMessage("Failed to load resource: net::ERR_CONNECTION_FAILED", assetURL));

  await assert.rejects(observer.assertClean(), /unexpected application request failures/);
});

function routeThatFails(page, url, method) {
  const request = failedRequest(url, method, "net::ERR_CONNECTION_FAILED");
  return {
    request: () => request,
    abort: async () => {
      page.emit("requestfailed", request);
      page.emit("console", consoleMessage("Failed to load resource: net::ERR_CONNECTION_FAILED", url));
    },
  };
}

function failedRequest(url, method, errorText) {
  return {
    url: () => url,
    method: () => "POST",
    postDataJSON: () => method ? { method } : undefined,
    failure: () => ({ errorText }),
  };
}

function consoleMessage(text, url) {
  return {
    type: () => "error",
    text: () => text,
    location: () => ({ url, lineNumber: 0, columnNumber: 0 }),
  };
}
