import assert from "node:assert/strict";

import { isExpectedSandboxConsoleLine } from "./smoke-console-policy.mjs";

export function observePageFailures(page, applicationBaseURL) {
  const consoleRecords = [];
  const pageErrors = [];
  const apiFailureReads = [];
  const expectedRPCFaults = [];
  const observedRPCFaultLabels = [];
  const expectedRPCTransportFaults = [];
  const observedRPCTransportFaultLabels = [];
  const expectedResourceFailures = [];
  const unexpectedRequestFailures = [];
  page.on("console", (message) => {
    const location = typeof message.location === "function" ? message.location() : undefined;
    consoleRecords.push({
      line: `${message.type()}: ${message.text()}`,
      url: location?.url || "",
    });
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("response", (response) => {
    if (!response.url().startsWith(applicationBaseURL) || response.status() < 500) return;
    apiFailureReads.push(Promise.all([
      response.headerValue("x-redevplugin-smoke-fault"),
      response.text().catch(() => ""),
    ]).then(([faultLabel, body]) => {
      if (faultLabel) {
        const expected = expectedRPCFaults.find((fault) => fault.label === faultLabel && fault.url === response.url());
        if (expected && !observedRPCFaultLabels.includes(faultLabel)) {
          observedRPCFaultLabels.push(faultLabel);
          return "";
        }
      }
      return `${response.status()} ${response.url()}${body ? ` ${body}` : ""}`;
    }));
  });
  page.on("requestfailed", (request) => {
    const url = request.url();
    if (!url.startsWith(applicationBaseURL)) return;
    const errorText = request.failure()?.errorText || "request failed";
    const method = request.postDataJSON()?.method;
    const expected = expectedRPCTransportFaults.find((fault) =>
      fault.url === url &&
      fault.method === method &&
      fault.errorText === errorText &&
      !observedRPCTransportFaultLabels.includes(fault.label)
    );
    if (expected) {
      observedRPCTransportFaultLabels.push(expected.label);
      return;
    }
    const requestMethod = typeof request.method === "function" ? request.method() : "unknown";
    const rpcMethod = request.postDataJSON()?.method;
    const rpcContext = typeof rpcMethod === "string" ? ` [plugin_method=${rpcMethod}]` : "";
    unexpectedRequestFailures.push(`${requestMethod} ${url}: ${errorText}${rpcContext}`);
  });

  return {
    get consoleLines() {
      return consoleRecords.map((record) => record.line);
    },
    pageErrors,
    expectResourceFailure(status, statusText, url) {
      expectedResourceFailures.push({
        line: `error: Failed to load resource: the server responded with a status of ${status} (${statusText})`,
        url,
      });
    },
    async fulfillRPCFault(route, label, message, mutationOutcome) {
      assert.equal(expectedRPCFaults.some((fault) => fault.label === label), false, `duplicate expected RPC fault label ${label}`);
      assert.equal(
        mutationOutcome === "not_committed" || mutationOutcome === "unknown",
        true,
        `RPC fault ${label} must declare a mutation outcome`,
      );
      expectedRPCFaults.push({ label, url: route.request().url() });
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        headers: { "x-redevplugin-smoke-fault": label },
        body: JSON.stringify({
          ok: false,
          error: {
            code: "PLUGIN_RUNTIME_UNAVAILABLE",
            message,
            details: {},
            mutation_outcome: mutationOutcome,
          },
        }),
      });
    },
    async abortRPCResponse(route, label, method) {
      assert.equal(expectedRPCTransportFaults.some((fault) => fault.label === label), false, `duplicate expected RPC transport fault label ${label}`);
      expectedRPCTransportFaults.push({
        label,
        method,
        url: route.request().url(),
        errorText: "net::ERR_CONNECTION_FAILED",
      });
      await route.abort("connectionfailed");
    },
    async read() {
      const expectedFailureConsoleLine = "error: Failed to load resource: the server responded with a status of 503 (Service Unavailable)";
      const expectedFailureConsoleRecords = consoleRecords.filter((record) =>
        record.line === expectedFailureConsoleLine &&
        expectedRPCFaults.some((fault) => fault.url === record.url)
      );
      const expectedTransportFailureConsoleRecords = consoleRecords.filter((record) =>
        expectedRPCTransportFaults.some((fault) =>
          fault.url === record.url && record.line === `error: Failed to load resource: ${fault.errorText}`
        )
      );
      const resourceFailures = expectedResourceFailures.map((expected) => ({
        ...expected,
        observedCount: consoleRecords.filter((record) => record.line === expected.line && record.url === expected.url).length,
      }));
      const expectedConsoleRecord = (record) =>
        expectedFailureConsoleRecords.includes(record) ||
        expectedTransportFailureConsoleRecords.includes(record) ||
        resourceFailures.some((failure) => failure.line === record.line && failure.url === record.url);
      return {
        consoleLines: consoleRecords.map((record) => record.line),
        pageErrors: [...pageErrors],
        apiFailures: (await Promise.all(apiFailureReads)).filter(Boolean),
        expectedRPCFaultLabels: expectedRPCFaults.map((fault) => fault.label).sort(),
        observedRPCFaultLabels: [...observedRPCFaultLabels].sort(),
        expectedRPCTransportFaultLabels: expectedRPCTransportFaults.map((fault) => fault.label).sort(),
        observedRPCTransportFaultLabels: [...observedRPCTransportFaultLabels].sort(),
        unexpectedRequestFailures: [...unexpectedRequestFailures],
        expectedFailureConsoleCount: expectedFailureConsoleRecords.length,
        expectedResourceFailures: resourceFailures,
        expectedTransportFailureConsoleCount: expectedTransportFailureConsoleRecords.length,
        transportFailureConsoleLines: expectedTransportFailureConsoleRecords.map((record) => record.line),
        unexpectedConsole: consoleRecords
          .filter((record) => !expectedConsoleRecord(record) && !isExpectedSandboxConsoleLine(record.line))
          .map((record) => record.line),
      };
    },
    async assertClean() {
      const summary = await this.read();
      assert.deepEqual(summary.pageErrors, []);
      assert.deepEqual(summary.observedRPCFaultLabels, summary.expectedRPCFaultLabels, "every expected RPC fault must produce exactly one labeled response");
      assert.deepEqual(summary.observedRPCTransportFaultLabels, summary.expectedRPCTransportFaultLabels, "every expected RPC transport fault must abort exactly one matching request");
      assert.deepEqual(summary.unexpectedRequestFailures, [], "unexpected application request failures");
      assert.equal(summary.expectedFailureConsoleCount, summary.expectedRPCFaultLabels.length, "every expected RPC fault must produce exactly one URL-bound browser network error");
      assert.deepEqual(
        summary.expectedResourceFailures.map(({ observedCount }) => observedCount === 1),
        summary.expectedResourceFailures.map(() => true),
        `every explicitly expected resource failure must occur exactly once: ${JSON.stringify(summary.expectedResourceFailures)}`,
      );
      assert.equal(
        summary.expectedTransportFailureConsoleCount,
        summary.expectedRPCTransportFaultLabels.length,
        "every expected RPC transport fault must produce exactly one URL-bound browser network error",
      );
      assert.deepEqual(summary.apiFailures, []);
      assert.deepEqual(summary.unexpectedConsole, []);
      return summary;
    },
  };
}
