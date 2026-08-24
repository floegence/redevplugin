import assert from "node:assert/strict";
import { test } from "node:test";

import { PluginPlatformRequestError, PluginTransportError } from "../src/errors.js";
import { readPlatformResponse } from "../src/http.js";

function response(status: number, value: unknown, ok = status >= 200 && status < 300) {
  return {
    ok,
    status,
    json: async () => {
      if (value instanceof Error) throw value;
      return value;
    },
  };
}

test("platform response decoding classifies non-JSON HTTP rejections", async () => {
  await assert.rejects(
    readPlatformResponse(response(403, new SyntaxError("Unexpected token"))),
    (error: unknown) => error instanceof PluginTransportError &&
      error.httpStatus === 403 &&
      error.message === "Plugin platform endpoint rejected the request with HTTP 403",
  );
});

test("platform response decoding keeps successful invalid JSON distinct", async () => {
  await assert.rejects(
    readPlatformResponse(response(200, new SyntaxError("Unexpected token"))),
    (error: unknown) => error instanceof PluginTransportError &&
      error.httpStatus === 200 &&
      error.message === "Plugin platform endpoint returned invalid JSON with HTTP 200",
  );
});

test("platform response decoding preserves stable error envelopes", async () => {
  await assert.rejects(
    readPlatformResponse(response(403, {
      ok: false,
      error: {
        code: "PLUGIN_SESSION_REVOKED",
        message: "Plugin session revoked",
        details: {},
      },
    })),
    (error: unknown) => error instanceof PluginPlatformRequestError &&
      error.errorCode === "PLUGIN_SESSION_REVOKED" &&
      error.message === "Plugin session revoked",
  );
});
