import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import test from "node:test";

const require = createRequire(import.meta.url);
require("./redocly_minimatch_compat.cjs");

test("the OpenAPI generator uses the scoped Redocly minimatch compatibility loader", async () => {
  const generator = await readFile(new URL("./generate_openapi_types.mjs", import.meta.url), "utf8");
  assert.match(generator, /--require", minimatchCompatibilityLoader, cli/u);
});

test("Redocly matches brace patterns through the audited minimatch release", async () => {
  const redoclyRequire = createRequire(require.resolve("@redocly/openapi-core/package.json"));
  const minimatchPackage = redoclyRequire("minimatch/package.json");
  assert.equal(minimatchPackage.version, "10.2.5");
  assert.equal(typeof redoclyRequire("minimatch"), "function");

  let receivedHeaders;
  const { readFileFromUrl } = require("@redocly/openapi-core/lib/utils.js");
  await readFileFromUrl("https://example.test/schemas/plugin.ts", {
    headers: [{ matches: "example.test/schemas/*.{ts,tsx}", name: "x-contract-test", value: "matched" }],
    customFetch: async (_url, init) => {
      receivedHeaders = init.headers;
      return {
        ok: true,
        headers: { get: () => "text/plain" },
        text: async () => "schema",
      };
    },
  });
  assert.deepEqual(receivedHeaders, { "x-contract-test": "matched" });
});
