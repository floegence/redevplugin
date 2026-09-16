import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import test from "node:test";

const generated = await readFile(new URL("../packages/redevplugin-ui/src/surface-integrity.gen.ts", import.meta.url), "utf8");
const script = JSON.parse(generated.match(/export const surfaceIntegrityScript = (.+);\n$/)[1]);

test("sandbox SHA-256 matches standard vectors without Web Crypto", () => {
  const hash = runInNewContext(script + "\nredevpluginIntegrity.sha256", { Uint8Array, Uint32Array, DataView });
  for (const bytes of [new Uint8Array(), new TextEncoder().encode("abc"), new Uint8Array(1_000_000).fill(97), new Uint8Array([0, 1, 2, 3, 4]).subarray(1, 4)]) {
    assert.equal(Buffer.from(hash(bytes)).toString("hex"), createHash("sha256").update(bytes).digest("hex"));
  }
  assert.match(script, /Copyright/);
  assert.doesNotMatch(script, /<\/script/i);
});
