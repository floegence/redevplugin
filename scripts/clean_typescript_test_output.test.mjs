import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { cleanTypeScriptTestOutput } from "./clean_typescript_test_output.mjs";

test("TypeScript tests remove stale compiled files before rebuilding", () => {
  const root = mkdtempSync(join(tmpdir(), "redevplugin-typescript-test-output-"));
  const output = join(root, "dist-test");
  mkdirSync(join(output, "test"), { recursive: true });
  writeFileSync(join(output, "test", "retired-contract.test.js"), "throw new Error('stale');\n");

  cleanTypeScriptTestOutput(output);

  assert.equal(existsSync(output), false);
});

test("TypeScript test cleanup is restricted to dist-test directories", () => {
  assert.throws(() => cleanTypeScriptTestOutput("build"), /must be a dist-test directory/);
});
