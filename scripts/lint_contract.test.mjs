import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
function lint(source, directory = "internal/authorpreview") {
  const temporary = mkdtempSync(join(root, directory, ".lint-contract-"));
  try {
    const file = join(temporary, "fixture.ts");
    writeFileSync(file, source);
    const result = spawnSync(process.execPath, ["node_modules/oxlint/bin/oxlint", "--format=json", file], { cwd: root, encoding: "utf8" });
    assert.equal(result.signal, null, result.stderr);
    assert.ok(result.status === 0 || result.status === 1, result.stderr);
    return { status: result.status, ...JSON.parse(result.stdout) };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

// These behavioral fixtures retain each formerly enabled recommended rule.
// The compiler continues to own type-dependent correctness checks.
const rejected = {
  "no-var": "export var value = 1;",
  "prefer-const": "let value = 1; console.log(value);",
  "prefer-rest-params": "export function values() { return arguments; }",
  "prefer-spread": "export const result = fn.apply(undefined, args);",
  "ban-ts-comment": "// @ts-ignore\nexport const value = 1;",
  "no-array-constructor": "export const values = new Array(1, 2);",
  "no-duplicate-enum-values": "export enum Values { A = 1, B = 1 }",
  "no-empty-object-type": "export type Empty = {};",
  "no-explicit-any": "export type Value = any;",
  "no-extra-non-null-assertion": "export const value = input!!;",
  "no-misused-new": "export interface Factory { new(): Factory; }",
  "no-namespace": "export namespace Values { export const value = 1; }",
  "no-non-null-asserted-optional-chain": "export const value = input?.field!;",
  "no-require-imports": "export const value = require('node:fs');",
  "no-this-alias": "export function value() { const that = this; return that; }",
  "no-unnecessary-type-constraint": "export function value<T extends unknown>(input: T) { return input; }",
  "no-unsafe-declaration-merging": "export class Value {} export interface Value { read(): void; }",
  "no-unsafe-function-type": "export type Callback = Function;",
  "no-unused-expressions": "input;",
  "no-unused-vars": "const unused = 1;",
  "no-wrapper-object-types": "export type Value = String;",
  "prefer-as-const": "export const value = 'text' as 'text';",
  "prefer-namespace-keyword": "export module Values { export const value = 1; }",
  "triple-slash-reference": "/// <reference path='./other.ts' />\nexport {};",
};
for (const [rule, source] of Object.entries(rejected)) {
  test(`lint rejects ${rule}`, () => {
    const result = lint(source);
    assert.equal(result.status, 1);
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code.endsWith(`(${rule})`) && diagnostic.severity === "error"), JSON.stringify(result));
  });
}
test("SDK fixtures retain explicit any and intentionally unused argument allowances", () => {
  const result = lint("export function accept(_value: any) { try { return 1; } catch (_error) { return 0; } }", "packages/redevplugin-ui/test");
  assert.equal(result.status, 0, JSON.stringify(result));
  assert.deepEqual(result.diagnostics, []);
});
