import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as contracts from "../src/index.js";

type SummaryAPI = {
  normalizeSecuritySummary(value: unknown): Record<string, unknown>;
  canonicalSecuritySummaryJSON(value: unknown): string;
  securitySummarySHA256(value: unknown): Promise<string>;
  capabilityContractSetSHA256(value: unknown): Promise<string>;
};
const api = contracts as unknown as SummaryAPI;
const fixture = JSON.parse(readFileSync(new URL("../../../../spec/plugin/security-summary-fixtures.json", import.meta.url), "utf8")) as {
  valid: { name: string; summary: Record<string, unknown>; canonical_json: string; sha256: string; capability_contract_set_sha256: string }[];
  invalid: {name: string; path: (string|number)[]; key: string; value?: unknown; remove?: boolean}[];
};
function reversed(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reversed);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).reverse().map(([key, child]) => [key,reversed(child)]));
  return value;
}
for (const item of fixture.valid) test(`security summary matches Go canonical bytes: ${item.name}`, async () => {
  assert.equal(typeof api.normalizeSecuritySummary, "function", "published contracts must own summary validation");
  const input = reversed(item.summary);
  const normalized = api.normalizeSecuritySummary(input);
  assert.deepEqual(normalized, item.summary);
  assert.equal(api.canonicalSecuritySummaryJSON(input), item.canonical_json);
  assert.equal(await api.securitySummarySHA256(input), item.sha256);
  assert.equal(await api.capabilityContractSetSHA256(input), item.capability_contract_set_sha256);
  (normalized.surfaces as unknown[]).push({});
  assert.deepEqual(input, reversed(item.summary), "normalization returns a detached value");
});
for (const item of fixture.invalid) test(`security summary rejects ${item.name}`, async () => {
  const value = structuredClone(fixture.valid[1].summary);
  let parent = value;
  for (const key of item.path) parent = parent[key] as Record<string, unknown>;
  if (item.remove) delete parent[item.key]; else parent[item.key] = item.value;
  assert.throws(() => api.normalizeSecuritySummary(value), TypeError);
  await assert.rejects(api.securitySummarySHA256(value), TypeError);
});
test("security summary ignores only its own digest and binds execution declarations", async () => {
  const empty = fixture.valid[0].summary;
  assert.equal(await api.securitySummarySHA256({...empty, summary_sha256: `sha256:${"f".repeat(64)}`}), fixture.valid[0].sha256);
  assert.ok(fixture.valid[0].sha256 !== fixture.valid[2].sha256);
  assert.ok(fixture.valid[0].sha256 !== fixture.valid[3].sha256);
});
test("security summary rejects non-JSON numbers and strings", () => {
  for (const value of [NaN, Infinity, -Infinity]) {
    const summary = structuredClone(fixture.valid[1].summary);
    const surfaces = summary.surfaces as {default_size: {height: number}}[];
    surfaces[0].default_size.height = value;
    assert.throws(() => api.normalizeSecuritySummary(summary), TypeError);
  }
  const summary = structuredClone(fixture.valid[1].summary);
  (summary.surfaces as {label: string}[])[0].label = "\ud800";
  assert.throws(() => api.normalizeSecuritySummary(summary), TypeError);
  assert.throws(() => api.normalizeSecuritySummary({...fixture.valid[0].summary, methods: new Array(1)}), TypeError);
  assert.throws(() => api.normalizeSecuritySummary({...fixture.valid[0].summary, summary_sha256: fixture.valid[0].sha256 + "\n"}), TypeError);
});
