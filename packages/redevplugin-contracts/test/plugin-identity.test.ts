import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { githubPluginIdentity, validateGitHubPluginIdentity } from "../src/plugin-identity.js";

type Fixture = { repository_id: number; slug: string; publisher_id: string; plugin_id: string };
const fixtures = JSON.parse(readFileSync(new URL("../../../../spec/plugin/repository-identity-fixtures.json", import.meta.url), "utf8")) as { valid: Fixture[]; invalid: Fixture[] };

test("Go and TypeScript share the source-derived identity fixtures", () => {
  for (const item of fixtures.valid) {
    assert.deepEqual(githubPluginIdentity(item.repository_id, item.slug), { publisher_id: item.publisher_id, plugin_id: item.plugin_id });
    validateGitHubPluginIdentity(item.repository_id, item.publisher_id, item.plugin_id);
  }
  for (const item of fixtures.invalid) assert.throws(() => validateGitHubPluginIdentity(item.repository_id, item.publisher_id, item.plugin_id));
  for (const id of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) assert.throws(() => githubPluginIdentity(id, "plugin"));
  for (const slug of ["", "A", "a.b", "a_b", "a--b", "a-", "-a", "a".repeat(81)]) assert.throws(() => githubPluginIdentity(1, slug));
});
