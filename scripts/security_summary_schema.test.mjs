import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { parse } from "yaml";
import { securitySummaryJSONSchema } from "../packages/redevplugin-contracts/dist-test/src/index.js";

const fixture = JSON.parse(await readFile(new URL("../spec/plugin/security-summary-fixtures.json", import.meta.url), "utf8"));
const openAPI = parse(await readFile(new URL("../spec/openapi/plugin-platform.yaml", import.meta.url), "utf8"));
const validator = new Ajv2020({strict: true, allErrors: true}).compile(securitySummaryJSONSchema);

test("published summary JSON Schema accepts and rejects the shared evidence fixtures", () => {
  for (const item of fixture.valid) assert.equal(validator(item.summary), true, item.name + JSON.stringify(validator.errors));
  for (const item of fixture.invalid) {
    const value = structuredClone(fixture.valid[1].summary);
    let parent = value;
    for (const key of item.path) parent = parent[key];
    if (item.remove) delete parent[item.key]; else parent[item.key] = item.value;
    assert.equal(validator(value), false, item.name);
  }
});

function stripMetadata(value) {
  if (Array.isArray(value)) return value.map(stripMetadata);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !["description", "title"].includes(key))
    .map(([key, child]) => [key, key === "$ref" ? child.replace("#/components/schemas/", "#/$defs/") : stripMetadata(child)]));
}
test("published summary schema derives every definition from OpenAPI without a second field list", () => {
  for (const [name, schema] of Object.entries(securitySummaryJSONSchema.$defs)) {
    assert.deepEqual(schema, stripMetadata(openAPI.components.schemas[name]), name);
  }
});
