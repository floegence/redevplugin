import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { parse } from "yaml";
import { securitySummaryJSONSchema, packageInspectionJSONSchema } from "../packages/redevplugin-contracts/dist-test/src/index.js";

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

function stripMetadata(value, properties = false) {
  if (Array.isArray(value)) return value.map(item => stripMetadata(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => properties || !["description", "title", "$schema", "$id"].includes(key))
    .map(([key, child]) => [key, key === "$ref" ? child.replace("#/components/schemas/", "#/$defs/") : stripMetadata(child, key === "properties")]));
}
const iconSchema = JSON.parse(await readFile(new URL("../spec/plugin/presentation-icon-evidence-v1.schema.json", import.meta.url), "utf8"));
openAPI.components.schemas.PresentationIconEvidence = iconSchema;
test("published summary schema derives every definition from OpenAPI without a second field list", () => {
  for (const [name, schema] of Object.entries(securitySummaryJSONSchema.$defs)) {
    assert.deepEqual(schema, stripMetadata(openAPI.components.schemas[name]), name);
  }
});


test("package inspection schema shares exact package, presentation, and capability projections", () => {
  const validate = new Ajv2020({strict:true, allErrors:true}).compile(packageInspectionJSONSchema);
  const digest = "sha256:" + "a".repeat(64);
  const value = {publisher_id:"example",plugin_id:"example.app",version:"1.0.0",package_sha256:digest,entries_sha256:digest,manifest_sha256:digest,presentation_sha256:digest,contract_set_sha256:digest,presentation:{default_locale:"en-US",locales:[{locale:"en-US",plugin_name:"App",summary:"Summary",description:["Description"],highlights:[],keywords:["app"],surfaces:[],settings:[]}]},security_summary:fixture.valid[0].summary};
  assert.equal(validate(value),true,JSON.stringify(validate.errors));
  assert.equal(validate({...value,signature:"retired"}),false);
  assert.equal(validate({...value,package_sha256:"not-a-digest"}),false);
});
