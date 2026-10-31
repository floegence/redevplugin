import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

const root = new URL("../", import.meta.url);
const readJSON = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

test("stored manifests preserve history without widening package admission", async () => {
 const current = await readJSON("spec/plugin/manifest-v9.schema.json");
 const stored = await readJSON("spec/plugin/stored-manifest.schema.json");
 const ajv = new Ajv2020({strict: false, validateFormats: false});
 ajv.addSchema(await readJSON("spec/plugin/host-capability-pin-v1.schema.json"));
 const admit = ajv.compile(current);
 const retain = ajv.compile(stored);
 const original = await readJSON("testdata/generated_plugins/method-contract/manifest.json");
 assert.equal(admit(original), true);
 assert.equal(retain(original), true);
 const historical = structuredClone(original);
 for (const surface of historical.surfaces) delete surface.web;
 assert.equal(admit(historical), false);
 assert.equal(retain(historical), true);
 for (const mutate of [
  (value) => { value.surfaces[0].web = {}; },
  (value) => { value.surfaces[0].unknown = true; },
  (value) => { value.surfaces.push({...original.surfaces[0], surface_id: "current"}); },
  (value) => { value.schema_version = "redevplugin.manifest.v10"; },
 ]) {
  const invalid = structuredClone(historical); mutate(invalid); assert.equal(retain(invalid), false);
 }
 const openAPI = await readFile(new URL("spec/openapi/plugin-platform.yaml", root), "utf8");
 for (const name of ["PluginRecord", "PluginVersion"]) {
  const block = openAPI.split(`    ${name}:`)[1].split(/\n    [A-Z]/)[0];
  assert.match(block, /stored-manifest.schema.json/);
 }
});
