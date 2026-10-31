import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { listCanonicalContractArtifacts } from "./generate_platform_release_manifest.mjs";

const schema = JSON.parse(await readFile(new URL("../spec/plugin/data-upgrade.schema.json", import.meta.url)));
const fixtures = JSON.parse(await readFile(new URL("../spec/plugin/data-upgrade-fixtures.json", import.meta.url)));
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
test("upgrade control accepts only closed scope-bound data requests", () => {
  for (const fixture of fixtures.valid) assert.equal(validate(fixture.request), true, fixture.name + JSON.stringify(validate.errors));
  for (const fixture of fixtures.invalid) assert.equal(validate(fixture.request), false, fixture.name);
});
test("upgrade schema and fixtures belong to the exact release artifact closure", async () => {
  const names = new Set((await listCanonicalContractArtifacts()).map(item => item.name));
  for (const name of ["data-upgrade.schema.json", "data-upgrade-fixtures.json"]) assert.ok(names.has("contract:plugin/" + name));
});
