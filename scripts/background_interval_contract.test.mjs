import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { parse } from "yaml";

const manifest = JSON.parse(await readFile(new URL("../spec/plugin/manifest-v9.schema.json", import.meta.url)));
const openapi = parse(await readFile(new URL("../spec/openapi/plugin-platform.yaml", import.meta.url), "utf8"));
const validate = new Ajv2020({ strict: false }).compile(manifest.properties.background);
const valid = { strategy: "interval", worker_id: "refresh", method: "refresh", interval_ms: 60000, max_runtime_ms: 10000 };
test("interval declarations require explicit method and bounded scheduling inputs", () => {
  assert.equal(validate(valid), true, JSON.stringify(validate.errors));
  for (const key of ["method", "interval_ms", "max_runtime_ms"]) {
    const value = { ...valid }; delete value[key];
    assert.equal(validate(value), false, key);
  }
  for (const change of [{ interval_ms: 999 }, { interval_ms: 86400001 }, { max_runtime_ms: 300001 }, { max_runtime_ms: null }, { strategy: "runtime_start" }, { extra: true }]) {
    assert.equal(validate({ ...valid, ...change }), false, JSON.stringify(change));
  }
  assert.equal(validate({ strategy: "on_demand", worker_id: "refresh" }), true);
});
test("inventory projects bounded interval state without exposing durable claim authority", () => {
  const schema = openapi.components.schemas.BackgroundIntervalStatus;
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, ["state", "interval_ms", "max_runtime_ms"]);
  assert.deepEqual(schema.properties.state.enum, ["scheduled", "running", "stopped", "blocked"]);
  assert.equal(Object.hasOwn(schema.properties, "claim_id"), false);
  assert.equal(Object.hasOwn(openapi.paths, "/v1/background/claim"), false);
});
