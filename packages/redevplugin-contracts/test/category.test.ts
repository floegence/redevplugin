import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { pluginCategories, resolvePluginCategory } from "../src/category.js";

test("categories match package and author schemas with an explicit default", () => {
  for (const name of ["manifest-v9", "source-manifest", "stored-manifest"]) {
    const schema = JSON.parse(readFileSync(new URL(`../../../../spec/plugin/${name}.schema.json`, import.meta.url), "utf8"));
    assert.deepEqual(schema.properties.presentation.properties.category.enum, [...pluginCategories]);
  }
  for (const category of pluginCategories) assert.equal(resolvePluginCategory(category), category);
  assert.equal(resolvePluginCategory(undefined), "other");
  for (const invalid of [null, "", "weather", "Data", "data ", [], 1]) {
    assert.throws(() => resolvePluginCategory(invalid), TypeError);
  }
});
