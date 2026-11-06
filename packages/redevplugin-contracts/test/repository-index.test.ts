import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { sourceManifestJSONSchema, repositoryIndexJSONSchema, repositoryIndexSchemaVersion, repositoryIndexRenderTemplate, repositoryIndexVersionFromTag } from "../src/repository-index.js";

test("repository index contract has a closed versioned identity", () => {
  assert.equal(repositoryIndexSchemaVersion, "redevplugin.repository-index.v1");
  assert.equal(repositoryIndexJSONSchema.additionalProperties, false);
  assert.equal(repositoryIndexJSONSchema.properties.schema_version.const, repositoryIndexSchemaVersion);
  assert.equal(repositoryIndexJSONSchema.$defs.target.properties.plugins.maxItems, 256);
});

test("release templates match the complete stable tag", () => {
  assert.equal(repositoryIndexRenderTemplate("weather-v{version}", "1.2.3"), "weather-v1.2.3");
  assert.equal(repositoryIndexVersionFromTag("weather-v{version}", "weather-v1.2.3"), "1.2.3");
  assert.equal(repositoryIndexVersionFromTag("weather-v{version}", "other-weather-v1.2.3"), undefined);
  assert.equal(repositoryIndexVersionFromTag("v{version}", "v1.2.3-rc.1"), undefined);
  assert.throws(() => repositoryIndexRenderTemplate("v{version}", "01.2.3"));
});

test("release templates match the shared platform fixtures", () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../../spec/plugin/repository-index-fixtures.json", import.meta.url), "utf8")) as {
    templates: Array<{ template: string; version: string; tag: string }>;
    invalid_versions: string[];
  };
  for (const item of fixture.templates) {
    assert.equal(repositoryIndexRenderTemplate(item.template, item.version), item.tag);
    assert.equal(repositoryIndexVersionFromTag(item.template, item.tag), item.version);
  }
  for (const version of fixture.invalid_versions) assert.throws(() => repositoryIndexRenderTemplate("v{version}", version));
});

test("author schemas contain short slugs and exclude generated identity", () => {
 assert.deepEqual(repositoryIndexJSONSchema.$defs.plugin.required, ["slug", "path", "manifest", "release"]);
 assert.equal("plugin_id" in repositoryIndexJSONSchema.$defs.plugin.properties, false);
 assert.equal(sourceManifestJSONSchema.properties.schema_version.const, "redevplugin.source.v1");
 assert.equal("publisher_id" in sourceManifestJSONSchema.properties.publisher.properties, false);
 assert.equal("plugin_id" in sourceManifestJSONSchema.properties.plugin.properties, false);
 assert.ok(sourceManifestJSONSchema.properties.plugin.required.includes("slug"));
});
