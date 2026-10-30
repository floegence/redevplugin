import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { isWebSurfaceDocument } from "../src/surface.js";

const fixture = JSON.parse(readFileSync(new URL("../../../../testdata/contracts/web-surface-parent-origins.json", import.meta.url), "utf8")) as { cases: { origin: string; accepted: boolean }[] };
const origin = "http://" + "a".repeat(48) + ".localhost:4100";
for (const item of fixture.cases) test(`Web surface canonical parent ${item.origin}`, () => {
  assert.equal(isWebSurfaceDocument({
    schema_version: "redevplugin.web_surface.v1",
    origin, parent_origin: item.origin,
    bootstrap_url: origin + "/_redevplugin_web/bootstrap#" + "b".repeat(64),
    entry_url: origin + "/index.html",
  }), item.accepted);
});

test("loopback IP permission is limited to the parent", () => {
  for (const child of ["http://127.0.0.1:4100", "http://[::1]:4100"]) {
    assert.equal(isWebSurfaceDocument({
      schema_version: "redevplugin.web_surface.v1",
      origin: child, parent_origin: "http://localhost:4100",
      bootstrap_url: child + "/_redevplugin_web/bootstrap#" + "b".repeat(64),
      entry_url: child + "/index.html",
    }), false);
  }
});
