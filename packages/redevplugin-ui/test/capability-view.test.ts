import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCapabilityViewManifest } from "../src/capability-view.js";

test("capability view descriptor rejects foreign URLs, unsupported protocols and extra authority", () => {
  const valid = { schema_version: "redevplugin.capability_view.v1", module: "assets/view.js", styles: ["view.css"] };
  assert.deepEqual(parseCapabilityViewManifest(valid), valid);
  for (const module of ["", "/app.js", "//other/app.js", "https://other/app.js", "data:text/javascript,alert(1)", "../app.js", "assets/../app.js", "app.js?token=secret", "app.js#x", "assets/%2e/app.js", "assets\\app.js"]) {
    assert.throws(() => parseCapabilityViewManifest({ ...valid, module }));
  }
  assert.throws(() => parseCapabilityViewManifest({ ...valid, schema_version: "future" }));
  assert.throws(() => parseCapabilityViewManifest({ ...valid, token: "not allowed" }));
  assert.throws(() => parseCapabilityViewManifest({ ...valid, styles: ["view.css", "view.css"] }));
  const parsed = parseCapabilityViewManifest(valid);
  valid.styles[0] = "changed.css";
  assert.deepEqual(parsed.styles, ["view.css"]);
});
