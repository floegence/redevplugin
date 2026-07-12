import assert from "node:assert/strict";
import { test } from "node:test";

import * as pluginEntrypoint from "../src/plugin.js";
import * as rootEntrypoint from "../src/index.js";
import * as trustedParentEntrypoint from "../src/trusted-parent.js";
import type { PluginJSONObject, PluginUIVNode } from "../src/plugin.js";

// @ts-expect-error trusted parent transport must not be available to plugin workers
import type { ReDevPluginSurfaceTransport } from "../src/plugin.js";
// @ts-expect-error trusted parent method results must not expose stream tickets to plugin workers
import type { PluginTrustedMethodResult } from "../src/plugin.js";

const pluginParams: PluginJSONObject = { ready: true };
const pluginTree: PluginUIVNode = "ready";
void pluginParams;
void pluginTree;
void (null as unknown as ReDevPluginSurfaceTransport);
void (null as unknown as PluginTrustedMethodResult);

test("plugin worker entrypoint exposes only the bridge client at runtime", () => {
  assert.deepEqual(Object.keys(pluginEntrypoint), ["PluginBridgeClient"]);
  for (const forbidden of [
    "PluginPlatformClient",
    "PluginSurfaceHost",
    "createOpaquePluginBootstrapHTML",
    "createReDevPluginSurfaceTransport",
  ]) {
    assert.equal(forbidden in pluginEntrypoint, false);
  }
});

test("root entrypoint is the trusted parent allowlist", () => {
  assert.deepEqual(Object.keys(rootEntrypoint).sort(), Object.keys(trustedParentEntrypoint).sort());
  assert.equal("createOpaquePluginBootstrapHTML" in rootEntrypoint, false);
  assert.equal("PluginBridgeClient" in rootEntrypoint, false);
});
