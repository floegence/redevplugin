import assert from "node:assert/strict";
import { test } from "node:test";

import * as pluginEntrypoint from "../src/plugin.js";
import * as rootEntrypoint from "../src/index.js";
import * as trustedParentEntrypoint from "../src/trusted-parent.js";
import type { PluginJSONObject, PluginUIVNode } from "../src/plugin.js";
import type {
  PluginCatalogResult,
  PluginDiagnosticEventList,
  PluginIntentList,
  PluginOperationList,
  PluginPermissionList,
  PluginRuntimeHealth,
} from "../src/trusted-parent.js";

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

// @ts-expect-error generated catalog lists require the plugins array
const invalidCatalog: PluginCatalogResult = {};
// @ts-expect-error generated operation lists require the operations array
const invalidOperations: PluginOperationList = {};
// @ts-expect-error generated intent lists require the intents array
const invalidIntents: PluginIntentList = {};
// @ts-expect-error generated permission lists require the permissions array
const invalidPermissions: PluginPermissionList = {};
// @ts-expect-error generated diagnostic lists require the diagnostic_events array
const invalidDiagnostics: PluginDiagnosticEventList = {};
// @ts-expect-error runtime health is manager health and requires shards
const invalidRuntimeHealth: PluginRuntimeHealth = { ready: true };
void invalidCatalog;
void invalidOperations;
void invalidIntents;
void invalidPermissions;
void invalidDiagnostics;
void invalidRuntimeHealth;

test("plugin worker entrypoint exposes only bridge and generated capability client primitives", () => {
  assert.deepEqual(Object.keys(pluginEntrypoint), [
    "PluginBridgeClient",
    "PluginBridgeError",
    "callCapabilityOperation",
    "callCapabilityStream",
    "callCapabilitySync",
    "isCapabilityBusinessError",
  ]);
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
