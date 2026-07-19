import assert from "node:assert/strict";
import { test } from "node:test";

import * as pluginEntrypoint from "../src/plugin.js";
import * as rootEntrypoint from "../src/index.js";
import * as trustedParentEntrypoint from "../src/trusted-parent.js";
import type { PluginBridgeRequestOptions, PluginJSONObject, PluginUIVNode } from "../src/plugin.js";
import type {
  PluginCatalogResult,
  PluginDiagnosticDetails,
  PluginDiagnosticEventList,
  PluginDiagnosticMutationOutcome,
  PluginIntentList,
  PluginOperationList,
  PluginPermissionList,
  PluginPlatformClient,
  PluginRuntimeHealth,
  PluginRuntimeLimits,
  PluginSurfaceSlot,
} from "../src/trusted-parent.js";

// @ts-expect-error trusted parent transport must not be available to plugin workers
import type { ReDevPluginSurfaceTransport } from "../src/plugin.js";
// @ts-expect-error trusted parent method results must not expose stream tickets to plugin workers
import type { PluginTrustedMethodResult } from "../src/plugin.js";

const pluginParams: PluginJSONObject = { ready: true };
const pluginRequestOptions: PluginBridgeRequestOptions = { signal: new AbortController().signal };
// @ts-expect-error capability effect is generated from the signed contract, not caller options
const invalidPluginRequestOptions: PluginBridgeRequestOptions = { effect: "read" };
const pluginTree: PluginUIVNode = { type: "text", key: "ready-text", text: "ready" };
// @ts-expect-error raw string text nodes are not part of the v5 UI protocol
const invalidPluginTree: PluginUIVNode = "ready";
void pluginParams;
void pluginRequestOptions;
void invalidPluginRequestOptions;
void pluginTree;
void invalidPluginTree;
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
const validDiagnosticOutcome: PluginDiagnosticMutationOutcome = "committed";
// @ts-expect-error diagnostic outcomes are a closed contract
const invalidDiagnosticOutcome: PluginDiagnosticMutationOutcome = "partial";
const validDiagnosticDetails: PluginDiagnosticDetails = { operation: "runtime.start" };
// @ts-expect-error diagnostic details reject undeclared fields
const invalidDiagnosticDetails: PluginDiagnosticDetails = { effective_directive: "script-src" };
// @ts-expect-error runtime health is manager health and requires shards
const invalidRuntimeHealth: PluginRuntimeHealth = { ready: true };
const validRuntimeLimits: PluginRuntimeLimits = {
  worker_count: 8,
  queue_capacity: 32,
  per_plugin_concurrency: 4,
  module_cache_entries: 64,
  module_cache_source_bytes: 134217728,
};
function mutateRuntimeLimits(limits: PluginRuntimeLimits): void {
  // @ts-expect-error negotiated runtime limits are observational
  limits.worker_count = 9;
}
void invalidCatalog;
void invalidOperations;
void invalidIntents;
void invalidPermissions;
void invalidDiagnostics;
void validDiagnosticOutcome;
void invalidDiagnosticOutcome;
void validDiagnosticDetails;
void invalidDiagnosticDetails;
void invalidRuntimeHealth;
void validRuntimeLimits;
void mutateRuntimeLimits;

function assertTrustedSurfaceOrchestration(client: PluginPlatformClient, slot: PluginSurfaceSlot): void {
  // @ts-expect-error raw bootstrap opening is private to the orchestrated slot flow
  void client.openSurface({});
  // @ts-expect-error slots cannot adopt caller-created bootstrap options
  void slot.open({});
}
void assertTrustedSurfaceOrchestration;

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
  assert.equal("PluginSurfaceHost" in rootEntrypoint, false);
  assert.equal("toPluginSurfaceHostBootstrap" in rootEntrypoint, false);
});
