import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  currentBridgeContractDescriptors,
  validateUIBridgeInputs,
  validateUIBridgeRepository,
} from "./check_redevplugin_ui_bridge.mjs";

const root = resolve(import.meta.dirname, "..");
const descriptors = currentBridgeContractDescriptors();
const baseline = {
  descriptors,
  activeSchema: JSON.parse(await readFile(join(root, descriptors.active.path), "utf8")),
  activeTransportSchema: JSON.parse(await readFile(join(root, descriptors.active.transportPath), "utf8")),
  surface: await readFile(join(root, "packages/redevplugin-ui/src/surface.ts"), "utf8"),
  contracts: await readFile(join(root, "packages/redevplugin-ui/src/contracts.gen.ts"), "utf8"),
};

test("UI bridge gate uses the single current schema", async () => {
  assert.deepEqual(descriptors.active, {
    bridgeSchemaVersion: "bridge",
    path: "spec/plugin/bridge.schema.json",
    transportSchemaVersion: "opaque-surface-transport-v6",
    transportPath: "spec/plugin/opaque-surface-transport-v6.schema.json",
  });
  await assert.doesNotReject(validateUIBridgeRepository(root));
});

test("current UI contract requires closed execution cancel, query, and events frames", () => {
  for (const definition of ["execution_cancel", "execution_query", "execution_events"]) {
    const withoutDefinition = structuredClone(baseline);
    delete withoutDefinition.activeSchema.$defs[definition];
    assert.throws(() => validateUIBridgeInputs(withoutDefinition), new RegExp(`${definition} frame is not closed and exact`));

    const withoutReference = structuredClone(baseline);
    withoutReference.activeSchema.oneOf = withoutReference.activeSchema.oneOf.filter(
      ({ $ref }) => $ref !== `#/$defs/${definition}`,
    );
    assert.throws(() => validateUIBridgeInputs(withoutReference), new RegExp(`exactly one ${definition} frame reference`));

    const withUnexpectedProperty = structuredClone(baseline);
    withUnexpectedProperty.activeSchema.$defs[definition].properties.unexpected = { type: "string" };
    assert.throws(() => validateUIBridgeInputs(withUnexpectedProperty), new RegExp(`${definition} frame is not closed and exact`));
  }

});

test("current UI contract rejects an independent UI protocol axis", () => {
  for (const [target, source] of [
    ["surface", "ui_protocol_version"],
    ["contracts", 'pluginUIProtocolVersion = "plugin-ui-v7"'],
    ["activeTransportSchema", { ui_protocol_version: { const: "plugin-ui-v7" } }],
  ]) {
    const stale = structuredClone(baseline);
    if (target === "activeTransportSchema") {
      stale.activeTransportSchema.$defs.port_envelope.properties.ui_protocol_version = source.ui_protocol_version;
    } else {
      stale[target] += `\n${source}`;
    }
    assert.throws(() => validateUIBridgeInputs(stale), /retains an independent UI protocol axis/);
  }
});
