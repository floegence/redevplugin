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

test("current UI contract exposes one closed finite canvas wheel event", () => {
  const variants = baseline.activeSchema.$defs.canvas_input.properties.event.oneOf;
  const wheel = variants.find((variant) => variant.properties?.type?.const === "wheel");
  assert.ok(wheel, "canvas wheel input must be part of the current bridge schema");
  assert.equal(wheel.additionalProperties, false);
  assert.deepEqual(wheel.required, [
    "type", "x", "y", "delta_x", "delta_y", "delta_mode",
    "alt_key", "ctrl_key", "meta_key", "shift_key",
  ]);
  assert.deepEqual(wheel.properties.delta_mode.enum, [0, 1, 2]);
  for (const name of ["x", "y", "delta_x", "delta_y"]) {
    assert.equal(wheel.properties[name].type, "number");
  }
});

test("current UI contract exposes closed surface keyboard bindings and input", () => {
  for (const definition of ["keyboard_bindings", "keyboard_input"]) {
    const withoutDefinition = structuredClone(baseline);
    delete withoutDefinition.activeSchema.$defs[definition];
    assert.throws(() => validateUIBridgeInputs(withoutDefinition), new RegExp(`current ${definition} frame is not closed and exact`));

    const withoutReference = structuredClone(baseline);
    withoutReference.activeSchema.oneOf = withoutReference.activeSchema.oneOf.filter(
      ({ $ref }) => $ref !== `#/$defs/${definition}`,
    );
    assert.throws(() => validateUIBridgeInputs(withoutReference), new RegExp(`exactly one ${definition} frame reference`));
  }

  const withOpenBinding = structuredClone(baseline);
  withOpenBinding.activeSchema.$defs.keyboard_binding.properties.unexpected = { type: "string" };
  assert.throws(() => validateUIBridgeInputs(withOpenBinding), /keyboard_binding declaration is not closed and exact/);

  const withOpenEvent = structuredClone(baseline);
  withOpenEvent.activeSchema.$defs.keyboard_input.properties.event.properties.unexpected = { type: "string" };
  assert.throws(() => validateUIBridgeInputs(withOpenEvent), /keyboard_input frame is not closed and exact/);
});

test("current UI contract exposes one closed user-action file export frame", () => {
  const withoutDefinition = structuredClone(baseline);
  delete withoutDefinition.activeSchema.$defs.file_export;
  assert.throws(() => validateUIBridgeInputs(withoutDefinition), /file_export frame is not closed and exact/);

  const withoutReference = structuredClone(baseline);
  withoutReference.activeSchema.oneOf = withoutReference.activeSchema.oneOf.filter(
    ({ $ref }) => $ref !== "#/$defs/file_export",
  );
  assert.throws(() => validateUIBridgeInputs(withoutReference), /exactly one file_export frame reference/);

  const withUnexpectedProperty = structuredClone(baseline);
  withUnexpectedProperty.activeSchema.$defs.file_export.properties.unexpected = { type: "string" };
  assert.throws(() => validateUIBridgeInputs(withUnexpectedProperty), /file_export frame is not closed and exact/);

  const withoutTransfer = structuredClone(baseline);
  delete withoutTransfer.activeSchema.$defs.file_export["x-redevplugin-transfer"];
  assert.throws(() => validateUIBridgeInputs(withoutTransfer), /file_export frame is not closed and exact/);
});
