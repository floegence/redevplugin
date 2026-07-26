import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  resolveBridgeContractDescriptors,
  validateUIBridgeInputs,
  validateUIBridgeRepository,
} from "./check_redevplugin_ui_bridge.mjs";

const root = resolve(import.meta.dirname, "..");
const source = JSON.parse(await readFile(join(root, "internal/contracts/active-contracts.json"), "utf8"));
const descriptors = resolveBridgeContractDescriptors(source);
const baseline = {
  descriptors,
  activeSchema: JSON.parse(await readFile(join(root, descriptors.active.path), "utf8")),
  activeTransportSchema: JSON.parse(await readFile(join(root, descriptors.active.transportPath), "utf8")),
  legacySchema: JSON.parse(await readFile(join(root, descriptors.legacy.path), "utf8")),
  surface: await readFile(join(root, "packages/redevplugin-ui/src/surface.ts"), "utf8"),
  contracts: await readFile(join(root, "packages/redevplugin-ui/src/contracts.gen.ts"), "utf8"),
  rendererPerformance: await readFile(join(root, "scripts/measure_redevplugin_renderer_performance.mjs"), "utf8"),
};

test("UI bridge gate resolves the active schema from the closed contract source", async () => {
  assert.deepEqual(descriptors.active, {
    uiProtocolVersion: "plugin-ui-v6",
    bridgeSchemaVersion: "bridge-v6",
    path: "spec/plugin/bridge-v6.schema.json",
    transportSchemaVersion: "opaque-surface-transport-v5",
    transportPath: "spec/plugin/opaque-surface-transport-v5.schema.json",
  });
  assert.deepEqual(descriptors.legacy, {
    uiProtocolVersion: "plugin-ui-v5",
    bridgeSchemaVersion: "bridge-v5",
    path: "spec/plugin/bridge-v5.schema.json",
  });
  await assert.doesNotReject(validateUIBridgeRepository(root));
});

test("UI bridge gate rejects matrix and active artifact drift", () => {
  const malformedMapping = structuredClone(source);
  malformedMapping.matrix.plugin_ui_transport_mappings[0].unexpected = true;
  assert.throws(
    () => resolveBridgeContractDescriptors(malformedMapping),
    /UI transport mapping must be a closed object/,
  );

  const wrongMatrix = structuredClone(source);
  wrongMatrix.matrix.bridge_schema_version = "bridge-v5";
  assert.throws(
    () => resolveBridgeContractDescriptors(wrongMatrix),
    /active UI protocol, bridge, and surface transport do not match/,
  );

  const wrongArtifact = structuredClone(source);
  const artifact = wrongArtifact.artifacts.find(({ id }) => id === "iframe-bridge-schema");
  artifact.version = "bridge-v5";
  assert.throws(
    () => resolveBridgeContractDescriptors(wrongArtifact),
    /active bridge artifact does not match/,
  );

  const wrongMatrixTransport = structuredClone(source);
  wrongMatrixTransport.matrix.opaque_surface_transport_schema_version = "opaque-surface-transport-v4";
  assert.throws(
    () => resolveBridgeContractDescriptors(wrongMatrixTransport),
    /surface transport do not match the transport mapping/,
  );

  const wrongMappedTransport = structuredClone(source);
  const activeMapping = wrongMappedTransport.matrix.plugin_ui_transport_mappings.find(
    ({ plugin_ui_protocol_version }) => plugin_ui_protocol_version === "plugin-ui-v6",
  );
  activeMapping.opaque_surface_transport_schema_version = "opaque-surface-transport-v4";
  assert.throws(
    () => resolveBridgeContractDescriptors(wrongMappedTransport),
    /surface transport do not match the transport mapping/,
  );

  const wrongTransportArtifact = structuredClone(source);
  const transportArtifact = wrongTransportArtifact.artifacts.find(({ id }) => id === "opaque-surface-transport-schema");
  transportArtifact.version = "opaque-surface-transport-v4";
  assert.throws(
    () => resolveBridgeContractDescriptors(wrongTransportArtifact),
    /active surface transport artifact does not match/,
  );
});

test("UI bridge gate fails closed for an unreviewed future active protocol", () => {
  const future = structuredClone(baseline);
  future.descriptors.active.uiProtocolVersion = "plugin-ui-v7";
  assert.throws(() => validateUIBridgeInputs(future), /does not understand active UI protocol plugin-ui-v7/);
});

test("plugin-ui-v6 requires one closed operation snapshot frame and both runtime gates", () => {
  const withoutDefinition = structuredClone(baseline);
  delete withoutDefinition.activeSchema.$defs.operation_snapshot;
  assert.throws(() => validateUIBridgeInputs(withoutDefinition), /operation snapshot frame is not closed and exact/);

  const withoutReference = structuredClone(baseline);
  withoutReference.activeSchema.oneOf = withoutReference.activeSchema.oneOf.filter(
    ({ $ref }) => $ref !== "#/$defs/operation_snapshot",
  );
  assert.throws(() => validateUIBridgeInputs(withoutReference), /exactly one operation snapshot frame reference/);

  const withUnexpectedProperty = structuredClone(baseline);
  withUnexpectedProperty.activeSchema.$defs.operation_snapshot.properties.unexpected = { type: "string" };
  assert.throws(() => validateUIBridgeInputs(withUnexpectedProperty), /operation snapshot frame is not closed and exact/);

  const withoutWorkerGate = structuredClone(baseline);
  withoutWorkerGate.surface = withoutWorkerGate.surface.replace(
    'protocolVersion !== "plugin-ui-v6"',
    'protocolVersion !== "plugin-ui-v7"',
  );
  assert.throws(() => validateUIBridgeInputs(withoutWorkerGate), /surface gate is missing/);

  const withoutRendererGate = structuredClone(baseline);
  withoutRendererGate.surface = withoutRendererGate.surface.replace(
    'this.bootstrap.uiProtocolVersion !== "plugin-ui-v6"',
    'this.bootstrap.uiProtocolVersion !== "plugin-ui-v7"',
  );
  assert.throws(() => validateUIBridgeInputs(withoutRendererGate), /surface gate is missing/);
});

test("legacy bridge-v5 remains isolated from snapshot and trusted-parent fields", () => {
  const withSnapshot = structuredClone(baseline);
  withSnapshot.legacySchema.$defs.operation_snapshot = structuredClone(baseline.activeSchema.$defs.operation_snapshot);
  assert.throws(() => validateUIBridgeInputs(withSnapshot), /legacy bridge-v5 must not expose operation snapshot/);

  const withTrustedField = structuredClone(baseline);
  withTrustedField.legacySchema.$defs.trusted_leak = { bridge_channel_id: { type: "string" } };
  assert.throws(() => validateUIBridgeInputs(withTrustedField), /legacy bridge-v5 schema exposes trusted-parent field bridge_channel_id/);
});

test("generated bridge versions must equal the active contract source", () => {
  const staleUI = structuredClone(baseline);
  staleUI.contracts = staleUI.contracts.replace(
    '"plugin_ui_protocol_version": "plugin-ui-v6"',
    '"plugin_ui_protocol_version": "plugin-ui-v5"',
  );
  assert.throws(() => validateUIBridgeInputs(staleUI), /generated contract plugin_ui_protocol_version does not match/);

  const staleBridge = structuredClone(baseline);
  staleBridge.contracts = staleBridge.contracts.replace(
    '  "bridge_schema_version": "bridge-v6",',
    '  "bridge_schema_version": "bridge-v5",',
  );
  assert.throws(() => validateUIBridgeInputs(staleBridge), /generated contract bridge_schema_version does not match/);
});

test("renderer performance harness must use the generated active UI protocol", () => {
  const staleHarness = structuredClone(baseline);
  staleHarness.rendererPerformance = staleHarness.rendererPerformance.replace(
    "uiProtocolVersion: pluginUIProtocolVersion,",
    'uiProtocolVersion: "plugin-ui-v5",',
  );
  assert.throws(() => validateUIBridgeInputs(staleHarness), /not structurally bound to the generated active UI protocol/);

  const commentDecoy = structuredClone(baseline);
  commentDecoy.rendererPerformance = commentDecoy.rendererPerformance
    .replace(
      'import { pluginUIProtocolVersion } from "./packages/redevplugin-ui/src/contracts.gen.ts";',
      '// import { pluginUIProtocolVersion } from "./packages/redevplugin-ui/src/contracts.gen.ts";',
    )
    .replace(
      "uiProtocolVersion: pluginUIProtocolVersion,",
      'uiProtocolVersion: "plugin-ui-v5", // uiProtocolVersion: pluginUIProtocolVersion,',
    );
  assert.throws(() => validateUIBridgeInputs(commentDecoy), /not structurally bound to the generated active UI protocol/);

  const shadowedProtocol = structuredClone(baseline);
  shadowedProtocol.rendererPerformance = shadowedProtocol.rendererPerformance
    .replace(
      "const host = createPreparedPluginSurfaceHost({",
      'const host = (() => {\n  const pluginUIProtocolVersion = "plugin-ui-v5";\n  return createPreparedPluginSurfaceHost({',
    )
    .replace(
      "});\ndocument.querySelector(\"#surface-root\").append(host.element);",
      "});\n})();\ndocument.querySelector(\"#surface-root\").append(host.element);",
    );
  assert.throws(() => validateUIBridgeInputs(shadowedProtocol), /not structurally bound to the generated active UI protocol/);

  const shadowedHostFactory = structuredClone(baseline);
  shadowedHostFactory.rendererPerformance = shadowedHostFactory.rendererPerformance
    .replace(
      "const host = createPreparedPluginSurfaceHost({",
      "const host = (() => {\n  const createPreparedPluginSurfaceHost = () => ({ element: document.createElement(\"div\") });\n  return createPreparedPluginSurfaceHost({",
    )
    .replace(
      "});\ndocument.querySelector(\"#surface-root\").append(host.element);",
      "});\n})();\ndocument.querySelector(\"#surface-root\").append(host.element);",
    );
  assert.throws(() => validateUIBridgeInputs(shadowedHostFactory), /not structurally bound to the generated active UI protocol/);

  for (const override of [
    'uiProtocolVersion: pluginUIProtocolVersion,\n    ...{ uiProtocolVersion: "plugin-ui-v5" },',
    'uiProtocolVersion: pluginUIProtocolVersion,\n    ["uiProtocolVersion"]: "plugin-ui-v5",',
    'uiProtocolVersion: pluginUIProtocolVersion,\n    get uiProtocolVersion() { return "plugin-ui-v5"; },',
  ]) {
    const bootstrapOverride = structuredClone(baseline);
    bootstrapOverride.rendererPerformance = bootstrapOverride.rendererPerformance.replace(
      "uiProtocolVersion: pluginUIProtocolVersion,",
      override,
    );
    assert.throws(() => validateUIBridgeInputs(bootstrapOverride), /not structurally bound to the generated active UI protocol/);
  }

  const hostOptionsOverride = structuredClone(baseline);
  hostOptionsOverride.rendererPerformance = hostOptionsOverride.rendererPerformance.replace(
    '  onError: (error) => { globalThis.__redevpluginError = error.message; },\n});',
    '  onError: (error) => { globalThis.__redevpluginError = error.message; },\n  ...{ bootstrap: {} },\n});',
  );
  assert.throws(() => validateUIBridgeInputs(hostOptionsOverride), /not structurally bound to the generated active UI protocol/);
});
