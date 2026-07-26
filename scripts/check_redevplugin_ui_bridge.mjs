#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const operationSnapshotFrame = "redevplugin.bridge.operation.snapshot";
const trustedParentFields = [
  "redevplugin.bridge.handshake",
  "handshake_transcript_sha256",
  "bridge_channel_id",
  "plugin_gateway_token",
  "asset_ticket",
  "asset_session",
  "stream_ticket",
  "confirmation_token",
];
const commonFrames = [
  "redevplugin.bridge.call",
  "redevplugin.bridge.stream.read",
  "redevplugin.ui.mount",
  "redevplugin.ui.patch",
  "redevplugin.bridge.cancel",
  "redevplugin.ui.action",
  "redevplugin.bridge.response",
  "redevplugin.bridge.lifecycle",
];

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await validateUIBridgeRepository(resolve(process.argv[2] ?? defaultRoot));
}

export async function validateUIBridgeRepository(rootDir = defaultRoot) {
  const sourcePath = join(rootDir, "internal/contracts/active-contracts.json");
  const source = parseJSON(await readFile(sourcePath, "utf8"), "active contract source");
  const descriptors = resolveBridgeContractDescriptors(source);
  const activeSchemaPath = resolveRepositoryPath(rootDir, descriptors.active.path, "active bridge artifact");
  const activeTransportPath = resolveRepositoryPath(rootDir, descriptors.active.transportPath, "active surface transport artifact");
  const legacySchemaPath = resolveRepositoryPath(rootDir, descriptors.legacy.path, "legacy bridge artifact");
  const [activeSchema, activeTransportSchema, legacySchema, surface, contracts, rendererPerformance] = await Promise.all([
    readJSON(activeSchemaPath, "active bridge schema"),
    readJSON(activeTransportPath, "active surface transport schema"),
    readJSON(legacySchemaPath, "legacy bridge schema"),
    readFile(join(rootDir, "packages/redevplugin-ui/src/surface.ts"), "utf8"),
    readFile(join(rootDir, "packages/redevplugin-ui/src/contracts.gen.ts"), "utf8"),
    readFile(join(rootDir, "scripts/measure_redevplugin_renderer_performance.mjs"), "utf8"),
  ]);
  validateUIBridgeInputs({ descriptors, activeSchema, activeTransportSchema, legacySchema, surface, contracts, rendererPerformance });
}

export function resolveBridgeContractDescriptors(source) {
  if (!isRecord(source) || !hasExactKeys(source, ["schema_version", "matrix", "artifacts"]) ||
      source.schema_version !== "redevplugin.contract_source.v1") {
    throw new Error("active bridge gate requires the closed redevplugin contract source");
  }
  const matrix = source.matrix;
  if (!isRecord(matrix)) throw new Error("active bridge gate requires a contract matrix");
  const activeUI = requireVersion(matrix.plugin_ui_protocol_version, /^plugin-ui-v[1-9][0-9]*$/, "active UI protocol");
  const activeBridge = requireVersion(matrix.bridge_schema_version, /^bridge-v[1-9][0-9]*$/, "active bridge schema");
  const activeTransport = requireVersion(
    matrix.opaque_surface_transport_schema_version,
    /^opaque-surface-transport-v[1-9][0-9]*$/,
    "active surface transport schema",
  );
  if (!Array.isArray(matrix.supported_plugin_ui_protocol_versions) ||
      new Set(matrix.supported_plugin_ui_protocol_versions).size !== matrix.supported_plugin_ui_protocol_versions.length ||
      !matrix.supported_plugin_ui_protocol_versions.includes(activeUI)) {
    throw new Error("supported UI protocols must be unique and include the active protocol");
  }
  if (!Array.isArray(matrix.plugin_ui_transport_mappings) ||
      matrix.plugin_ui_transport_mappings.length !== matrix.supported_plugin_ui_protocol_versions.length) {
    throw new Error("UI transport mappings must exactly cover supported UI protocols");
  }
  const mappings = new Map();
  for (const mapping of matrix.plugin_ui_transport_mappings) {
    if (!isRecord(mapping) || !hasExactKeys(mapping, [
      "plugin_ui_protocol_version",
      "opaque_surface_transport_schema_version",
      "bridge_schema_version",
    ])) {
      throw new Error("UI transport mapping must be a closed object");
    }
    const protocol = requireVersion(mapping.plugin_ui_protocol_version, /^plugin-ui-v[1-9][0-9]*$/, "mapped UI protocol");
    const bridge = requireVersion(mapping.bridge_schema_version, /^bridge-v[1-9][0-9]*$/, "mapped bridge schema");
    const transport = requireVersion(
      mapping.opaque_surface_transport_schema_version,
      /^opaque-surface-transport-v[1-9][0-9]*$/,
      "mapped surface transport",
    );
    if (mappings.has(protocol)) throw new Error(`duplicate UI transport mapping for ${protocol}`);
    mappings.set(protocol, { bridge, transport });
  }
  const activeMapping = mappings.get(activeUI);
  if ([...mappings.keys()].some((protocol) => !matrix.supported_plugin_ui_protocol_versions.includes(protocol)) ||
      activeMapping?.bridge !== activeBridge || activeMapping?.transport !== activeTransport) {
    throw new Error("active UI protocol, bridge, and surface transport do not match the transport mapping");
  }

  if (!Array.isArray(source.artifacts)) throw new Error("active bridge gate requires contract artifacts");
  const activeArtifact = requireActiveArtifact(source.artifacts, "iframe-bridge-schema", activeBridge, "bridge");
  const activeTransportArtifact = requireActiveArtifact(
    source.artifacts,
    "opaque-surface-transport-schema",
    activeTransport,
    "surface transport",
  );

  const legacyUI = "plugin-ui-v5";
  const legacyBridge = mappings.get(legacyUI);
  if (legacyBridge?.bridge !== "bridge-v5" || legacyBridge.transport !== "opaque-surface-transport-v4") {
    throw new Error("legacy plugin-ui-v5 must remain mapped to bridge-v5");
  }
  return {
    active: {
      uiProtocolVersion: activeUI,
      bridgeSchemaVersion: activeBridge,
      path: activeArtifact.path,
      transportSchemaVersion: activeTransport,
      transportPath: activeTransportArtifact.path,
    },
    legacy: { uiProtocolVersion: legacyUI, bridgeSchemaVersion: legacyBridge.bridge, path: `spec/plugin/${legacyBridge.bridge}.schema.json` },
  };
}

export function validateUIBridgeInputs({
  descriptors,
  activeSchema,
  activeTransportSchema,
  legacySchema,
  surface,
  contracts,
  rendererPerformance,
}) {
  if (!isRecord(descriptors) || !isRecord(descriptors.active) || !isRecord(descriptors.legacy) ||
      typeof surface !== "string" || typeof contracts !== "string" || typeof rendererPerformance !== "string") {
    throw new Error("bridge gate inputs are invalid");
  }
  validateBridgeSchemaIdentity(activeSchema, descriptors.active);
  validateTransportSchemaIdentity(activeTransportSchema, descriptors.active);
  validateBridgeSchemaIdentity(legacySchema, descriptors.legacy);
  validatePluginVisibleIsolation(activeSchema, "active bridge schema");
  validatePluginVisibleIsolation(legacySchema, "legacy bridge-v5 schema");

  const activeText = JSON.stringify(activeSchema);
  for (const frame of commonFrames) {
    if (!activeText.includes(frame)) throw new Error(`active bridge schema is missing ${frame}`);
    if (!surface.includes(frame)) throw new Error(`surface SDK is missing ${frame}`);
  }
  if (activeText.includes("redevplugin.ui.render") || surface.includes("redevplugin.ui.render")) {
    throw new Error("active plugin UI must not retain the full-tree render frame");
  }
  switch (descriptors.active.uiProtocolVersion) {
  case "plugin-ui-v6":
    validateOperationSnapshotSchema(activeSchema);
    for (const required of [
      operationSnapshotFrame,
      'protocolVersion !== "plugin-ui-v6"',
      'this.bootstrap.uiProtocolVersion !== "plugin-ui-v6"',
    ]) {
      if (!surface.includes(required)) throw new Error(`plugin-ui-v6 surface gate is missing ${required}`);
    }
    break;
  case "plugin-ui-v5":
    if (activeText.includes(operationSnapshotFrame) || activeSchema.$defs?.operation_snapshot !== undefined) {
      throw new Error("plugin-ui-v5 active bridge must not expose operation snapshot");
    }
    break;
  default:
    throw new Error(`bridge gate does not understand active UI protocol ${descriptors.active.uiProtocolVersion}`);
  }

  const legacyText = JSON.stringify(legacySchema);
  if (legacyText.includes(operationSnapshotFrame) || legacySchema.$defs?.operation_snapshot !== undefined) {
    throw new Error("legacy bridge-v5 must not expose operation snapshot");
  }
  requireGeneratedVersion(contracts, "plugin_ui_protocol_version", descriptors.active.uiProtocolVersion);
  requireGeneratedVersion(contracts, "bridge_schema_version", descriptors.active.bridgeSchemaVersion);
  validateRendererPerformanceProtocolBinding(rendererPerformance);

  const responseDef = JSON.stringify(activeSchema.$defs?.response);
  for (const forbidden of trustedParentFields.slice(3)) {
    if (responseDef.includes(forbidden)) throw new Error(`plugin-visible bridge response exposes ${forbidden}`);
  }
  for (const forbidden of ["window.parent.postMessage", "parent_origin", "sandbox_origin", "allow-same-origin"]) {
    if (surface.includes(forbidden)) throw new Error(`surface SDK contains forbidden bridge mechanism ${forbidden}`);
  }
  if (!activeSchema["x-redevplugin-render-policy"]) {
    throw new Error("active bridge schema is missing the generated renderer policy source");
  }
}

function validateRendererPerformanceProtocolBinding(source) {
  const outer = ts.createSourceFile(
    "measure_redevplugin_renderer_performance.mjs",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS,
  );
  const harnessTemplates = [];
  walkTypeScript(outer, (node) => {
    if (!ts.isTemplateExpression(node)) return;
    const staticText = node.head.text + node.templateSpans.map((span) => span.literal.text).join("");
    if (staticText.includes("createPreparedPluginSurfaceHost")) harnessTemplates.push(node);
  });
  if (harnessTemplates.length !== 1) throw rendererPerformanceProtocolBindingError();

  const template = harnessTemplates[0];
  const embeddedSource = template.head.text + template.templateSpans.map(
    (span) => '"__REDEVPLUGIN_EMBEDDED_VALUE__"' + span.literal.text,
  ).join("");
  const embedded = ts.createSourceFile(
    "redevplugin-renderer-performance-host.ts",
    embeddedSource,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  if (embedded.parseDiagnostics.length > 0) throw rendererPerformanceProtocolBindingError();

  const protocolImports = embedded.statements.filter((statement) =>
    ts.isImportDeclaration(statement) &&
    ts.isStringLiteral(statement.moduleSpecifier) &&
    statement.moduleSpecifier.text === "./packages/redevplugin-ui/src/contracts.gen.ts" &&
    statement.importClause?.isTypeOnly !== true &&
    statement.importClause?.namedBindings &&
    ts.isNamedImports(statement.importClause.namedBindings) &&
    statement.importClause.namedBindings.elements.some((element) =>
      element.isTypeOnly !== true &&
      (element.propertyName?.text ?? element.name.text) === "pluginUIProtocolVersion" &&
      element.name.text === "pluginUIProtocolVersion"),
  );
  if (protocolImports.length !== 1) throw rendererPerformanceProtocolBindingError();

  const hostCalls = [];
  walkTypeScript(embedded, (node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) &&
        node.expression.text === "createPreparedPluginSurfaceHost") {
      hostCalls.push(node);
    }
  });
  if (hostCalls.length !== 1 || hostCalls[0].arguments.length !== 1 ||
      !ts.isObjectLiteralExpression(hostCalls[0].arguments[0])) {
    throw rendererPerformanceProtocolBindingError();
  }
  const bootstrap = exactObjectProperty(hostCalls[0].arguments[0], "bootstrap");
  if (!bootstrap || !ts.isObjectLiteralExpression(bootstrap.initializer)) throw rendererPerformanceProtocolBindingError();
  const protocol = exactObjectProperty(bootstrap.initializer, "uiProtocolVersion");
  if (!protocol || !ts.isIdentifier(protocol.initializer) || protocol.initializer.text !== "pluginUIProtocolVersion") {
    throw rendererPerformanceProtocolBindingError();
  }
}

function exactObjectProperty(object, name) {
  const matches = object.properties.filter((property) =>
    ts.isPropertyAssignment(property) &&
    ((ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) && property.name.text === name),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function walkTypeScript(node, visit) {
  visit(node);
  ts.forEachChild(node, (child) => walkTypeScript(child, visit));
}

function rendererPerformanceProtocolBindingError() {
  return new Error("renderer performance harness is not structurally bound to the generated active UI protocol");
}

function validateOperationSnapshotSchema(schema) {
  const snapshot = schema.$defs?.operation_snapshot;
  if (!isRecord(snapshot) || snapshot.type !== "object" || snapshot.additionalProperties !== false ||
      JSON.stringify(snapshot.required) !== JSON.stringify(["type", "id", "operation_id"]) ||
      !hasExactKeys(snapshot.properties, ["type", "id", "operation_id"]) ||
      snapshot.properties?.type?.const !== operationSnapshotFrame ||
      snapshot.properties?.id?.$ref !== "#/$defs/request_id" ||
      snapshot.properties?.operation_id?.$ref !== "#/$defs/opaque_handle") {
    throw new Error("plugin-ui-v6 operation snapshot frame is not closed and exact");
  }
  const references = Array.isArray(schema.oneOf) ? schema.oneOf.filter((entry) => entry?.$ref === "#/$defs/operation_snapshot") : [];
  if (references.length !== 1) throw new Error("plugin-ui-v6 must publish exactly one operation snapshot frame reference");
}

function validateTransportSchemaIdentity(schema, descriptor) {
  if (!isRecord(schema) || schema.$id !== `https://schemas.redevplugin.dev/plugin/${descriptor.transportSchemaVersion}.schema.json`) {
    throw new Error(`${descriptor.uiProtocolVersion} surface transport schema identity does not match ${descriptor.transportSchemaVersion}`);
  }
}

function validateBridgeSchemaIdentity(schema, descriptor) {
  if (!isRecord(schema) || schema.$id !== `https://schemas.redevplugin.dev/plugin/${descriptor.bridgeSchemaVersion}.schema.json`) {
    throw new Error(`${descriptor.uiProtocolVersion} bridge schema identity does not match ${descriptor.bridgeSchemaVersion}`);
  }
}

function validatePluginVisibleIsolation(schema, label) {
  const schemaText = JSON.stringify(schema);
  for (const forbidden of trustedParentFields) {
    if (schemaText.includes(forbidden)) throw new Error(`${label} exposes trusted-parent field ${forbidden}`);
  }
}

function requireGeneratedVersion(source, key, expected) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = [...source.matchAll(new RegExp(`^  "${escaped}"\\s*:\\s*"([^"]+)",?$`, "gm"))];
  if (matches.length !== 1 || matches[0][1] !== expected) {
    throw new Error(`generated contract ${key} does not match active value ${expected}`);
  }
}

function validContractPath(value) {
  return typeof value === "string" && /^spec\/plugin\/[A-Za-z0-9._/-]+$/.test(value) &&
    !value.includes("..") && !value.includes("\\") && value.endsWith(".schema.json");
}

function requireActiveArtifact(artifacts, id, expectedVersion, label) {
  const matches = artifacts.filter((artifact) => isRecord(artifact) && artifact.id === id);
  if (matches.length !== 1 || !hasExactKeys(matches[0], ["id", "path", "version"])) {
    throw new Error(`active contract source must contain one closed ${label} artifact`);
  }
  if (matches[0].version !== expectedVersion || !validContractPath(matches[0].path)) {
    throw new Error(`active ${label} artifact does not match the matrix schema version`);
  }
  return matches[0];
}

function resolveRepositoryPath(rootDir, candidate, label) {
  if (!validContractPath(candidate) || isAbsolute(candidate)) throw new Error(`${label} path is invalid`);
  const resolvedRoot = resolve(rootDir);
  const resolvedPath = resolve(resolvedRoot, candidate);
  if (resolvedPath !== resolvedRoot && !resolvedPath.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error(`${label} escapes the repository root`);
  }
  return resolvedPath;
}

async function readJSON(filename, label) {
  return parseJSON(await readFile(filename, "utf8"), `${label} ${relative(defaultRoot, filename)}`);
}

function parseJSON(source, label) {
  try {
    return JSON.parse(source);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function requireVersion(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isRecord(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
