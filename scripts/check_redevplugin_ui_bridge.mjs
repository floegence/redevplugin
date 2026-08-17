#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const defaultRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const executionFrames = [
  "redevplugin.bridge.execution.cancel",
  "redevplugin.bridge.execution.query",
  "redevplugin.bridge.execution.events",
];
const trustedParentFields = [
  "redevplugin.bridge.handshake",
  "handshake_transcript_sha256",
  "bridge_channel_id",
  "plugin_gateway_token",
  "asset_ticket",
  "asset_session",
  "confirmation_token",
];
const commonFrames = [
  "redevplugin.bridge.call",
  ...executionFrames,
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
  const descriptors = currentBridgeContractDescriptors();
  const activeSchemaPath = resolveRepositoryPath(rootDir, descriptors.active.path, "active bridge artifact");
  const activeTransportPath = resolveRepositoryPath(rootDir, descriptors.active.transportPath, "active surface transport artifact");
  const [activeSchema, activeTransportSchema, surface, contracts] = await Promise.all([
    readJSON(activeSchemaPath, "active bridge schema"),
    readJSON(activeTransportPath, "active surface transport schema"),
    readFile(join(rootDir, "packages/redevplugin-ui/src/surface.ts"), "utf8"),
    readFile(join(rootDir, "packages/redevplugin-ui/src/contracts.gen.ts"), "utf8"),
  ]);
  validateUIBridgeInputs({ descriptors, activeSchema, activeTransportSchema, surface, contracts });
}

export function currentBridgeContractDescriptors() {
  return {
    active: {
      bridgeSchemaVersion: "bridge",
      path: "spec/plugin/bridge.schema.json",
      transportSchemaVersion: "opaque-surface-transport-v6",
      transportPath: "spec/plugin/opaque-surface-transport-v6.schema.json",
    },
  };
}

export function validateUIBridgeInputs({
  descriptors,
  activeSchema,
  activeTransportSchema,
  surface,
  contracts,
}) {
  if (!isRecord(descriptors) || !isRecord(descriptors.active) ||
      typeof surface !== "string" || typeof contracts !== "string") {
    throw new Error("bridge gate inputs are invalid");
  }
  validateBridgeSchemaIdentity(activeSchema, descriptors.active);
  validateTransportSchemaIdentity(activeTransportSchema, descriptors.active);
  validatePluginVisibleIsolation(activeSchema, "active bridge schema");

  validateExecutionSchemas(activeSchema);
  const activeText = JSON.stringify(activeSchema);
  for (const frame of commonFrames) {
    if (!activeText.includes(frame)) throw new Error(`active bridge schema is missing ${frame}`);
    if (!surface.includes(frame)) throw new Error(`surface SDK is missing ${frame}`);
  }
  if (activeText.includes("redevplugin.ui.render") || surface.includes("redevplugin.ui.render")) {
    throw new Error("active plugin UI must not retain the full-tree render frame");
  }
  if (!activeSchema.$defs?.context || !surface.includes("redevplugin.bridge.context") || !surface.includes("redevplugin.surface.context")) {
    throw new Error("current surface context contract is missing");
  }
  for (const required of [...executionFrames, "redevplugin.bridge.context", "redevplugin.surface.context"]) {
    if (!surface.includes(required)) throw new Error(`current surface gate is missing ${required}`);
  }
  const currentSources = [surface, contracts, JSON.stringify(activeTransportSchema)];
  if (currentSources.some((source) => source.includes("pluginUIProtocolVersion") || source.includes("ui_protocol_version") || /plugin-ui-v[0-9]+\b/.test(source))) {
    throw new Error("current UI contract retains an independent UI protocol axis");
  }
  const bridgeProtocolLiterals = [...new Set(surface.match(/bridge-v[0-9]+/g) ?? [])];
  if (bridgeProtocolLiterals.length > 0) throw new Error("surface SDK retains a retired bridge protocol");

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

function validateExecutionSchemas(schema) {
  validateExecutionFrame(schema, "execution_cancel", {
    required: ["type", "id", "execution_id"],
    properties: ["type", "id", "execution_id", "reason"],
    frame: "redevplugin.bridge.execution.cancel",
    validate: (properties) => properties.reason?.type === "string" && properties.reason?.maxLength === 256,
  });
  validateExecutionFrame(schema, "execution_query", {
    required: ["type", "id", "execution_id"],
    properties: ["type", "id", "execution_id"],
    frame: "redevplugin.bridge.execution.query",
  });
  validateExecutionFrame(schema, "execution_events", {
    required: ["type", "id", "execution_id", "after_cursor"],
    properties: ["type", "id", "execution_id", "after_cursor"],
    frame: "redevplugin.bridge.execution.events",
    validate: (properties) => properties.after_cursor?.type === "integer" &&
      properties.after_cursor?.minimum === 0 && properties.after_cursor?.maximum === 9007199254740991,
  });
}

function validateExecutionFrame(schema, definition, contract) {
  const frame = schema.$defs?.[definition];
  const properties = frame?.properties;
  if (!isRecord(frame) || frame.type !== "object" || frame.additionalProperties !== false ||
      JSON.stringify(frame.required) !== JSON.stringify(contract.required) ||
      !hasExactKeys(properties, contract.properties) ||
      properties?.type?.const !== contract.frame ||
      properties?.id?.$ref !== "#/$defs/request_id" ||
      properties?.execution_id?.$ref !== "#/$defs/opaque_handle" ||
      (contract.validate && !contract.validate(properties))) {
    throw new Error(`current ${definition} frame is not closed and exact`);
  }
  const references = Array.isArray(schema.oneOf)
    ? schema.oneOf.filter((entry) => entry?.$ref === `#/$defs/${definition}`)
    : [];
  if (references.length !== 1) throw new Error(`current contract must publish exactly one ${definition} frame reference`);
}

function validateTransportSchemaIdentity(schema, descriptor) {
  if (!isRecord(schema) || schema.$id !== `https://schemas.redevplugin.dev/plugin/${descriptor.transportSchemaVersion}.schema.json`) {
    throw new Error(`surface transport schema identity does not match ${descriptor.transportSchemaVersion}`);
  }
}

function validateBridgeSchemaIdentity(schema, descriptor) {
  if (!isRecord(schema) || schema.$id !== `https://schemas.redevplugin.dev/plugin/${descriptor.bridgeSchemaVersion}.schema.json`) {
    throw new Error(`bridge schema identity does not match ${descriptor.bridgeSchemaVersion}`);
  }
}

function validatePluginVisibleIsolation(schema, label) {
  const schemaText = JSON.stringify(schema);
  for (const forbidden of trustedParentFields) {
    if (schemaText.includes(forbidden)) throw new Error(`${label} exposes trusted-parent field ${forbidden}`);
  }
}

function validContractPath(value) {
  return typeof value === "string" && /^spec\/plugin\/[A-Za-z0-9._/-]+$/.test(value) &&
    !value.includes("..") && !value.includes("\\") && value.endsWith(".schema.json");
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

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isRecord(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
