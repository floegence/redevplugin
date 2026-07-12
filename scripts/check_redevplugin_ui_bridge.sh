#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
BRIDGE_SCHEMA="$ROOT_DIR/spec/plugin/bridge-v2.schema.json"
SURFACE_SRC="$ROOT_DIR/packages/redevplugin-ui/src/surface.ts"
CONTRACTS_SRC="$ROOT_DIR/packages/redevplugin-ui/src/contracts.gen.ts"

cd "$ROOT_DIR"
npm run contracts:check

node - "$BRIDGE_SCHEMA" "$SURFACE_SRC" "$CONTRACTS_SRC" "$ROOT_DIR" <<'NODE'
const fs = require("fs");
const path = require("path");

const [schemaPath, surfacePath, contractsPath, rootDir] = process.argv.slice(2);
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const surface = fs.readFileSync(surfacePath, "utf8");
const contracts = fs.readFileSync(contractsPath, "utf8");

const requiredFrames = [
  "redevplugin.bridge.call",
  "redevplugin.bridge.stream.read",
  "redevplugin.ui.render",
  "redevplugin.bridge.cancel",
  "redevplugin.ui.action",
  "redevplugin.bridge.response",
  "redevplugin.bridge.lifecycle",
];
const schemaText = JSON.stringify(schema);
for (const frame of requiredFrames) {
  if (!schemaText.includes(frame)) throw new Error(`bridge schema is missing ${frame}`);
  if (!surface.includes(frame)) throw new Error(`surface SDK is missing ${frame}`);
}
for (const forbidden of [
  "redevplugin.bridge.handshake",
  "handshake_transcript_sha256",
  "bridge_channel_id",
  "plugin_gateway_token",
  "asset_ticket",
  "asset_session",
  "stream_ticket",
  "confirmation_token",
]) {
  if (schemaText.includes(forbidden)) {
    throw new Error(`plugin-visible bridge schema exposes trusted-parent field ${forbidden}`);
  }
}
if (!contracts.includes('"plugin_ui_protocol_version": "plugin-ui-v2"')) {
  throw new Error("generated UI protocol version is not plugin-ui-v2");
}
if (!schema["x-redevplugin-render-policy"]) {
  throw new Error("bridge schema is missing the generated renderer policy source");
}

const responseDef = JSON.stringify(schema.$defs.response);
for (const forbidden of ["plugin_gateway_token", "asset_ticket", "asset_session", "stream_ticket", "confirmation_token"]) {
  if (responseDef.includes(forbidden)) {
    throw new Error(`plugin-visible bridge response must not expose ${forbidden}`);
  }
}
for (const forbidden of ["window.parent.postMessage", "parent_origin", "sandbox_origin", "allow-same-origin"]) {
  if (surface.includes(forbidden)) {
    throw new Error(`surface SDK contains forbidden bridge mechanism ${forbidden}`);
  }
}

const wildcardTransfers = surface.match(/\}, "\*", \[channel\.port2\]\);/g) ?? [];
if (wildcardTransfers.length !== 1) {
  throw new Error(`surface SDK must contain exactly one opaque-origin bootstrap port transfer, found ${wildcardTransfers.length}`);
}
const transferStart = surface.lastIndexOf("iframeWindow.postMessage({", surface.indexOf(wildcardTransfers[0]));
const transferBlock = surface.slice(transferStart, surface.indexOf(wildcardTransfers[0]) + wildcardTransfers[0].length);
for (const required of ["redevplugin.surface.port", "frame_generation_id", "ui_protocol_version"]) {
  if (!transferBlock.includes(required)) throw new Error(`bootstrap transfer is missing ${required}`);
}
for (const forbidden of ["plugin_id", "surface_instance_id", "active_fingerprint", "bridge_nonce", "asset_session", "token", "ticket"]) {
  if (transferBlock.includes(forbidden)) throw new Error(`bootstrap transfer exposes ${forbidden}`);
}

const pluginSourceFiles = [
  "demo/browser/opaque-plugin-worker.ts",
  "demo/browser/real-plugin-worker.ts",
  "demo/browser/scaffold-plugin-worker.ts",
];
for (const relativePath of pluginSourceFiles) {
  const source = fs.readFileSync(path.join(rootDir, relativePath), "utf8");
  if (!source.includes("packages/redevplugin-ui/src/plugin.js")) {
    throw new Error(`${relativePath} must import the plugin-only SDK entrypoint`);
  }
  for (const forbiddenEntrypoint of ["/src/index.js", "/src/trusted-parent.js", "/dist/index.js", "/dist/trusted-parent.js"]) {
    if (source.includes(forbiddenEntrypoint)) {
      throw new Error(`${relativePath} imports forbidden trusted-parent entrypoint ${forbiddenEntrypoint}`);
    }
  }
}

const scannedPluginFiles = [
  ...pluginSourceFiles,
  ...walkFiles(path.join(rootDir, "demo/browser/generated")),
  ...walkFiles(path.join(rootDir, "cmd/redevplugin/demo_assets")),
  ...walkFiles(path.join(rootDir, "testdata/generated_plugins")),
].map((entry) => path.isAbsolute(entry) ? entry : path.join(rootDir, entry));
const wildcardPostMessage = /(?:\bpostMessage|\.postMessage)\s*\([^)]*,\s*["']\*["']/g;
for (const filename of new Set(scannedPluginFiles)) {
  if (!/\.(?:html|js|mjs|ts)$/.test(filename)) continue;
  const source = fs.readFileSync(filename, "utf8");
  const matches = source.match(wildcardPostMessage) ?? [];
  if (matches.length > 0) {
    throw new Error(`${path.relative(rootDir, filename)} contains forbidden wildcard postMessage (${matches.length})`);
  }
}

function walkFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(filename));
    else if (entry.isFile()) files.push(filename);
  }
  return files;
}
NODE

npm run test:ui
