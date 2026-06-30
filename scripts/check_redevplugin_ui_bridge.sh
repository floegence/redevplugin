#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
SDK_SRC="$ROOT_DIR/packages/redevplugin-ui/src"
BRIDGE_SCHEMA="$ROOT_DIR/spec/plugin/bridge-v1.schema.json"

if grep -R 'postMessage([^,]*,[[:space:]]*["'\'']\*["'\'']' "$SDK_SRC" >/dev/null; then
  echo "redevplugin-ui must not use wildcard postMessage targetOrigin" >&2
  exit 1
fi

grep -q '"type": { "const": "redevplugin.bridge.handshake" }' "$BRIDGE_SCHEMA"
grep -q '"type": { "const": "redevplugin.bridge.call" }' "$BRIDGE_SCHEMA"
grep -q '"type": { "const": "redevplugin.bridge.response" }' "$BRIDGE_SCHEMA"
grep -q '"type": { "const": "redevplugin.bridge.lifecycle" }' "$BRIDGE_SCHEMA"
grep -q '"ui_protocol_version": { "const": "plugin-ui-v1" }' "$BRIDGE_SCHEMA"
grep -q '"params": {' "$BRIDGE_SCHEMA"
grep -q '"type": "object"' "$BRIDGE_SCHEMA"
grep -q '"PLUGIN_CONFIRMATION_REQUIRED"' "$BRIDGE_SCHEMA"
grep -q '"PLUGIN_CONFIRMATION_REJECTED"' "$BRIDGE_SCHEMA"
grep -q '"PLUGIN_BRIDGE_HANDSHAKE_REQUIRED"' "$BRIDGE_SCHEMA"

grep -q 'type: "redevplugin.bridge.handshake"' "$SDK_SRC/index.ts"
grep -q 'type: "redevplugin.bridge.call"' "$SDK_SRC/index.ts"
grep -q 'type: "redevplugin.bridge.response"' "$SDK_SRC/index.ts"
grep -q 'type: "redevplugin.bridge.lifecycle"' "$SDK_SRC/index.ts"
grep -q 'ui_protocol_version: "plugin-ui-v1"' "$SDK_SRC/index.ts"

node - "$BRIDGE_SCHEMA" "$SDK_SRC/index.ts" <<'NODE'
const fs = require("fs");

const [schemaPath, sdkPath] = process.argv.slice(2);
const schemaRaw = fs.readFileSync(schemaPath, "utf8");
const schema = JSON.parse(schemaRaw);
const sdk = fs.readFileSync(sdkPath, "utf8");

const schemaConstants = new Set(schemaRaw.match(/redevplugin\.bridge\.[a-z_]+|plugin-ui-v1/g) ?? []);
for (const value of ["redevplugin.bridge.handshake", "redevplugin.bridge.call", "redevplugin.bridge.response", "redevplugin.bridge.lifecycle", "plugin-ui-v1"]) {
  if (!schemaConstants.has(value)) {
    throw new Error(`bridge schema is missing ${value}`);
  }
  if (!sdk.includes(value)) {
    throw new Error(`bridge SDK is missing ${value}`);
  }
}

const responseDef = JSON.stringify(schema.$defs.response);
for (const forbidden of ["plugin_gateway_token", "confirmation_token"]) {
  if (responseDef.includes(forbidden)) {
    throw new Error(`bridge response schema must not expose ${forbidden}`);
  }
}

const responseType = sdk.match(/export type PluginBridgeResponse =([\s\S]*?);\n\nexport type PluginBridgeCallMessage/);
if (!responseType) {
  throw new Error("bridge SDK response type was not found");
}
for (const forbidden of ["plugin_gateway_token", "confirmation_token"]) {
  if (responseType[1].includes(forbidden)) {
    throw new Error(`bridge SDK response type must not expose ${forbidden}`);
  }
}
NODE
