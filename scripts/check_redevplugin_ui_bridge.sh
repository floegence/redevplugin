#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
SURFACE_SRC="$ROOT_DIR/packages/redevplugin-ui/src/surface.ts"

cd "$ROOT_DIR"
npm run contracts:check
node scripts/check_redevplugin_ui_bridge.mjs "$ROOT_DIR"

node - "$SURFACE_SRC" "$ROOT_DIR" <<'NODE'
const fs = require("fs");
const path = require("path");

const [surfacePath, rootDir] = process.argv.slice(2);
const surface = fs.readFileSync(surfacePath, "utf8");

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
  "examples/plugin-ui/memos.ts",
  "examples/plugin-ui/weather.ts",
  "examples/plugin-ui/sky-strike.ts",
  "internal/scaffoldtemplate/plugin-worker.ts",
  "testdata/browser-harness/opaque-surface/plugin-worker.ts",
];
for (const relativePath of pluginSourceFiles) {
  const source = fs.readFileSync(path.join(rootDir, relativePath), "utf8");
  const importsPluginEntrypoint = source.includes("packages/redevplugin-ui/src/plugin.js") ||
    source.includes('from "@floegence/redevplugin-ui/plugin"') ||
    source.includes("from '@floegence/redevplugin-ui/plugin'");
  if (!importsPluginEntrypoint) {
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
  ...walkFiles(path.join(rootDir, "examples/plugins")),
  ...walkFiles(path.join(rootDir, "cmd/redevplugin/scaffold_assets")),
  ...walkFiles(path.join(rootDir, "testdata/browser-harness")),
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

npm run ui-bridge-contract:test
npm run test:ui
