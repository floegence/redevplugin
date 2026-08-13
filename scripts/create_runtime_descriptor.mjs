#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runtimeTargetForPlatform } from "./runtime_targets.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [binaryPath, platformTarget, outputPath] = process.argv.slice(2);

if (!binaryPath || !platformTarget || !outputPath || process.argv.length !== 5) {
  throw new Error("usage: create_runtime_descriptor.mjs <runtime-binary> <linux/amd64|linux/arm64> <output.json>");
}
const target = runtimeTargetForPlatform(platformTarget);
if (target.os !== "linux") throw new Error(`runtime admission does not support ${platformTarget}`);

const packageSet = JSON.parse(readFileSync(resolve(root, "spec/plugin/platform-package-set-v2.json"), "utf8"));
const binarySHA256 = createHash("sha256").update(readFileSync(resolve(binaryPath))).digest("hex");
const descriptor = {
  schema_version: "runtime-descriptor-v2",
  platform_version: packageSet.platform_version,
  target: platformTarget,
  rust_ipc_version: "rust-ipc-v6",
  wasm_abi_version: "redevplugin-wasm-worker-v2",
  contract_set_sha256: packageSet.contract_set_sha256,
  binary_sha256: binarySHA256,
};
writeFileSync(resolve(outputPath), `${JSON.stringify(descriptor, null, 2)}\n`, { mode: 0o600 });
