#!/usr/bin/env node

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const [rawVersion, rawOutDir] = process.argv.slice(2);
if (!rawVersion || !rawOutDir) {
  console.error("usage: build_redevplugin_contracts_package.mjs <version> <out-dir>");
  process.exit(2);
}
if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(rawVersion)) {
  console.error("contracts package version must be semantic version text");
  process.exit(2);
}

const rootDir = resolve(import.meta.dirname, "..");
const sourceDir = join(rootDir, "packages", "redevplugin-contracts");
const outDir = resolve(rawOutDir);
const tempDir = mkdtempSync(join(tmpdir(), "redevplugin-contracts-pack-"));
const packageDir = join(tempDir, "redevplugin-contracts");

try {
  mkdirSync(packageDir, { recursive: true });
  cpSync(join(sourceDir, "dist"), join(packageDir, "dist"), { recursive: true });
  cpSync(join(rootDir, "LICENSE"), join(packageDir, "LICENSE"));
  const packageJSON = JSON.parse(readFileSync(join(sourceDir, "package.json"), "utf8"));
  packageJSON.version = rawVersion;
  const packageJSONPath = join(packageDir, "package.json");
  writeFileSync(packageJSONPath, `${JSON.stringify(packageJSON, null, 2)}\n`);
  mkdirSync(outDir, { recursive: true });
  const packed = spawnSync("npm", ["pack", "--ignore-scripts", "--pack-destination", outDir, "--json"], {
    cwd: packageDir,
    encoding: "utf8",
  });
  if (packed.status !== 0) {
    process.stderr.write(packed.stderr || packed.stdout);
    process.exit(packed.status ?? 1);
  }
  const result = JSON.parse(packed.stdout);
  if (!Array.isArray(result) || result.length !== 1 || typeof result[0]?.filename !== "string") {
    throw new Error(`npm pack returned an unexpected result: ${packed.stdout}`);
  }
  console.log(join(outDir, result[0].filename));
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
