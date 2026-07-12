#!/usr/bin/env node
import { mkdtempSync, mkdirSync, cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const [rawVersion, rawOutDir] = process.argv.slice(2);
if (!rawVersion || !rawOutDir) {
  console.error("usage: build_redevplugin_ui_package.mjs <version> <out-dir>");
  process.exit(2);
}

const rootDir = resolve(import.meta.dirname, "..");
const sourceDir = join(rootDir, "packages", "redevplugin-ui");
const outDir = resolve(rawOutDir);
const tempDir = mkdtempSync(join(tmpdir(), "redevplugin-ui-pack-"));
const packageDir = join(tempDir, "redevplugin-ui");

try {
  mkdirSync(packageDir, { recursive: true });
  cpSync(join(sourceDir, "dist"), join(packageDir, "dist"), { recursive: true });
  cpSync(join(rootDir, "LICENSE"), join(packageDir, "LICENSE"));
  const packageJSONPath = join(packageDir, "package.json");
  const packageJSON = JSON.parse(readFileSync(join(sourceDir, "package.json"), "utf8"));
  packageJSON.version = rawVersion;
  writeFileSync(packageJSONPath, JSON.stringify(packageJSON, null, 2) + "\n");
  mkdirSync(outDir, { recursive: true });
  const packed = spawnSync("npm", ["pack", "--pack-destination", outDir, "--json"], {
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
