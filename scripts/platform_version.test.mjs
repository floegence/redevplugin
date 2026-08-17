import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { parse as parseYAML } from "yaml";

const root = resolve(import.meta.dirname, "..");

test("VERSION is the exact platform version projected by every package", async () => {
  const [versionBytes, goMod, cargoToml, cargoLock, contractsPackage, uiPackage, packageLock, openAPIBytes] = await Promise.all([
    readFile(join(root, "VERSION"), "utf8"),
    readFile(join(root, "go.mod"), "utf8"),
    readFile(join(root, "Cargo.toml"), "utf8"),
    readFile(join(root, "Cargo.lock"), "utf8"),
    readJSON("packages/redevplugin-contracts/package.json"),
    readJSON("packages/redevplugin-ui/package.json"),
    readJSON("package-lock.json"),
    readFile(join(root, "spec/openapi/plugin-platform.yaml"), "utf8"),
  ]);
  const version = versionBytes.trim();
  assert.equal(version, "3.0.0");
  assert.match(goMod, /^module github\.com\/floegence\/redevplugin\/v3$/m);
  assert.match(cargoToml, new RegExp(`^version = ${JSON.stringify(version)}$`, "m"));
  for (const crate of ["redevplugin-runtime", "redevplugin-worker-sdk"]) {
    assert.match(cargoLock, new RegExp(`name = ${JSON.stringify(crate)}\\nversion = ${JSON.stringify(version)}`));
  }
  assert.equal(contractsPackage.version, version);
  assert.equal(uiPackage.version, version);
  assert.equal(uiPackage.dependencies["@floegence/redevplugin-contracts"], version);
  assert.equal(packageLock.packages["packages/redevplugin-contracts"].version, version);
  assert.equal(packageLock.packages["packages/redevplugin-ui"].version, version);
  assert.equal(
    packageLock.packages["packages/redevplugin-ui"].dependencies["@floegence/redevplugin-contracts"],
    version,
  );
  assert.equal(parseYAML(openAPIBytes).info.version, version);
});

async function readJSON(relativePath) {
  return JSON.parse(await readFile(join(root, relativePath), "utf8"));
}
