#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeReleaseVersion,
  sourceReleaseVersion,
  validateReleaseMetadataSources,
} from "./check_redevplugin_release_metadata.mjs";

const root = "/tmp/redevplugin-release-metadata-test";
const canonicalPackage = {
  name: "redevplugin-worker-sdk",
  version: "0.4.0",
  manifest_path: join(root, "crates", "redevplugin-worker-sdk", "Cargo.toml"),
};
const valid = {
  version: "v0.4.0",
  versionFile: "0.4.0\n",
  changelog: "# Changelog\n\n## v0.4.0\n\n- Release.\n\n## v0.3.2\n",
  cargoMetadata: { packages: [canonicalPackage] },
  root,
};

assert.equal(validateReleaseMetadataSources(valid), "0.4.0");
assert.equal(sourceReleaseVersion(valid.changelog), "0.4.0");
assert.equal(normalizeReleaseVersion("v0.4.0"), "0.4.0");

for (const [label, mutation, expected] of [
  ["tag drift", { version: "0.4.1" }, /VERSION/],
  ["VERSION drift", { versionFile: "0.4.1\n" }, /VERSION/],
  ["VERSION whitespace drift", { versionFile: "0.4.0\n\n" }, /VERSION/],
  ["CHANGELOG drift", { changelog: valid.changelog.replace("## v0.4.0", "## v0.4.1") }, /CHANGELOG first release/],
  ["Worker SDK drift", { cargoMetadata: { packages: [{ ...canonicalPackage, version: "0.4.1" }] } }, /Worker SDK version/],
  ["Worker SDK path drift", { cargoMetadata: { packages: [{ ...canonicalPackage, manifest_path: join(root, "other", "Cargo.toml") }] } }, /one canonical/],
]) {
  assert.throws(() => validateReleaseMetadataSources({ ...valid, ...mutation }), expected, label);
}

assert.throws(() => normalizeReleaseVersion("0.4"), /invalid release version/);
assert.throws(() => sourceReleaseVersion("# Changelog\n"), /versioned release section/);

const isolatedRoot = mkdtempSync(join(tmpdir(), "redevplugin-metadata-path-"));
try {
  const bin = join(isolatedRoot, "bin");
  mkdirSync(bin);
  writeFileSync(join(isolatedRoot, "VERSION"), valid.versionFile);
  writeFileSync(join(isolatedRoot, "CHANGELOG.md"), valid.changelog);
  const metadata = { packages: [{ ...canonicalPackage, manifest_path: join(isolatedRoot, "crates", "redevplugin-worker-sdk", "Cargo.toml") }] };
  writeFileSync(join(bin, "cargo"), `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(JSON.stringify(metadata))});\n`, { mode: 0o700 });
  const result = spawnSync(process.execPath, [join(import.meta.dirname, "check_redevplugin_release_metadata.mjs"), "--source", isolatedRoot], {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `release checker must use Cargo from PATH: ${result.stderr || result.error}`);
  assert.match(result.stdout, /release metadata matches 0\.4\.0/);
} finally {
  rmSync(isolatedRoot, { recursive: true, force: true });
}
process.stdout.write("release metadata mutation tests passed\n");
