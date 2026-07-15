#!/usr/bin/env node

import assert from "node:assert/strict";
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
  versionSource: 'const developmentCompatibilityVersion = "0.4.0"\n',
  changelog: "# Changelog\n\n## v0.4.0\n\n- Release.\n\n## v0.3.2\n",
  cargoMetadata: { packages: [canonicalPackage] },
  root,
};

assert.equal(validateReleaseMetadataSources(valid), "0.4.0");
assert.equal(sourceReleaseVersion(valid.changelog), "0.4.0");
assert.equal(normalizeReleaseVersion("v0.4.0"), "0.4.0");

for (const [label, mutation, expected] of [
  ["tag drift", { version: "0.4.1" }, /Go compatibility version/],
  ["Go compatibility drift", { versionSource: 'const developmentCompatibilityVersion = "0.4.1"\n' }, /Go compatibility version/],
  ["duplicate Go compatibility source", { versionSource: `${valid.versionSource}${valid.versionSource}` }, /one developmentCompatibilityVersion/],
  ["CHANGELOG drift", { changelog: valid.changelog.replace("## v0.4.0", "## v0.4.1") }, /CHANGELOG first release/],
  ["Worker SDK drift", { cargoMetadata: { packages: [{ ...canonicalPackage, version: "0.4.1" }] } }, /Worker SDK version/],
  ["Worker SDK path drift", { cargoMetadata: { packages: [{ ...canonicalPackage, manifest_path: join(root, "other", "Cargo.toml") }] } }, /one canonical/],
]) {
  assert.throws(() => validateReleaseMetadataSources({ ...valid, ...mutation }), expected, label);
}

assert.throws(() => normalizeReleaseVersion("0.4"), /invalid release version/);
assert.throws(() => sourceReleaseVersion("# Changelog\n"), /versioned release section/);
process.stdout.write("release metadata mutation tests passed\n");
