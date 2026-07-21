#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  decodePlatformPackagePublication,
  decodePlatformPackageSet,
  parseStrictJSON,
} from "./generate_platform_package_contracts.mjs";

const root = resolve(import.meta.dirname, "..");
export const publicationAssetName = "platform-package-publication-v1.json";
export const publicationAssetContentType = "application/vnd.floegence.redevplugin-platform-publication.v1+json";
const maxPublicationBytes = 128 * 1024;

export function createPlatformPackagePublication({ sourceCommit, goReadback, npmReadback, rustReadback }) {
  const packageSet = readPackageSet();
  assertCommit(sourceCommit, "publication source commit");
  exactKeys(goReadback, ["module", "version", "h1", "go_mod_h1", "source_commit"], "Go readback");
  if (goReadback.source_commit !== sourceCommit) throw new Error("Go readback source commit mismatch");
  assertReadbackArray(npmReadback, packageSet.npm_packages, sourceCommit, "npm", [
    "name", "version", "integrity", "provenance_subject_sha512", "source_commit",
  ]);
  assertReadbackArray(rustReadback, packageSet.rust_crates, sourceCommit, "Rust", [
    "name", "version", "registry_checksum_sha256", "source_commit",
  ]);

  const publication = {
    schema_version: "redevplugin.platform_package_publication.v1",
    platform_version: packageSet.platform_version,
    source_commit: sourceCommit,
    workflow: {
      repository: "floegence/redevplugin",
      path: ".github/workflows/release.yml",
      ref: `refs/tags/v${packageSet.platform_version}`,
      sha: sourceCommit,
    },
    go_module: {
      module: goReadback.module,
      version: goReadback.version,
      h1: goReadback.h1,
      go_mod_h1: goReadback.go_mod_h1,
    },
    npm_packages: npmReadback.map(({ name, version, integrity, provenance_subject_sha512 }) => ({
      name,
      version,
      integrity,
      provenance_subject_sha512,
    })),
    rust_crates: rustReadback.map(({ name, version, registry_checksum_sha256 }) => ({
      name,
      version,
      registry_checksum_sha256,
    })),
    contract_set_sha256: packageSet.contract_set_sha256,
  };
  return decodePlatformPackagePublication(
    Buffer.from(JSON.stringify(publication), "utf8"),
    packageSet.contract_set_sha256,
  );
}

export function verifyPlatformPackagePublication(raw, { expectedVersion, expectedCommit } = {}) {
  const packageSet = readPackageSet();
  const publication = decodePlatformPackagePublication(raw, packageSet.contract_set_sha256);
  if (expectedVersion !== undefined && publication.platform_version !== expectedVersion) {
    throw new Error("platform publication version mismatch");
  }
  if (expectedCommit !== undefined && publication.source_commit !== expectedCommit) {
    throw new Error("platform publication source commit mismatch");
  }
  if (publication.platform_version !== packageSet.platform_version
      || publication.go_module.module !== packageSet.go_module.module
      || publication.go_module.version !== packageSet.go_module.version) {
    throw new Error("platform publication Go coordinate mismatch");
  }
  for (let index = 0; index < packageSet.npm_packages.length; index += 1) {
    if (publication.npm_packages[index].name !== packageSet.npm_packages[index].name
        || publication.npm_packages[index].version !== packageSet.npm_packages[index].version) {
      throw new Error(`platform publication npm coordinate mismatch at ${index}`);
    }
  }
  for (let index = 0; index < packageSet.rust_crates.length; index += 1) {
    if (publication.rust_crates[index].name !== packageSet.rust_crates[index].name
        || publication.rust_crates[index].version !== packageSet.rust_crates[index].version) {
      throw new Error(`platform publication Rust coordinate mismatch at ${index}`);
    }
  }
  return publication;
}

export function verifyPlatformReleaseDirectory(directory, options = {}) {
  const absoluteDirectory = resolve(directory);
  const entries = readdirSync(absoluteDirectory).sort();
  if (entries.length !== 1 || entries[0] !== publicationAssetName) {
    throw new Error(`GitHub Release assets must be exactly ${publicationAssetName}`);
  }
  const path = join(absoluteDirectory, publicationAssetName);
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > maxPublicationBytes) {
    throw new Error("platform publication asset must be a bounded regular file");
  }
  return verifyPlatformPackagePublication(readFileSync(path), options);
}

function readPackageSet() {
  return decodePlatformPackageSet(readFileSync(join(root, "spec/plugin/platform-package-set-v1.json")));
}

function assertReadbackArray(values, coordinates, sourceCommit, label, keys) {
  if (!Array.isArray(values) || values.length !== coordinates.length) {
    throw new Error(`${label} readback must contain the exact package set`);
  }
  for (let index = 0; index < coordinates.length; index += 1) {
    const value = values[index];
    exactKeys(value, keys, `${label} readback ${index}`);
    if (value.name !== coordinates[index].name || value.version !== coordinates[index].version) {
      throw new Error(`${label} readback coordinate mismatch at ${index}`);
    }
    if (value.source_commit !== sourceCommit) throw new Error(`${label} readback source commit mismatch at ${index}`);
  }
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}

function assertCommit(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new Error(`${label} is invalid`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "verify" && (args.length === 1 || args.length === 3)) {
    const options = args.length === 3 ? { expectedVersion: args[1], expectedCommit: args[2] } : {};
    const path = resolve(args[0]);
    const info = lstatSync(path);
    if (info.isDirectory()) {
      verifyPlatformReleaseDirectory(path, options);
    } else if (basename(path) === publicationAssetName && info.isFile() && !info.isSymbolicLink()) {
      verifyPlatformPackagePublication(readFileSync(path), options);
    } else {
      throw new Error(`publication input must be ${publicationAssetName} or a release directory`);
    }
    console.log("platform package publication verified");
    return;
  }
  if (command === "create") {
    const options = parseCreateArgs(args);
    const publication = createPlatformPackagePublication({
      sourceCommit: options.sourceCommit,
      goReadback: readStrictJSON(options.goReadback, "Go readback"),
      npmReadback: readStrictJSON(options.npmReadback, "npm readback"),
      rustReadback: readStrictJSON(options.rustReadback, "Rust readback"),
    });
    writeFileSync(options.out, `${JSON.stringify(publication, null, 2)}\n`, { flag: "wx" });
    console.log(options.out);
    return;
  }
  console.error("usage: platform_package_publication.mjs verify PATH [VERSION COMMIT]");
  console.error("       platform_package_publication.mjs create --out FILE --source-commit OID --go-readback FILE --npm-readback FILE --rust-readback FILE");
  process.exit(2);
}

function parseCreateArgs(args) {
  const names = {
    "--out": "out",
    "--source-commit": "sourceCommit",
    "--go-readback": "goReadback",
    "--npm-readback": "npmReadback",
    "--rust-readback": "rustReadback",
  };
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = names[args[index]];
    if (!key || index + 1 >= args.length || options[key] !== undefined) throw new Error(`invalid create argument ${args[index]}`);
    options[key] = key === "sourceCommit" ? args[index + 1] : resolve(args[index + 1]);
  }
  for (const key of Object.values(names)) {
    if (!options[key]) throw new Error(`missing publication option ${key}`);
  }
  return options;
}

function readStrictJSON(path, label) {
  return parseStrictJSON(readFileSync(path), label, maxPublicationBytes);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
