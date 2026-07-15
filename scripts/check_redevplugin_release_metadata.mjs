#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptPath = fileURLToPath(import.meta.url);
const defaultRoot = resolve(dirname(scriptPath), "..");
const releaseVersionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$/;

export function validateReleaseMetadataSources({ version, versionSource, changelog, cargoMetadata, root }) {
  const normalizedVersion = normalizeReleaseVersion(version);
  const compatibilityVersions = [...versionSource.matchAll(/developmentCompatibilityVersion\s*=\s*"([^"]+)"/g)];
  if (compatibilityVersions.length !== 1) {
    throw new Error("pkg/version/version.go must contain one developmentCompatibilityVersion assignment");
  }
  if (compatibilityVersions[0][1] !== normalizedVersion) {
    throw new Error(`Go compatibility version ${compatibilityVersions[0][1]} does not match release ${normalizedVersion}`);
  }

  const changelogVersion = changelog.match(/^## v([^\s]+)\s*$/m)?.[1];
  if (!changelogVersion) throw new Error("CHANGELOG.md must begin with a versioned release section");
  if (changelogVersion !== normalizedVersion) {
    throw new Error(`CHANGELOG first release ${changelogVersion} does not match release ${normalizedVersion}`);
  }

  const canonicalManifest = join(resolve(root), "crates", "redevplugin-worker-sdk", "Cargo.toml");
  const workerPackages = cargoMetadata.packages?.filter((pkg) => pkg?.name === "redevplugin-worker-sdk") ?? [];
  if (workerPackages.length !== 1 || resolve(workerPackages[0].manifest_path ?? "") !== canonicalManifest) {
    throw new Error("Cargo metadata must contain one canonical redevplugin-worker-sdk package");
  }
  if (workerPackages[0].version !== normalizedVersion) {
    throw new Error(`Worker SDK version ${workerPackages[0].version} does not match release ${normalizedVersion}`);
  }
  return normalizedVersion;
}

export function sourceReleaseVersion(changelog) {
  const version = changelog.match(/^## v([^\s]+)\s*$/m)?.[1];
  if (!version) throw new Error("CHANGELOG.md must begin with a versioned release section");
  return normalizeReleaseVersion(version);
}

export function normalizeReleaseVersion(rawVersion) {
  const version = String(rawVersion ?? "").replace(/^v/, "");
  if (!releaseVersionPattern.test(version)) throw new Error(`invalid release version ${JSON.stringify(rawVersion)}`);
  return version;
}

function cargoMetadata(root) {
  const cargo = join(homedir(), ".cargo", "bin", "cargo");
  const result = spawnSync(cargo, ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: root,
    env: { ...process.env, PATH: `${join(homedir(), ".cargo", "bin")}:${process.env.PATH ?? ""}` },
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`cargo metadata failed: ${result.stderr || result.stdout || result.error}`);
  }
  return JSON.parse(result.stdout);
}

function main() {
  const [rawVersion, rawRoot] = process.argv.slice(2);
  const root = resolve(rawRoot ?? defaultRoot);
  const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  const version = rawVersion === "--source" ? sourceReleaseVersion(changelog) : normalizeReleaseVersion(rawVersion);
  validateReleaseMetadataSources({
    version,
    versionSource: readFileSync(join(root, "pkg", "version", "version.go"), "utf8"),
    changelog,
    cargoMetadata: cargoMetadata(root),
    root,
  });
  process.stdout.write(`release metadata matches ${version}\n`);
}

if (resolve(process.argv[1] ?? "") === scriptPath) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  }
}
