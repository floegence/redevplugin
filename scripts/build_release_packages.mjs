#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildRustSourcePackages, rustSourcePackages } from "./rust_source_packages.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmPackages = Object.freeze([
  Object.freeze({
    name: "@floegence/redevplugin-contracts",
    builder: "build_redevplugin_contracts_package.mjs",
  }),
  Object.freeze({
    name: "@floegence/redevplugin-ui",
    builder: "build_redevplugin_ui_package.mjs",
  }),
]);

export async function buildReleasePackages({ outDir, version, sourceCommit, requireClean = false }) {
  assertVersion(version);
  assertCommit(sourceCommit);
  if (readFileSync(join(root, "VERSION"), "utf8").trim() !== version) {
    throw new Error("release package version must equal VERSION");
  }
  if (git("rev-parse", "HEAD").trim() !== sourceCommit) {
    throw new Error("release package source commit must equal HEAD");
  }
  if (requireClean && git("status", "--porcelain=v1", "--untracked-files=all").trim() !== "") {
    throw new Error("release package source must be clean");
  }

  const destination = resolve(outDir);
  rmSync(destination, { recursive: true, force: true });
  const npmDir = join(destination, "npm");
  const rustDir = join(destination, "rust");
  mkdirSync(npmDir, { recursive: true });
  mkdirSync(rustDir, { recursive: true });

  run("npm", ["run", "build"]);
  for (const coordinate of npmPackages) {
    run("node", [join(root, "scripts", coordinate.builder), version, npmDir]);
  }

  const rustBuild = await buildRustSourcePackages({ allowDirty: !requireClean });
  try {
    for (const artifact of rustBuild.artifacts) {
      cpSync(artifact.archivePath, join(rustDir, basename(artifact.archivePath)));
    }
  } finally {
    rustBuild.cleanup();
  }

  const cargoMetadata = JSON.parse(execFileSync(
    "cargo",
    ["metadata", "--locked", "--format-version", "1", "--no-deps"],
    { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
  ));
  writeFileSync(
    join(rustDir, "rust-publish-metadata-v1.json"),
    `${JSON.stringify(createRustPublishMetadata({ cargoMetadata, version, sourceCommit }), null, 2)}\n`,
    { flag: "wx" },
  );
}

export function createRustPublishMetadata({ cargoMetadata, version, sourceCommit }) {
  assertVersion(version);
  assertCommit(sourceCommit);
  const packages = rustSourcePackages.map(({ name }) => {
    const pkg = cargoMetadata.packages?.find((candidate) => candidate.name === name && candidate.version === version);
    if (!pkg) throw new Error(`cargo metadata omitted ${name}@${version}`);
    return {
      name: pkg.name,
      vers: pkg.version,
      deps: pkg.dependencies.map((dependency) => ({
        name: dependency.name,
        version_req: dependency.req,
        features: [...dependency.features].sort(),
        optional: dependency.optional,
        default_features: dependency.uses_default_features,
        target: dependency.target,
        kind: dependency.kind ?? "normal",
        registry: dependency.registry,
        explicit_name_in_toml: dependency.rename,
      })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
      features: pkg.features,
      authors: pkg.authors,
      description: pkg.description,
      documentation: pkg.documentation,
      homepage: pkg.homepage,
      readme: pkg.readme ? readFileSync(join(dirname(pkg.manifest_path), pkg.readme), "utf8") : null,
      readme_file: pkg.readme,
      keywords: pkg.keywords,
      categories: pkg.categories,
      license: pkg.license,
      license_file: pkg.license_file,
      repository: pkg.repository,
      badges: {},
      links: pkg.links,
      rust_version: pkg.rust_version,
    };
  });
  return {
    schema_version: "redevplugin.rust_publish_metadata.v1",
    source_commit: sourceCommit,
    packages,
  };
}

function git(...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" });
}

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", stdio: "inherit" });
  if (result.status !== 0) throw new Error(`${command} failed with status ${result.status}`);
}

function assertVersion(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("release package version must be stable SemVer");
  }
}

function assertCommit(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error("release package source commit must be a full Git SHA");
  }
}

function parseArgs(argv) {
  const result = { outDir: "", version: "", sourceCommit: "", requireClean: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--require-clean") {
      result.requireClean = true;
    } else if (argument === "--out-dir") {
      result.outDir = argv[++index] ?? "";
    } else if (argument === "--version") {
      result.version = argv[++index] ?? "";
    } else if (argument === "--source-commit") {
      result.sourceCommit = argv[++index] ?? "";
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (!result.outDir) throw new Error("--out-dir is required");
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildReleasePackages(parseArgs(process.argv.slice(2)));
}
