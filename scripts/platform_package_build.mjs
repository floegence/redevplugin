#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { validateTarGzipArchive } from "./archive_contract.mjs";
import { parseStrictJSON } from "./generate_platform_package_contracts.mjs";
import { buildRustSourcePackages, rustSourcePackages, rustToolchain } from "./rust_source_packages.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildSchemaVersion = "redevplugin.platform_package_build.v1";
const npmCoordinates = Object.freeze([
  Object.freeze({
    name: "@floegence/redevplugin-contracts",
    directory: "packages/redevplugin-contracts",
    builder: "build_redevplugin_contracts_package.mjs",
    filenamePrefix: "floegence-redevplugin-contracts-",
  }),
  Object.freeze({
    name: "@floegence/redevplugin-ui",
    directory: "packages/redevplugin-ui",
    builder: "build_redevplugin_ui_package.mjs",
    filenamePrefix: "floegence-redevplugin-ui-",
  }),
]);

export async function buildPlatformPackages({
  outDir,
  version,
  sourceCommit,
  requireClean = false,
} = {}) {
  validateBuildInputs({ outDir, version, sourceCommit });
  const platformPackageSet = parseStrictJSON(
    readFileSync(join(root, "spec/plugin/platform-package-set-v1.json")),
    "platform package set",
  );
  if (platformPackageSet.platform_version !== version) {
    throw new Error(`platform package version ${platformPackageSet.platform_version} does not match ${version}`);
  }
  if (requireClean) assertCleanSource();

  const absoluteOutDir = resolve(outDir);
  rmSync(absoluteOutDir, { recursive: true, force: true });
  const npmDir = join(absoluteOutDir, "npm");
  const rustDir = join(absoluteOutDir, "rust");
  mkdirSync(npmDir, { recursive: true });
  mkdirSync(rustDir, { recursive: true });

  run("npm", ["run", "build"], "build npm packages");
  const artifacts = [];
  for (const coordinate of npmCoordinates) {
    run("node", [join(root, "scripts", coordinate.builder), version, npmDir], `pack ${coordinate.name}`);
    const filename = `${coordinate.filenamePrefix}${version}.tgz`;
    const path = join(npmDir, filename);
    if (!existsSync(path)) throw new Error(`${coordinate.name} pack omitted ${filename}`);
    artifacts.push(packageArtifact({
      kind: "npm",
      name: coordinate.name,
      version,
      path,
      outDir: absoluteOutDir,
      includeIntegrity: true,
    }));
  }

  const rustBuild = await buildRustSourcePackages({ allowDirty: !requireClean, keepTemporary: true });
  try {
    for (const artifact of rustBuild.artifacts) {
      const destination = join(rustDir, basename(artifact.archivePath));
      cpSync(artifact.archivePath, destination);
      artifacts.push(packageArtifact({
        kind: "rust",
        name: artifact.name,
        version: artifact.version,
        path: destination,
        outDir: absoluteOutDir,
      }));
    }
    const rustPublishMetadataPath = join(rustDir, "rust-publish-metadata-v1.json");
    writeRustPublishMetadata(
      rustPublishMetadataPath,
      version,
      sourceCommit,
    );
    verifyRustPublishMetadata(rustPublishMetadataPath, { version, sourceCommit });
  } finally {
    rustBuild.cleanup();
    rmSync(rustBuild.temporaryRoot, { recursive: true, force: true });
  }

  artifacts.sort((left, right) => artifactKey(left).localeCompare(artifactKey(right)));
  const manifest = {
    schema_version: buildSchemaVersion,
    platform_version: version,
    source_commit: sourceCommit,
    contract_set_sha256: platformPackageSet.contract_set_sha256,
    artifacts,
  };
  const manifestPath = join(absoluteOutDir, "platform-package-build-v1.json");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  verifyPlatformPackageBuild(manifestPath);
  return Object.freeze({ outDir: absoluteOutDir, manifestPath, manifest });
}

function writeRustPublishMetadata(path, version, sourceCommit) {
  const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--locked", "--format-version", "1", "--no-deps"], {
    cwd: root,
    env: { ...process.env, GOWORK: "off" },
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  }));
  const packageNames = rustSourcePackages.map(({ name }) => name);
  const packages = packageNames.map((name) => {
    const pkg = metadata.packages.find((candidate) => candidate.name === name && candidate.version === version);
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
  writeFileSync(path, `${JSON.stringify({
    schema_version: "redevplugin.rust_publish_metadata.v1",
    source_commit: sourceCommit,
    packages,
  }, null, 2)}\n`, { flag: "wx" });
}

export function verifyRustPublishMetadata(path, { version, sourceCommit }) {
  assertVersion(version);
  assertCommit(sourceCommit);
  const metadata = parseStrictJSON(readFileSync(path), "Rust publication metadata", 128 * 1024);
  exactKeys(metadata, ["schema_version", "source_commit", "packages"], "Rust publication metadata");
  if (metadata.schema_version !== "redevplugin.rust_publish_metadata.v1"
      || metadata.source_commit !== sourceCommit) {
    throw new Error("Rust publication metadata identity mismatch");
  }
  if (!Array.isArray(metadata.packages) || metadata.packages.length !== rustSourcePackages.length) {
    throw new Error("Rust publication metadata package set is incomplete");
  }
  const internalDependencies = new Map([
    ["redevplugin-ipc", new Map([["redevplugin-contracts", "dev"]])],
    ["redevplugin-target-classifier", new Map([["redevplugin-contracts", "dev"]])],
    ["redevplugin-runtime", new Map([
      ["redevplugin-ipc", "normal"],
      ["redevplugin-wasm-abi", "normal"],
    ])],
  ]);
  const firstPartyNames = new Set(rustSourcePackages.map(({ name }) => name));
  for (let index = 0; index < rustSourcePackages.length; index += 1) {
    const pkg = metadata.packages[index];
    exactKeys(pkg, [
      "name", "vers", "deps", "features", "authors", "description", "documentation",
      "homepage", "readme", "readme_file", "keywords", "categories", "license", "license_file",
      "repository", "badges", "links", "rust_version",
    ], `Rust publication package ${index}`);
    const expectedName = rustSourcePackages[index].name;
    if (pkg.name !== expectedName || pkg.vers !== version || pkg.readme_file !== "README.md"
        || pkg.license !== "MIT" || pkg.repository !== "https://github.com/floegence/redevplugin"
        || pkg.rust_version !== rustToolchain || !isNonEmptyString(pkg.description, 1_024)
        || !isNonEmptyString(pkg.readme, 128 * 1024)
        || !isNullableString(pkg.documentation, 2_048) || !isNullableString(pkg.homepage, 2_048)
        || !isNullableString(pkg.license_file, 256) || !isNullableString(pkg.links, 256)) {
      throw new Error(`Rust publication metadata identity is invalid for ${expectedName}`);
    }
    assertStringArray(pkg.authors, 64, `Rust publication ${expectedName} authors`);
    assertStringArray(pkg.keywords, 16, `Rust publication ${expectedName} keywords`);
    assertStringArray(pkg.categories, 16, `Rust publication ${expectedName} categories`);
    if (!isClosedStringArrayMap(pkg.features) || !isEmptyObject(pkg.badges) || !Array.isArray(pkg.deps)) {
      throw new Error(`Rust publication metadata collections are invalid for ${expectedName}`);
    }
    const expectedInternal = internalDependencies.get(expectedName) ?? new Map();
    const actualInternal = new Map();
    const dependencyKeys = new Set();
    for (const dependency of pkg.deps) {
      exactKeys(dependency, [
        "name", "version_req", "features", "optional", "default_features",
        "target", "kind", "registry", "explicit_name_in_toml",
      ], `Rust publication dependency for ${expectedName}`);
      if (!isNonEmptyString(dependency.name, 128) || !isNonEmptyString(dependency.version_req, 256)
          || !["normal", "dev", "build"].includes(dependency.kind)
          || typeof dependency.optional !== "boolean" || typeof dependency.default_features !== "boolean"
          || !isNullableString(dependency.target, 512) || dependency.registry !== null
          || !isNullableString(dependency.explicit_name_in_toml, 128)) {
        throw new Error(`Rust publication dependency is invalid for ${expectedName}`);
      }
      assertStringArray(dependency.features, 128, `Rust publication ${expectedName} dependency features`);
      const dependencyKey = JSON.stringify([
        dependency.name, dependency.kind, dependency.target, dependency.explicit_name_in_toml,
      ]);
      if (dependencyKeys.has(dependencyKey)) throw new Error(`duplicate Rust publication dependency for ${expectedName}`);
      dependencyKeys.add(dependencyKey);
      if (firstPartyNames.has(dependency.name)) {
        if (dependency.version_req !== `=${version}` || dependency.optional
            || dependency.target !== null || dependency.explicit_name_in_toml !== null
            || expectedInternal.get(dependency.name) !== dependency.kind) {
          throw new Error(`Rust publication internal dependency is invalid for ${expectedName}`);
        }
        actualInternal.set(dependency.name, dependency.kind);
      }
    }
    if (JSON.stringify([...actualInternal]) !== JSON.stringify([...expectedInternal])) {
      throw new Error(`Rust publication internal dependency set is incomplete for ${expectedName}`);
    }
  }
  return metadata;
}

function isNonEmptyString(value, maximumLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maximumLength;
}

function isNullableString(value, maximumLength) {
  return value === null || (typeof value === "string" && value.length <= maximumLength);
}

function assertStringArray(value, maximumEntries, label) {
  if (!Array.isArray(value) || value.length > maximumEntries
      || value.some((item) => !isNonEmptyString(item, 512))
      || new Set(value).size !== value.length) {
    throw new Error(`${label} is invalid`);
  }
}

function isClosedStringArrayMap(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(([key, entries]) => isNonEmptyString(key, 128)
    && Array.isArray(entries) && entries.length <= 128
    && entries.every((entry) => isNonEmptyString(entry, 256))
    && new Set(entries).size === entries.length);
}

function isEmptyObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;
}

export function verifyPlatformPackageBuild(manifestPath, { verifyArchives = true } = {}) {
  const absoluteManifestPath = resolve(manifestPath);
  const outDir = dirname(absoluteManifestPath);
  const manifest = parseStrictJSON(readFileSync(absoluteManifestPath), "platform package build manifest");
  exactKeys(manifest, [
    "schema_version",
    "platform_version",
    "source_commit",
    "contract_set_sha256",
    "artifacts",
  ], "platform package build manifest");
  if (manifest.schema_version !== buildSchemaVersion) throw new Error("unsupported platform package build schema");
  assertVersion(manifest.platform_version);
  assertCommit(manifest.source_commit);
  assertSHA256(manifest.contract_set_sha256, "platform package build contract digest");

  const packageSet = parseStrictJSON(
    readFileSync(join(root, "spec/plugin/platform-package-set-v1.json")),
    "platform package set",
  );
  if (manifest.platform_version !== packageSet.platform_version
      || manifest.contract_set_sha256 !== packageSet.contract_set_sha256) {
    throw new Error("platform package build does not match the active package set");
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 8) {
    throw new Error("platform package build must contain exactly eight package artifacts");
  }

  const expected = new Map([
    ...npmCoordinates.map((coordinate) => [
      `npm:${coordinate.name}`,
      `npm/${coordinate.filenamePrefix}${manifest.platform_version}.tgz`,
    ]),
    ...rustSourcePackages.map((coordinate) => [
      `rust:${coordinate.name}`,
      `rust/${coordinate.name}-${manifest.platform_version}.crate`,
    ]),
  ]);
  const seen = new Set();
  let previousArtifactKey = "";
  for (const artifact of manifest.artifacts) {
    exactKeys(artifact, artifact.kind === "npm"
      ? ["kind", "name", "version", "path", "size", "sha256", "integrity", "sha512"]
      : ["kind", "name", "version", "path", "size", "sha256"], "platform package artifact");
    const key = `${artifact.kind}:${artifact.name}`;
    if (seen.has(key) || !expected.has(key)) throw new Error(`unexpected or duplicate package artifact ${key}`);
    if (previousArtifactKey !== "" && previousArtifactKey.localeCompare(key) >= 0) {
      throw new Error("platform package artifacts are not canonically ordered");
    }
    previousArtifactKey = key;
    seen.add(key);
    if (artifact.version !== manifest.platform_version || artifact.path !== expected.get(key)) {
      throw new Error(`package artifact coordinate mismatch for ${key}`);
    }
    assertSafeRelativePath(artifact.path);
    const path = resolve(outDir, artifact.path);
    assertContainedRegularFile(outDir, path, artifact.path);
    const bytes = readFileSync(path);
    if (!Number.isSafeInteger(artifact.size) || artifact.size !== bytes.length || artifact.size < 1) {
      throw new Error(`package artifact size mismatch for ${key}`);
    }
    assertSHA256(artifact.sha256, `${key} sha256`);
    if (sha256(bytes) !== artifact.sha256) throw new Error(`package artifact sha256 mismatch for ${key}`);
    if (artifact.kind === "npm") {
      const sha512 = createHash("sha512").update(bytes).digest("hex");
      if (artifact.sha512 !== sha512
          || artifact.integrity !== `sha512-${Buffer.from(sha512, "hex").toString("base64")}`) {
        throw new Error(`npm package integrity mismatch for ${key}`);
      }
    }
    if (verifyArchives) verifyPackageArchive(path, artifact);
  }
  if (seen.size !== expected.size) throw new Error("platform package build is incomplete");
  return manifest;
}

function verifyPackageArchive(path, artifact) {
  const expectedRoot = artifact.kind === "npm" ? "package" : `${artifact.name}-${artifact.version}`;
  validateTarGzipArchive(path, { expectedRoot, label: `${artifact.name} package` });
  const packageJSON = artifact.kind === "npm" ? readArchiveJSON(path, "package/package.json") : undefined;
  if (packageJSON) {
    if (packageJSON.name !== artifact.name || packageJSON.version !== artifact.version) {
      throw new Error(`${artifact.name} npm package identity mismatch`);
    }
    if (artifact.name === "@floegence/redevplugin-ui") {
      const expectedDependencies = { "@floegence/redevplugin-contracts": artifact.version };
      if (JSON.stringify(packageJSON.dependencies) !== JSON.stringify(expectedDependencies)) {
        throw new Error("UI npm package must pin the exact contracts package version");
      }
    }
  }
  if (artifact.kind === "rust") {
    const cargoManifest = execFileSync("tar", ["-xOzf", path, `${expectedRoot}/Cargo.toml`], {
      encoding: "utf8",
      maxBuffer: 2 * 1024 * 1024,
    });
    if (!cargoManifest.includes(`name = "${artifact.name}"`)
        || !cargoManifest.includes(`version = "${artifact.version}"`)
        || /^\s*\[(?:patch|replace)(?:\.|\])/m.test(cargoManifest)) {
      throw new Error(`${artifact.name} packaged Cargo manifest is invalid`);
    }
  }
}

function readArchiveJSON(path, member) {
  const raw = execFileSync("tar", ["-xOzf", path, member], {
    maxBuffer: 2 * 1024 * 1024,
  });
  return parseStrictJSON(raw, member, 2 * 1024 * 1024);
}

function packageArtifact({ kind, name, version, path, outDir, includeIntegrity = false }) {
  const bytes = readFileSync(path);
  const result = {
    kind,
    name,
    version,
    path: relative(outDir, path).split(sep).join("/"),
    size: bytes.length,
    sha256: sha256(bytes),
  };
  if (includeIntegrity) {
    result.integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    result.sha512 = createHash("sha512").update(bytes).digest("hex");
  }
  return result;
}

function artifactKey(artifact) {
  return `${artifact.kind}:${artifact.name}`;
}

function validateBuildInputs({ outDir, version, sourceCommit }) {
  if (typeof outDir !== "string" || outDir.length === 0) throw new Error("package output directory is required");
  assertVersion(version);
  assertCommit(sourceCommit);
}

function assertCleanSource() {
  const result = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0 || result.stdout !== "") {
    throw new Error("release package build requires a clean source tree");
  }
}

function run(command, args, label) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: { ...process.env, GOWORK: "off" },
    encoding: "utf8",
    stdio: "inherit",
  });
  if (result.status !== 0) throw new Error(`${label} failed`);
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}

function assertSafeRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || path.length > 256
      || path.startsWith("/") || path.includes("\\") || path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`unsafe package artifact path ${path}`);
  }
}

function assertContainedRegularFile(parent, path, label) {
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} must be a regular file`);
  const parentRealPath = realpathSync(parent);
  const fileRealPath = realpathSync(path);
  const rel = relative(parentRealPath, fileRealPath);
  if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) throw new Error(`${label} escapes the package root`);
  if (statSync(path).size > 32 * 1024 * 1024) throw new Error(`${label} exceeds the package size limit`);
}

function assertVersion(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error("platform package version must be stable SemVer");
  }
}

function assertCommit(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new Error("source commit is invalid");
}

function assertSHA256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} is invalid`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "verify" && args.length === 1) {
    verifyPlatformPackageBuild(args[0]);
    console.log("platform package build verified");
    return;
  }
  if (command === "build") {
    const options = parseBuildArgs(args);
    const result = await buildPlatformPackages(options);
    console.log(result.manifestPath);
    return;
  }
  console.error("usage: platform_package_build.mjs build --out-dir DIR --version X.Y.Z --source-commit OID [--require-clean]");
  console.error("       platform_package_build.mjs verify MANIFEST");
  process.exit(2);
}

function parseBuildArgs(args) {
  const options = { requireClean: false };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--require-clean") {
      options.requireClean = true;
      continue;
    }
    const key = { "--out-dir": "outDir", "--version": "version", "--source-commit": "sourceCommit" }[argument];
    if (!key || index + 1 >= args.length) throw new Error(`unknown or incomplete argument ${argument}`);
    options[key] = args[++index];
  }
  return options;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
