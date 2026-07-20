#!/usr/bin/env node

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { validateTarGzipArchive } from "./archive_contract.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [version, rawOutputDirectory] = process.argv.slice(2);
const releaseVersionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$/;

if (!releaseVersionPattern.test(version ?? "") || !rawOutputDirectory) {
  console.error("usage: build_redevplugin_worker_sdk_package.mjs <version> <output-directory>");
  process.exit(2);
}

const outputDirectory = resolve(rawOutputDirectory);
const sourceDirectory = join(root, "crates", "redevplugin-worker-sdk");
const baseCargoEnvironment = {
  ...process.env,
  PATH: `${join(homedir(), ".cargo", "bin")}:${process.env.PATH ?? ""}`,
};
const toolchainResult = spawnSync("rustup", ["show", "active-toolchain"], {
  cwd: root,
  env: baseCargoEnvironment,
  encoding: "utf8",
});
if (toolchainResult.status !== 0) {
  throw new Error(`rustup show active-toolchain failed: ${toolchainResult.stderr || toolchainResult.stdout || toolchainResult.error}`);
}
const activeToolchain = toolchainResult.stdout.trim().split(/\s+/, 1)[0];
if (!/^[A-Za-z0-9_.-]+$/.test(activeToolchain ?? "")) {
  throw new Error("rustup returned an invalid active toolchain");
}
const cargoEnvironment = {
  ...baseCargoEnvironment,
  RUSTUP_TOOLCHAIN: activeToolchain,
};
const metadataResult = runCargo(["metadata", "--format-version", "1", "--no-deps"]);
const metadata = JSON.parse(metadataResult.stdout);
const workerSDK = metadata.packages.find((pkg) => pkg.name === "redevplugin-worker-sdk");
if (!workerSDK || resolve(workerSDK.manifest_path) !== join(sourceDirectory, "Cargo.toml")) {
  throw new Error("workspace metadata does not contain the canonical ReDevPlugin worker SDK package");
}

const tempDirectory = mkdtempSync(join(tmpdir(), "redevplugin-worker-sdk-pack-"));
const packageDirectory = join(tempDirectory, "redevplugin-worker-sdk");
const targetDirectory = join(tempDirectory, "target");

try {
  mkdirSync(packageDirectory, { recursive: true });
  cpSync(join(sourceDirectory, "src"), join(packageDirectory, "src"), { recursive: true });
  cpSync(join(root, "LICENSE"), join(packageDirectory, "LICENSE"));

  const sourceReadme = readFileSync(join(sourceDirectory, "README.md"), "utf8");
  if (!sourceReadme.includes(`redevplugin-worker-sdk = "=${workerSDK.version}"`) ||
      /\bgit\s*=|GitHub Release/.test(sourceReadme)) {
    throw new Error("worker SDK source README must document only the exact registry dependency");
  }
  const legacyReadme = `${sourceReadme.replaceAll(workerSDK.version, version)}

## Legacy Release Bundle

This transitional bundle is tied to the immutable source release:

\`\`\`toml
redevplugin-worker-sdk = { git = "https://github.com/floegence/redevplugin", tag = "v${version}" }
\`\`\`

The bundled source archive is \`redevplugin-worker-sdk-${version}.crate\`.
`;
  writeFileSync(
    join(packageDirectory, "README.md"),
    legacyReadme,
  );

  const manifestPath = join(packageDirectory, "Cargo.toml");
  let temporaryManifest = readFileSync(join(sourceDirectory, "Cargo.toml"), "utf8");
  for (const [inherited, concrete] of [
    ["version.workspace = true", `version = "${version}"\npublish = false`],
    ["edition.workspace = true", `edition = ${JSON.stringify(workerSDK.edition)}`],
    ["license.workspace = true", `license = ${JSON.stringify(workerSDK.license)}`],
    ["repository.workspace = true", `repository = ${JSON.stringify(workerSDK.repository)}`],
    ["rust-version.workspace = true", `rust-version = ${JSON.stringify(workerSDK.rust_version)}`],
  ]) {
    const lines = temporaryManifest.split("\n");
    const indexes = lines.flatMap((line, index) => line === inherited ? [index] : []);
    if (indexes.length !== 1) {
      throw new Error(`worker SDK manifest must contain one ${inherited} entry`);
    }
    lines[indexes[0]] = concrete;
    temporaryManifest = lines.join("\n");
  }
  writeFileSync(manifestPath, temporaryManifest);

  const lockPath = join(packageDirectory, "Cargo.lock");
  const sourceLock = readFileSync(join(root, "Cargo.lock"), "utf8");
  const sourceLockEntry = `[[package]]\nname = "redevplugin-worker-sdk"\nversion = "${workerSDK.version}"`;
  if (sourceLock.split(sourceLockEntry).length !== 2) {
    throw new Error("workspace lock must contain one canonical worker SDK package entry");
  }
  writeFileSync(lockPath, sourceLock.replace(sourceLockEntry, `[[package]]\nname = "redevplugin-worker-sdk"\nversion = "${version}"`));

  const packageCargoEnvironment = {
    ...cargoEnvironment,
    CARGO_HOME: join(tempDirectory, "cargo-home"),
  };
  const packageOptions = {
    cwd: packageDirectory,
    env: { ...packageCargoEnvironment, CARGO_TARGET_DIR: targetDirectory },
  };
  runCargo([
    "update",
    "--manifest-path",
    manifestPath,
    "--package",
    `redevplugin-worker-sdk@${version}`,
    "--precise",
    version,
  ], packageOptions);
  runCargo([
    "package",
    "--manifest-path",
    manifestPath,
    "--allow-dirty",
    "--locked",
    "--no-verify",
  ], packageOptions);

  const filename = `redevplugin-worker-sdk-${version}.crate`;
  const packagedPath = join(targetDirectory, "package", filename);
  const packageRootName = `redevplugin-worker-sdk-${version}`;
  const packageRoot = `${packageRootName}/`;
  const archiveEntries = validateTarGzipArchive(packagedPath, {
    expectedRoot: packageRootName,
    label: "worker SDK crate",
  });
  const requiredEntries = new Set([
    `${packageRoot}Cargo.lock`,
    `${packageRoot}Cargo.toml`,
    `${packageRoot}Cargo.toml.orig`,
    `${packageRoot}LICENSE`,
    `${packageRoot}README.md`,
    `${packageRoot}src/lib.rs`,
  ]);
  for (const entry of archiveEntries) {
    if (!entry.startsWith(packageRoot) || entry.includes("\\") || entry.split("/").includes("..")) {
      throw new Error(`worker SDK crate contains unsafe path ${entry}`);
    }
    requiredEntries.delete(entry);
  }
  if (requiredEntries.size !== 0) {
    throw new Error(`worker SDK crate is missing ${[...requiredEntries].sort().join(", ")}`);
  }

  const unpackDirectory = join(tempDirectory, "unpacked");
  mkdirSync(unpackDirectory, { recursive: true });
  run("tar", ["-xzf", packagedPath, "-C", unpackDirectory]);
  runCargo([
    "check",
    "--locked",
    "--target",
    "wasm32-unknown-unknown",
  ], {
    cwd: join(unpackDirectory, packageRootName),
    env: { ...packageCargoEnvironment, CARGO_TARGET_DIR: join(tempDirectory, "unpacked-target") },
  });

  mkdirSync(outputDirectory, { recursive: true });
  const outputPath = join(outputDirectory, filename);
  rmSync(outputPath, { force: true });
  cpSync(packagedPath, outputPath);
  process.stdout.write(`${outputPath}\n`);
} finally {
  rmSync(tempDirectory, { recursive: true, force: true });
}

function runCargo(args, options = {}) {
  return run("cargo", args, { cwd: root, env: cargoEnvironment, ...options });
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: cargoEnvironment,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${basename(command)} ${args.join(" ")} failed: ${result.stderr || result.stdout || result.error}`);
  }
  return result;
}
