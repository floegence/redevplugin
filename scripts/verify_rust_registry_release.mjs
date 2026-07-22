#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { validateTarGzipArchive } from "./archive_contract.mjs";
import { parseStrictJSON } from "./generate_platform_package_contracts.mjs";
import { rustSourcePackages } from "./rust_source_packages.mjs";

const maxIndexBytes = 8 * 1024 * 1024;
const maxCrateBytes = 16 * 1024 * 1024;

export async function verifyRustRegistryRelease({
  version,
  sourceCommit,
  indexBaseURL = "https://index.crates.io",
  crateBaseURL = "https://static.crates.io/crates",
  fetchImpl = globalThis.fetch,
}) {
  assertVersion(version);
  assertCommit(sourceCommit);
  assertOrigin(indexBaseURL, "index base URL");
  assertOrigin(crateBaseURL, "crate base URL", true);
  if (typeof fetchImpl !== "function") throw new Error("fetch implementation is required");

  const temporaryRoot = mkdtempSync(join(tmpdir(), "redevplugin-crates-readback-"));
  try {
    const results = [];
    for (const coordinate of rustSourcePackages) {
      const indexURL = new URL(`/${registryIndexPath(coordinate.name)}`, indexBaseURL);
      const indexBytes = await fetchBounded(fetchImpl, indexURL, maxIndexBytes, "crate index");
      const entry = selectIndexEntry(indexBytes, coordinate.name, version);
      const crateURL = new URL(
        `${coordinate.name}/${coordinate.name}-${version}.crate`,
        `${crateBaseURL.replace(/\/?$/, "/")}`,
      );
      const crateBytes = await fetchBounded(fetchImpl, crateURL, maxCrateBytes, "crate archive");
      const digest = createHash("sha256").update(crateBytes).digest("hex");
      if (digest !== entry.cksum) throw new Error(`${coordinate.name} registry checksum mismatch`);

      const archivePath = join(temporaryRoot, `${coordinate.name}-${version}.crate`);
      writeFileSync(archivePath, crateBytes, { flag: "wx" });
      const archiveRoot = `${coordinate.name}-${version}`;
      validateTarGzipArchive(archivePath, { expectedRoot: archiveRoot, label: `${coordinate.name} crate` });
      const vcsRaw = execFileSync("tar", ["-xOzf", archivePath, `${archiveRoot}/.cargo_vcs_info.json`], {
        maxBuffer: 256 * 1024,
      });
      verifyCargoVCSInfo(vcsRaw, {
        sourceCommit,
        pathInVCS: `crates/${coordinate.name}`,
      });
      results.push({
        name: coordinate.name,
        version,
        registry_checksum_sha256: digest,
        source_commit: sourceCommit,
      });
    }
    return results;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

export function selectIndexEntry(raw, name, version) {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  const matches = text.split("\n").filter(Boolean).map((line) => parseStrictJSON(line, "crate index line"))
    .filter((entry) => entry.name === name && entry.vers === version);
  if (matches.length !== 1) throw new Error(`${name}@${version} must have exactly one registry index entry`);
  const entry = matches[0];
  if (typeof entry.cksum !== "string" || !/^[0-9a-f]{64}$/.test(entry.cksum) || entry.yanked !== false) {
    throw new Error(`${name}@${version} registry entry is not consumable`);
  }
  return entry;
}

export function verifyCargoVCSInfo(raw, { sourceCommit, pathInVCS }) {
  const value = parseStrictJSON(raw, "Cargo VCS info", 64 * 1024);
  exactKeys(value, ["git", "path_in_vcs"], "Cargo VCS info");
  exactKeys(value.git, ["sha1"], "Cargo VCS git info");
  if (value.git.sha1 !== sourceCommit || value.path_in_vcs !== pathInVCS) {
    throw new Error("Cargo VCS source identity mismatch");
  }
  return value;
}

async function fetchBounded(fetchImpl, url, maxBytes, label) {
  let lastError;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (attempt > 0) await new Promise((resolveDelay) => setTimeout(resolveDelay, attempt * 500));
    try {
      const response = await fetchImpl(url, {
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
        headers: { Accept: "application/octet-stream" },
      });
      if (!response.ok) {
        if (response.status === 429 || response.status >= 500) throw new Error(`${label} returned HTTP ${response.status}`);
        throw new Error(`${label} returned terminal HTTP ${response.status}`);
      }
      const length = Number(response.headers.get("content-length") ?? "0");
      if (length > maxBytes) throw new Error(`${label} exceeds its size limit`);
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length < 1 || bytes.length > maxBytes) throw new Error(`${label} exceeds its size limit`);
      return bytes;
    } catch (error) {
      lastError = error;
      if (error instanceof Error && error.message.includes("terminal HTTP")) throw error;
    }
  }
  throw new Error(`${label} remained unavailable after bounded retries`, { cause: lastError });
}

function registryIndexPath(name) {
  const normalized = name.toLowerCase();
  if (normalized.length === 1) return `1/${normalized}`;
  if (normalized.length === 2) return `2/${normalized}`;
  if (normalized.length === 3) return `3/${normalized[0]}/${normalized}`;
  return `${normalized.slice(0, 2)}/${normalized.slice(2, 4)}/${normalized}`;
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}

function assertVersion(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(value)) {
    throw new Error("Rust release version must be stable SemVer");
  }
}

function assertCommit(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new Error("Rust release source commit is invalid");
}

function assertOrigin(value, label, allowPath = false) {
  const parsed = new URL(value);
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (!allowPath && parsed.pathname !== "/")) {
    throw new Error(`${label} must be an uncredentialed origin`);
  }
}

async function main() {
  const [version, sourceCommit, output] = process.argv.slice(2);
  if (!version || !sourceCommit || !output || process.argv.length !== 5) {
    console.error("usage: verify_rust_registry_release.mjs <version> <source-commit> <output-json>");
    process.exit(2);
  }
  const result = await verifyRustRegistryRelease({ version, sourceCommit });
  writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  console.log(`verified ${result.length} Rust source crates`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
