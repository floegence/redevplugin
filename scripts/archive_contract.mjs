import { execFileSync } from "node:child_process";

const archivePathPattern = /^[A-Za-z0-9._/@+-]+\/?$/;

export function validateTarGzipArchive(archivePath, { expectedRoot, label }) {
  if (typeof expectedRoot !== "string" || !/^[A-Za-z0-9._@+-]+$/.test(expectedRoot)) {
    throw new Error(`${label} expected root is invalid`);
  }
  const entries = listTarEntries(archivePath, ["-tzf"], label);
  if (entries.length === 0) {
    throw new Error(`${label} must contain a non-empty archive`);
  }

  const seenPaths = new Set();
  const roots = new Set();
  for (const entry of entries) {
    if (!archivePathPattern.test(entry) || entry.startsWith("/") || entry.includes("\\")) {
      throw new Error(`${label} contains unsafe archive path ${JSON.stringify(entry)}`);
    }
    const directory = entry.endsWith("/");
    const path = directory ? entry.slice(0, -1) : entry;
    const segments = path.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error(`${label} contains unsafe archive path ${JSON.stringify(entry)}`);
    }
    if (seenPaths.has(path)) {
      throw new Error(`${label} contains duplicate archive path ${JSON.stringify(path)}`);
    }
    seenPaths.add(path);
    roots.add(segments[0]);
    if (segments.length === 1) {
      if (!directory) {
        throw new Error(`${label} contains top-level file ${JSON.stringify(entry)}`);
      }
    }
  }
  if (roots.size !== 1 || !roots.has(expectedRoot)) {
    throw new Error(`${label} must contain exactly one non-symlink archive root ${JSON.stringify(expectedRoot)}`);
  }

  const detailedEntries = listTarEntries(archivePath, ["-tvzf"], label);
  if (detailedEntries.length !== entries.length) {
    throw new Error(`${label} archive member listings disagree`);
  }
  for (const detail of detailedEntries) {
    const type = detail[0];
    if (type !== "-" && type !== "d") {
      throw new Error(`${label} must contain only regular files and directories`);
    }
  }
  return entries;
}

function listTarEntries(archivePath, args, label) {
  let output;
  try {
    output = execFileSync("tar", [...args, archivePath], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    throw new Error(`${label} cannot be inspected: ${error instanceof Error ? error.message : String(error)}`);
  }
  return output.split("\n").filter((entry) => entry.length > 0);
}
