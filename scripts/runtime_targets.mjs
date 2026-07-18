#!/usr/bin/env node

import { pathToFileURL } from "node:url";

export const runtimeTargets = Object.freeze([
  Object.freeze({ platformTarget: "linux/amd64", os: "linux", arch: "amd64", buildTriple: "x86_64-unknown-linux-gnu", format: "elf", machine: 62 }),
  Object.freeze({ platformTarget: "linux/arm64", os: "linux", arch: "arm64", buildTriple: "aarch64-unknown-linux-gnu", format: "elf", machine: 183 }),
  Object.freeze({ platformTarget: "darwin/amd64", os: "darwin", arch: "amd64", buildTriple: "x86_64-apple-darwin", format: "macho", machine: 0x01000007 }),
  Object.freeze({ platformTarget: "darwin/arm64", os: "darwin", arch: "arm64", buildTriple: "aarch64-apple-darwin", format: "macho", machine: 0x0100000c }),
]);

export function runtimeTargetForPlatform(platformTarget) {
  const target = runtimeTargets.find((candidate) => candidate.platformTarget === platformTarget);
  if (!target) throw new Error(`unsupported runtime platform target ${platformTarget}`);
  return target;
}

export function runtimeTargetForBuildTriple(buildTriple) {
  const target = runtimeTargets.find((candidate) => candidate.buildTriple === buildTriple);
  if (!target) throw new Error(`unsupported runtime build triple ${buildTriple}`);
  return target;
}

export function runtimeTargetPayloadForPlatform(platformTarget) {
  const target = runtimeTargetForPlatform(platformTarget);
  return { os: target.os, arch: target.arch };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, value] = process.argv.slice(2);
  if (command !== "--platform-for-build" || !value || process.argv.length !== 4) {
    process.stderr.write("usage: runtime_targets.mjs --platform-for-build <rust-build-triple>\n");
    process.exit(2);
  }
  try {
    process.stdout.write(runtimeTargetForBuildTriple(value).platformTarget);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
