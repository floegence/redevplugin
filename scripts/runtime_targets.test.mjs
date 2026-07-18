import assert from "node:assert/strict";
import test from "node:test";

import { runtimeTargetPayloadForPlatform } from "./runtime_targets.mjs";

test("Node x64 host aliases cannot change the canonical release hello target", () => {
  const nodeHost = { platform: "linux", arch: "x64" };
  const target = runtimeTargetPayloadForPlatform("linux/amd64");

  assert.equal(nodeHost.arch, "x64");
  assert.deepEqual(target, { os: "linux", arch: "amd64" });
  assert.notEqual(target.arch, nodeHost.arch);
});

test("release hello targets reject build triples and platform aliases", () => {
  for (const value of ["x86_64-unknown-linux-gnu", "linux/x64", "macos/arm64"]) {
    assert.throws(
      () => runtimeTargetPayloadForPlatform(value),
      new RegExp(`^Error: unsupported runtime platform target ${value.replaceAll("/", "\\/")}$`),
    );
  }
});
