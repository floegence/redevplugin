import assert from "node:assert/strict";
import test from "node:test";

import { selectIndexEntry, verifyCargoVCSInfo } from "./verify_rust_registry_release.mjs";

const name = "redevplugin-runtime";
const version = "0.6.0";
const sourceCommit = "1".repeat(40);

test("Rust registry index selection is exact and rejects yanked or ambiguous versions", () => {
  const entry = { name, vers: version, cksum: "a".repeat(64), yanked: false };
  assert.deepEqual(selectIndexEntry(Buffer.from(`${JSON.stringify(entry)}\n`), name, version), entry);
  assert.throws(() => selectIndexEntry(Buffer.from(`${JSON.stringify({ ...entry, yanked: true })}\n`), name, version));
  assert.throws(() => selectIndexEntry(Buffer.from(`${JSON.stringify(entry)}\n${JSON.stringify(entry)}\n`), name, version));
  assert.throws(() => selectIndexEntry(Buffer.from(`${JSON.stringify(entry).replace('"name"', '"name":"duplicate","name"')}\n`), name, version));
});

test("Cargo VCS info requires the exact clean source commit and crate path", () => {
  const value = {
    git: { sha1: sourceCommit, dirty: false },
    path_in_vcs: `crates/${name}`,
  };
  assert.deepEqual(verifyCargoVCSInfo(Buffer.from(JSON.stringify(value)), {
    sourceCommit,
    pathInVCS: `crates/${name}`,
  }), value);
  for (const mutate of [
    (candidate) => { candidate.git.sha1 = "2".repeat(40); },
    (candidate) => { candidate.git.dirty = true; },
    (candidate) => { candidate.path_in_vcs = "crates/other"; },
    (candidate) => { candidate.extra = true; },
  ]) {
    const candidate = structuredClone(value);
    mutate(candidate);
    assert.throws(() => verifyCargoVCSInfo(Buffer.from(JSON.stringify(candidate)), {
      sourceCommit,
      pathInVCS: `crates/${name}`,
    }));
  }
});
