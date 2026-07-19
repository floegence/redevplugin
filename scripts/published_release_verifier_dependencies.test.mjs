import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import test from "node:test";

const scriptsRoot = import.meta.dirname;
const fixturePath = join(scriptsRoot, "test_published_release_verifier.mjs");

test("isolated published verifier copies its complete module dependency closure", () => {
  const fixtureSource = readFileSync(fixturePath, "utf8");
  const copiedScripts = new Set(
    [...fixtureSource.matchAll(/cpSync\(join\(root, "scripts", "([^"]+\.mjs)"\)/g)]
      .map((match) => match[1]),
  );

  for (const script of copiedScripts) {
    const source = readFileSync(join(scriptsRoot, script), "utf8");
    for (const match of source.matchAll(/from "(\.\/[^\"]+\.mjs)"/g)) {
      const dependency = basename(match[1]);
      assert.ok(copiedScripts.has(dependency), `${script} imports ${dependency}, but the isolated verifier does not copy it`);
    }
  }
});
