import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
const root = new URL("../", import.meta.url);
for (const [source, target] of [
  ["spec/plugin/data-upgrade.schema.json", "internal/dataupgradecontract/schema.gen.json"],
  ["spec/plugin/data-upgrade-fixtures.json", "crates/redevplugin-worker-sdk/testdata/data-upgrade-fixtures.json"],
]) {
  const expected = await readFile(new URL(source, root));
  if (process.argv.includes("--check")) {
    const actual = await readFile(new URL(target, root));
    if (!actual.equals(expected)) throw new Error(target + " differs from its canonical source; run npm run data-upgrade:generate");
  } else {
    const file = new URL(target, root);
    await mkdir(dirname(file.pathname), { recursive: true });
    await writeFile(file, expected);
  }
}
