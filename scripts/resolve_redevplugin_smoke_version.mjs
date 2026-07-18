import { readFileSync } from "node:fs";

const [suffix = "ci.local"] = process.argv.slice(2);
if (!/^[0-9A-Za-z.-]+$/.test(suffix) || suffix.startsWith(".") || suffix.endsWith(".")) {
  throw new Error(`invalid smoke version suffix: ${JSON.stringify(suffix)}`);
}
const match = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8").match(/^## v([^\s]+)$/m);
if (!match || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(match[1])) {
  throw new Error("CHANGELOG.md must start with a stable semantic version heading");
}
process.stdout.write(`${match[1]}-${suffix}`);
