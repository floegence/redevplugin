import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = new URL("../packages/redevplugin-ui/", import.meta.url);
// A removed public module must never survive in a subsequent npm archive.
rmSync(new URL("dist/", root), { recursive: true, force: true });
const compiler = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));
const result = spawnSync(process.execPath, [compiler, "-p", "tsconfig.json"], { cwd: root, stdio: "inherit" });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
