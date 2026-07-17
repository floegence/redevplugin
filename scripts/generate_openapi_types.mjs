import { readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const source = join(root, "spec/openapi/plugin-platform-v4.yaml");
const output = join(root, "packages/redevplugin-ui/src/openapi.gen.ts");
const check = process.argv.includes("--check");
const generated = check
  ? join(tmpdir(), `redevplugin-openapi-${process.pid}-${Date.now()}.ts`)
  : `${output}.tmp`;

const cli = join(root, "node_modules/openapi-typescript/bin/cli.js");
const result = spawnSync(process.execPath, [cli, source, "--output", generated], {
  cwd: root,
  encoding: "utf8",
  stdio: "pipe",
});

if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  await rm(generated, { force: true });
  process.exit(result.status ?? 1);
}

if (check) {
  const [actual, expected] = await Promise.all([
    readFile(generated, "utf8"),
    readFile(output, "utf8").catch(() => ""),
  ]);
  await rm(generated, { force: true });
  if (actual !== expected) {
    process.stderr.write("OpenAPI TypeScript output is stale; run npm run openapi:generate.\n");
    process.exit(1);
  }
} else {
  await rename(generated, output);
}
