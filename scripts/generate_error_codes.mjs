import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const contractSource = JSON.parse(await readFile(join(root, "internal/contracts/active-contracts.json"), "utf8"));
const errorCodeContract = contractSource.artifacts.find((artifact) => artifact.id === "error-codes-schema");
if (!errorCodeContract || typeof errorCodeContract.path !== "string") {
  throw new Error("active error code contract is missing");
}
const source = join(root, errorCodeContract.path);
const output = join(root, "packages/redevplugin-ui/src/error-codes.gen.ts");
const check = process.argv.includes("--check");
const generated = check
  ? join(tmpdir(), `redevplugin-error-codes-${process.pid}-${Date.now()}.ts`)
  : `${output}.tmp`;

const schema = JSON.parse(await readFile(source, "utf8"));
const definitions = schema.$defs ?? {};
const groups = [
  ["pluginPlatformErrorCodes", "platform_error_code"],
  ["pluginBridgeErrorCodes", "bridge_error_code"],
  ["pluginClientErrorCodes", "typescript_client_error_code"],
  ["runtimeProcessFailureCodes", "runtime_process_failure_code"],
];

let contents = `// Generated from ${errorCodeContract.path}. Do not edit.\n\n`;
for (const [exportName, definitionName] of groups) {
  const values = definitions[definitionName]?.enum;
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    throw new Error(`error code definition ${definitionName} is invalid`);
  }
  contents += `export const ${exportName} = ${JSON.stringify(values, null, 2)} as const;\n\n`;
}
contents = `${contents.trimEnd()}\n`;

await writeFile(generated, contents);

if (check) {
  const expected = await readFile(output, "utf8").catch(() => "");
  await rm(generated, { force: true });
  if (contents !== expected) {
    process.stderr.write("Generated TypeScript error codes are stale; run npm run error-codes:generate.\n");
    process.exit(1);
  }
} else {
  await rename(generated, output);
}
