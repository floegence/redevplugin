import { rmSync } from "node:fs";
import { resolve } from "node:path";

export function cleanTypeScriptTestOutput(directory) {
  if (typeof directory !== "string" || directory.trim() === "") {
    throw new Error("TypeScript test output directory is required");
  }
  const output = resolve(directory);
  if (!output.endsWith(`${process.platform === "win32" ? "\\" : "/"}dist-test`)) {
    throw new Error("TypeScript test output must be a dist-test directory");
  }
  rmSync(output, { recursive: true, force: true });
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  cleanTypeScriptTestOutput(process.argv[2]);
}
