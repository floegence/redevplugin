import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { verifyRustRegistryRelease } from "./rust_registry_release.mjs";
export * from "./rust_registry_release.mjs";

async function main() {
  const [version, sourceCommit, output] = process.argv.slice(2);
  if (!version || !sourceCommit || !output || process.argv.length !== 5) {
    console.error("usage: verify_rust_registry_release.mjs <version> <source-commit> <output-json>");
    process.exit(2);
  }
  const result = await verifyRustRegistryRelease({ version, sourceCommit });
  writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  console.log(`verified ${result.length} Rust source crates`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
