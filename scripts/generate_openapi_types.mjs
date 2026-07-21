import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { parse as parseYAML, stringify as stringifyYAML } from "yaml";

const root = resolve(import.meta.dirname, "..");
const source = join(root, "spec/openapi/plugin-platform-v8.yaml");
const output = join(root, "packages/redevplugin-ui/src/openapi.gen.ts");
const check = process.argv.includes("--check");
const generated = check
  ? join(tmpdir(), `redevplugin-openapi-${process.pid}-${Date.now()}.ts`)
  : `${output}.tmp`;
const bundledSource = join(tmpdir(), `redevplugin-openapi-bundled-${process.pid}-${Date.now()}.yaml`);
const schemaMetadata = new Set(["$schema", "$id", "$anchor", "$dynamicAnchor", "$comment", "title"]);

const openAPI = parseYAML(await readFile(source, "utf8"));
const bundledOpenAPI = await bundleExternalSchemas(openAPI);
await writeFile(bundledSource, stringifyYAML(bundledOpenAPI));

const cli = join(root, "node_modules/openapi-typescript/bin/cli.js");
const result = spawnSync(process.execPath, [cli, bundledSource, "--output", generated], {
  cwd: root,
  encoding: "utf8",
  stdio: "pipe",
});
await rm(bundledSource, { force: true });

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

async function bundleExternalSchemas(document) {
  const bundled = structuredClone(document);
  const components = bundled.components ?? (bundled.components = {});
  const schemas = components.schemas ?? (components.schemas = {});
  const bundledFiles = new Map();
  async function loadExternal(filename) {
    filename = resolve(filename);
    if (!filename.startsWith(`${root}/spec/plugin/`)) {
      throw new Error(`external OpenAPI schema escapes the plugin schema directory: ${filename}`);
    }
    const existing = bundledFiles.get(filename);
    if (existing) return existing;
    const namespace = schemaNamespace(filename);
    bundledFiles.set(filename, namespace);
    const external = JSON.parse(await readFile(filename, "utf8"));
    schemas[namespace] = {};
    const baseDir = resolve(filename, "..");
    const definitions = external.$defs;
    if (definitions && typeof definitions === "object" && !Array.isArray(definitions)) {
      for (const [name, definition] of Object.entries(definitions)) {
        schemas[`${namespace}${pascalCase(name)}`] = await rewriteSchema(definition, namespace, baseDir);
      }
    }
    schemas[namespace] = await rewriteSchema(external, namespace, baseDir);
    return namespace;
  }

  async function rewriteSchema(value, namespace, baseDir) {
    if (Array.isArray(value)) return Promise.all(value.map((item) => rewriteSchema(item, namespace, baseDir)));
    if (!value || typeof value !== "object") return value;
    if (typeof value.$ref === "string") {
      const reference = value.$ref;
      if (reference.startsWith("#/$defs/")) {
        return { $ref: `#/components/schemas/${namespace}${pascalCase(reference.slice("#/$defs/".length))}` };
      }
      if (reference.endsWith(".schema.json") || reference.includes(".schema.json#")) {
        const [referencePath, fragment = ""] = reference.split("#", 2);
        const childNamespace = await loadExternal(resolve(baseDir, referencePath));
        return { $ref: fragment.startsWith("/$defs/")
          ? `#/components/schemas/${childNamespace}${pascalCase(fragment.slice("/$defs/".length))}`
          : `#/components/schemas/${childNamespace}` };
      }
    }
    const result = {};
    for (const [key, child] of Object.entries(value)) {
      if (schemaMetadata.has(key) || key === "$defs") continue;
      result[key] = await rewriteSchema(child, namespace, baseDir);
    }
    return result;
  }

  async function rewriteDocument(value, baseDir) {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) value[index] = await rewriteDocument(value[index], baseDir);
      return value;
    }
    if (!value || typeof value !== "object") return value;
    if (typeof value.$ref === "string" && value.$ref.startsWith("../plugin/")) {
      const [referencePath, fragment = ""] = value.$ref.split("#", 2);
      const namespace = await loadExternal(resolve(baseDir, referencePath));
      return { $ref: fragment.startsWith("/$defs/")
        ? `#/components/schemas/${namespace}${pascalCase(fragment.slice("/$defs/".length))}`
        : `#/components/schemas/${namespace}` };
    }
    for (const [key, child] of Object.entries(value)) value[key] = await rewriteDocument(child, baseDir);
    return value;
  }

  await rewriteDocument(bundled, resolve(root, "spec/openapi"));
  return bundled;
}

function schemaNamespace(filename) {
  const basename = filename.split("/").at(-1).replace(/\.schema\.json$/, "");
  return pascalCase(basename);
}

function pascalCase(value) {
  return value
    .split(/[^A-Za-z0-9]+/u)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}
