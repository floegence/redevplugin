import { readFile, writeFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const schema = JSON.parse(await readFile(new URL("spec/plugin/manifest-v9.schema.json", root), "utf8"));
schema.$id = "https://schemas.redevplugin.dev/plugin-api/1/stored-manifest.schema.json";
schema.title = "Stored plugin manifest identity";
schema.description = "Read-only installed and historical package identity. Pre-Web surfaces have no web declaration and cannot execute. New package admission uses manifest-v9.schema.json exclusively.";
const surface = schema.properties.surfaces.items;
surface.required = surface.required.filter((field) => field !== "web");
schema.properties.surfaces.allOf = [{ anyOf: [
 { items: { required: ["web"] } },
 { items: { not: { required: ["web"] } } },
] }];
const expected = JSON.stringify(schema, null, 2) + String.fromCharCode(10);
const output = new URL("spec/plugin/stored-manifest.schema.json", root);
if (process.argv.includes("--check")) {
 if (await readFile(output, "utf8") !== expected) throw new Error("Stored manifest projection is stale; run npm run stored-manifest:generate");
} else { await writeFile(output, expected); }
