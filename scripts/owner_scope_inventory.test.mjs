#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parseStrictJSON } from "./generate_platform_package_contracts.mjs";
import { validateRegistry } from "./generate_owner_scope_inventories.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const raw = readFileSync(join(root, "spec/plugin/owner-scope-inventories-v1.json"));
const registry = parseStrictJSON(raw, "owner scope inventory registry", 1024 * 1024);

function clone(value) {
  return structuredClone(value);
}

function rejected(value) {
  assert.throws(() => validateRegistry(value));
}

test("owner scope inventory registry is closed, canonical, and non-overlapping", () => {
  validateRegistry(registry);
  assert.equal(raw.toString("utf8"), `${JSON.stringify(registry, null, 2)}\n`);
  assert.deepEqual(
    registry.inventories.flatMap(({ platform_versions: versions }) => versions),
    [
      "0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6",
      "0.2.0", "0.2.1", "0.2.2", "0.3.0", "0.3.1", "0.3.2",
      "0.4.0", "0.4.1", "0.4.2", "0.4.3", "0.5.0", "0.5.1",
      "0.6.5",
    ],
  );
});

test("owner scope inventory parser rejects duplicate and oversized JSON", () => {
  const duplicate = Buffer.from(raw.toString("utf8").replace(
    '"schema_version": "owner-scope-inventory-v1",',
    '"schema_version": "owner-scope-inventory-v1",\n  "schema_version": "owner-scope-inventory-v1",',
  ));
  assert.throws(() => parseStrictJSON(duplicate, "duplicate inventory", 1024 * 1024));
  assert.throws(() => parseStrictJSON(Buffer.alloc(1024 * 1024 + 1, 0x20), "oversized inventory", 1024 * 1024));
});

test("owner scope inventory validation rejects open, unsafe, unsorted, and stale values", () => {
  const unknown = clone(registry);
  unknown.inventories[0].unknown = true;
  rejected(unknown);

  const traversal = clone(registry);
  traversal.inventories[0].sqlite_databases[0].path = "db/../registry.sqlite";
  rejected(traversal);

  const unsortedInventories = clone(registry);
  [unsortedInventories.inventories[0], unsortedInventories.inventories[1]] = [unsortedInventories.inventories[1], unsortedInventories.inventories[0]];
  rejected(unsortedInventories);

  const unsortedDatabases = clone(registry);
  [unsortedDatabases.inventories[0].sqlite_databases[0], unsortedDatabases.inventories[0].sqlite_databases[1]] = [
    unsortedDatabases.inventories[0].sqlite_databases[1],
    unsortedDatabases.inventories[0].sqlite_databases[0],
  ];
  rejected(unsortedDatabases);

  const unsortedSchema = clone(registry);
  [unsortedSchema.inventories[0].sqlite_databases[0].schema_objects[0], unsortedSchema.inventories[0].sqlite_databases[0].schema_objects[1]] = [
    unsortedSchema.inventories[0].sqlite_databases[0].schema_objects[1],
    unsortedSchema.inventories[0].sqlite_databases[0].schema_objects[0],
  ];
  rejected(unsortedSchema);

  const staleDigest = clone(registry);
  staleDigest.inventories[0].sqlite_databases[0].schema_sha256 = "0".repeat(64);
  rejected(staleDigest);

  const optionalDatabase = clone(registry);
  optionalDatabase.inventories.at(-1).tree_rules.optional_files = ["db/unfingerprinted.sqlite"];
  rejected(optionalDatabase);

  const missingRequiredDatabaseRoot = clone(registry);
  missingRequiredDatabaseRoot.inventories.at(-1).root_entries.find(({ path }) => path === "db").required = false;
  rejected(missingRequiredDatabaseRoot);

  const mismatchedVariableTrees = clone(registry);
  mismatchedVariableTrees.inventories.at(-1).tree_rules.variable_trees.pop();
  rejected(mismatchedVariableTrees);

  const invalidRequiredFlag = clone(registry);
  invalidRequiredFlag.inventories.at(-1).sqlite_databases[0].required = "false";
  rejected(invalidRequiredFlag);

  const tooManyDatabases = clone(registry);
  tooManyDatabases.inventories[0].sqlite_databases = Array.from({ length: 65 }, (_, index) => ({
    ...clone(registry.inventories[0].sqlite_databases[0]),
    path: `db/store_${String(index).padStart(2, "0")}.sqlite`,
  }));
  rejected(tooManyDatabases);
});
