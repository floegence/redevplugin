import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { parse as parseYAML } from "yaml";

const root = resolve(import.meta.dirname, "..");

async function readOpenAPI() {
  return parseYAML(await readFile(join(root, "spec/openapi/plugin-platform-v6.yaml"), "utf8"));
}

async function readIPCSchema() {
  return JSON.parse(await readFile(join(root, "spec/plugin/ipc-v4.schema.json"), "utf8"));
}

test("PatchSettingsRequest requires a non-empty set or remove object", async () => {
  const openAPI = await readOpenAPI();
  const schema = openAPI.components.schemas.PatchSettingsRequest;
  assert.equal(schema.type, "object");
  assert.deepEqual(schema.required, ["scope", "expected_values_revision"]);
  assert.equal(schema.minProperties, 3, "scope, expected revision, and at least one patch operation");
  assert.equal(schema.oneOf, undefined, "patch shape must not rely on a union that widens generated types");
  assert.equal(schema.properties.set.minProperties, 1);
  assert.equal(schema.properties.remove.minItems, 1);
});

test("settings routes and responses require a closed resource scope", async () => {
  const openAPI = await readOpenAPI();
  const paths = openAPI.paths;
  const schemaRoute = paths["/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema"].get;
  const settingsRoute = paths["/_redevplugin/api/plugins/{plugin_instance_id}/settings"].get;
  for (const route of [schemaRoute, settingsRoute]) {
    assert.deepEqual(route.parameters.at(-1), { $ref: "#/components/parameters/SettingsScope" });
  }
  assert.deepEqual(openAPI.components.parameters.SettingsScope, {
    name: "scope",
    in: "query",
    required: true,
    schema: { $ref: "#/components/schemas/ResourceScopeKind" },
  });
  assert.deepEqual(openAPI.components.schemas.ResourceScopeKind, {
    type: "string",
    enum: ["user", "environment"],
  });
  for (const name of ["PluginSettingsSchema", "PluginSettingsSnapshot"]) {
    assert.ok(openAPI.components.schemas[name].required.includes("scope"));
    assert.deepEqual(openAPI.components.schemas[name].properties.scope, { $ref: "#/components/schemas/ResourceScopeKind" });
  }
});

test("OpenAPI source keeps external schema references for structured bundling", async () => {
  const openAPI = await readOpenAPI();
  assert.equal(
    openAPI.components.schemas.CapabilityContractPin.$ref,
    "../plugin/host-capability-pin-v1.schema.json",
  );
});

test("generated OpenAPI types contain a closed capability pin and patch type", async () => {
  const generated = await readFile(join(root, "packages/redevplugin-ui/src/openapi.gen.ts"), "utf8");
  assert.match(generated, /CapabilityContractPin: components\["schemas"\]\["HostCapabilityPinV1"\]/);
  assert.doesNotMatch(generated, /\$defs\s*:/);
  assert.doesNotMatch(generated, /PatchSettingsRequest:[\s\S]{0,600}?\| unknown/);
});

test("diagnostic events use closed details and a dedicated mutation outcome", async () => {
  const openAPI = await readOpenAPI();
  const schemas = openAPI.components.schemas;
  assert.deepEqual(schemas.DiagnosticMutationOutcome.enum, ["committed", "not_committed", "unknown"]);
  assert.deepEqual(schemas.MutationOutcome.enum, ["not_committed", "unknown"]);
  assert.equal(schemas.PluginDiagnosticDetails.additionalProperties, false);
  assert.deepEqual(Object.keys(schemas.PluginDiagnosticDetails.properties).sort(), [
    "arch",
    "artifact",
    "code",
    "connector_id",
    "failure_code",
    "hostcall",
    "invocation_id",
    "method",
    "operation",
    "operation_id",
    "operations_deleted",
    "os",
    "package_hash",
    "plugin_instance_id",
    "reason",
    "revoke_epoch",
    "runtime_artifact_sha256",
    "runtime_generation_id",
    "runtime_instance_id",
    "runtime_target_arch",
    "runtime_target_os",
    "runtime_version",
    "rust_ipc_version",
    "stage_id",
    "store_id",
    "stream",
    "stream_id",
    "streams_deleted",
    "surface_instance_id",
    "transport",
    "wasm_abi_version",
  ]);
  for (const field of ["operations_deleted", "streams_deleted", "revoke_epoch"]) {
    assert.deepEqual(schemas.PluginDiagnosticDetails.properties[field], {
      type: "integer",
      minimum: 0,
      maximum: 9007199254740991,
    });
  }
  assert.deepEqual(schemas.PluginDiagnosticEvent.properties.details, {
    $ref: "#/components/schemas/PluginDiagnosticDetails",
  });
  assert.deepEqual(schemas.PluginDiagnosticEvent.properties.mutation_outcome, {
    $ref: "#/components/schemas/DiagnosticMutationOutcome",
  });
});

test("OpenAPI and IPC runtime limits have identical bounds and descriptions", async () => {
  const [openAPI, ipcSchema] = await Promise.all([readOpenAPI(), readIPCSchema()]);
  const openAPILimits = openAPI.components.schemas.RuntimeLimits;
  const ipcLimits = ipcSchema.$defs.runtime_limits;
  assert.equal(openAPILimits.type, ipcLimits.type);
  assert.equal(openAPILimits.additionalProperties, ipcLimits.additionalProperties);
  assert.equal(openAPILimits.description, ipcLimits.description);
  assert.deepEqual(openAPILimits.required, ipcLimits.required);
  for (const field of openAPILimits.required) {
    assert.deepEqual(
      openAPILimits.properties[field],
      ipcLimits.properties[field],
      `${field} must have one cross-language contract`,
    );
  }
});
