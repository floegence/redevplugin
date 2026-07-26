import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import Ajv from "ajv";
import { parse as parseYAML } from "yaml";

const root = resolve(import.meta.dirname, "..");

async function readOpenAPI() {
  return parseYAML(await readFile(join(root, "spec/openapi/plugin-platform-v9.yaml"), "utf8"));
}

async function readIPCSchema() {
  return JSON.parse(await readFile(join(root, "spec/plugin/ipc-v6.schema.json"), "utf8"));
}

async function readSessionScopeSchema() {
  return JSON.parse(await readFile(join(root, "spec/plugin/session-scope-v1.schema.json"), "utf8"));
}

async function readSessionScopeMaintenanceContract() {
  return JSON.parse(await readFile(join(root, "spec/plugin/session-scope-maintenance-v1.json"), "utf8"));
}

async function readCompatibilitySchema() {
  return JSON.parse(await readFile(join(root, "spec/plugin/compatibility-manifest-v11.schema.json"), "utf8"));
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
  const schemaRoute = paths["/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema/query"].post;
  const settingsRoute = paths["/_redevplugin/api/plugins/{plugin_instance_id}/settings/query"].post;
  for (const route of [schemaRoute, settingsRoute]) {
    assert.deepEqual(route.requestBody, { $ref: "#/components/requestBodies/SettingsQueryRequest" });
    assert.equal(route["x-redevplugin-route-effect"], "query");
  }
  assert.deepEqual(openAPI.components.schemas.SettingsQueryRequest.required, ["scope"]);
  assert.equal(openAPI.components.schemas.SettingsQueryRequest.additionalProperties, false);
  assert.deepEqual(openAPI.components.schemas.ResourceScopeKind, {
    type: "string",
    enum: ["user", "environment"],
  });
  for (const name of ["PluginSettingsSchema", "PluginSettingsSnapshot"]) {
    assert.ok(openAPI.components.schemas[name].required.includes("scope"));
    assert.deepEqual(openAPI.components.schemas[name].properties.scope, { $ref: "#/components/schemas/ResourceScopeKind" });
  }
});

test("session revoke is one closed authenticated-session mutation contract", async () => {
  const openAPI = await readOpenAPI();
  const route = openAPI.paths["/_redevplugin/api/plugins/session/revoke-scope"]?.post;
  assert.ok(route);
  assert.equal(openAPI.paths["/_redevplugin/api/plugins/surfaces/revoke-scope"], undefined);
  assert.equal(route.operationId, "revokePluginSessionScope");
  assert.equal(route["x-redevplugin-route-effect"], "mutation");
  assert.deepEqual(route.requestBody, { $ref: "#/components/requestBodies/RevokeSessionScopeRequest" });
  assert.deepEqual(route.responses["200"], { $ref: "#/components/responses/SessionScopeRevokeResponse" });
  assert.deepEqual(route.responses.default, { $ref: "#/components/responses/MutationPlatformErrorResponse" });

  const request = openAPI.components.schemas.RevokeSessionScopeRequest;
  assert.deepEqual(request, {
    type: "object",
    additionalProperties: false,
    maxProperties: 0,
  });
  assert.deepEqual(
    openAPI.components.schemas.SessionScopeRevokeSuccessResponse.properties.data,
    { $ref: "#/components/schemas/SessionScopeRevokeCompleteResult" },
  );

  const incompleteError = openAPI.components.schemas.MutationSessionTeardownPlatformError;
  assert.deepEqual(incompleteError.required, ["code", "message", "details", "mutation_outcome"]);
  assert.deepEqual(incompleteError.properties.code, { const: "PLUGIN_SESSION_TEARDOWN_INCOMPLETE" });
  assert.deepEqual(incompleteError.properties.mutation_outcome, { const: "committed" });
  assert.deepEqual(
    incompleteError.properties.details,
    { $ref: "#/components/schemas/SessionTeardownIncompleteErrorDetails" },
  );
});

test("session scope contract closes identity, phases, counts, and public result shapes", async () => {
  const schema = await readSessionScopeSchema();
  const defs = schema.$defs;
  const identityFields = [
    "owner_session_hash",
    "owner_user_hash",
    "owner_env_hash",
    "session_channel_id_hash",
  ];
  assert.deepEqual(defs.session_scope.required, identityFields);
  assert.equal(defs.session_scope.additionalProperties, false);
  assert.deepEqual(Object.keys(defs.session_scope.properties), identityFields);
  assert.deepEqual(defs.teardown_phase.enum, ["bridge", "confirmation", "execution", "operation", "stream", "runtime"]);

  const countFields = [
    "surfaces",
    "asset_tickets",
    "asset_sessions",
    "plugin_gateway_tokens",
    "confirmation_tokens",
    "stream_tickets",
    "handle_grants",
    "confirmations",
    "operations",
    "streams",
    "runtime_executions",
    "active_network_requests",
    "sockets",
    "network_streams",
    "storage_hostcalls",
  ];
  assert.deepEqual(defs.revoke_counts.required, countFields);
  assert.equal(defs.revoke_counts.additionalProperties, false);
  assert.deepEqual(Object.keys(defs.revoke_counts.properties), countFields);
  for (const field of countFields) {
    assert.deepEqual(defs.revoke_counts.properties[field], { $ref: "#/$defs/count" });
  }
  assert.deepEqual(defs.count, {
    type: "integer",
    minimum: 0,
    maximum: Number.MAX_SAFE_INTEGER,
  });

  assert.deepEqual(defs.complete_revoke_result.required, ["state", "fenced", "complete", "counts"]);
  assert.deepEqual(defs.complete_revoke_result.properties.state, { const: "complete" });
  assert.deepEqual(defs.complete_revoke_result.properties.fenced, { const: true });
  assert.deepEqual(defs.complete_revoke_result.properties.complete, { const: true });
  assert.deepEqual(defs.incomplete_revoke_result.properties.state, { const: "incomplete" });
  assert.deepEqual(defs.incomplete_revoke_result.properties.fenced, { const: true });
  assert.deepEqual(defs.incomplete_revoke_result.properties.complete, { const: false });
  for (const result of [defs.complete_revoke_result, defs.incomplete_revoke_result]) {
    assert.equal(result.additionalProperties, false);
    for (const privateField of [...identityFields, "operation_identity", "closed_session_proof"]) {
      assert.equal(result.properties[privateField], undefined);
    }
  }
});

test("Rust IPC v6 carries closed session revoke request and acknowledgement frames", async () => {
  const schema = await readIPCSchema();
  assert.equal(schema.properties.ipc_version.const, "rust-ipc-v6");
  assert.ok(schema.properties.frame_type.enum.includes("session_revoke"));
  assert.ok(schema.properties.frame_type.enum.includes("session_revoke_ack"));

  const request = schema.$defs.session_revoke_request_payload;
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(request.required, [
    "session_revoke_sequence",
    "owner_session_hash",
    "owner_user_hash",
    "owner_env_hash",
    "session_channel_id_hash",
  ]);
  assert.deepEqual(request.properties.session_revoke_sequence, {
    type: "integer",
    minimum: 1,
    maximum: Number.MAX_SAFE_INTEGER,
  });

  const result = schema.$defs.session_revoke_ack_result;
  assert.equal(result.additionalProperties, false);
  assert.deepEqual(result.required, ["session_revoke_sequence", "state", "counts"]);
  assert.deepEqual(result.properties.state, { const: "complete" });
  for (const count of Object.values(schema.$defs.session_revoke_ack_counts.properties)) {
    assert.deepEqual(count, { $ref: "#/$defs/session_revoke_count" });
  }
  assert.equal(schema.$defs.session_revoke_count.maximum, Number.MAX_SAFE_INTEGER);
});

test("session maintenance publishes the closed fail-closed recovery matrix", async () => {
  const contract = await readSessionScopeMaintenanceContract();
  assert.equal(contract.schema_version, "redevplugin.session_scope_maintenance.v1");
  assert.equal(contract.go_host_protocol_version, "plugin-host-v7");
  assert.deepEqual(contract.phases, ["prepared", "closed", "finalizing"]);
  assert.deepEqual(contract.teardown_statuses, ["incomplete", "complete", "absent"]);
  assert.deepEqual(contract.finalization_statuses, ["finalized", "absent"]);
  assert.equal(contract.platform_commit_point, "fence_deleted");
  assert.equal(contract.default_behavior, "fail_closed_without_mutation");
  assert.equal(contract.visibility.transport, "go_host_only");
  assert.equal(contract.visibility.http_route, false);
  assert.equal(contract.visibility.plugin_callable, false);
  assert.equal(contract.visibility.teardown_identity, "opaque");

  const states = new Map(contract.allowed_states.map((state) => [
    `${state.fence}:${state.record}:${state.terminal_evidence}:${state.identity_binding}`,
    state,
  ]));
  assert.equal(states.size, 7);
  assert.equal(states.get("absent:absent:absent:absent")?.finalize, "absent");
  assert.equal(states.get("absent:terminal_intent:required:absent")?.close, "prepare_and_begin_teardown");
  assert.equal(states.get("complete:closed:required:exact")?.finalize, "prepare_delete_fence_commit");
  assert.equal(states.get("complete:finalizing:required:exact")?.resume, "handoff_to_finalization");
  assert.equal(states.get("absent:finalizing:required:exact")?.finalize, "post_commit_cleanup");
  assert.doesNotMatch(JSON.stringify(contract), /closed_session_proof|operation_id|proof_sha256/);
});

test("compatibility v11 publishes the complete session revoke and UI transport matrix", async () => {
  const schema = await readCompatibilitySchema();
  const matrix = schema.properties.matrix;
  assert.ok(matrix.required.includes("session_scope_schema_version"));
  assert.ok(matrix.required.includes("session_scope_maintenance_schema_version"));
  assert.deepEqual(matrix.properties.plugin_host_protocol_version, { const: "plugin-host-v8" });
  assert.deepEqual(matrix.properties.rust_ipc_version, { const: "rust-ipc-v6" });
  assert.deepEqual(matrix.properties.token_ticket_schema_version, { const: "token-ticket-v4" });
  assert.deepEqual(matrix.properties.session_scope_schema_version, { const: "session-scope-v1" });
  assert.deepEqual(matrix.properties.session_scope_maintenance_schema_version, { const: "session-scope-maintenance-v1" });
  assert.deepEqual(matrix.properties.error_codes_schema_version, { const: "error-codes-v7" });
  assert.deepEqual(matrix.properties.supported_plugin_ui_protocol_versions, { const: ["plugin-ui-v5", "plugin-ui-v6"] });
  assert.equal(matrix.properties.plugin_ui_transport_mappings.const.length, 2);
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

test("confirmation preparation accepts typed and contract-defined object plans", async () => {
  const openAPI = await readOpenAPI();
  const plan = openAPI.components.schemas.PluginMethodConfirmationPreparation.properties.plan;
  assert.equal(plan.anyOf, undefined);
  assert.deepEqual(plan.oneOf, [
    { $ref: "#/components/schemas/RiskPlan" },
    {
      type: "object",
      additionalProperties: true,
      properties: {
        schema_version: {
          not: {
            type: "string",
            pattern: "^redevplugin\\.capability\\.risk_plan\\.",
          },
        },
      },
    },
  ]);

  const riskPlan = openAPI.components.schemas.RiskPlan;
  assert.deepEqual(riskPlan.required, ["schema_version", "summary", "risk_flags"]);
  assert.equal(riskPlan.properties.schema_version.const, "redevplugin.capability.risk_plan.v1");
  assert.equal(riskPlan.additionalProperties, false);
  assert.equal(plan.oneOf[1].type, "object", "contract-defined domain plans remain object-only");

  const validate = new Ajv({ allErrors: true, schemaId: "auto" }).compile({
    components: {
      schemas: {
        RiskFlag: openAPI.components.schemas.RiskFlag,
        RiskPlan: riskPlan,
        ConfirmationPlan: plan,
      },
    },
    $ref: "#/components/schemas/ConfirmationPlan",
  });
  const typedPlan = {
    schema_version: "redevplugin.capability.risk_plan.v1",
    summary: "Start container",
    risk_flags: [],
  };
  const domainPlan = {
    action: "start",
    risk_level: "medium",
    warnings: ["starts a stopped resource"],
  };
  for (const [label, value] of [["typed", typedPlan], ["domain", domainPlan]]) {
    assert.equal(validate(value), true, `${label} plan rejected: ${JSON.stringify(validate.errors)}`);
  }
  for (const [label, value] of [
    ["malformed typed", { schema_version: "redevplugin.capability.risk_plan.v1" }],
    ["unknown reserved", { schema_version: "redevplugin.capability.risk_plan.v2", summary: "Start" }],
    ["scalar", "start"],
  ]) {
    assert.equal(validate(value), false, `${label} plan unexpectedly accepted`);
  }
});

test("diagnostic events use closed details and a dedicated mutation outcome", async () => {
  const openAPI = await readOpenAPI();
  const schemas = openAPI.components.schemas;
  assert.deepEqual(schemas.DiagnosticMutationOutcome.enum, ["committed", "not_committed", "unknown"]);
  assert.deepEqual(schemas.MutationOutcome.enum, ["committed", "not_committed", "unknown"]);
  assert.equal(schemas.PluginDiagnosticDetails.additionalProperties, false);
  assert.deepEqual(Object.keys(schemas.PluginDiagnosticDetails.properties).sort(), [
    "arch",
    "artifact",
    "code",
    "connector_id",
    "contract_set_sha256",
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
    "runtime_binary_sha256",
    "runtime_generation_id",
    "runtime_instance_id",
    "runtime_process_failure_code",
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
  assert.deepEqual(schemas.PluginDiagnosticDetails.properties.runtime_process_failure_code, {
    $ref: "../plugin/error-codes-v7.schema.json#/$defs/runtime_process_failure_code",
  });
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

test("runtime module cache metrics stay within negotiated platform maxima", async () => {
  const openAPI = await readOpenAPI();
  const metrics = openAPI.components.schemas.RuntimeModuleCacheMetrics;
  assert.equal(metrics.properties.entries.minimum, 0);
  assert.equal(metrics.properties.entries.maximum, 1024);
  assert.equal(metrics.properties.source_bytes.minimum, 0);
  assert.equal(metrics.properties.source_bytes.maximum, 134217728);
});
