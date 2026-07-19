#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYAML } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.slice(2).includes("--check");
const registryPath = join(root, "spec/plugin/contract-registry-v1.json");
const goOutputPath = join(root, "pkg/version/contracts_gen.go");
const tsOutputPath = join(root, "packages/redevplugin-ui/src/contracts.gen.ts");
const goRenderPolicyOutputPath = join(root, "pkg/pluginpkg/opaque_surface_policy_gen.go");
const tsRenderPolicyOutputPath = join(root, "packages/redevplugin-ui/src/opaque-surface-policy.gen.ts");
const routesOutputPath = join(root, "testdata/contracts/routes.json");

const registry = JSON.parse(await readFile(registryPath, "utf8"));
validateRegistry(registry);
const renderPolicy = await readRenderPolicy(registry);

const contracts = [];
for (const contract of registry.contracts) {
  const absolutePath = resolve(root, contract.path);
  if (!isWithinRoot(absolutePath)) {
    throw new Error(`contract path escapes repository root: ${contract.path}`);
  }
  const content = await readFile(absolutePath);
  contracts.push({
    id: contract.id,
    path: contract.path,
    version: registry.matrix[contract.version_key],
    sha256: createHash("sha256").update(content).digest("hex"),
  });
}

const outputs = new Map([
  [goOutputPath, formatGo(renderGo(registry.matrix, contracts))],
  [tsOutputPath, renderTypeScript(registry.matrix, contracts)],
  [goRenderPolicyOutputPath, formatGo(renderGoRenderPolicy(renderPolicy))],
  [tsRenderPolicyOutputPath, renderTypeScriptRenderPolicy(renderPolicy)],
  [routesOutputPath, await renderRoutes(registry)],
]);

for (const [filename, content] of outputs) {
  if (checkOnly) {
    const current = await readFile(filename, "utf8").catch(() => "");
    if (current !== content) {
      throw new Error(`${relative(root, filename)} is stale; run npm run contracts:generate`);
    }
    continue;
  }
  await writeFile(filename, content);
}

function validateRegistry(value) {
  if (!isRecord(value) || !hasExactKeys(value, ["schema_version", "matrix", "contracts"])) {
    throw new Error("contract registry must be a closed object");
  }
  if (value.schema_version !== "redevplugin.contract_registry.v1") {
    throw new Error(`unsupported contract registry schema_version: ${value.schema_version}`);
  }
  if (!isRecord(value.matrix) || Object.keys(value.matrix).length === 0) {
    throw new Error("contract registry matrix is required");
  }
  for (const [key, version] of Object.entries(value.matrix)) {
    if (!/^[a-z][a-z0-9_]+$/.test(key) || typeof version !== "string" || version.length === 0) {
      throw new Error(`invalid contract matrix entry: ${key}`);
    }
  }
  if (!Array.isArray(value.contracts) || value.contracts.length === 0) {
    throw new Error("contract registry contracts are required");
  }
  const ids = new Set();
  const paths = new Set();
  for (const contract of value.contracts) {
    if (!isRecord(contract) || !hasExactKeys(contract, ["id", "path", "version_key"])) {
      throw new Error("contract registry entries must be closed objects");
    }
    if (!/^[a-z][a-z0-9-]+$/.test(contract.id) || ids.has(contract.id)) {
      throw new Error(`invalid or duplicate contract id: ${contract.id}`);
    }
    if (!/^(spec\/openapi|spec\/plugin)\/[A-Za-z0-9._/-]+$/.test(contract.path) || paths.has(contract.path)) {
      throw new Error(`invalid or duplicate contract path: ${contract.path}`);
    }
    if (contract.path.includes("..") || contract.path.includes("\\")) {
      throw new Error(`unsafe contract path: ${contract.path}`);
    }
    if (!(contract.version_key in value.matrix)) {
      throw new Error(`unknown version_key ${contract.version_key} for ${contract.id}`);
    }
    ids.add(contract.id);
    paths.add(contract.path);
  }
}

function renderGo(matrix, contracts) {
  const constants = [
    ["PluginUIProtocolVersion", "plugin_ui_protocol_version"],
    ["PluginHostProtocolVersion", "plugin_host_protocol_version"],
    ["RustIPCVersion", "rust_ipc_version"],
    ["WASMABIVersion", "wasm_abi_version"],
    ["ManifestSchemaVersion", "manifest_schema_version"],
    ["PackageSignatureSchemaVersion", "package_signature_schema_version"],
    ["ReleaseMetadataSchemaVersion", "release_metadata_schema_version"],
    ["SourcePolicySchemaVersion", "source_policy_schema_version"],
    ["SourceRevocationsSchemaVersion", "source_revocations_schema_version"],
    ["TokenTicketSchemaVersion", "token_ticket_schema_version"],
    ["BridgeSchemaVersion", "bridge_schema_version"],
    ["OpaqueSurfaceDocumentSchemaVersion", "opaque_surface_document_schema_version"],
    ["OpaqueSurfaceTransportSchemaVersion", "opaque_surface_transport_schema_version"],
    ["TargetClassifierVersion", "target_classifier_version"],
    ["NetworkGrantSchemaVersion", "network_grant_schema_version"],
    ["ResourceScopeSchemaVersion", "resource_scope_schema_version"],
    ["PluginPlatformOpenAPIVersion", "plugin_platform_openapi_version"],
    ["CompatibilityManifestVersion", "compatibility_manifest_version"],
    ["CompatibilitySchemaVersion", "compatibility_schema_version"],
    ["ReleaseManifestSchemaVersion", "release_manifest_schema_version"],
    ["WorkerInvocationSchemaVersion", "worker_invocation_schema_version"],
    ["HostCapabilityContractSchemaVersion", "host_capability_contract_schema_version"],
    ["HostCapabilityPinSchemaVersion", "host_capability_pin_schema_version"],
    ["HostCapabilityManifestSchemaVersion", "host_capability_manifest_schema_version"],
    ["HostCapabilityCompatibilitySchemaVersion", "host_capability_compatibility_schema_version"],
    ["HostCapabilitySignatureSchemaVersion", "host_capability_signature_schema_version"],
    ["HostCapabilityNoticesSchemaVersion", "host_capability_notices_schema_version"],
    ["ErrorCodesSchemaVersion", "error_codes_schema_version"],
    ["PerformanceContractVersion", "performance_contract_version"],
    ["PerformanceEvidenceSchemaVersion", "performance_evidence_schema_version"],
    ["ContractRegistryVersion", "contract_registry_version"],
  ];
  const constantLines = constants.map(([name, key]) => `\t${name} = ${JSON.stringify(matrix[key])}`).join("\n");
  const contractLines = contracts.map((contract) => [
    "\t{",
    `\t\tID: ${JSON.stringify(contract.id)},`,
    `\t\tPath: ${JSON.stringify(contract.path)},`,
    `\t\tVersion: ${JSON.stringify(contract.version)},`,
    `\t\tSHA256: ${JSON.stringify(contract.sha256)},`,
    "\t},",
  ].join("\n")).join("\n");
  return `// Code generated by scripts/generate_contract_registry.mjs; DO NOT EDIT.\n\npackage version\n\nconst (\n${constantLines}\n)\n\nvar generatedContractArtifacts = []ContractArtifact{\n${contractLines}\n}\n`;
}

function formatGo(source) {
  const result = spawnSync("gofmt", { input: source, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`gofmt failed while generating contracts_gen.go: ${result.stderr || result.error}`);
  }
  return result.stdout;
}

function renderTypeScript(matrix, contracts) {
  const entries = Object.entries(matrix)
    .map(([key, value]) => `  ${JSON.stringify(key)}: ${JSON.stringify(value)},`)
    .join("\n");
  const artifacts = contracts.map((contract) => [
    "  {",
    `    id: ${JSON.stringify(contract.id)},`,
    `    path: ${JSON.stringify(contract.path)},`,
    `    version: ${JSON.stringify(contract.version)},`,
    `    sha256: ${JSON.stringify(contract.sha256)},`,
    "  },",
  ].join("\n")).join("\n");
  return `// Code generated by scripts/generate_contract_registry.mjs; DO NOT EDIT.\n\nexport const pluginUIProtocolVersion = ${JSON.stringify(matrix.plugin_ui_protocol_version)} as const;\nexport const pluginHostProtocolVersion = ${JSON.stringify(matrix.plugin_host_protocol_version)} as const;\nexport const bridgeSchemaVersion = ${JSON.stringify(matrix.bridge_schema_version)} as const;\nexport const tokenTicketSchemaVersion = ${JSON.stringify(matrix.token_ticket_schema_version)} as const;\n\nexport const redevPluginContractVersions = {\n${entries}\n} as const;\n\nexport type ReDevPluginContractArtifact = {\n  readonly id: string;\n  readonly path: string;\n  readonly version: string;\n  readonly sha256: string;\n};\n\nexport const redevPluginContractArtifacts = [\n${artifacts}\n] as const satisfies readonly ReDevPluginContractArtifact[];\n`;
}

async function readRenderPolicy(registry) {
  const bridgeContract = registry.contracts.find((contract) => contract.id === "iframe-bridge-schema");
  if (!bridgeContract) {
    throw new Error("iframe-bridge-schema contract is missing");
  }
  const schema = JSON.parse(await readFile(join(root, bridgeContract.path), "utf8"));
  const policy = schema["x-redevplugin-render-policy"];
  const expectedKeys = [
    "max_message_bytes",
    "max_in_flight_requests",
    "max_renders_per_second",
    "max_render_depth",
    "max_render_nodes",
    "max_patch_operations",
    "max_attributes_per_element",
    "max_text_length",
    "max_attribute_value_length",
    "max_form_fields",
    "max_canvas_count",
    "max_canvas_dimension",
    "max_canvas_total_pixels",
    "max_canvas_pointer_events_per_second",
    "max_image_count",
    "max_image_dimension",
    "max_image_total_pixels",
    "worker_heartbeat_interval_ms",
    "worker_heartbeat_timeout_ms",
    "global_attributes",
    "tag_attributes",
    "safe_input_types",
  ];
  if (!isRecord(policy) || !hasExactKeys(policy, expectedKeys)) {
    throw new Error("bridge render policy must be a closed object");
  }
  const limits = {};
  const numericKeys = expectedKeys.filter((key) => key.startsWith("max_") || key.endsWith("_ms"));
  for (const key of numericKeys) {
    if (!Number.isSafeInteger(policy[key]) || policy[key] <= 0) {
      throw new Error(`bridge render policy ${key} must be a positive integer`);
    }
    limits[key] = policy[key];
  }
  const vnode = schema?.$defs?.element_vnode ?? schema?.$defs?.vnode?.oneOf?.[1];
  const allowedTags = vnode?.properties?.tag?.enum;
  if (!isUniqueStringArray(allowedTags)) {
    throw new Error("bridge vnode tag enum must be a unique string array");
  }
  const globalAttributes = policy.global_attributes;
  const safeInputTypes = policy.safe_input_types;
  if (!isUniqueStringArray(globalAttributes) || !isUniqueStringArray(safeInputTypes)) {
    throw new Error("bridge render policy attribute and input lists must contain unique strings");
  }
  if (!isRecord(policy.tag_attributes)) {
    throw new Error("bridge render policy tag_attributes must be an object");
  }
  const tagAttributes = {};
  for (const [tag, attributes] of Object.entries(policy.tag_attributes)) {
    if (!allowedTags.includes(tag) || !isUniqueStringArray(attributes)) {
      throw new Error(`bridge render policy attributes are invalid for tag ${tag}`);
    }
    tagAttributes[tag] = attributes;
  }
  return { allowedTags, globalAttributes, tagAttributes, safeInputTypes, limits };
}

function renderGoRenderPolicy(policy) {
  const constantNames = {
    max_message_bytes: "opaqueSurfaceMaxMessageBytes",
    max_in_flight_requests: "opaqueSurfaceMaxInFlightRequests",
    max_renders_per_second: "opaqueSurfaceMaxRendersPerSecond",
    max_render_depth: "opaqueSurfaceMaxRenderDepth",
    max_render_nodes: "opaqueSurfaceMaxRenderNodes",
    max_patch_operations: "opaqueSurfaceMaxPatchOperations",
    max_attributes_per_element: "opaqueSurfaceMaxAttributesPerElement",
    max_text_length: "opaqueSurfaceMaxTextLength",
    max_attribute_value_length: "opaqueSurfaceMaxAttributeValueLength",
    max_form_fields: "opaqueSurfaceMaxFormFields",
    max_canvas_count: "opaqueSurfaceMaxCanvasCount",
    max_canvas_dimension: "opaqueSurfaceMaxCanvasDimension",
    max_canvas_total_pixels: "opaqueSurfaceMaxCanvasTotalPixels",
    max_canvas_pointer_events_per_second: "opaqueSurfaceMaxCanvasPointerEventsPerSecond",
    max_image_count: "opaqueSurfaceMaxImageCount",
    max_image_dimension: "opaqueSurfaceMaxImageDimension",
    max_image_total_pixels: "opaqueSurfaceMaxImageTotalPixels",
    worker_heartbeat_interval_ms: "opaqueSurfaceWorkerHeartbeatIntervalMS",
    worker_heartbeat_timeout_ms: "opaqueSurfaceWorkerHeartbeatTimeoutMS",
  };
  const constants = Object.entries(constantNames)
    .map(([key, name]) => `\t${name} = ${policy.limits[key]}`)
    .join("\n");
  const renderSet = (values, indent = "\t") => values.map((value) => `${indent}${JSON.stringify(value)}: {},`).join("\n");
  const tagAttributes = Object.entries(policy.tagAttributes)
    .map(([tag, attributes]) => `\t${JSON.stringify(tag)}: {\n${renderSet(attributes, "\t\t")}\n\t},`)
    .join("\n");
  return `// Code generated by scripts/generate_contract_registry.mjs; DO NOT EDIT.\n\npackage pluginpkg\n\nconst (\n${constants}\n)\n\nvar opaqueSurfaceAllowedTags = map[string]struct{}{\n${renderSet(policy.allowedTags)}\n}\n\nvar opaqueSurfaceGlobalAttributes = map[string]struct{}{\n${renderSet(policy.globalAttributes)}\n}\n\nvar opaqueSurfaceTagAttributes = map[string]map[string]struct{}{\n${tagAttributes}\n}\n\nvar opaqueSurfaceSafeInputTypes = map[string]struct{}{\n${renderSet(policy.safeInputTypes)}\n}\n`;
}

function renderTypeScriptRenderPolicy(policy) {
  return `// Code generated by scripts/generate_contract_registry.mjs; DO NOT EDIT.\n\nexport const opaqueSurfaceAllowedTags = ${JSON.stringify(policy.allowedTags, null, 2)} as const;\nexport type OpaqueSurfaceAllowedTag = (typeof opaqueSurfaceAllowedTags)[number];\n\nexport const opaqueSurfaceGlobalAttributes = ${JSON.stringify(policy.globalAttributes, null, 2)} as const;\n\nexport const opaqueSurfaceTagAttributes = ${JSON.stringify(policy.tagAttributes, null, 2)} as const;\n\nexport const opaqueSurfaceSafeInputTypes = ${JSON.stringify(policy.safeInputTypes, null, 2)} as const;\n\nexport const opaqueSurfaceRenderLimits = ${JSON.stringify(policy.limits, null, 2)} as const;\n`;
}

async function renderRoutes(registry) {
  const openAPIContract = registry.contracts.find((contract) => contract.id === "plugin-platform-openapi");
  if (!openAPIContract) {
    throw new Error("plugin-platform-openapi contract is missing");
  }
  const openAPI = parseYAML(await readFile(join(root, openAPIContract.path), "utf8"));
  if (!isRecord(openAPI) || !isRecord(openAPI.paths)) {
    throw new Error("OpenAPI paths object is missing");
  }
  const routes = [];
  for (const [path, pathItem] of Object.entries(openAPI.paths)) {
    if (!isRecord(pathItem)) continue;
    for (const method of ["delete", "get", "patch", "post", "put"]) {
      const operation = pathItem[method];
      if (!isRecord(operation)) continue;
      const effect = operation["x-redevplugin-route-effect"];
      if (effect !== "query" && effect !== "mutation") {
        throw new Error(`OpenAPI route ${method.toUpperCase()} ${path} has invalid or missing x-redevplugin-route-effect`);
      }
      routes.push({
        method: method.toUpperCase(),
        path,
        effect,
      });
    }
  }
  routes.sort((left, right) => left.path.localeCompare(right.path) || left.method.localeCompare(right.method));
  return JSON.stringify(routes, null, 2) + "\n";
}

function hasExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUniqueStringArray(value) {
  return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string" && item.length > 0) && new Set(value).size === value.length;
}

function isWithinRoot(filename) {
  const rel = relative(root, filename);
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !resolve(filename).startsWith(`${root}${sep}..${sep}`);
}
