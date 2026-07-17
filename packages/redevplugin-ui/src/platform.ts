import { defaultFetch, readMutationPlatformResponse, readPlatformResponse, trimTrailingSlash, type FetchLike } from "./http.js";
import { PluginPlatformRequestError, PluginTransportError } from "./errors.js";
import type { components, operations } from "./openapi.gen.js";
import type { PluginSurfaceHostBootstrap, PluginTrustedMethodResult } from "./surface.js";
import {
  defaultPluginSurfaceScope,
  disposePluginSurfaceScope,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export type PluginPlatformClientOptions = {
  fetch?: FetchLike;
  apiBaseURL?: string;
  surfaceScope?: PluginSurfaceScope;
  onMutationOutcomeUnknown?: (pluginInstanceId?: string) => void;
};

type PlatformSchemas = components["schemas"];

export type PluginCatalogResult = PlatformSchemas["PluginCatalogResult"];
export type PluginCatalogRecord = PluginCatalogResult["plugins"][number];
export type PluginCompatibilityManifest = PlatformSchemas["PluginCompatibilityManifest"];
export type PluginCompatibilityMatrix = PluginCompatibilityManifest["matrix"];
export type PluginContractArtifact = PluginCompatibilityManifest["contracts"][number];
export type PluginTrustState = PlatformSchemas["TrustState"];
export type PluginTrustHashSet = PlatformSchemas["TrustHashSet"];
export type PluginVerifiedSignature = PlatformSchemas["VerifiedSignature"];
export type PluginTrustAssessment = PlatformSchemas["TrustAssessment"];
export type PluginLocalImportProvenance = PlatformSchemas["LocalImportProvenance"];
export type PluginVersionRecord = PlatformSchemas["PluginVersion"];
export type PluginRecord = PlatformSchemas["PluginRecord"];
export type PluginEnableState = PluginRecord["enable_state"];
export type PluginPackageHashSet = PlatformSchemas["PackageHashSet"];
export type PluginReleaseRef = PlatformSchemas["PluginReleaseRef"];
export type PluginInstallReleaseRefRequest = PlatformSchemas["InstallReleaseRefRequest"];
export type PluginUpdateReleaseRefRequest = PlatformSchemas["UpdateReleaseRefRequest"];
export type PluginDowngradeRequest = PlatformSchemas["DowngradeRequest"];
export type PluginEnableRequest = PlatformSchemas["EnableRequest"];
export type PluginDisableRequest = PlatformSchemas["DisableRequest"];
export type PluginUninstallRequest = PlatformSchemas["UninstallRequest"];
export type PluginOpenSurfaceRequest = PlatformSchemas["OpenSurfaceRequest"];

export type PluginSurfaceScopeRevokeResult = PlatformSchemas["SurfaceScopeRevokeResult"];

export type PluginSurfaceBootstrapResult = PlatformSchemas["SurfaceBootstrap"];

export function toPluginSurfaceHostBootstrap(value: PluginSurfaceBootstrapResult): PluginSurfaceHostBootstrap {
  return {
    pluginId: value.plugin_id,
    pluginInstanceId: value.plugin_instance_id,
    pluginVersion: value.plugin_version,
    surfaceId: value.surface_id,
    surfaceInstanceId: value.surface_instance_id,
    activeFingerprint: value.active_fingerprint,
    bridgeNonce: value.bridge_nonce,
    entryPath: value.entry_path,
    entrySHA256: value.entry_sha256,
    assetTicket: value.asset_ticket,
    assetSessionNonce: value.asset_session_nonce,
    managementRevision: value.management_revision,
    revokeEpoch: value.revoke_epoch,
    runtimeGenerationId: value.runtime_generation_id,
  };
}

export type PluginRuntimeStartRequest = PlatformSchemas["StartRuntimeRequest"];
export type PluginRuntimeTarget = NonNullable<PluginRuntimeStartRequest["target"]>;
export type PluginRuntimeHealth = PlatformSchemas["PluginRuntimeHealth"];
export type PluginRuntimeShardHealth = PlatformSchemas["PluginRuntimeShardHealth"];
export type PluginRuntimeStopResult = PlatformSchemas["PluginRuntimeStopResult"];
export type PluginRuntimeRefreshResult = PlatformSchemas["PluginRuntimeRefreshResult"];

export type PluginSettingsField = PlatformSchemas["PluginSettingsField"];
export type PluginSettingsSchema = PlatformSchemas["PluginSettingsSchema"];
export type PluginSettingsSnapshot = PlatformSchemas["PluginSettingsSnapshot"];
type PluginSettingsPatchBase = Pick<PlatformSchemas["PatchSettingsRequest"], "expected_values_revision">;
export type PluginSettingsPatchRequest = PluginSettingsPatchBase & (
  | { set: Record<string, unknown>; remove?: [string, ...string[]] }
  | { set?: Record<string, unknown>; remove: [string, ...string[]] }
);

export type PluginCapabilityContractPin = PlatformSchemas["HostCapabilityPinV1"];
export type PluginExecutionBinding = PlatformSchemas["ExecutionBinding"];
export type PluginOperationRecord = PlatformSchemas["OperationRecord"];
export type PluginOperationList = PlatformSchemas["PluginOperationList"];
export type PluginOperationListOptions = NonNullable<operations["listPluginOperations"]["parameters"]["query"]>;

export type PluginIntentRecord = PlatformSchemas["PluginIntentRecord"];
export type PluginIntentList = PlatformSchemas["PluginIntentList"];
export type PluginIntentListOptions = NonNullable<operations["listPluginIntents"]["parameters"]["query"]>;
export type PluginIntentInvokeRequest = PlatformSchemas["InvokeIntentRequest"];

export type PluginPermissionGrant = PlatformSchemas["PluginPermissionGrant"];
export type PluginPermissionMutationResult = PlatformSchemas["PluginPermissionMutationResult"];
export type PluginPermissionList = PlatformSchemas["PluginPermissionList"];
export type PluginPermissionListOptions = NonNullable<operations["listPluginPermissionGrants"]["parameters"]["query"]>;
export type PluginPermissionGrantRequest = PlatformSchemas["GrantPermissionRequest"];
export type PluginPermissionRevokeRequest = PlatformSchemas["RevokePermissionRequest"];
export type PluginSecurityPolicy = PlatformSchemas["PluginSecurityPolicy"];
export type PluginSecurityPolicyList = PlatformSchemas["PluginSecurityPolicyList"];
export type PluginSecurityPolicyPutRequest = PlatformSchemas["PutSecurityPolicyRequest"];
export type PluginSecurityPolicyDeleteRequest = PlatformSchemas["DeleteSecurityPolicyRequest"];
export type PluginSecurityPolicyDeleteResult = PlatformSchemas["PluginSecurityPolicyDeleteResult"];

export type PluginDataExportRequest = PlatformSchemas["ExportDataRequest"];
export type PluginDataExportResult = PlatformSchemas["PluginDataExportResult"];
export type PluginDataExportDeleteRequest = PlatformSchemas["DeleteDataExportRequest"];
export type PluginDataExportDeleteResult = PlatformSchemas["PluginDataExportDeleteResult"];
export type PluginDataImportRequest = PlatformSchemas["ImportDataRequest"];
export type PluginDataBinding = PlatformSchemas["PluginDataBinding"];
export type PluginRetainedDataListOptions = NonNullable<operations["listPluginRetainedData"]["parameters"]["query"]>;
export type PluginRetainedDataList = PlatformSchemas["RetainedDataList"];
export type PluginRetainedDataDeleteRequest = PlatformSchemas["DeleteRetainedDataRequest"];
export type PluginRetainedDataBindRequest = PlatformSchemas["BindRetainedDataRequest"];
export type PluginRetainedDataCleanupRequest = PlatformSchemas["CleanupExpiredRetainedDataRequest"];
export type PluginRetainedDataCleanupResult = PlatformSchemas["RetainedDataCleanupResult"];

export type PluginSecretRefRequest = PlatformSchemas["SecretRefRequest"];
export type PluginSecretBindResult = PlatformSchemas["PluginSecretBindResult"];
export type PluginSecretTestResult = PlatformSchemas["PluginSecretTestResult"];
export type PluginSecretDeleteResult = PlatformSchemas["PluginSecretDeleteResult"];

export type PluginDiagnosticEvent = PlatformSchemas["PluginDiagnosticEvent"];
export type PluginDiagnosticEventList = PlatformSchemas["PluginDiagnosticEventList"];
export type PluginDiagnosticListOptions = NonNullable<operations["listPluginDiagnosticEvents"]["parameters"]["query"]>;
export type PluginDiagnosticSeverity = NonNullable<PluginDiagnosticListOptions["severity"]>;

export class PluginPlatformClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #surfaceScope: PluginSurfaceScope;
  #onMutationOutcomeUnknown?: (pluginInstanceId?: string) => void;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#surfaceScope = options.surfaceScope ?? defaultPluginSurfaceScope;
    this.#onMutationOutcomeUnknown = options.onMutationOutcomeUnknown;
  }

  catalog(): Promise<PluginCatalogResult> { return this.#getJSON("/_redevplugin/api/plugins/catalog"); }
  getCompatibility(): Promise<PluginCompatibilityManifest> { return this.#getJSON("/_redevplugin/api/plugins/platform/compatibility"); }
  installReleaseRef(request: PluginInstallReleaseRefRequest): Promise<PluginRecord> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/install-release-ref", request); }
  updateReleaseRef(request: PluginUpdateReleaseRefRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/update-release-ref", request); }
  downgradePlugin(request: PluginDowngradeRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/downgrade", request); }
  enablePlugin(request: PluginEnableRequest): Promise<PluginRecord> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/enable", request); }
  disablePlugin(request: PluginDisableRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/disable", request); }
  uninstallPlugin(request: PluginUninstallRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/uninstall", request); }
  openSurface(request: PluginOpenSurfaceRequest): Promise<PluginSurfaceBootstrapResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/surfaces/open", request); }
  async revokeSurfaceScope(): Promise<PluginSurfaceScopeRevokeResult> {
    try {
      const result = await this.#requestMutation<PluginSurfaceScopeRevokeResult>("POST", "/_redevplugin/api/plugins/surfaces/revoke-scope", {});
      disposePluginSurfaceScope(this.#surfaceScope);
      return result;
    } catch (error) {
      this.#handleMutationFailure(error);
      throw error;
    }
  }
  startRuntime(request: PluginRuntimeStartRequest): Promise<PluginRuntimeHealth> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/runtime/start", request); }
  stopRuntime(): Promise<PluginRuntimeStopResult> { return this.#requestMutation<PluginRuntimeStopResult>("POST", "/_redevplugin/api/plugins/runtime/stop", {}); }
  refreshEnabledRuntimeState(): Promise<PluginRuntimeRefreshResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/runtime/refresh-enabled", {}); }
  runtimeHealth(): Promise<PluginRuntimeHealth> { return this.#getJSON("/_redevplugin/api/plugins/runtime/health"); }
  getSettingsSchema(pluginInstanceId: string): Promise<PluginSettingsSchema> { return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema`); }
  getSettings(pluginInstanceId: string): Promise<PluginSettingsSnapshot> { return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`); }
  patchSettings(pluginInstanceId: string, request: PluginSettingsPatchRequest): Promise<PluginSettingsSnapshot> {
    return this.#mutatePluginAt("PATCH", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`, pluginInstanceId, request);
  }
  listOperations(options: PluginOperationListOptions = {}): Promise<PluginOperationList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id) params.set("plugin_instance_id", options.plugin_instance_id);
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/operations${query ? `?${query}` : ""}`);
  }
  getOperation(operationId: string): Promise<PluginOperationRecord> { return this.#getJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}`); }
  cancelOperation(operationId: string, reason?: string): Promise<PluginOperationRecord> { return this.#requestMutation("POST", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`, reason ? { reason } : {}); }

  listIntents(options: PluginIntentListOptions = {}): Promise<PluginIntentList> {
    const params = new URLSearchParams();
    if (options.intent_id !== undefined) params.set("intent_id", options.intent_id);
    if (options.plugin_instance_id !== undefined) params.set("plugin_instance_id", options.plugin_instance_id);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/intents${query ? `?${query}` : ""}`);
  }

  invokeIntent<T = unknown>(request: PluginIntentInvokeRequest): Promise<PluginTrustedMethodResult<T>> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/intents/invoke", request);
  }

  exportData(request: PluginDataExportRequest): Promise<PluginDataExportResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/data/export", request); }
  deleteDataExport(request: PluginDataExportDeleteRequest): Promise<PluginDataExportDeleteResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/data/export/delete", request); }
  importData(request: PluginDataImportRequest): Promise<PluginRecord> {
    return this.#mutatePluginAt("POST", "/_redevplugin/api/plugins/data/import", request.plugin_instance_id, request);
  }

  listRetainedData(options: PluginRetainedDataListOptions = {}): Promise<PluginRetainedDataList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id) params.set("plugin_instance_id", options.plugin_instance_id);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/retained-data${query ? `?${query}` : ""}`);
  }

  deleteRetainedData(request: PluginRetainedDataDeleteRequest): Promise<PluginDataBinding> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/delete", request); }
  bindRetainedData(request: PluginRetainedDataBindRequest): Promise<PluginDataBinding> {
    return this.#mutatePluginAt("POST", "/_redevplugin/api/plugins/retained-data/bind", request.target_plugin_instance_id, request);
  }
  cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest = {}): Promise<PluginRetainedDataCleanupResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/cleanup-expired", request); }

  listPermissions(options: PluginPermissionListOptions = {}): Promise<PluginPermissionList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id !== undefined) params.set("plugin_instance_id", options.plugin_instance_id);
    if (options.active_only !== undefined) params.set("active_only", options.active_only ? "true" : "false");
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/permissions${query ? `?${query}` : ""}`);
  }

  grantPermission(request: PluginPermissionGrantRequest): Promise<PluginPermissionMutationResult> { return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/grant", request); }
  revokePermission(request: PluginPermissionRevokeRequest): Promise<PluginPermissionMutationResult> { return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/revoke", request); }
  listSecurityPolicies(): Promise<PluginSecurityPolicyList> { return this.#getJSON("/_redevplugin/api/plugins/security-policies"); }
  getSecurityPolicy(pluginInstanceId: string): Promise<PluginSecurityPolicy> { return this.#getJSON(`/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`); }
  putSecurityPolicy(pluginInstanceId: string, request: PluginSecurityPolicyPutRequest): Promise<PluginSecurityPolicy> {
    return this.#mutatePluginAt("PUT", `/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`, pluginInstanceId, request);
  }
  deleteSecurityPolicy(pluginInstanceId: string, request: PluginSecurityPolicyDeleteRequest): Promise<PluginSecurityPolicyDeleteResult> {
    return this.#mutatePluginAt("DELETE", `/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`, pluginInstanceId, request);
  }
  bindSecret(request: PluginSecretRefRequest): Promise<PluginSecretBindResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/bind", request); }
  testSecret(request: PluginSecretRefRequest): Promise<PluginSecretTestResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/test", request); }
  deleteSecret(request: PluginSecretRefRequest): Promise<PluginSecretDeleteResult> { return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/delete", request); }
  listDiagnosticEvents(options: PluginDiagnosticListOptions = {}): Promise<PluginDiagnosticEventList> { return this.#getJSON(`/_redevplugin/api/plugins/diagnostics${queryString(options)}`); }

  #getJSON<T>(path: string): Promise<T> { return this.#requestJSON<T>("GET", path); }
  #mutatePlugin<Result>(path: string, request: { plugin_instance_id: string } & Record<string, unknown>): Promise<Result> {
    return this.#mutatePluginAt("POST", path, request.plugin_instance_id, request);
  }

  async #mutatePluginAt<Result>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, pluginInstanceId: string, request: unknown): Promise<Result> {
    try {
      const result = await this.#requestMutation<Result>(method, path, request);
      disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
      return result;
    } catch (error) {
      this.#handleMutationFailure(error, pluginInstanceId);
      throw error;
    }
  }

  #handleMutationFailure(error: unknown, pluginInstanceId?: string): void {
    if (error instanceof PluginPlatformRequestError && error.mutationOutcome === "not_committed") return;
    disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
    this.#onMutationOutcomeUnknown?.(pluginInstanceId);
  }

  async #requestJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let response;
    try {
      response = await this.#fetch(this.#apiBaseURL + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "same-origin",
      });
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request failed for ${method} ${path}`, cause);
    }
    return readPlatformResponse<T>(response);
  }

  async #requestMutation<T>(method: "POST" | "PUT" | "PATCH" | "DELETE", path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };
    let response;
    try {
      response = await this.#fetch(this.#apiBaseURL + path, {
        method,
        headers,
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request failed for ${method} ${path}`, cause, "unknown");
    }
    return readMutationPlatformResponse<T>(response);
  }
}

function queryString(values: Record<string, string | number | boolean | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}
