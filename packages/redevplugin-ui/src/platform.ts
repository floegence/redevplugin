import { defaultFetch, readMutationPlatformResponse, readPlatformResponse, trimTrailingSlash, type FetchLike } from "./http.js";
import { PluginPlatformRequestError, PluginTransportError } from "./errors.js";
import type { components, operations } from "./openapi.gen.js";
import {
  createReDevPluginSurfaceTransport,
  type PluginSurfaceHost,
  type PluginSurfaceHostBootstrap,
  type PluginSurfaceHostOptions,
  type PluginSurfaceSlot,
  type PluginTrustedMethodResult,
  type ReDevPluginSurfaceTransport,
} from "./surface.js";
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

export type PluginRequestOptions = {
  signal?: AbortSignal;
};

type PlatformSchemas = components["schemas"];

export type PluginCatalogResult = PlatformSchemas["PluginCatalogResult"];
export type PluginCatalogRecord = PluginCatalogResult["plugins"][number];
export type PluginFeatures = PlatformSchemas["PluginFeaturesSuccessResponse"]["data"];
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
export type PluginOpenSurfaceInSlotOptions =
  Omit<PluginSurfaceHostOptions, "bootstrap" | "hostTransport" | "surfaceScope"> & PluginRequestOptions;

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
export type PluginResourceScopeKind = PlatformSchemas["ResourceScopeKind"];
type PluginSettingsPatchBase = Pick<PlatformSchemas["PatchSettingsRequest"], "scope" | "expected_values_revision">;
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
  #surfaceTransport?: ReDevPluginSurfaceTransport;
  #onMutationOutcomeUnknown?: (pluginInstanceId?: string) => void;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#surfaceScope = options.surfaceScope ?? defaultPluginSurfaceScope;
    this.#onMutationOutcomeUnknown = options.onMutationOutcomeUnknown;
  }

  catalog(options: PluginRequestOptions = {}): Promise<PluginCatalogResult> { return this.#getJSON("/_redevplugin/api/plugins/catalog", options); }
  features(options: PluginRequestOptions = {}): Promise<PluginFeatures> { return this.#getJSON("/_redevplugin/api/plugins/features", options); }
  getCompatibility(options: PluginRequestOptions = {}): Promise<PluginCompatibilityManifest> { return this.#getJSON("/_redevplugin/api/plugins/platform/compatibility", options); }
  installReleaseRef(request: PluginInstallReleaseRefRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/install-release-ref", request, options);
  }
  updateReleaseRef(request: PluginUpdateReleaseRefRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/update-release-ref", request, options);
  }
  downgradePlugin(request: PluginDowngradeRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/downgrade", request, options);
  }
  enablePlugin(request: PluginEnableRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/enable", request, options);
  }
  disablePlugin(request: PluginDisableRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/disable", request, options);
  }
  uninstallPlugin(request: PluginUninstallRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/uninstall", request, options);
  }
  openSurface(request: PluginOpenSurfaceRequest, options: PluginRequestOptions = {}): Promise<PluginSurfaceBootstrapResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/surfaces/open", request, options);
  }
  openSurfaceInSlot(
    slot: PluginSurfaceSlot,
    request: PluginOpenSurfaceRequest,
    options: PluginOpenSurfaceInSlotOptions = {},
  ): Promise<PluginSurfaceHost> {
    const { signal, ...hostOptions } = options;
    const surfaceTransport = this.#surfaceTransport ??= createReDevPluginSurfaceTransport({
      fetch: this.#fetch,
      apiBaseURL: surfaceTransportAPIBaseURL(this.#apiBaseURL),
    });
    return slot.open(this.openSurface(request, { signal }).then((result) => ({
      ...hostOptions,
      bootstrap: toPluginSurfaceHostBootstrap(result),
      hostTransport: surfaceTransport,
      surfaceScope: this.#surfaceScope,
    })));
  }
  async revokeSurfaceScope(options: PluginRequestOptions = {}): Promise<PluginSurfaceScopeRevokeResult> {
    try {
      const result = await this.#requestMutation<PluginSurfaceScopeRevokeResult>("POST", "/_redevplugin/api/plugins/surfaces/revoke-scope", {}, options);
      disposePluginSurfaceScope(this.#surfaceScope);
      return result;
    } catch (error) {
      this.#handleMutationFailure(error);
      throw error;
    }
  }
  startRuntime(request: PluginRuntimeStartRequest, options: PluginRequestOptions = {}): Promise<PluginRuntimeHealth> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/runtime/start", request, options);
  }
  stopRuntime(options: PluginRequestOptions = {}): Promise<PluginRuntimeStopResult> {
    return this.#requestMutation<PluginRuntimeStopResult>("POST", "/_redevplugin/api/plugins/runtime/stop", {}, options);
  }
  refreshEnabledRuntimeState(options: PluginRequestOptions = {}): Promise<PluginRuntimeRefreshResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/runtime/refresh-enabled", {}, options);
  }
  runtimeHealth(options: PluginRequestOptions = {}): Promise<PluginRuntimeHealth> { return this.#getJSON("/_redevplugin/api/plugins/runtime/health", options); }
  getSettingsSchema(pluginInstanceId: string, scope: PluginResourceScopeKind, options: PluginRequestOptions = {}): Promise<PluginSettingsSchema> {
    return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema?scope=${encodeURIComponent(scope)}`, options);
  }
  getSettings(pluginInstanceId: string, scope: PluginResourceScopeKind, options: PluginRequestOptions = {}): Promise<PluginSettingsSnapshot> {
    return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings?scope=${encodeURIComponent(scope)}`, options);
  }
  patchSettings(pluginInstanceId: string, request: PluginSettingsPatchRequest, options: PluginRequestOptions = {}): Promise<PluginSettingsSnapshot> {
    return this.#mutatePluginAt("PATCH", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`, pluginInstanceId, request, options);
  }
  listOperations(options: PluginOperationListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginOperationList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id) params.set("plugin_instance_id", options.plugin_instance_id);
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/operations${query ? `?${query}` : ""}`, requestOptions);
  }
  getOperation(operationId: string, options: PluginRequestOptions = {}): Promise<PluginOperationRecord> {
    return this.#getJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}`, options);
  }
  cancelOperation(operationId: string, reason?: string, options: PluginRequestOptions = {}): Promise<PluginOperationRecord> {
    return this.#requestMutation("POST", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`, reason ? { reason } : {}, options);
  }

  listIntents(options: PluginIntentListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginIntentList> {
    const params = new URLSearchParams();
    if (options.intent_id !== undefined) params.set("intent_id", options.intent_id);
    if (options.plugin_instance_id !== undefined) params.set("plugin_instance_id", options.plugin_instance_id);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/intents${query ? `?${query}` : ""}`, requestOptions);
  }

  invokeIntent<T = unknown>(request: PluginIntentInvokeRequest, options: PluginRequestOptions = {}): Promise<PluginTrustedMethodResult<T>> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/intents/invoke", request, options);
  }

  exportData(request: PluginDataExportRequest, options: PluginRequestOptions = {}): Promise<PluginDataExportResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/data/export", request, options);
  }
  deleteDataExport(request: PluginDataExportDeleteRequest, options: PluginRequestOptions = {}): Promise<PluginDataExportDeleteResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/data/export/delete", request, options);
  }
  importData(request: PluginDataImportRequest, options: PluginRequestOptions = {}): Promise<PluginRecord> {
    return this.#mutatePluginAt("POST", "/_redevplugin/api/plugins/data/import", request.plugin_instance_id, request, options);
  }

  listRetainedData(options: PluginRetainedDataListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginRetainedDataList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id) params.set("plugin_instance_id", options.plugin_instance_id);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/retained-data${query ? `?${query}` : ""}`, requestOptions);
  }

  deleteRetainedData(request: PluginRetainedDataDeleteRequest, options: PluginRequestOptions = {}): Promise<PluginDataBinding> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/delete", request, options);
  }
  bindRetainedData(request: PluginRetainedDataBindRequest, options: PluginRequestOptions = {}): Promise<PluginDataBinding> {
    return this.#mutatePluginAt("POST", "/_redevplugin/api/plugins/retained-data/bind", request.target_plugin_instance_id, request, options);
  }
  cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest = {}, options: PluginRequestOptions = {}): Promise<PluginRetainedDataCleanupResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/retained-data/cleanup-expired", request, options);
  }

  listPermissions(options: PluginPermissionListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginPermissionList> {
    const params = new URLSearchParams();
    if (options.plugin_instance_id !== undefined) params.set("plugin_instance_id", options.plugin_instance_id);
    if (options.active_only !== undefined) params.set("active_only", options.active_only ? "true" : "false");
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/permissions${query ? `?${query}` : ""}`, requestOptions);
  }

  grantPermission(request: PluginPermissionGrantRequest, options: PluginRequestOptions = {}): Promise<PluginPermissionMutationResult> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/grant", request, options);
  }
  revokePermission(request: PluginPermissionRevokeRequest, options: PluginRequestOptions = {}): Promise<PluginPermissionMutationResult> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/revoke", request, options);
  }
  listSecurityPolicies(options: PluginRequestOptions = {}): Promise<PluginSecurityPolicyList> {
    return this.#getJSON("/_redevplugin/api/plugins/security-policies", options);
  }
  getSecurityPolicy(pluginInstanceId: string, options: PluginRequestOptions = {}): Promise<PluginSecurityPolicy> {
    return this.#getJSON(`/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`, options);
  }
  putSecurityPolicy(pluginInstanceId: string, request: PluginSecurityPolicyPutRequest, options: PluginRequestOptions = {}): Promise<PluginSecurityPolicy> {
    return this.#mutatePluginAt("PUT", `/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`, pluginInstanceId, request, options);
  }
  deleteSecurityPolicy(pluginInstanceId: string, request: PluginSecurityPolicyDeleteRequest, options: PluginRequestOptions = {}): Promise<PluginSecurityPolicyDeleteResult> {
    return this.#mutatePluginAt("DELETE", `/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}`, pluginInstanceId, request, options);
  }
  bindSecret(request: PluginSecretRefRequest, options: PluginRequestOptions = {}): Promise<PluginSecretBindResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/bind", request, options);
  }
  testSecret(request: PluginSecretRefRequest, options: PluginRequestOptions = {}): Promise<PluginSecretTestResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/test", request, options);
  }
  deleteSecret(request: PluginSecretRefRequest, options: PluginRequestOptions = {}): Promise<PluginSecretDeleteResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/secrets/delete", request, options);
  }
  listDiagnosticEvents(options: PluginDiagnosticListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginDiagnosticEventList> {
    return this.#getJSON(`/_redevplugin/api/plugins/diagnostics${queryString(options)}`, requestOptions);
  }

  #getJSON<T>(path: string, options: PluginRequestOptions): Promise<T> {
    return this.#requestJSON<T>("GET", path, options);
  }
  #mutatePlugin<Result>(
    path: string,
    request: { plugin_instance_id: string } & Record<string, unknown>,
    options: PluginRequestOptions,
  ): Promise<Result> {
    return this.#mutatePluginAt("POST", path, request.plugin_instance_id, request, options);
  }

  async #mutatePluginAt<Result>(
    method: "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    pluginInstanceId: string,
    request: unknown,
    options: PluginRequestOptions,
  ): Promise<Result> {
    try {
      const result = await this.#requestMutation<Result>(method, path, request, options);
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

  async #requestJSON<T>(method: string, path: string, options: PluginRequestOptions): Promise<T> {
    let response;
    try {
      response = await this.#fetch(this.#apiBaseURL + path, {
        method,
        headers: { "Accept": "application/json" },
        credentials: "same-origin",
        signal: options.signal,
      });
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request failed for ${method} ${path}`, cause);
    }
    return readPlatformResponse<T>(response);
  }

  async #requestMutation<T>(
    method: "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    body: unknown,
    options: PluginRequestOptions,
  ): Promise<T> {
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
        signal: options.signal,
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

function surfaceTransportAPIBaseURL(value: string): string {
  if (!value || value.startsWith("/")) return value;
  const parsed = new URL(value);
  const currentOrigin = (globalThis as { location?: { origin?: string } }).location?.origin;
  if (!currentOrigin || currentOrigin === "null" || parsed.origin !== currentOrigin ||
      parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new TypeError("Plugin surface transport apiBaseURL must be same-origin");
  }
  return trimTrailingSlash(parsed.pathname);
}
