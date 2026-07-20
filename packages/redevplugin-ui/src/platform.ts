import {
  assertMutationDispatchable,
  defaultFetch,
  dispatchMutationRequest,
  dispatchQueryRequest,
  readMutationPlatformResponse,
  readPlatformResponse,
  trimTrailingSlash,
  type FetchLike,
} from "./http.js";
import {
  PluginBridgeError,
  PluginMutationLifecycleError,
  PluginTransportError,
  pluginMutationOutcome,
} from "./errors.js";
import type { components } from "./openapi.gen.js";
import {
  createReDevPluginSurfaceTransport,
  openPluginSurfaceInSlot,
  type PluginConfirmationHandler,
  type PluginSurfaceHost,
  type PluginSurfaceHostBootstrap,
  type PluginSurfaceOpeningProgress,
  type PluginSurfaceReloadLimiter,
  type PluginSurfaceSlot,
  type PluginTrustedMethodResult,
  type ReDevPluginSurfaceTransport,
} from "./surface.js";
import {
  defaultPluginSurfaceScope,
  disposePluginSurfaceScope,
  invalidatePluginSurfaceScope,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export type PluginPlatformClientOptions = {
  fetch?: FetchLike;
  apiBaseURL?: string;
  surfaceScope?: PluginSurfaceScope;
  surfaceTransport?: ReDevPluginSurfaceTransport;
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
export type PluginOpenSurfaceInSlotOptions = PluginRequestOptions & {
  bridgeChannelId?: string;
  loadTimeoutMs?: number;
  requestTimeoutMs?: number;
  leaseRenewalLeadMs?: number;
  reloadLimiter?: PluginSurfaceReloadLimiter;
  confirm?: PluginConfirmationHandler;
  onOpeningProgress?: (progress: PluginSurfaceOpeningProgress) => void;
  onError?: (error: import("./errors.js").PluginBridgeError) => void;
};

export type PluginSessionScopeRevokeCounts = Readonly<PlatformSchemas["SessionScopeRevokeCounts"]>;
export type PluginSessionScopeRevokeResult = Readonly<PlatformSchemas["SessionScopeRevokeCompleteResult"]>;
export type PluginSessionScopeState = PluginSessionScopeRevokeResult["state"];

export type PluginSurfaceBootstrapResult = PlatformSchemas["SurfaceBootstrap"];

function toPluginSurfaceHostBootstrap(value: PluginSurfaceBootstrapResult): PluginSurfaceHostBootstrap {
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
/** Negotiated limits reported by runtime health; configuration is Host-owned. */
export type PluginRuntimeLimits = Readonly<PlatformSchemas["RuntimeLimits"]>;
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
export type PluginPublicOperationBinding = PlatformSchemas["PublicOperationBinding"];
export type PluginOperationRecord = PlatformSchemas["OperationRecord"];
export type PluginOperationList = PlatformSchemas["PluginOperationList"];
export type PluginOperationListOptions = PlatformSchemas["ListOperationsQueryRequest"];

export type PluginIntentRecord = PlatformSchemas["PluginIntentRecord"];
export type PluginIntentList = PlatformSchemas["PluginIntentList"];
export type PluginIntentListOptions = PlatformSchemas["ListIntentsQueryRequest"];
export type PluginIntentInvokeRequest = PlatformSchemas["InvokeIntentRequest"];

export type PluginPermissionGrant = PlatformSchemas["PluginPermissionGrant"];
export type PluginPermissionMutationResult = PlatformSchemas["PluginPermissionMutationResult"];
export type PluginPermissionList = PlatformSchemas["PluginPermissionList"];
export type PluginPermissionListOptions = PlatformSchemas["ListPermissionsQueryRequest"];
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
export type PluginRetainedDataListOptions = PlatformSchemas["ListRetainedDataQueryRequest"];
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
export type PluginDiagnosticDetails = PlatformSchemas["PluginDiagnosticDetails"];
export type PluginDiagnosticMutationOutcome = PlatformSchemas["DiagnosticMutationOutcome"];
export type PluginDiagnosticListOptions = PlatformSchemas["ListDiagnosticsQueryRequest"];
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
    this.#surfaceTransport = options.surfaceTransport;
    this.#onMutationOutcomeUnknown = options.onMutationOutcomeUnknown;
  }

  catalog(options: PluginRequestOptions = {}): Promise<PluginCatalogResult> { return this.#requestQuery("/_redevplugin/api/plugins/catalog/query", {}, options); }
  features(options: PluginRequestOptions = {}): Promise<PluginFeatures> { return this.#requestQuery("/_redevplugin/api/plugins/features/query", {}, options); }
  getCompatibility(options: PluginRequestOptions = {}): Promise<PluginCompatibilityManifest> { return this.#requestQuery("/_redevplugin/api/plugins/platform/compatibility/query", {}, options); }
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
  #openSurface(request: PluginOpenSurfaceRequest): Promise<PluginSurfaceBootstrapResult> {
    return this.#requestMutation("POST", "/_redevplugin/api/plugins/surfaces/open", request, {});
  }
  openSurfaceInSlot(
    slot: PluginSurfaceSlot,
    request: PluginOpenSurfaceRequest,
    options: PluginOpenSurfaceInSlotOptions = {},
  ): Promise<PluginSurfaceHost> {
    const { signal, ...hostOptions } = options;
    const pluginInstanceId = typeof request.plugin_instance_id === "string"
      ? request.plugin_instance_id.trim()
      : "";
    if (!pluginInstanceId) {
      return Promise.reject(new PluginBridgeError(
        "PLUGIN_INVALID_REQUEST",
        "Plugin surface opening requires a canonical plugin instance identifier",
      ));
    }
    if (signal?.aborted) {
      return Promise.reject(new PluginTransportError(
        "Plugin surface opening was aborted before dispatch",
        signal.reason,
        "not_committed",
      ));
    }
    const surfaceTransport = this.#surfaceTransport ??= createReDevPluginSurfaceTransport({
      fetch: this.#fetch,
      apiBaseURL: surfaceTransportAPIBaseURL(this.#apiBaseURL),
    });
    const canonicalRequest: PluginOpenSurfaceRequest = {
      ...request,
      plugin_instance_id: pluginInstanceId,
    };
    return openPluginSurfaceInSlot(slot, {
      pluginInstanceId,
      surfaceScope: this.#surfaceScope,
      signal,
      abortError: () => new PluginTransportError(
        "Plugin surface opening was aborted after dispatch",
        signal?.reason,
        "unknown",
      ),
      open: () => this.#openSurface(canonicalRequest).then((result) => ({
        ...hostOptions,
        bootstrap: toPluginSurfaceHostBootstrap(result),
        hostTransport: surfaceTransport,
        surfaceScope: this.#surfaceScope,
      })),
    });
  }
  async revokeSessionScope(options: PluginRequestOptions = {}): Promise<PluginSessionScopeRevokeResult> {
    let result: PluginSessionScopeRevokeResult;
    try {
      const raw = await this.#requestMutation<unknown>("POST", "/_redevplugin/api/plugins/session/revoke-scope", {}, options);
      if (!isPluginSessionScopeRevokeResult(raw)) {
        throw new PluginTransportError(
          "Plugin session scope revocation returned an invalid result",
          new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Invalid session scope revocation result"),
          "unknown",
        );
      }
      result = raw;
    } catch (error) {
      await this.#handleSessionRevokeFailure(error);
      throw error;
    }
    await invalidatePluginSurfaceScope(this.#surfaceScope);
    return result;
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
  runtimeHealth(options: PluginRequestOptions = {}): Promise<PluginRuntimeHealth> { return this.#requestQuery("/_redevplugin/api/plugins/runtime/health/query", {}, options); }
  getSettingsSchema(pluginInstanceId: string, scope: PluginResourceScopeKind, options: PluginRequestOptions = {}): Promise<PluginSettingsSchema> {
    return this.#requestQuery(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema/query`, { scope }, options);
  }
  getSettings(pluginInstanceId: string, scope: PluginResourceScopeKind, options: PluginRequestOptions = {}): Promise<PluginSettingsSnapshot> {
    return this.#requestQuery(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/query`, { scope }, options);
  }
  patchSettings(pluginInstanceId: string, request: PluginSettingsPatchRequest, options: PluginRequestOptions = {}): Promise<PluginSettingsSnapshot> {
    return this.#mutatePluginAt("PATCH", `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`, pluginInstanceId, request, options);
  }
  listOperations(options: PluginOperationListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginOperationList> {
    return this.#requestQuery("/_redevplugin/api/plugins/operations/query", options, requestOptions);
  }
  getOperation(operationId: string, options: PluginRequestOptions = {}): Promise<PluginOperationRecord> {
    return this.#requestQuery(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/query`, {}, options);
  }
  cancelOperation(operationId: string, reason?: string, options: PluginRequestOptions = {}): Promise<PluginOperationRecord> {
    return this.#requestMutation("POST", `/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`, reason ? { reason } : {}, options);
  }

  listIntents(options: PluginIntentListOptions = {}, requestOptions: PluginRequestOptions = {}): Promise<PluginIntentList> {
    return this.#requestQuery("/_redevplugin/api/plugins/intents/query", options, requestOptions);
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
    return this.#requestQuery("/_redevplugin/api/plugins/retained-data/query", options, requestOptions);
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
    return this.#requestQuery("/_redevplugin/api/plugins/permissions/query", options, requestOptions);
  }

  grantPermission(request: PluginPermissionGrantRequest, options: PluginRequestOptions = {}): Promise<PluginPermissionMutationResult> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/grant", request, options);
  }
  revokePermission(request: PluginPermissionRevokeRequest, options: PluginRequestOptions = {}): Promise<PluginPermissionMutationResult> {
    return this.#mutatePlugin("/_redevplugin/api/plugins/permissions/revoke", request, options);
  }
  listSecurityPolicies(options: PluginRequestOptions = {}): Promise<PluginSecurityPolicyList> {
    return this.#requestQuery("/_redevplugin/api/plugins/security-policies/query", {}, options);
  }
  getSecurityPolicy(pluginInstanceId: string, options: PluginRequestOptions = {}): Promise<PluginSecurityPolicy> {
    return this.#requestQuery(`/_redevplugin/api/plugins/security-policies/${encodeURIComponent(pluginInstanceId)}/query`, {}, options);
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
    return this.#requestQuery("/_redevplugin/api/plugins/diagnostics/query", options, requestOptions);
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
    let result: Result;
    try {
      result = await this.#requestMutation<Result>(method, path, request, options);
    } catch (error) {
      await this.#handleMutationFailure(error, pluginInstanceId, "Plugin mutation and local surface teardown failed");
      throw error;
    }
    await disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
    return result;
  }

  async #handleMutationFailure(error: unknown, pluginInstanceId: string | undefined, message: string): Promise<void> {
    const outcome = pluginMutationOutcome(error);
    if (outcome === "not_committed" || outcome === undefined) return;
    const lifecycleErrors: unknown[] = [];
    try {
      await disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
    } catch (caught) {
      lifecycleErrors.push(caught);
    }
    if (outcome === "unknown") {
      try {
        this.#onMutationOutcomeUnknown?.(pluginInstanceId);
      } catch (caught) {
        lifecycleErrors.push(caught);
      }
    }
    if (lifecycleErrors.length > 0) throw new PluginMutationLifecycleError(message, error, lifecycleErrors);
  }

  async #handleSessionRevokeFailure(error: unknown): Promise<void> {
    const outcome = pluginMutationOutcome(error);
    if (outcome === "not_committed") return;
    const lifecycleErrors: unknown[] = [];
    if (outcome === "committed" || outcome === "unknown") {
      try {
        await invalidatePluginSurfaceScope(this.#surfaceScope);
      } catch (caught) {
        lifecycleErrors.push(caught);
      }
    }
    if (outcome === "unknown") {
      try {
        this.#onMutationOutcomeUnknown?.();
      } catch (caught) {
        lifecycleErrors.push(caught);
      }
    }
    if (lifecycleErrors.length > 0) {
      throw new PluginMutationLifecycleError(
        "Plugin session scope revocation and local invalidation failed",
        error,
        lifecycleErrors,
      );
    }
  }

  async #requestQuery<T>(path: string, body: unknown, options: PluginRequestOptions): Promise<T> {
    const operation = `POST ${path}`;
    let encodedBody: string;
    try {
      encodedBody = JSON.stringify(body);
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform query body serialization failed for ${operation}`, cause);
    }
    const response = await dispatchQueryRequest(this.#fetch, this.#apiBaseURL + path, {
      method: "POST",
      headers: { "Accept": "application/json", "Content-Type": "application/json" },
      body: encodedBody,
      credentials: "same-origin",
      signal: options.signal,
    }, operation);
    return readPlatformResponse<T>(response);
  }

  async #requestMutation<T>(
    method: "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    body: unknown,
    options: PluginRequestOptions,
  ): Promise<T> {
    const operation = `${method} ${path}`;
    assertMutationDispatchable(options.signal, operation);
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };
    let encodedBody: string | undefined;
    try {
      encodedBody = JSON.stringify(body);
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request body serialization failed for ${operation}`, cause, "not_committed");
    }
    const response = await dispatchMutationRequest(this.#fetch, this.#apiBaseURL + path, {
      method,
      headers,
      body: encodedBody,
      credentials: "same-origin",
      signal: options.signal,
    }, operation);
    return readMutationPlatformResponse<T>(response);
  }
}

const sessionScopeCountKeys = [
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
] as const;

function isPluginSessionScopeRevokeResult(value: unknown): value is PluginSessionScopeRevokeResult {
  if (!isExactRecord(value, ["state", "fenced", "complete", "counts"]) ||
      value.state !== "complete" || value.fenced !== true || value.complete !== true) return false;
  const counts = value.counts;
  if (!isExactRecord(counts, sessionScopeCountKeys)) return false;
  return sessionScopeCountKeys.every((key) => Number.isSafeInteger(counts[key]) && Number(counts[key]) >= 0);
}

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
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
