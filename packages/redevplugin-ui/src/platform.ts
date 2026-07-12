import { defaultFetch, readHostEnvelope, trimTrailingSlash, type FetchLike } from "./http.js";
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
};

export type PluginCatalogRecord = Record<string, unknown>;

export type PluginCatalogResult = {
  plugins?: PluginCatalogRecord[];
  [key: string]: unknown;
};

export type PluginCompatibilityMatrix = {
  redevplugin_go_version: string;
  redevplugin_ui_version: string;
  redevplugin_runtime_version: string;
  plugin_ui_protocol_version: string;
  plugin_host_protocol_version: string;
  rust_ipc_version: string;
  wasm_abi_version: string;
  manifest_schema_version: string;
  package_signature_schema_version: string;
  release_metadata_schema_version: string;
  source_policy_schema_version: string;
  source_revocations_schema_version: string;
  token_ticket_schema_version: string;
  bridge_schema_version: string;
  opaque_surface_document_schema_version: string;
  opaque_surface_transport_schema_version: string;
  target_classifier_version: string;
  network_grant_schema_version: string;
  plugin_platform_openapi_version: string;
  compatibility_schema_version: string;
  release_manifest_schema_version: string;
  worker_invocation_schema_version: string;
  error_codes_schema_version: string;
  contract_registry_version: string;
  [key: string]: unknown;
};

export type PluginContractArtifact = {
  id: string;
  path: string;
  version: string;
  sha256: string;
  [key: string]: unknown;
};

export type PluginCompatibilityManifest = {
  schema_version: string;
  matrix: PluginCompatibilityMatrix;
  contracts: PluginContractArtifact[];
  [key: string]: unknown;
};

export type PluginTrustState = "verified" | "unsigned_local" | "untrusted" | "needs_review" | "trust_unavailable" | "blocked_security";
export type PluginEnableState = "disabled" | "enabled" | "disabled_by_policy";
export type PluginRetainedDataRecordState = "retained" | "expired" | "bound" | "deleted" | "delete_failed_retryable";
export type PluginRetainedDataState = "none" | PluginRetainedDataRecordState;

export type PluginTrustHashSet = {
  package_sha256: string;
  manifest_sha256: string;
  entries_sha256: string;
};

export type PluginVerifiedSignature = {
  algorithm: string;
  key_id: string;
};

export type PluginTrustAssessment = {
  trust_state: PluginTrustState | string;
  reason_codes?: string[];
  verified_hashes: PluginTrustHashSet;
  verified_signature?: PluginVerifiedSignature;
  trust_assessment_epoch?: string;
  policy_epoch?: string;
  revocation_epoch?: string;
  metadata?: Record<string, string>;
};

export type PluginLocalImportProvenance = {
  import_id: string;
  distribution: "local_import" | string;
  policy_epoch: string;
  unsigned_policy: "dev_only" | "review_required" | "block" | string;
  assessed_at: string;
};

export type PluginVersionRecord = {
  version: string;
  active_fingerprint: string;
  package_hash: string;
  manifest_hash: string;
  entries_hash: string;
  trust_state: PluginTrustState | string;
  trust_assessment: PluginTrustAssessment;
  source_policy_snapshot_hash?: string;
  source_policy_snapshot?: Record<string, unknown>;
  local_import_provenance?: PluginLocalImportProvenance;
  metadata?: Record<string, string>;
  [key: string]: unknown;
};

export type PluginRecord = {
  plugin_instance_id: string;
  publisher_id?: string;
  plugin_id: string;
  version: string;
  active_fingerprint: string;
  package_hash?: string;
  manifest_hash?: string;
  entries_hash?: string;
  trust_state: PluginTrustState | string;
  trust_assessment: PluginTrustAssessment;
  source_policy_snapshot_hash?: string;
  source_policy_snapshot?: Record<string, unknown>;
  local_import_provenance?: PluginLocalImportProvenance;
  enable_state: PluginEnableState | string;
  disabled_reason?: string;
  retained_data_state?: PluginRetainedDataState | string;
  policy_revision?: number;
  management_revision?: number;
  revoke_epoch?: number;
  manifest?: Record<string, unknown>;
  package_entries?: Array<Record<string, unknown>>;
  version_history?: PluginVersionRecord[];
  installed_at?: string;
  enabled_at?: string;
  updated_at?: string;
  deleted_at?: string;
  metadata?: Record<string, string>;
  [key: string]: unknown;
};

export type PluginPackageHashSet = {
  package_sha256: string;
  manifest_sha256: string;
  entries_sha256: string;
};

export type PluginReleaseRef = {
  source_id: string;
  release_metadata_ref: string;
  release_metadata_sha256: string;
  publisher_id: string;
  plugin_id: string;
  version: string;
  expected_hashes: PluginPackageHashSet;
};

export type PluginInstallReleaseRefRequest = { release_ref: PluginReleaseRef; plugin_instance_id?: string; plugin_state_version: 0 };
export type PluginUpdateReleaseRefRequest = { plugin_instance_id: string; release_ref: PluginReleaseRef; plugin_state_version: number };
export type PluginDowngradeRequest = { plugin_instance_id: string; version?: string; package_hash?: string; plugin_state_version: number };
export type PluginEnableRequest = { plugin_instance_id: string; plugin_state_version: number };
export type PluginDisableRequest = { plugin_instance_id: string; plugin_state_version: number; reason?: string };
export type PluginUninstallRequest = { plugin_instance_id: string; plugin_state_version: number; delete_data: boolean };

export type PluginOpenSurfaceRequest = {
  plugin_instance_id: string;
  surface_id: string;
  surface_instance_id?: string;
  plugin_state_version: number;
};

export type PluginSurfaceScopeRevokeResult = {
  revoked_surface_count: number;
};

export type PluginSurfaceBootstrapResult = {
  plugin_id: string;
  plugin_instance_id: string;
  plugin_version: string;
  surface_id: string;
  surface_instance_id: string;
  active_fingerprint: string;
  entry_path: string;
  entry_sha256: string;
  asset_session_nonce: string;
  plugin_state_version: number;
  revoke_epoch: number;
  runtime_generation_id: string;
  asset_ticket: string;
  asset_ticket_id: string;
  bridge_nonce: string;
  issued_at: string;
  expires_at: string;
};

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
    pluginStateVersion: value.plugin_state_version,
    revokeEpoch: value.revoke_epoch,
    runtimeGenerationId: value.runtime_generation_id,
  };
}

export type PluginRuntimeTarget = { os?: string; arch?: string };
export type PluginRuntimeStartRequest = { target?: PluginRuntimeTarget };
export type PluginRuntimeHealth = {
  runtime_instance_id: string;
  runtime_generation_id: string;
  runtime_version?: string;
  rust_ipc_version?: string;
  wasm_abi_version?: string;
  ready: boolean;
};
export type PluginRuntimeStopResult = { stopped: boolean };
export type PluginRuntimeRefreshResult = { refreshed_plugins: PluginRecord[] };

export type PluginSettingsField = {
  key: string;
  type: string;
  label: string;
  scope: string;
  default?: unknown;
  secret_ref?: string;
  options?: string[];
  validation?: Record<string, unknown>;
};

export type PluginSettingsSchema = {
  plugin_instance_id: string;
  schema_version: number;
  migration?: Record<string, unknown>;
  fields: PluginSettingsField[];
  settings_revision: number;
};

export type PluginSettingsSnapshot = {
  plugin_instance_id: string;
  schema_version: number;
  settings_revision: number;
  values: Record<string, unknown>;
  updated_at: string;
};

export type PluginOperationRecord = {
  operation_id: string;
  plugin_id?: string;
  plugin_instance_id: string;
  method: string;
  effect?: string;
  execution: string;
  surface_instance_id?: string;
  session_channel_id_hash?: string;
  bridge_channel_id?: string;
  status: string;
  disable_behavior?: string;
  uninstall_behavior?: string;
  reason?: string;
  created_at: string;
  updated_at: string;
  cancel_requested_at?: string;
  orphaned_at?: string;
};

export type PluginOperationList = { operations?: PluginOperationRecord[]; [key: string]: unknown };

export type PluginIntentRecord = {
  plugin_id: string;
  plugin_instance_id: string;
  publisher_id: string;
  display_name: string;
  version: string;
  active_fingerprint: string;
  intent_id: string;
  method: string;
  effect: string;
  execution: string;
  payload_schema?: Record<string, unknown>;
};

export type PluginIntentList = { intents?: PluginIntentRecord[]; [key: string]: unknown };
export type PluginIntentListOptions = { intent_id?: string; plugin_instance_id?: string };
export type PluginIntentInvokeRequest = { plugin_instance_id?: string; intent_id: string; params?: Record<string, unknown> };

export type PluginPermissionGrant = {
  plugin_instance_id: string;
  permission_id: string;
  granted_by?: string;
  granted_at?: string;
  revoked_by?: string;
  revoked_at?: string;
  reason?: string;
  expires_at?: string;
  [key: string]: unknown;
};

export type PluginPermissionList = { permissions?: PluginPermissionGrant[]; [key: string]: unknown };
export type PluginPermissionGrantRequest = { plugin_instance_id: string; permission_id: string; granted_by?: string; expires_at?: string };
export type PluginPermissionRevokeRequest = { plugin_instance_id: string; permission_id: string; revoked_by?: string; reason?: string };

export type PluginDataExportRequest = { plugin_instance_id: string; include_secrets?: boolean };
export type PluginDataExportResult = { archive_ref?: string; settings_archive_ref?: string };
export type PluginDataImportRequest = { plugin_instance_id: string; archive_ref?: string; settings_archive_ref?: string; delete_existing?: boolean };

export type PluginRetainedDataRecord = {
  retained_id: string;
  source_plugin_instance_id: string;
  bound_plugin_instance_id?: string;
  publisher_id: string;
  plugin_id: string;
  version: string;
  package_hash: string;
  manifest_hash: string;
  state: PluginRetainedDataRecordState | string;
  storage_retained?: boolean;
  settings_retained?: boolean;
  usage_bytes?: number;
  delete_after?: string;
  delete_error?: string;
  metadata?: Record<string, string>;
  retained_at?: string;
  updated_at?: string;
  bound_at?: string;
  deleted_at?: string;
  last_accessed_at?: string;
  [key: string]: unknown;
};

export type PluginRetainedDataListOptions = {
  publisher_id?: string;
  plugin_id?: string;
  source_plugin_instance_id?: string;
  state?: PluginRetainedDataRecordState | string;
};
export type PluginRetainedDataList = { retained_data?: PluginRetainedDataRecord[]; [key: string]: unknown };
export type PluginRetainedDataBindRequest = { retained_id: string; target_plugin_instance_id: string };
export type PluginRetainedDataCleanupRequest = { retry_failed?: boolean; max_records?: number };
export type PluginRetainedDataCleanupResult = { deleted?: PluginRetainedDataRecord[]; failed?: PluginRetainedDataRecord[]; [key: string]: unknown };

export type PluginSecretRefRequest = { plugin_instance_id: string; secret_ref: string; scope: string };

export type PluginAuditEvent = {
  type: string;
  plugin_id?: string;
  plugin_instance_id?: string;
  occurred_at?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
};
export type PluginAuditEventList = { audit_events?: PluginAuditEvent[]; [key: string]: unknown };
export type PluginAuditListOptions = { plugin_id?: string; plugin_instance_id?: string; type?: string; limit?: number };

export type PluginDiagnosticEvent = {
  type: string;
  severity?: string;
  plugin_id?: string;
  plugin_instance_id?: string;
  surface_instance_id?: string;
  occurred_at?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
};
export type PluginDiagnosticEventList = { diagnostic_events?: PluginDiagnosticEvent[]; [key: string]: unknown };
export type PluginDiagnosticListOptions = { plugin_id?: string; plugin_instance_id?: string; surface_instance_id?: string; type?: string; severity?: string; limit?: number };

export class PluginPlatformClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #surfaceScope: PluginSurfaceScope;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#surfaceScope = options.surfaceScope ?? defaultPluginSurfaceScope;
  }

  catalog(): Promise<PluginCatalogResult> { return this.#getJSON("/_redevplugin/api/plugins/catalog"); }
  getCompatibility(): Promise<PluginCompatibilityManifest> { return this.#getJSON("/_redevplugin/api/plugins/platform/compatibility"); }
  installReleaseRef(request: PluginInstallReleaseRefRequest): Promise<PluginRecord> { return this.#postJSON("/_redevplugin/api/plugins/install-release-ref", request); }
  updateReleaseRef(request: PluginUpdateReleaseRefRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/update-release-ref", request); }
  downgradePlugin(request: PluginDowngradeRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/downgrade", request); }
  enablePlugin(request: PluginEnableRequest): Promise<PluginRecord> { return this.#postJSON("/_redevplugin/api/plugins/enable", request); }
  disablePlugin(request: PluginDisableRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/disable", request); }
  uninstallPlugin(request: PluginUninstallRequest): Promise<PluginRecord> { return this.#mutatePlugin("/_redevplugin/api/plugins/uninstall", request); }
  openSurface(request: PluginOpenSurfaceRequest): Promise<PluginSurfaceBootstrapResult> { return this.#postJSON("/_redevplugin/api/plugins/surfaces/open", request); }
  async revokeSurfaceScope(): Promise<PluginSurfaceScopeRevokeResult> {
    try {
      return await this.#postJSON("/_redevplugin/api/plugins/surfaces/revoke-scope", {});
    } finally {
      disposePluginSurfaceScope(this.#surfaceScope);
    }
  }
  startRuntime(request: PluginRuntimeStartRequest = {}): Promise<PluginRuntimeHealth> { return this.#postJSON("/_redevplugin/api/plugins/runtime/start", request); }
  async stopRuntime(): Promise<PluginRuntimeStopResult> {
    try {
      return await this.#postJSON("/_redevplugin/api/plugins/runtime/stop", {});
    } finally {
      disposePluginSurfaceScope(this.#surfaceScope);
    }
  }
  refreshEnabledRuntimeState(): Promise<PluginRuntimeRefreshResult> { return this.#postJSON("/_redevplugin/api/plugins/runtime/refresh-enabled", {}); }
  runtimeHealth(): Promise<PluginRuntimeHealth> { return this.#getJSON("/_redevplugin/api/plugins/runtime/health"); }
  getSettingsSchema(pluginInstanceId: string): Promise<PluginSettingsSchema> { return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema`); }
  getSettings(pluginInstanceId: string): Promise<PluginSettingsSnapshot> { return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`); }
  patchSettings(pluginInstanceId: string, values: Record<string, unknown>): Promise<PluginSettingsSnapshot> { return this.#patchJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`, { values }); }
  listOperations(pluginInstanceId?: string): Promise<PluginOperationList> { return this.#getJSON(`/_redevplugin/api/plugins/operations${pluginInstanceId ? `?plugin_instance_id=${encodeURIComponent(pluginInstanceId)}` : ""}`); }
  getOperation(operationId: string): Promise<PluginOperationRecord> { return this.#getJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}`); }
  cancelOperation(operationId: string, reason?: string): Promise<PluginOperationRecord> { return this.#postJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`, reason ? { reason } : {}); }

  listIntents(options: PluginIntentListOptions = {}): Promise<PluginIntentList> {
    const params = new URLSearchParams();
    if (options.intent_id) params.set("intent_id", options.intent_id);
    if (options.plugin_instance_id) params.set("plugin_instance_id", options.plugin_instance_id);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/intents${query ? `?${query}` : ""}`);
  }

  invokeIntent<T = unknown>(request: PluginIntentInvokeRequest): Promise<PluginTrustedMethodResult<T>> {
    return this.#postJSON("/_redevplugin/api/plugins/intents/invoke", request);
  }

  exportData(request: PluginDataExportRequest): Promise<PluginDataExportResult> { return this.#postJSON("/_redevplugin/api/plugins/data/export", request); }
  importData(request: PluginDataImportRequest): Promise<Record<string, unknown>> { return this.#postJSON("/_redevplugin/api/plugins/data/import", request); }

  listRetainedData(options: PluginRetainedDataListOptions = {}): Promise<PluginRetainedDataList> {
    const params = new URLSearchParams();
    if (options.publisher_id) params.set("publisher_id", options.publisher_id);
    if (options.plugin_id) params.set("plugin_id", options.plugin_id);
    if (options.source_plugin_instance_id) params.set("source_plugin_instance_id", options.source_plugin_instance_id);
    if (options.state) params.set("state", options.state);
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/retained-data${query ? `?${query}` : ""}`);
  }

  deleteRetainedData(retainedId: string): Promise<PluginRetainedDataRecord> { return this.#postJSON("/_redevplugin/api/plugins/retained-data/delete", { retained_id: retainedId }); }
  bindRetainedData(request: PluginRetainedDataBindRequest): Promise<PluginRetainedDataRecord> { return this.#postJSON("/_redevplugin/api/plugins/retained-data/bind", request); }
  cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest = {}): Promise<PluginRetainedDataCleanupResult> { return this.#postJSON("/_redevplugin/api/plugins/retained-data/cleanup-expired", request); }

  listPermissions(pluginInstanceId?: string, activeOnly?: boolean): Promise<PluginPermissionList> {
    const params = new URLSearchParams();
    if (pluginInstanceId) params.set("plugin_instance_id", pluginInstanceId);
    if (activeOnly != null) params.set("active_only", activeOnly ? "true" : "false");
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/permissions${query ? `?${query}` : ""}`);
  }

  grantPermission(request: PluginPermissionGrantRequest): Promise<PluginPermissionGrant> { return this.#postJSON("/_redevplugin/api/plugins/permissions/grant", request); }
  revokePermission(request: PluginPermissionRevokeRequest): Promise<PluginPermissionGrant> { return this.#postJSON("/_redevplugin/api/plugins/permissions/revoke", request); }
  bindSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> { return this.#postJSON("/_redevplugin/api/plugins/secrets/bind", request); }
  testSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> { return this.#postJSON("/_redevplugin/api/plugins/secrets/test", request); }
  deleteSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> { return this.#postJSON("/_redevplugin/api/plugins/secrets/delete", request); }
  listAuditEvents(options: PluginAuditListOptions = {}): Promise<PluginAuditEventList> { return this.#getJSON(`/_redevplugin/api/plugins/audit${queryString(options)}`); }
  listDiagnosticEvents(options: PluginDiagnosticListOptions = {}): Promise<PluginDiagnosticEventList> { return this.#getJSON(`/_redevplugin/api/plugins/diagnostics${queryString(options)}`); }

  #getJSON<T>(path: string): Promise<T> { return this.#requestJSON<T>("GET", path); }
  #postJSON<T>(path: string, body: unknown): Promise<T> { return this.#requestJSON<T>("POST", path, body); }
  #patchJSON<T>(path: string, body: unknown): Promise<T> { return this.#requestJSON<T>("PATCH", path, body); }

  async #mutatePlugin<T extends { plugin_instance_id: string }>(path: string, request: T): Promise<PluginRecord> {
    try {
      return await this.#postJSON<PluginRecord>(path, request);
    } finally {
      disposePluginSurfaceScope(this.#surfaceScope, request.plugin_instance_id);
    }
  }

  async #requestJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await this.#fetch(this.#apiBaseURL + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
    return readHostEnvelope<T>(response, "PLUGIN_PLATFORM_REQUEST_FAILED");
  }
}

function queryString(values: Record<string, string | number | boolean | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value != null && value !== "") params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}
