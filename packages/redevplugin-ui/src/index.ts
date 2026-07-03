export type BridgeLifecycleEvent =
  | { type: "ready" }
  | { type: "visible" }
  | { type: "hidden" }
  | { type: "dispose" };

export const pluginPlatformErrorCodes = [
  "PLUGIN_INVALID_REQUEST",
  "PLUGIN_MANIFEST_INVALID",
  "PLUGIN_PACKAGE_INVALID",
  "PLUGIN_PACKAGE_TOO_LARGE",
  "PLUGIN_PACKAGE_PATH_FORBIDDEN",
  "PLUGIN_SIGNATURE_INVALID",
  "PLUGIN_TRUST_STATE_DENIED",
  "PLUGIN_TRUST_VERIFICATION_REQUIRED",
  "PLUGIN_TRUST_VERIFICATION_INVALID",
  "PLUGIN_DISABLED",
  "PLUGIN_DISABLED_BY_POLICY",
  "PLUGIN_PERMISSION_DENIED",
  "PLUGIN_CONFIRMATION_REQUIRED",
  "PLUGIN_CONFIRMATION_INVALID",
  "PLUGIN_TOKEN_EXPIRED",
  "PLUGIN_TOKEN_REPLAY",
  "PLUGIN_GATEWAY_TOKEN_INVALID",
  "PLUGIN_GATEWAY_TOKEN_REPLAYED",
  "PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH",
  "PLUGIN_ASSET_TICKET_INVALID",
  "PLUGIN_ASSET_SESSION_INVALID",
  "PLUGIN_STREAM_TICKET_INVALID",
  "PLUGIN_STREAM_CANCELLED",
  "PLUGIN_LEASE_INVALID",
  "PLUGIN_LEASE_REPLAYED",
  "PLUGIN_GRANT_INVALID",
  "PLUGIN_STORAGE_QUOTA_EXCEEDED",
  "PLUGIN_OPERATION_BLOCKED",
  "PLUGIN_OPERATION_NOT_FOUND",
  "PLUGIN_OPERATION_NOT_CANCELABLE",
  "PLUGIN_NETWORK_TARGET_DENIED",
  "PLUGIN_NETWORK_RATE_LIMITED",
  "PLUGIN_RUNTIME_UNAVAILABLE",
  "PLUGIN_RUNTIME_VERSION_MISMATCH",
  "PLUGIN_JSON_LIMIT_EXCEEDED",
  "PLUGIN_CONTRACT_MISMATCH",
  "PLUGIN_CSRF_REQUIRED",
  "PLUGIN_RETAINED_DATA_CLEANUP_FAILED",
  "PLUGIN_RETAINED_DATA_BIND_FAILED",
] as const;

export const pluginBridgeErrorCodes = [
  ...pluginPlatformErrorCodes,
  "PLUGIN_CONFIRMATION_REJECTED",
  "PLUGIN_BRIDGE_TIMEOUT",
  "PLUGIN_BRIDGE_DISPOSED",
  "PLUGIN_BRIDGE_HANDSHAKE_FAILED",
  "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED",
] as const;

export const pluginClientErrorCodes = [
  ...pluginBridgeErrorCodes,
  "PLUGIN_PLATFORM_REQUEST_FAILED",
  "PLUGIN_STREAM_FAILED",
] as const;

export type PluginPlatformErrorCode = typeof pluginPlatformErrorCodes[number];
export type PluginBridgeErrorCode = typeof pluginBridgeErrorCodes[number];
export type PluginClientErrorCode = typeof pluginClientErrorCodes[number];

export type PluginBridgeHandshake = {
  type: "redevplugin.bridge.handshake";
  plugin_id: string;
  surface_id: string;
  surface_instance_id: string;
  active_fingerprint: string;
  bridge_nonce: string;
  ui_protocol_version: "plugin-ui-v1";
};

export type PluginBridgeRequest = {
  id: string;
  method: string;
  params?: unknown;
};

export type PluginBridgeResponse =
  | { type: "redevplugin.bridge.response"; id: string; ok: true; data?: unknown }
  | { type: "redevplugin.bridge.response"; id: string; ok: false; error_code: string; error: string };

export type PluginBridgeCallMessage = {
  type: "redevplugin.bridge.call";
  request: PluginBridgeRequest;
};

export type PluginBridgeMessage = PluginBridgeHandshake | PluginBridgeCallMessage;

export type PluginBridgeLifecycleMessage = {
  type: "redevplugin.bridge.lifecycle";
  event: BridgeLifecycleEvent;
};

export type PluginSurfaceBootstrap = {
  pluginId: string;
  surfaceId: string;
  surfaceInstanceId: string;
  activeFingerprint: string;
  bridgeNonce: string;
  parentOrigin: string;
};

export type PluginBridgeClientOptions = {
  timeoutMs?: number;
  target?: WindowLike;
  receiver?: WindowLike;
};

export const defaultPluginSurfaceReloadMax = 2;
export const defaultPluginSurfaceReloadWindowMs = 30_000;

export type PluginSurfaceReloadLimiterOptions = {
  maxReloads?: number;
  windowMs?: number;
  now?: () => number;
};

export type PluginSurfaceReloadDecision =
  | {
      allowed: true;
      attempt: number;
      remaining: number;
      windowStartedAtMs: number;
    }
  | {
      allowed: false;
      attempt: number;
      remaining: 0;
      windowStartedAtMs: number;
      nextRetryAtMs: number;
      reason: "reload_limit_exceeded";
    };

export type PluginSurfaceReloadState = {
  reloads: number;
  remaining: number;
  windowStartedAtMs?: number;
  nextRetryAtMs?: number;
};

export type WindowLike = {
  postMessage(message: unknown, targetOrigin: string): void;
  addEventListener?(type: "message", listener: (event: MessageEventLike) => void): void;
  removeEventListener?(type: "message", listener: (event: MessageEventLike) => void): void;
};

export type MessageEventLike = {
  origin: string;
  data: unknown;
  source?: WindowLike | null;
};

export class PluginBridgeError extends Error {
  readonly errorCode: string;
  readonly data?: unknown;
  readonly details?: unknown;

  constructor(errorCode: string, message: string, data?: unknown, details?: unknown) {
    super(message);
    this.name = "PluginBridgeError";
    this.errorCode = errorCode;
    this.data = data;
    this.details = details ?? data;
  }
}

export class PluginSurfaceReloadLimiter {
  readonly maxReloads: number;
  readonly windowMs: number;
  #now: () => number;
  #windowStartedAtMs?: number;
  #reloads = 0;

  constructor(options: PluginSurfaceReloadLimiterOptions = {}) {
    this.maxReloads = normalizeReloadMax(options.maxReloads ?? defaultPluginSurfaceReloadMax);
    this.windowMs = normalizeReloadWindow(options.windowMs ?? defaultPluginSurfaceReloadWindowMs);
    this.#now = options.now ?? (() => Date.now());
  }

  recordCrash(nowMs = this.#now()): PluginSurfaceReloadDecision {
    nowMs = normalizeNowMs(nowMs);
    this.#ensureWindow(nowMs);
    const windowStartedAtMs = this.#windowStartedAtMs ?? nowMs;
    if (this.#reloads >= this.maxReloads) {
      return {
        allowed: false,
        attempt: this.#reloads + 1,
        remaining: 0,
        windowStartedAtMs,
        nextRetryAtMs: windowStartedAtMs + this.windowMs,
        reason: "reload_limit_exceeded",
      };
    }
    this.#reloads += 1;
    return {
      allowed: true,
      attempt: this.#reloads,
      remaining: this.maxReloads - this.#reloads,
      windowStartedAtMs,
    };
  }

  recordHealthyLoad(): void {
    this.reset();
  }

  reset(): void {
    this.#windowStartedAtMs = undefined;
    this.#reloads = 0;
  }

  get state(): PluginSurfaceReloadState {
    const remaining = Math.max(0, this.maxReloads - this.#reloads);
    return {
      reloads: this.#reloads,
      remaining,
      windowStartedAtMs: this.#windowStartedAtMs,
      nextRetryAtMs:
        remaining === 0 && this.#windowStartedAtMs !== undefined
          ? this.#windowStartedAtMs + this.windowMs
          : undefined,
    };
  }

  #ensureWindow(nowMs: number): void {
    if (
      this.#windowStartedAtMs === undefined ||
      nowMs < this.#windowStartedAtMs ||
      nowMs >= this.#windowStartedAtMs + this.windowMs
    ) {
      this.#windowStartedAtMs = nowMs;
      this.#reloads = 0;
    }
  }
}

class PluginConfirmationRequiredError extends PluginBridgeError {}

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
};

export class PluginBridgeClient {
  readonly bootstrap: PluginSurfaceBootstrap;
  readonly timeoutMs: number;
  #nextID = 1;
  #target: WindowLike;
  #receiver: WindowLike;
  #pending = new Map<string, PendingCall>();
  #lifecycleHandlers = new Set<(event: BridgeLifecycleEvent) => void>();
  #disposed = false;
  #onMessage = (event: MessageEventLike): void => {
    this.#handleMessage(event);
  };

  constructor(bootstrap: PluginSurfaceBootstrap, options: PluginBridgeClientOptions = {}) {
    if (!bootstrap.parentOrigin || bootstrap.parentOrigin === "*") {
      throw new Error("parentOrigin must be an exact origin");
    }
    this.bootstrap = bootstrap;
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
    this.#target = options.target ?? window.parent;
    this.#receiver = options.receiver ?? window;
    this.#receiver.addEventListener?.("message", this.#onMessage);
  }

  handshake(): void {
    this.#assertActive();
    const message: PluginBridgeHandshake = {
      type: "redevplugin.bridge.handshake",
      plugin_id: this.bootstrap.pluginId,
      surface_id: this.bootstrap.surfaceId,
      surface_instance_id: this.bootstrap.surfaceInstanceId,
      active_fingerprint: this.bootstrap.activeFingerprint,
      bridge_nonce: this.bootstrap.bridgeNonce,
      ui_protocol_version: "plugin-ui-v1",
    };
    this.#target.postMessage(message, this.bootstrap.parentOrigin);
  }

  call<T = unknown>(method: string, params?: unknown): Promise<T> {
    this.#assertActive();
    const request: PluginBridgeRequest = {
      id: String(this.#nextID++),
      method,
      params,
    };
    const message: PluginBridgeCallMessage = { type: "redevplugin.bridge.call", request };
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(request.id);
        reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", `Plugin bridge call ${request.id} timed out`));
      }, this.timeoutMs);
      this.#pending.set(request.id, {
        resolve: (value: unknown) => resolve(value as T),
        reject,
        timer,
      });
    });
    this.#target.postMessage(message, this.bootstrap.parentOrigin);
    return result;
  }

  onLifecycle(handler: (event: BridgeLifecycleEvent) => void): () => void {
    this.#assertActive();
    this.#lifecycleHandlers.add(handler);
    return () => {
      this.#lifecycleHandlers.delete(handler);
    };
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    this.#receiver.removeEventListener?.("message", this.#onMessage);
    for (const [id, pending] of this.#pending) {
      clearTimeout(pending.timer);
      pending.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", `Plugin bridge call ${id} was disposed`));
    }
    this.#pending.clear();
    this.#lifecycleHandlers.clear();
  }

  #handleMessage(event: MessageEventLike): void {
    if (this.#disposed || event.origin !== this.bootstrap.parentOrigin) {
      return;
    }
    const data = event.data;
    if (isBridgeResponse(data)) {
      const pending = this.#pending.get(data.id);
      if (!pending) {
        return;
      }
      this.#pending.delete(data.id);
      clearTimeout(pending.timer);
      if (data.ok) {
        pending.resolve(data.data);
      } else {
        pending.reject(new PluginBridgeError(data.error_code, data.error));
      }
      return;
    }
    if (isLifecycleMessage(data)) {
      for (const handler of this.#lifecycleHandlers) {
        handler(data.event);
      }
    }
  }

  #assertActive(): void {
    if (this.#disposed) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin bridge client is disposed");
    }
  }
}

export type PluginSurfaceHostBootstrap = {
  pluginId: string;
  pluginInstanceId: string;
  surfaceId: string;
  surfaceInstanceId: string;
  activeFingerprint: string;
  bridgeNonce: string;
  ownerSessionHash?: string;
  ownerUserHash?: string;
  sessionChannelIdHash?: string;
};

export type PluginSurfaceHostOptions = {
  bootstrap: PluginSurfaceHostBootstrap;
  iframeOrigin: string;
  iframeWindow: WindowLike;
  parentWindow?: WindowLike;
  bridgeChannelId?: string;
  fetch?: FetchLike;
  apiBaseURL?: string;
  ownerSessionHashHeader?: string;
  confirm?: PluginConfirmationHandler;
  onError?: (error: PluginBridgeError) => void;
};

export type PluginConfirmationHandler = (intent: PluginConfirmationIntent) => Promise<PluginConfirmationDecision> | PluginConfirmationDecision;

export type PluginConfirmationIntent = {
  requestId: string;
  method: string;
  params?: Record<string, unknown>;
  requestHash: string;
  confirmationTokenId: string;
};

export type PluginConfirmationDecision = boolean | { confirmed: boolean };

export type FetchLike = (input: string, init: FetchInitLike) => Promise<FetchResponseLike>;

export type FetchInitLike = {
  method: string;
  headers: Record<string, string>;
  body?: string;
  credentials?: "same-origin" | "include" | "omit";
};

export type FetchResponseLike = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

export type StreamFetchLike = (input: string, init?: StreamFetchInitLike) => Promise<StreamFetchResponseLike>;

export type StreamFetchInitLike = {
  method?: string;
  headers?: Record<string, string>;
  credentials?: "same-origin" | "include" | "omit";
};

export type StreamFetchResponseLike = {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json?(): Promise<unknown>;
};

export type PluginGatewayTokenResult = {
  plugin_gateway_token: string;
  plugin_gateway_token_id: string;
  issued_at?: string;
  expires_at?: string;
};

export type PluginMethodResult<T = unknown> = {
  data?: T;
  operation_id?: string;
  stream_id?: string;
  stream_ticket?: string;
  stream_ticket_id?: string;
  confirmation_required?: boolean;
  confirmation_token_id?: string;
  request_hash?: string;
};

export type PluginStreamEvent = {
  stream_id: string;
  sequence: number;
  kind: string;
  data?: string;
  error?: string;
  at: string;
};

export type ReadPluginStreamOptions = {
  streamId?: string;
  streamTicket?: string;
  result?: PluginMethodResult;
  fetch?: StreamFetchLike;
  apiBaseURL?: string;
};

export type PluginConfirmationResult = {
  confirmation_id: string;
  confirmation_token_id: string;
  request_hash: string;
  expires_at?: string;
};

export type PluginPlatformClientOptions = {
  fetch?: FetchLike;
  apiBaseURL?: string;
  ownerSessionHashHeader?: string;
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
  plugin_host_protocol_version: string;
  rust_ipc_version: string;
  wasm_abi_version: string;
  manifest_schema_version: string;
  package_signature_schema_version: string;
  token_ticket_schema_version: string;
  bridge_schema_version: string;
  target_classifier_version: string;
  network_grant_schema_version: string;
  plugin_platform_openapi_version: string;
  compatibility_schema_version: string;
  worker_invocation_schema_version: string;
  error_codes_schema_version: string;
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

export type PluginTrustState = "bundled" | "verified" | "unsigned_local" | "untrusted" | "needs_review" | "blocked_security";

export type PluginEnableState = "disabled" | "enabled" | "disabled_by_policy";

export type PluginRetainedDataRecordState = "retained" | "expired" | "bound" | "deleted" | "delete_failed_retryable";

export type PluginRetainedDataState = "none" | PluginRetainedDataRecordState;

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
  enable_state: PluginEnableState | string;
  disabled_reason?: string;
  retained_data_state?: PluginRetainedDataState | string;
  policy_revision?: number;
  management_revision?: number;
  revoke_epoch?: number;
  manifest?: Record<string, unknown>;
  package_entries?: Array<Record<string, unknown>>;
  version_history?: Array<Record<string, unknown>>;
  installed_at?: string;
  enabled_at?: string;
  updated_at?: string;
  deleted_at?: string;
  metadata?: Record<string, string>;
  [key: string]: unknown;
};

export type PluginInstallRequest = {
  package_base64: string;
  trust_state?: PluginTrustState | string;
  plugin_instance_id?: string;
};

export type PluginUpdateRequest = {
  plugin_instance_id: string;
  package_base64: string;
  trust_state?: PluginTrustState | string;
};

export type PluginDowngradeRequest = {
  plugin_instance_id: string;
  version?: string;
  package_hash?: string;
};

export type PluginEnableRequest = {
  plugin_instance_id: string;
};

export type PluginDisableRequest = {
  plugin_instance_id: string;
  reason?: string;
};

export type PluginUninstallRequest = {
  plugin_instance_id: string;
  delete_data: boolean;
};

export type PluginOpenSurfaceRequest = {
  plugin_instance_id: string;
  surface_id: string;
  surface_instance_id?: string;
  owner_session_hash?: string;
  owner_user_hash?: string;
  session_channel_id_hash?: string;
  sandbox_origin?: string;
};

export type PluginSurfaceBootstrapResult = {
  plugin_id: string;
  plugin_instance_id: string;
  surface_id: string;
  surface_instance_id: string;
  active_fingerprint: string;
  owner_session_hash?: string;
  session_channel_id_hash?: string;
  asset_ticket: string;
  asset_ticket_id: string;
  bridge_nonce: string;
  issued_at: string;
  expires_at: string;
};

export type PluginRuntimeTarget = {
  os?: string;
  arch?: string;
};

export type PluginRuntimeStartRequest = {
  target?: PluginRuntimeTarget;
};

export type PluginRuntimeHealth = {
  runtime_instance_id: string;
  runtime_generation_id: string;
  runtime_version?: string;
  rust_ipc_version?: string;
  wasm_abi_version?: string;
  ready: boolean;
};

export type PluginRuntimeStopResult = {
  stopped: boolean;
};

export type PluginRuntimeRefreshResult = {
  refreshed_plugins: PluginRecord[];
};

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

export type PluginOperationList = {
  operations?: PluginOperationRecord[];
  [key: string]: unknown;
};

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

export type PluginIntentList = {
  intents?: PluginIntentRecord[];
  [key: string]: unknown;
};

export type PluginIntentListOptions = {
  intent_id?: string;
  plugin_instance_id?: string;
};

export type PluginIntentInvokeRequest = {
  plugin_instance_id?: string;
  intent_id: string;
  params?: Record<string, unknown>;
  owner_session_hash?: string;
  owner_user_hash?: string;
  session_channel_id_hash?: string;
};

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

export type PluginPermissionList = {
  permissions?: PluginPermissionGrant[];
  [key: string]: unknown;
};

export type PluginPermissionGrantRequest = {
  plugin_instance_id: string;
  permission_id: string;
  granted_by?: string;
  expires_at?: string;
};

export type PluginPermissionRevokeRequest = {
  plugin_instance_id: string;
  permission_id: string;
  revoked_by?: string;
  reason?: string;
};

export type PluginDataExportRequest = {
  plugin_instance_id: string;
  include_secrets?: boolean;
};

export type PluginDataExportResult = {
  archive_ref?: string;
  settings_archive_ref?: string;
};

export type PluginDataImportRequest = {
  plugin_instance_id: string;
  archive_ref?: string;
  settings_archive_ref?: string;
  delete_existing?: boolean;
};

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
  browser_site_retained?: boolean;
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

export type PluginRetainedDataList = {
  retained_data?: PluginRetainedDataRecord[];
  [key: string]: unknown;
};

export type PluginRetainedDataBindRequest = {
  retained_id: string;
  target_plugin_instance_id: string;
};

export type PluginRetainedDataCleanupRequest = {
  retry_failed?: boolean;
  max_records?: number;
};

export type PluginRetainedDataCleanupResult = {
  deleted?: PluginRetainedDataRecord[];
  failed?: PluginRetainedDataRecord[];
  [key: string]: unknown;
};

export type PluginSecretRefRequest = {
  plugin_instance_id: string;
  secret_ref: string;
  scope: string;
};

export type PluginAuditEvent = {
  type: string;
  plugin_id?: string;
  plugin_instance_id?: string;
  occurred_at?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
};

export type PluginAuditEventList = {
  audit_events?: PluginAuditEvent[];
  [key: string]: unknown;
};

export type PluginAuditListOptions = {
  plugin_id?: string;
  plugin_instance_id?: string;
  type?: string;
  limit?: number;
};

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

export type PluginDiagnosticEventList = {
  diagnostic_events?: PluginDiagnosticEvent[];
  [key: string]: unknown;
};

export type PluginDiagnosticListOptions = {
  plugin_id?: string;
  plugin_instance_id?: string;
  surface_instance_id?: string;
  type?: string;
  severity?: string;
  limit?: number;
};

export class PluginPlatformClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #ownerSessionHashHeader?: string;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#ownerSessionHashHeader = options.ownerSessionHashHeader;
  }

  catalog(): Promise<PluginCatalogResult> {
    return this.#getJSON("/_redevplugin/api/plugins/catalog");
  }

  getCompatibility(): Promise<PluginCompatibilityManifest> {
    return this.#getJSON("/_redevplugin/api/plugins/platform/compatibility");
  }

  installPlugin(request: PluginInstallRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/install", request);
  }

  updatePlugin(request: PluginUpdateRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/update", request);
  }

  downgradePlugin(request: PluginDowngradeRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/downgrade", request);
  }

  enablePlugin(pluginInstanceIdOrRequest: string | PluginEnableRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/enable", pluginInstanceRequest(pluginInstanceIdOrRequest));
  }

  disablePlugin(request: PluginDisableRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/disable", request);
  }

  uninstallPlugin(request: PluginUninstallRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/uninstall", request);
  }

  openSurface(request: PluginOpenSurfaceRequest): Promise<PluginSurfaceBootstrapResult> {
    return this.#postJSON("/_redevplugin/api/plugins/surfaces/open", request);
  }

  startRuntime(request: PluginRuntimeStartRequest = {}): Promise<PluginRuntimeHealth> {
    return this.#postJSON("/_redevplugin/api/plugins/runtime/start", request);
  }

  stopRuntime(): Promise<PluginRuntimeStopResult> {
    return this.#postJSON("/_redevplugin/api/plugins/runtime/stop", {});
  }

  refreshEnabledRuntimeState(): Promise<PluginRuntimeRefreshResult> {
    return this.#postJSON("/_redevplugin/api/plugins/runtime/refresh-enabled", {});
  }

  runtimeHealth(): Promise<PluginRuntimeHealth> {
    return this.#getJSON("/_redevplugin/api/plugins/runtime/health");
  }

  getSettingsSchema(pluginInstanceId: string): Promise<PluginSettingsSchema> {
    return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings/schema`);
  }

  getSettings(pluginInstanceId: string): Promise<PluginSettingsSnapshot> {
    return this.#getJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`);
  }

  patchSettings(pluginInstanceId: string, values: Record<string, unknown>): Promise<PluginSettingsSnapshot> {
    return this.#patchJSON(`/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/settings`, { values });
  }

  listOperations(pluginInstanceId?: string): Promise<PluginOperationList> {
    const query = pluginInstanceId ? `?plugin_instance_id=${encodeURIComponent(pluginInstanceId)}` : "";
    return this.#getJSON(`/_redevplugin/api/plugins/operations${query}`);
  }

  getOperation(operationId: string): Promise<PluginOperationRecord> {
    return this.#getJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}`);
  }

  cancelOperation(operationId: string, reason?: string): Promise<PluginOperationRecord> {
    const body = reason ? { reason } : {};
    return this.#postJSON(`/_redevplugin/api/plugins/operations/${encodeURIComponent(operationId)}/cancel`, body);
  }

  listIntents(options: PluginIntentListOptions = {}): Promise<PluginIntentList> {
    const params = new URLSearchParams();
    if (options.intent_id) {
      params.set("intent_id", options.intent_id);
    }
    if (options.plugin_instance_id) {
      params.set("plugin_instance_id", options.plugin_instance_id);
    }
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/intents${query ? `?${query}` : ""}`);
  }

  invokeIntent<T = unknown>(request: PluginIntentInvokeRequest): Promise<PluginMethodResult<T>> {
    return this.#postJSON("/_redevplugin/api/plugins/intents/invoke", request);
  }

  exportData(request: PluginDataExportRequest): Promise<PluginDataExportResult> {
    return this.#postJSON("/_redevplugin/api/plugins/data/export", request);
  }

  importData(request: PluginDataImportRequest): Promise<Record<string, unknown>> {
    return this.#postJSON("/_redevplugin/api/plugins/data/import", request);
  }

  listRetainedData(options: PluginRetainedDataListOptions = {}): Promise<PluginRetainedDataList> {
    const params = new URLSearchParams();
    if (options.publisher_id) {
      params.set("publisher_id", options.publisher_id);
    }
    if (options.plugin_id) {
      params.set("plugin_id", options.plugin_id);
    }
    if (options.source_plugin_instance_id) {
      params.set("source_plugin_instance_id", options.source_plugin_instance_id);
    }
    if (options.state) {
      params.set("state", options.state);
    }
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/retained-data${query ? `?${query}` : ""}`);
  }

  deleteRetainedData(retainedId: string): Promise<PluginRetainedDataRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/retained-data/delete", { retained_id: retainedId });
  }

  bindRetainedData(request: PluginRetainedDataBindRequest): Promise<PluginRetainedDataRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/retained-data/bind", request);
  }

  cleanupExpiredRetainedData(request: PluginRetainedDataCleanupRequest = {}): Promise<PluginRetainedDataCleanupResult> {
    return this.#postJSON("/_redevplugin/api/plugins/retained-data/cleanup-expired", request);
  }

  listPermissions(pluginInstanceId?: string, activeOnly?: boolean): Promise<PluginPermissionList> {
    const params = new URLSearchParams();
    if (pluginInstanceId) {
      params.set("plugin_instance_id", pluginInstanceId);
    }
    if (activeOnly != null) {
      params.set("active_only", activeOnly ? "true" : "false");
    }
    const query = params.toString();
    return this.#getJSON(`/_redevplugin/api/plugins/permissions${query ? `?${query}` : ""}`);
  }

  grantPermission(request: PluginPermissionGrantRequest): Promise<PluginPermissionGrant> {
    return this.#postJSON("/_redevplugin/api/plugins/permissions/grant", request);
  }

  revokePermission(request: PluginPermissionRevokeRequest): Promise<PluginPermissionGrant> {
    return this.#postJSON("/_redevplugin/api/plugins/permissions/revoke", request);
  }

  bindSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> {
    return this.#postJSON("/_redevplugin/api/plugins/secrets/bind", request);
  }

  testSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> {
    return this.#postJSON("/_redevplugin/api/plugins/secrets/test", request);
  }

  deleteSecret(request: PluginSecretRefRequest): Promise<Record<string, unknown>> {
    return this.#postJSON("/_redevplugin/api/plugins/secrets/delete", request);
  }

  listAuditEvents(options: PluginAuditListOptions = {}): Promise<PluginAuditEventList> {
    return this.#getJSON(`/_redevplugin/api/plugins/audit${queryString(options)}`);
  }

  listDiagnosticEvents(options: PluginDiagnosticListOptions = {}): Promise<PluginDiagnosticEventList> {
    return this.#getJSON(`/_redevplugin/api/plugins/diagnostics${queryString(options)}`);
  }

  #getJSON<T>(path: string): Promise<T> {
    return this.#requestJSON<T>("GET", path);
  }

  #postJSON<T>(path: string, body: unknown): Promise<T> {
    return this.#requestJSON<T>("POST", path, body);
  }

  #patchJSON<T>(path: string, body: unknown): Promise<T> {
    return this.#requestJSON<T>("PATCH", path, body);
  }

  async #requestJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await this.#fetch(this.#apiBaseURL + path, {
      method,
      headers: this.#headers(body !== undefined),
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
    return readHostEnvelope<T>(response, "PLUGIN_PLATFORM_REQUEST_FAILED");
  }

  #headers(hasBody: boolean): Record<string, string> {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (hasBody) {
      headers["Content-Type"] = "application/json";
    }
    if (this.#ownerSessionHashHeader) {
      headers["X-ReDevPlugin-Owner-Session-Hash"] = this.#ownerSessionHashHeader;
    }
    return headers;
  }
}

type HostEnvelope<T> =
  | { ok: true; data?: T }
  | { ok: false; data?: unknown; error?: string; error_code?: string; error_details?: Record<string, unknown> };

export class PluginSurfaceHost {
  readonly bootstrap: PluginSurfaceHostBootstrap;
  readonly iframeOrigin: string;
  readonly bridgeChannelId: string;
  #iframeWindow: WindowLike;
  #parentWindow: WindowLike;
  #fetch: FetchLike;
  #apiBaseURL: string;
  #ownerSessionHashHeader?: string;
  #confirm?: PluginConfirmationHandler;
  #onError?: (error: PluginBridgeError) => void;
  #gatewayToken?: string;
  #disposed = false;
  #onMessage = (event: MessageEventLike): void => {
    void this.#handleMessage(event);
  };

  constructor(options: PluginSurfaceHostOptions) {
    if (!options.iframeOrigin || options.iframeOrigin === "*") {
      throw new Error("iframeOrigin must be an exact origin");
    }
    this.bootstrap = options.bootstrap;
    this.iframeOrigin = options.iframeOrigin;
    this.bridgeChannelId = options.bridgeChannelId ?? randomBridgeChannelID();
    this.#iframeWindow = options.iframeWindow;
    this.#parentWindow = options.parentWindow ?? window;
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#ownerSessionHashHeader = options.ownerSessionHashHeader ?? options.bootstrap.ownerSessionHash;
    this.#confirm = options.confirm;
    this.#onError = options.onError;
    this.#parentWindow.addEventListener?.("message", this.#onMessage);
  }

  sendLifecycle(event: BridgeLifecycleEvent): void {
    this.#assertActive();
    this.#postToIframe({ type: "redevplugin.bridge.lifecycle", event });
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    this.#gatewayToken = undefined;
    this.#parentWindow.removeEventListener?.("message", this.#onMessage);
    this.#postToIframe({ type: "redevplugin.bridge.lifecycle", event: { type: "dispose" } });
  }

  async #handleMessage(event: MessageEventLike): Promise<void> {
    if (this.#disposed || event.origin !== this.iframeOrigin) {
      return;
    }
    if (event.source != null && event.source !== this.#iframeWindow) {
      return;
    }
    const data = event.data;
    if (isBridgeHandshake(data)) {
      await this.#handleHandshake(data);
      return;
    }
    if (isBridgeCallMessage(data)) {
      await this.#handleCall(data.request);
    }
  }

  async #handleHandshake(handshake: PluginBridgeHandshake): Promise<void> {
    if (!handshakeMatchesBootstrap(handshake, this.bootstrap)) {
      this.#reportError(new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin bridge handshake did not match the surface bootstrap"));
      return;
    }
    try {
      const token = await this.#postJSON<PluginGatewayTokenResult>(`/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/bridge-token`, {
        bridge_channel_id: this.bridgeChannelId,
        handshake,
      });
      this.#gatewayToken = token.plugin_gateway_token;
      this.#postToIframe({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
    } catch (error) {
      this.#reportError(toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED"));
    }
  }

  async #handleCall(request: PluginBridgeRequest): Promise<void> {
    if (!this.#gatewayToken) {
      this.#postError(request.id, "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin bridge call arrived before a successful handshake");
      return;
    }
    if (!validRPCParams(request.params)) {
      this.#postError(request.id, "PLUGIN_INVALID_REQUEST", "Plugin bridge call params must be a JSON object when present");
      return;
    }
    try {
      const result = await this.#callRPC(request);
      this.#postToIframe({ type: "redevplugin.bridge.response", id: request.id, ok: true, data: result });
    } catch (error) {
      const bridgeError = toBridgeError(error, "PLUGIN_PERMISSION_DENIED");
      if (bridgeError instanceof PluginConfirmationRequiredError) {
        await this.#handleConfirmationRequired(request, bridgeError);
        return;
      }
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message);
    }
  }

  async #handleConfirmationRequired(request: PluginBridgeRequest, originalError: PluginConfirmationRequiredError): Promise<void> {
    if (!this.#confirm) {
      this.#postError(request.id, originalError.errorCode, originalError.message);
      return;
    }
    try {
      const confirmation = await this.#prepareConfirmation(request);
      const decision = await this.#confirm({
        requestId: request.id,
        method: request.method,
        params: validRPCParams(request.params) ? request.params : undefined,
        requestHash: confirmation.request_hash,
        confirmationTokenId: confirmation.confirmation_token_id,
      });
      if (!confirmationDecisionAccepted(decision)) {
        this.#postError(request.id, "PLUGIN_CONFIRMATION_REJECTED", "Plugin method confirmation was rejected");
        return;
      }
      const result = await this.#callRPC(request, confirmation.confirmation_id);
      this.#postToIframe({ type: "redevplugin.bridge.response", id: request.id, ok: true, data: result });
    } catch (error) {
      const bridgeError = toBridgeError(error, "PLUGIN_PERMISSION_DENIED");
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message);
    }
  }

  #callRPC(request: PluginBridgeRequest, confirmationId?: string): Promise<PluginMethodResult> {
    return this.#postJSON<PluginMethodResult>(`/_redevplugin/api/plugins/rpc`, this.#rpcBody(request, confirmationId));
  }

  #prepareConfirmation(request: PluginBridgeRequest): Promise<PluginConfirmationResult> {
    return this.#postJSON<PluginConfirmationResult>(`/_redevplugin/api/plugins/confirm`, this.#rpcBody(request));
  }

  #rpcBody(request: PluginBridgeRequest, confirmationId?: string): Record<string, unknown> {
    const body: Record<string, unknown> = {
      plugin_instance_id: this.bootstrap.pluginInstanceId,
      surface_instance_id: this.bootstrap.surfaceInstanceId,
      session_channel_id_hash: this.bootstrap.sessionChannelIdHash,
      owner_session_hash: this.bootstrap.ownerSessionHash,
      owner_user_hash: this.bootstrap.ownerUserHash,
      bridge_channel_id: this.bridgeChannelId,
      plugin_gateway_token: this.#gatewayToken,
      method: request.method,
      params: request.params,
    };
    if (confirmationId) {
      body.confirmation_id = confirmationId;
    }
    return body;
  }

  async #postJSON<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };
    if (this.#ownerSessionHashHeader) {
      headers["X-ReDevPlugin-Owner-Session-Hash"] = this.#ownerSessionHashHeader;
    }
    const response = await this.#fetch(this.#apiBaseURL + path, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    return readHostEnvelope<T>(response, "PLUGIN_PERMISSION_DENIED");
  }

  #postError(id: string, errorCode: string, error: string): void {
    this.#postToIframe({ type: "redevplugin.bridge.response", id, ok: false, error_code: errorCode, error });
  }

  #postToIframe(message: PluginBridgeResponse | PluginBridgeLifecycleMessage): void {
    this.#iframeWindow.postMessage(message, this.iframeOrigin);
  }

  #reportError(error: PluginBridgeError): void {
    this.#onError?.(error);
  }

  #assertActive(): void {
    if (this.#disposed) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface host is disposed");
    }
  }
}

export async function readPluginStream(options: ReadPluginStreamOptions): Promise<PluginStreamEvent[]> {
  const streamId = options.streamId ?? options.result?.stream_id;
  const streamTicket = options.streamTicket ?? options.result?.stream_ticket;
  if (!streamId || !streamTicket) {
    throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "stream_id and stream_ticket are required to read a plugin stream");
  }
  const fetchLike = options.fetch ?? defaultStreamFetch();
  const url = `${trimTrailingSlash(options.apiBaseURL ?? "")}/_redevplugin/stream/${encodeURIComponent(streamId)}?ticket=${encodeURIComponent(streamTicket)}`;
  const response = await fetchLike(url, {
    method: "GET",
    headers: { "Accept": "application/x-ndjson, application/json" },
    credentials: "same-origin",
  });
  const raw = await response.text();
  if (!response.ok) {
    throw streamErrorFromBody(raw, response.status);
  }
  return parseNDJSONEvents(raw);
}

export function decodePluginStreamText(event: PluginStreamEvent): string {
  if (!event.data) {
    return "";
  }
  if (typeof TextDecoder === "function" && typeof atob === "function") {
    const binary = atob(event.data);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  const bufferLike = (globalThis as { Buffer?: { from(value: string, encoding: "base64"): { toString(encoding: "utf8"): string } } }).Buffer;
  if (bufferLike) {
    return bufferLike.from(event.data, "base64").toString("utf8");
  }
  throw new PluginBridgeError("PLUGIN_STREAM_FAILED", "No base64 decoder is available for plugin stream data");
}

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs == null) {
    return 30_000;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive finite number");
  }
  return timeoutMs;
}

function normalizeReloadMax(maxReloads: number): number {
  if (!Number.isInteger(maxReloads) || maxReloads < 0) {
    throw new Error("maxReloads must be a non-negative integer");
  }
  return maxReloads;
}

function normalizeReloadWindow(windowMs: number): number {
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new Error("windowMs must be a positive finite number");
  }
  return windowMs;
}

function normalizeNowMs(nowMs: number): number {
  if (!Number.isFinite(nowMs)) {
    throw new Error("nowMs must be a finite number");
  }
  return nowMs;
}

function defaultFetch(): FetchLike {
  const fetchLike = (globalThis as { fetch?: FetchLike }).fetch;
  if (!fetchLike) {
    throw new Error("fetch is required when globalThis.fetch is unavailable");
  }
  return fetchLike.bind(globalThis) as FetchLike;
}

function defaultStreamFetch(): StreamFetchLike {
  const fetchLike = (globalThis as { fetch?: StreamFetchLike }).fetch;
  if (!fetchLike) {
    throw new Error("fetch is required when globalThis.fetch is unavailable");
  }
  return fetchLike.bind(globalThis) as StreamFetchLike;
}

function randomBridgeChannelID(): string {
  const cryptoLike = globalThis as { crypto?: { randomUUID?: () => string } };
  if (cryptoLike.crypto?.randomUUID) {
    return `bridge_${cryptoLike.crypto.randomUUID()}`;
  }
  return `bridge_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function queryString(values: Record<string, string | number | boolean | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value != null && value !== "") {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function pluginInstanceRequest(value: string | PluginEnableRequest): PluginEnableRequest {
  return typeof value === "string" ? { plugin_instance_id: value } : value;
}

function isBridgeHandshake(value: unknown): value is PluginBridgeHandshake {
  return isRecord(value) &&
    value.type === "redevplugin.bridge.handshake" &&
    typeof value.plugin_id === "string" &&
    typeof value.surface_id === "string" &&
    typeof value.surface_instance_id === "string" &&
    typeof value.active_fingerprint === "string" &&
    typeof value.bridge_nonce === "string" &&
    value.ui_protocol_version === "plugin-ui-v1";
}

function isBridgeCallMessage(value: unknown): value is PluginBridgeCallMessage {
  return isRecord(value) &&
    value.type === "redevplugin.bridge.call" &&
    isRecord(value.request) &&
    typeof value.request.id === "string" &&
    typeof value.request.method === "string";
}

function isBridgeResponse(value: unknown): value is PluginBridgeResponse {
  if (!isRecord(value) || value.type !== "redevplugin.bridge.response" || typeof value.id !== "string") {
    return false;
  }
  if (value.ok === true) {
    return true;
  }
  return value.ok === false && typeof value.error_code === "string" && typeof value.error === "string";
}

function isHostEnvelope(value: unknown): value is HostEnvelope<unknown> {
  if (!isRecord(value) || typeof value.ok !== "boolean") {
    return false;
  }
  if (value.ok) {
    return true;
  }
  return (value.error == null || typeof value.error === "string") &&
    (value.error_details == null || isRecord(value.error_details));
}

async function readHostEnvelope<T>(response: FetchResponseLike, fallbackCode: string): Promise<T> {
  const raw = await response.json();
  if (!isHostEnvelope(raw)) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin platform endpoint returned an invalid envelope with HTTP ${response.status}`);
  }
  if (!raw.ok) {
    const errorCode = raw.error_code ?? fallbackCode;
    const message = raw.error ?? `Plugin platform endpoint failed with HTTP ${response.status}`;
    if (errorCode === "PLUGIN_CONFIRMATION_REQUIRED") {
      throw new PluginConfirmationRequiredError(errorCode, message, raw.data, raw.error_details ?? raw.data);
    }
    throw new PluginBridgeError(errorCode, message, raw.data, raw.error_details ?? raw.data);
  }
  return raw.data as T;
}

function parseNDJSONEvents(raw: string): PluginStreamEvent[] {
  const events: PluginStreamEvent[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.trim() === "") {
      continue;
    }
    const event = JSON.parse(line) as unknown;
    if (!isStreamEvent(event)) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin stream endpoint returned an invalid event");
    }
    events.push(event);
  }
  return events;
}

function streamErrorFromBody(raw: string, status: number): PluginBridgeError {
  try {
    const body = JSON.parse(raw) as unknown;
    if (isHostEnvelope(body) && !body.ok) {
      return new PluginBridgeError(
        body.error_code ?? "PLUGIN_STREAM_FAILED",
        body.error ?? `Plugin stream endpoint failed with HTTP ${status}`,
        body.data,
        body.error_details ?? body.data,
      );
    }
  } catch {
    // Fall back to a generic error when the stream endpoint did not return JSON.
  }
  return new PluginBridgeError("PLUGIN_STREAM_FAILED", `Plugin stream endpoint failed with HTTP ${status}`);
}

function isStreamEvent(value: unknown): value is PluginStreamEvent {
  return isRecord(value) &&
    typeof value.stream_id === "string" &&
    typeof value.sequence === "number" &&
    typeof value.kind === "string" &&
    (value.data == null || typeof value.data === "string") &&
    (value.error == null || typeof value.error === "string") &&
    typeof value.at === "string";
}

function isLifecycleMessage(value: unknown): value is PluginBridgeLifecycleMessage {
  if (!isRecord(value) || value.type !== "redevplugin.bridge.lifecycle" || !isRecord(value.event)) {
    return false;
  }
  return value.event.type === "ready" || value.event.type === "visible" || value.event.type === "hidden" || value.event.type === "dispose";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function validRPCParams(value: unknown): value is Record<string, unknown> | undefined {
  return value == null || (isRecord(value) && !Array.isArray(value));
}

function confirmationDecisionAccepted(decision: PluginConfirmationDecision): boolean {
  return typeof decision === "boolean" ? decision : decision.confirmed;
}

function handshakeMatchesBootstrap(handshake: PluginBridgeHandshake, bootstrap: PluginSurfaceHostBootstrap): boolean {
  return handshake.plugin_id === bootstrap.pluginId &&
    handshake.surface_id === bootstrap.surfaceId &&
    handshake.surface_instance_id === bootstrap.surfaceInstanceId &&
    handshake.active_fingerprint === bootstrap.activeFingerprint &&
    handshake.bridge_nonce === bootstrap.bridgeNonce &&
    handshake.ui_protocol_version === "plugin-ui-v1";
}

function toBridgeError(error: unknown, fallbackCode: string): PluginBridgeError {
  if (error instanceof PluginBridgeError) {
    return error;
  }
  if (error instanceof Error) {
    return new PluginBridgeError(fallbackCode, error.message);
  }
  return new PluginBridgeError(fallbackCode, String(error));
}
