import { PluginBridgeError, pluginBridgeErrorCodes } from "./errors.js";
import { pluginUIProtocolVersion } from "./contracts.gen.js";
import {
  opaqueSurfaceAllowedTags,
  opaqueSurfaceGlobalAttributes,
  opaqueSurfaceRenderLimits,
  opaqueSurfaceSafeInputTypes,
  opaqueSurfaceTagAttributes,
  type OpaqueSurfaceAllowedTag,
} from "./opaque-surface-policy.gen.js";
import {
  defaultFetch,
  hasAllowedKeys,
  hasExactKeys,
  isRecord,
  readHostEnvelope,
  type FetchLike,
} from "./http.js";
import {
  defaultPluginSurfaceScope,
  registerPluginSurface,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export const opaqueSurfaceDocumentSchemaVersion = "redevplugin.opaque_surface_document.v1" as const;
export const pluginRiskPlanSchemaVersion = "redevplugin.capability.risk_plan.v1" as const;

export type PluginJSONValue = null | boolean | number | string | PluginJSONValue[] | PluginJSONObject;
export type PluginJSONObject = { [key: string]: PluginJSONValue };

export type BridgeLifecycleEvent =
  | { type: "ready" }
  | { type: "visible" }
  | { type: "hidden" }
  | { type: "dispose" };

export type TrustedParentBridgeHandshake = {
  type: "redevplugin.bridge.handshake";
  plugin_id: string;
  surface_id: string;
  surface_instance_id: string;
  active_fingerprint: string;
  bridge_nonce: string;
  asset_session_nonce: string;
  plugin_state_version: number;
  revoke_epoch: number;
  ui_protocol_version: typeof pluginUIProtocolVersion;
};

export type TrustedParentBridgeTokenRequest = {
  bridge_channel_id: string;
  handshake: TrustedParentBridgeHandshake;
  handshake_transcript_sha256: string;
  previous_plugin_gateway_token?: string;
};

export type PluginBridgeRequest = {
  id: string;
  method: string;
  params?: PluginJSONObject;
};

export type PluginBridgeResponse =
  | { type: "redevplugin.bridge.response"; id: string; ok: true; data?: unknown }
  | { type: "redevplugin.bridge.response"; id: string; ok: false; error_code: string; error: string; error_details?: PluginJSONObject };

export type PluginBridgeCancelMessage = {
  type: "redevplugin.bridge.cancel";
  id: string;
};

export type PluginBridgeLifecycleMessage = {
  type: "redevplugin.bridge.lifecycle";
  event: BridgeLifecycleEvent;
};

export type PluginUIActionEvent = {
  action: string;
  event: "click" | "input" | "change" | "submit";
  value?: string;
  checked?: boolean;
  form_data?: Record<string, string>;
};

export type PluginUIAttributeValue = string | number | boolean;

export type PluginUIVNode =
  | string
  | {
      type: "element";
      tag: OpaqueSurfaceAllowedTag;
      attributes?: Record<string, PluginUIAttributeValue>;
      children?: PluginUIVNode[];
    };

export type PluginMethodResult<T = unknown> = {
  data: T;
  operation_id?: string;
  stream_handle?: string;
  confirmation_required?: boolean;
  confirmation_token_id?: string;
  request_hash?: string;
};

export type PluginTrustedMethodResult<T = unknown> = Omit<PluginMethodResult<T>, "stream_handle"> & {
  stream_id?: string;
  stream_ticket?: string;
  stream_ticket_id?: string;
  stream_expires_at?: string;
};

export type PluginStreamEvent = {
  sequence: number;
  kind: string;
  data?: string;
  error?: string;
  at: string;
};

export type PluginStreamTerminalStatus = "closed" | "canceled" | "failed" | "orphaned_after_disable" | "orphaned_after_uninstall";

export type PluginStreamReadResult =
  | { events: PluginStreamEvent[]; done: false; retry_after_ms: number }
  | { events: PluginStreamEvent[]; done: true; terminal_status: PluginStreamTerminalStatus; retry_after_ms: 0 };

export type PluginRiskSeverity = "info" | "low" | "medium" | "high" | "critical";
export type PluginRiskEffect = "read" | "write" | "execute" | "delete" | "admin";

export type PluginRiskFlag = {
  id: string;
  severity: PluginRiskSeverity;
  summary: string;
  description?: string;
  requires_confirmation?: boolean;
  requires_admin?: boolean;
  data_loss_risk?: boolean;
  destructive?: boolean;
};

export type PluginRiskPlan = {
  schema_version: typeof pluginRiskPlanSchemaVersion;
  capability_id?: string;
  binding_id?: string;
  method?: string;
  target_method?: string;
  action?: string;
  effect?: PluginRiskEffect;
  resource_ref?: string;
  resource_display_name?: string;
  summary: string;
  risk_flags: PluginRiskFlag[];
  requires_confirmation?: boolean;
  requires_admin?: boolean;
  data_loss_risk?: boolean;
  destructive?: boolean;
  deny_reason?: string;
  details?: Record<string, unknown>;
};

export type PluginConfirmationPlan = PluginRiskPlan | Record<string, unknown>;

export type PluginConfirmationIntent = {
  requestId: string;
  method: string;
  params?: Record<string, unknown>;
  requestHash: string;
  planHash: string;
  plan?: PluginConfirmationPlan;
  confirmationTokenId: string;
  signal: AbortSignal;
};

export type PluginConfirmationDecision = boolean | { confirmed: boolean };
export type PluginConfirmationHandler = (intent: PluginConfirmationIntent) => Promise<PluginConfirmationDecision> | PluginConfirmationDecision;

export type MessageEventLike = {
  origin?: string;
  data: unknown;
  source?: WindowLike | null;
  ports?: MessagePortLike[];
};

export type MessagePortLike = {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: MessageEventLike) => void): void;
  removeEventListener(type: "message", listener: (event: MessageEventLike) => void): void;
  start(): void;
  close(): void;
};

export type WindowLike = {
  postMessage(message: unknown, targetOrigin: string, transfer?: MessagePortLike[]): void;
};

export type MessageChannelLike = {
  port1: MessagePortLike;
  port2: MessagePortLike;
};

type PluginSurfaceFrameLike = {
  srcdoc: string;
  contentWindow: WindowLike | null;
  credentialless?: boolean;
  setAttribute(name: string, value: string): void;
  addEventListener(type: "load", listener: () => void): void;
  removeEventListener(type: "load", listener: () => void): void;
};

export type PluginBridgeClientOptions = {
  timeoutMs?: number;
  port?: MessagePortLike;
  surfaceHandle?: string;
};

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
};

type WorkerBridgeClaim = { surfaceHandle: string; port: MessagePortLike };

type WorkerBridgeGlobal = {
  claim(): WorkerBridgeClaim | undefined;
};

const opaquePluginBridgeGlobalKey = "__redevpluginWorkerBridgeV2";
const maxPendingPluginBridgeRequests = 256;
const maxPluginBridgeMessageBytes = 256 * 1024;
const maxRetainedPluginStreamHandles = 128;
const streamCredentialInvalidatingErrorCodes = new Set([
  "PLUGIN_BRIDGE_DISPOSED",
  "PLUGIN_BRIDGE_HANDSHAKE_FAILED",
  "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED",
  "PLUGIN_BRIDGE_TIMEOUT",
  "PLUGIN_CONTRACT_MISMATCH",
  "PLUGIN_GATEWAY_TOKEN_CHANNEL_MISMATCH",
  "PLUGIN_GATEWAY_TOKEN_INVALID",
  "PLUGIN_GATEWAY_TOKEN_REPLAYED",
  "PLUGIN_GRANT_INVALID",
  "PLUGIN_LEASE_INVALID",
  "PLUGIN_LEASE_REPLAYED",
  "PLUGIN_STATE_VERSION_MISMATCH",
  "PLUGIN_STREAM_CANCELLED",
  "PLUGIN_STREAM_TICKET_INVALID",
  "PLUGIN_TOKEN_EXPIRED",
  "PLUGIN_TOKEN_REPLAY",
]);
const maxOpaqueSurfaceLazyAssets = 128;
const maxOpaqueSurfaceLazyBytes = 32 * 1024 * 1024;
const maxConcurrentAssetReads = 4;
const pluginBridgeErrorCodeSet = new Set<string>(pluginBridgeErrorCodes);
const hostCapabilityIDPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._-]*$");
const canonicalSemverPattern = new RegExp("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");
const lowercaseSHA256Pattern = new RegExp("^[0-9a-f]{64}$");
const businessErrorCodePattern = new RegExp("^[A-Z][A-Z0-9_]*$");

export class PluginBridgeClient {
  readonly surfaceHandle: string;
  readonly timeoutMs: number;
  #nextID = 1;
  #port: MessagePortLike;
  #pending = new Map<string, PendingCall>();
  #actionHandlers = new Map<string, Set<(event: PluginUIActionEvent) => void>>();
  #lifecycleHandlers = new Set<(event: BridgeLifecycleEvent) => void>();
  #ready = false;
  #readyPromise: Promise<void>;
  #resolveReady!: () => void;
  #rejectReady!: (reason: unknown) => void;
  #disposed = false;
  #onMessage = (event: MessageEventLike): void => {
    this.#handleMessage(event);
  };

  constructor(options: PluginBridgeClientOptions = {}) {
    const claimed = options.port
      ? { port: options.port, surfaceHandle: normalizeSurfaceHandle(options.surfaceHandle) }
      : claimOpaquePluginBridge();
    this.surfaceHandle = claimed.surfaceHandle;
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
    this.#port = claimed.port;
    this.#readyPromise = new Promise<void>((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
    void this.#readyPromise.catch(() => undefined);
    this.#port.addEventListener("message", this.#onMessage);
    this.#port.start();
  }

  ready(): Promise<void> {
    this.#assertActive();
    return this.#ready ? Promise.resolve() : this.#readyPromise;
  }

  call<T = unknown>(method: string, params?: PluginJSONObject): Promise<T> {
    this.#assertActive();
    if (!validMethod(method)) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin bridge method and params are invalid");
    }
    let normalizedParams: PluginJSONObject | undefined;
    try {
      normalizedParams = params === undefined ? undefined : normalizePluginJSONObject(params);
    } catch {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin bridge params must be canonical JSON");
    }
    const id = this.#requestID("rpc");
    const request: PluginBridgeRequest = normalizedParams === undefined
      ? { id, method }
      : { id, method, params: normalizedParams };
    return this.#request<T>(id, {
      type: "redevplugin.bridge.call",
      request,
    });
  }

  readStream(streamHandle: string): Promise<PluginStreamReadResult> {
    this.#assertActive();
    if (!validOpaqueHandle(streamHandle, "stream")) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin stream handle is invalid");
    }
    const id = this.#requestID("stream");
    return this.#request<PluginStreamReadResult>(id, {
      type: "redevplugin.bridge.stream.read",
      id,
      stream_handle: streamHandle,
    });
  }

  cancelOperation(operationID: string, reason?: string): Promise<void> {
    this.#assertActive();
    if (!validOpaqueHandle(operationID, "operation") || (reason !== undefined && (typeof reason !== "string" || reason.length > 256))) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin operation cancellation is invalid");
    }
    const id = this.#requestID("operation");
    return this.#request<void>(id, removeUndefined({
      type: "redevplugin.bridge.operation.cancel",
      id,
      operation_id: operationID,
      reason,
    }));
  }

  render(tree: PluginUIVNode | PluginUIVNode[]): Promise<void> {
    this.#assertActive();
    const id = this.#requestID("render");
    return this.#request<void>(id, {
      type: "redevplugin.ui.render",
      id,
      tree,
    });
  }

  onAction(action: string, handler: (event: PluginUIActionEvent) => void): () => void {
    this.#assertActive();
    if (!validActionID(action) || typeof handler !== "function") {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin action subscription is invalid");
    }
    const handlers = this.#actionHandlers.get(action) ?? new Set();
    handlers.add(handler);
    this.#actionHandlers.set(action, handlers);
    return () => {
      handlers.delete(handler);
      if (handlers.size === 0) this.#actionHandlers.delete(action);
    };
  }

  onLifecycle(handler: (event: BridgeLifecycleEvent) => void): () => void {
    this.#assertActive();
    this.#lifecycleHandlers.add(handler);
    return () => {
      this.#lifecycleHandlers.delete(handler);
    };
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    const disposedError = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin bridge client is disposed");
    if (!this.#ready) this.#rejectReady(disposedError);
    this.#port.removeEventListener("message", this.#onMessage);
    for (const [id, pending] of this.#pending) {
      clearTimeout(pending.timer);
      pending.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", `Plugin bridge request ${id} was disposed`));
    }
    this.#pending.clear();
    this.#actionHandlers.clear();
    this.#lifecycleHandlers.clear();
    this.#port.close();
  }

  #request<T>(id: string, message: unknown): Promise<T> {
    let normalizedMessage: PluginJSONObject;
    try {
      normalizedMessage = normalizePluginJSONObject(message);
    } catch {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin bridge request must be canonical JSON");
    }
    if (new TextEncoder().encode(JSON.stringify(normalizedMessage)).byteLength > maxPluginBridgeMessageBytes) {
      throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin bridge request exceeds the message size limit");
    }
    if (this.#pending.size >= maxPendingPluginBridgeRequests) {
      throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin bridge has too many pending requests");
    }
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.#pending.delete(id)) return;
        try {
          this.#port.postMessage({ type: "redevplugin.bridge.cancel", id } satisfies PluginBridgeCancelMessage);
        } catch {
          // The request is already locally cancelled when the port closes concurrently.
        }
        reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", `Plugin bridge request ${id} timed out`));
      }, this.timeoutMs);
      this.#pending.set(id, {
        resolve: (value: unknown) => resolve(value as T),
        reject,
        timer,
      });
    });
    try {
      this.#port.postMessage(normalizedMessage);
    } catch {
      const pending = this.#pending.get(id);
      if (pending) {
        this.#pending.delete(id);
        clearTimeout(pending.timer);
        pending.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", `Plugin bridge request ${id} could not be posted`));
      }
    }
    return result;
  }

  #handleMessage(event: MessageEventLike): void {
    if (this.#disposed || !messageWithinLimit(event.data)) return;
    const data = event.data;
    if (isBridgeResponseCandidate(data)) {
      const pending = this.#pending.get(data.id);
      if (!pending) return;
      this.#pending.delete(data.id);
      clearTimeout(pending.timer);
      if (!isBridgeResponse(data)) {
        pending.reject(new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin bridge response ${data.id} is invalid`));
        return;
      }
      if (data.ok) pending.resolve(data.data);
      else pending.reject(new PluginBridgeError(data.error_code, data.error, undefined, data.error_details));
      return;
    }
    if (isLifecycleMessage(data)) {
      if (data.event.type === "ready" && !this.#ready) {
        this.#ready = true;
        this.#resolveReady();
      }
      for (const handler of this.#lifecycleHandlers) handler(data.event);
      if (data.event.type === "dispose") this.dispose();
      return;
    }
    if (isActionMessage(data)) {
      for (const handler of this.#actionHandlers.get(data.action) ?? []) handler(data);
    }
  }

  #requestID(prefix: string): string {
    return `${prefix}_${this.#nextID++}`;
  }

  #assertActive(): void {
    if (this.#disposed) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin bridge client is disposed");
    }
  }
}

export const defaultPluginSurfaceReloadMax = 2;
export const defaultPluginSurfaceReloadWindowMs = 30_000;

export type PluginSurfaceReloadLimiterOptions = {
  maxReloads?: number;
  windowMs?: number;
  now?: () => number;
};

export type PluginSurfaceReloadDecision =
  | { allowed: true; attempt: number; remaining: number; windowStartedAtMs: number }
  | { allowed: false; attempt: number; remaining: 0; windowStartedAtMs: number; nextRetryAtMs: number; reason: "reload_limit_exceeded" };

export type PluginSurfaceReloadState = {
  reloads: number;
  remaining: number;
  windowStartedAtMs?: number;
  nextRetryAtMs?: number;
};

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
    return { allowed: true, attempt: this.#reloads, remaining: this.maxReloads - this.#reloads, windowStartedAtMs };
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
      nextRetryAtMs: remaining === 0 && this.#windowStartedAtMs !== undefined
        ? this.#windowStartedAtMs + this.windowMs
        : undefined,
    };
  }

  #ensureWindow(nowMs: number): void {
    if (this.#windowStartedAtMs === undefined || nowMs < this.#windowStartedAtMs || nowMs >= this.#windowStartedAtMs + this.windowMs) {
      this.#windowStartedAtMs = nowMs;
      this.#reloads = 0;
    }
  }
}

export function isPluginRiskPlan(plan: unknown): plan is PluginRiskPlan {
  return isRecord(plan) &&
    plan.schema_version === pluginRiskPlanSchemaVersion &&
    typeof plan.summary === "string" &&
    Array.isArray(plan.risk_flags) &&
    plan.risk_flags.every(isPluginRiskFlag) &&
    (plan.effect == null || isPluginRiskEffect(plan.effect)) &&
    (plan.details == null || isRecord(plan.details));
}

export function decodePluginStreamText(event: PluginStreamEvent): string {
  if (!event.data) return "";
  if (typeof TextDecoder === "function" && typeof atob === "function") {
    const binary = atob(event.data);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  const bufferLike = (globalThis as { Buffer?: { from(value: string, encoding: "base64"): { toString(encoding: "utf8"): string } } }).Buffer;
  if (bufferLike) return bufferLike.from(event.data, "base64").toString("utf8");
  throw new PluginBridgeError("PLUGIN_STREAM_FAILED", "No base64 decoder is available for plugin stream data");
}

export async function trustedParentBridgeHandshakeTranscriptSHA256(
  handshake: TrustedParentBridgeHandshake,
  bridgeChannelID: string,
): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Web Crypto SHA-256 is unavailable for plugin bridge handshake");
  }
  const encoder = new TextEncoder();
  const fields = [
    "redevplugin.bridge.handshake.v2",
    handshake.plugin_id,
    handshake.surface_id,
    handshake.surface_instance_id,
    handshake.active_fingerprint,
    handshake.bridge_nonce,
    handshake.asset_session_nonce,
    String(handshake.plugin_state_version),
    String(handshake.revoke_epoch),
    handshake.ui_protocol_version,
    bridgeChannelID,
  ];
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for (const field of fields) {
    const data = encoder.encode(field);
    const prefix = encoder.encode(`${data.byteLength}:`);
    const terminator = new Uint8Array([0]);
    chunks.push(prefix, data, terminator);
    totalBytes += prefix.byteLength + data.byteLength + terminator.byteLength;
  }
  const transcript = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    transcript.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const digest = await subtle.digest("SHA-256", transcript);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export type OpaqueSurfaceStyle = {
  path: string;
  sha256: string;
  content: string;
};

export type OpaqueSurfaceWorker = {
  path: string;
  sha256: string;
  type: "classic";
  content: string;
};

export type OpaqueSurfaceAsset = {
  binding_id: string;
  path: string;
  sha256: string;
  size: number;
  content_type: string;
};

export type OpaqueSurfaceDocument = {
  schema_version: typeof opaqueSurfaceDocumentSchemaVersion;
  entry_path: string;
  entry_sha256: string;
  title?: string;
  language?: string;
  direction?: string;
  body_html: string;
  styles: OpaqueSurfaceStyle[];
  worker: OpaqueSurfaceWorker;
  assets: OpaqueSurfaceAsset[];
  critical_bytes: number;
};

export type PluginSurfacePreparationResult = {
  asset_session: string;
  asset_session_id: string;
  asset_session_nonce: string;
  entry_path: string;
  entry_sha256: string;
  plugin_state_version: number;
  revoke_epoch: number;
  issued_at: string;
  expires_at: string;
  document: OpaqueSurfaceDocument;
};

export type PluginSurfaceHostBootstrap = {
  pluginId: string;
  pluginInstanceId: string;
  pluginVersion: string;
  surfaceId: string;
  surfaceInstanceId: string;
  activeFingerprint: string;
  bridgeNonce: string;
  entryPath: string;
  entrySHA256: string;
  assetTicket: string;
  assetSessionNonce: string;
  pluginStateVersion: number;
  revokeEpoch: number;
  runtimeGenerationId: string;
};

export type PluginSurfaceOpeningProgress = {
  phase: "opening";
  elapsedMs: number;
};

export type PluginSurfaceHostOptions = {
  bootstrap: PluginSurfaceHostBootstrap;
  hostTransport: ReDevPluginSurfaceTransport;
  surfaceScope?: PluginSurfaceScope;
  bridgeChannelId?: string;
  loadTimeoutMs?: number;
  requestTimeoutMs?: number;
  leaseRenewalLeadMs?: number;
  reloadLimiter?: PluginSurfaceReloadLimiter;
  confirm?: PluginConfirmationHandler;
  onOpeningProgress?: (progress: PluginSurfaceOpeningProgress) => void;
  onError?: (error: PluginBridgeError) => void;
};

declare const redevPluginSurfaceTransportBrand: unique symbol;

export type ReDevPluginSurfaceTransport = {
  readonly [redevPluginSurfaceTransportBrand]: true;
};

export type ReDevPluginSurfaceTransportOptions = {
  fetch?: FetchLike;
  apiBaseURL?: string;
};

type ReDevPluginSurfaceTransportInternals = {
  fetch: FetchLike;
  apiBaseURL: string;
};

const surfaceTransportInternals = new WeakMap<object, ReDevPluginSurfaceTransportInternals>();

export function createReDevPluginSurfaceTransport(
  options: ReDevPluginSurfaceTransportOptions = {},
): ReDevPluginSurfaceTransport {
  const transport = Object.freeze({}) as ReDevPluginSurfaceTransport;
  surfaceTransportInternals.set(transport, {
    fetch: options.fetch ?? defaultFetch(),
    apiBaseURL: normalizeSurfaceAPIBaseURL(options.apiBaseURL ?? ""),
  });
  return transport;
}

export type OpaquePluginBootstrapHTMLOptions = {
  scriptNonce?: string;
};

type PluginGatewayTokenResult = {
  plugin_gateway_token: string;
  plugin_gateway_token_id: string;
  asset_session: string;
  asset_session_id: string;
  issued_at: string;
  expires_at: string;
};

type PluginConfirmationResult = {
  confirmation_id: string;
  confirmation_token_id: string;
  request_hash: string;
  plan_hash: string;
  plan?: PluginConfirmationPlan;
  expires_at?: string;
};

type PluginConfirmationRejectionResult = {
  rejected: true;
};

type PluginSurfaceAssetReadResult = {
  path: string;
  sha256: string;
  content_type: string;
  content_base64: string;
};

type PluginSurfaceStreamReadResult = {
  events: Array<PluginStreamEvent & { stream_id: string }>;
  done: boolean;
  terminal_status?: PluginStreamTerminalStatus;
  next_stream_ticket?: string;
  next_stream_ticket_id?: string;
  next_stream_expires_at?: string;
};

type StreamCredential = {
  streamID: string;
  operationID: string;
  streamTicket: string;
  expiresAtMs: number;
  lastSequence: number;
  reading: boolean;
};

type OpenSignals = {
  portAcknowledged: Deferred<void>;
  firstPaint: Deferred<void>;
  workerReady: Deferred<void>;
};

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value?: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
};

export function createOpaquePluginBootstrapHTML(options: OpaquePluginBootstrapHTMLOptions = {}): string {
  const scriptNonce = options.scriptNonce ?? randomOpaqueNonce();
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(scriptNonce)) {
    throw new Error("scriptNonce must contain 8-128 URL-safe characters");
  }
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${scriptNonce}'`,
    `style-src 'nonce-${scriptNonce}'`,
    "img-src data: blob:",
    "font-src data: blob:",
    "media-src data: blob:",
    "connect-src 'none'",
    "frame-src 'none'",
    "worker-src blob:",
    "child-src blob:",
    "form-action 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'none'",
  ].join("; ");
  const bootstrapScript = `(() => {
  "use strict";
  const protocolVersion = ${JSON.stringify(pluginUIProtocolVersion)};
  const documentSchema = ${JSON.stringify(opaqueSurfaceDocumentSchemaVersion)};
  const workerGlobalKey = ${JSON.stringify(opaquePluginBridgeGlobalKey)};
  const scriptNonce = ${JSON.stringify(scriptNonce)};
  const maxMessageBytes = ${opaqueSurfaceRenderLimits.max_message_bytes};
  const maxInFlightRequests = ${opaqueSurfaceRenderLimits.max_in_flight_requests};
  const maxRendersPerSecond = ${opaqueSurfaceRenderLimits.max_renders_per_second};
  const maxRenderDepth = ${opaqueSurfaceRenderLimits.max_render_depth};
  const maxRenderNodes = ${opaqueSurfaceRenderLimits.max_render_nodes};
  const maxAttributesPerElement = ${opaqueSurfaceRenderLimits.max_attributes_per_element};
  const maxTextLength = ${opaqueSurfaceRenderLimits.max_text_length};
  const maxAttributeValueLength = ${opaqueSurfaceRenderLimits.max_attribute_value_length};
  const maxFormFields = ${opaqueSurfaceRenderLimits.max_form_fields};
  const maxCriticalDocumentBytes = ${8 * 1024 * 1024};
  const maxPrivateAssetBase64Length = ${Math.ceil((32 * 1024 * 1024) / 3) * 4};
  const maxLazyAssetCount = ${maxOpaqueSurfaceLazyAssets};
  const maxLazyAssetBytes = ${maxOpaqueSurfaceLazyBytes};
  const maxConcurrentAssetReads = ${maxConcurrentAssetReads};
  const allowedTags = new Set(${JSON.stringify(opaqueSurfaceAllowedTags)});
  const globalAttributes = new Set(${JSON.stringify(opaqueSurfaceGlobalAttributes)});
  const tagAttributes = Object.freeze(Object.fromEntries(
    Object.entries(${JSON.stringify(opaqueSurfaceTagAttributes)}).map(([tag, attributes]) => [tag, new Set(attributes)])
  ));
  const safeInputTypes = new Set(${JSON.stringify(opaqueSurfaceSafeInputTypes)});
  const exactKeys = (value, keys) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
  };
  const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const canonicalJSON = (value, depth = 0, state = { nodes: 0 }, seen = new Set()) => {
    state.nodes += 1;
    if (state.nodes > 4096 || depth > 64) return false;
    if (value === null || typeof value === "string" || typeof value === "boolean") return true;
    if (typeof value === "number") return Number.isFinite(value);
    if (typeof value !== "object" || seen.has(value)) return false;
    seen.add(value);
    if (Array.isArray(value)) {
      const valid = value.every((item) => canonicalJSON(item, depth + 1, state, seen));
      seen.delete(value);
      return valid;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) return false;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor) || !canonicalJSON(descriptor.value, depth + 1, state, seen)) return false;
    }
    seen.delete(value);
    return true;
  };
  const withinLimit = (value) => {
    try { return canonicalJSON(value) && new TextEncoder().encode(JSON.stringify(value)).byteLength <= maxMessageBytes; }
    catch { return false; }
  };
  const validIdentifier = (value) => typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  const validOpaqueHandle = (value, prefix) => typeof value === "string" && value.startsWith(prefix + "_") && /^[A-Za-z0-9_-]{8,160}$/.test(value);
  const validDigest = (value) => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
  const validPath = (value) => typeof value === "string" && value.length > 0 && value.length <= 512 && !value.startsWith("/") && !value.includes("\\\\") && !value.split("/").some((part) => !part || part === "." || part === "..");
  const validAttribute = (tag, name, value) => {
    const lower = name.toLowerCase();
    if (lower.startsWith("on") || lower === "style" || lower === "src" || lower === "srcset" || lower === "href" || lower === "srcdoc" || lower === "action" || lower === "formaction") return false;
    if (!globalAttributes.has(lower) && !lower.startsWith("aria-") && !(tagAttributes[tag] && tagAttributes[tag].has(lower))) return false;
    if (!["string", "number", "boolean"].includes(typeof value)) return false;
    if (lower === "data-redevplugin-action" && !validIdentifier(String(value))) return false;
    if (lower === "data-redevplugin-asset-binding" && !validOpaqueHandle(String(value), "asset")) return false;
    if (lower === "data-redevplugin-asset-attr" && !["src", "poster"].includes(String(value))) return false;
    if (tag === "input" && lower === "type" && !safeInputTypes.has(String(value).trim().toLowerCase() || "text")) return false;
    return String(value).length <= maxAttributeValueLength;
  };
  const validateDOMTree = (root) => {
    let nodes = 0;
    const walk = (node, depth) => {
      nodes += 1;
      if (nodes > maxRenderNodes || depth > maxRenderDepth) return false;
      if (node.nodeType === Node.TEXT_NODE) return (node.nodeValue || "").length <= maxTextLength;
      if (node.nodeType !== Node.ELEMENT_NODE) return false;
      const tag = node.tagName.toLowerCase();
      if (!allowedTags.has(tag)) return false;
      for (const attr of node.attributes) {
        if (!validAttribute(tag, attr.name, attr.value)) return false;
      }
      for (const child of node.childNodes) if (!walk(child, depth + 1)) return false;
      return true;
    };
    for (const child of root.childNodes) if (!walk(child, 1)) return false;
    return true;
  };
  const validStyle = (value) => exactKeys(value, ["path", "sha256", "content"]) && validPath(value.path) && validDigest(value.sha256) && typeof value.content === "string" && value.content.length <= 2097152;
  const validWorker = (value) => exactKeys(value, ["path", "sha256", "type", "content"]) && validPath(value.path) && validDigest(value.sha256) && value.type === "classic" && typeof value.content === "string" && value.content.length <= 4194304;
  const validAsset = (value) => exactKeys(value, ["binding_id", "path", "sha256", "size", "content_type"]) && validOpaqueHandle(value.binding_id, "asset") && validPath(value.path) && validDigest(value.sha256) && Number.isSafeInteger(value.size) && value.size >= 0 && value.size <= maxLazyAssetBytes && typeof value.content_type === "string" && value.content_type.length > 0 && value.content_type.length <= 256;
  const validDocument = (value) => isRecord(value) && Object.keys(value).every((key) => ["schema_version", "entry_path", "entry_sha256", "title", "language", "direction", "body_html", "styles", "worker", "assets", "critical_bytes"].includes(key)) && value.schema_version === documentSchema && validPath(value.entry_path) && validDigest(value.entry_sha256) && (value.title === undefined || (typeof value.title === "string" && value.title.length <= 256)) && (value.language === undefined || (typeof value.language === "string" && value.language.length <= 64)) && (value.direction === undefined || ["ltr", "rtl", "auto"].includes(value.direction)) && typeof value.body_html === "string" && value.body_html.length <= 4194304 && Array.isArray(value.styles) && value.styles.every(validStyle) && validWorker(value.worker) && Array.isArray(value.assets) && value.assets.length <= maxLazyAssetCount && value.assets.every(validAsset) && new Set(value.assets.map((asset) => asset.binding_id)).size === value.assets.length && new Set(value.assets.map((asset) => asset.path)).size === value.assets.length && value.assets.reduce((total, asset) => total + asset.size, 0) <= maxLazyAssetBytes && Number.isSafeInteger(value.critical_bytes) && value.critical_bytes >= 0 && value.critical_bytes <= maxCriticalDocumentBytes;
  let accepted = false;
  let initialized = false;
  let parentPort;
  let worker;
  let workerControlPort;
  let workerPort;
  let frameGenerationID = "";
  let surfaceHandle = "";
  let currentDocument;
  let workerReady = false;
  const pendingWorkerRequests = new Set();
  const requestSequence = { rpc: 0, stream: 0, render: 0, operation: 0 };
  let renderWindowStartedAt = 0;
  let renderCount = 0;
  const pendingAssets = new Map();
  const queuedAssets = [];
  let activeAssetReads = 0;
  let assetSequence = 0;
  const blobURLs = new Set();

  const sendParent = (message) => {
    if (parentPort && withinLimit(message)) parentPort.postMessage(message);
  };
  const sendWorker = (message) => {
    if (workerPort && withinLimit(message)) workerPort.postMessage(message);
  };
  const fail = (message) => {
    document.documentElement.lang = "en";
    document.body.replaceChildren();
    const error = document.createElement("pre");
    error.setAttribute("role", "alert");
    error.textContent = "Plugin surface failed to initialize.";
    document.body.append(error);
    sendParent({ type: "redevplugin.surface.error", error: String(message).slice(0, 512) });
    disposeRuntime();
  };
  const disposeRuntime = () => {
    if (workerControlPort) {
      workerControlPort.close();
      workerControlPort = undefined;
    }
    if (workerPort) {
      try { workerPort.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "dispose" } }); } catch {}
      workerPort.close();
      workerPort = undefined;
    }
    if (worker) {
      worker.terminate();
      worker = undefined;
    }
    for (const url of blobURLs) URL.revokeObjectURL(url);
    blobURLs.clear();
    pendingWorkerRequests.clear();
    pendingAssets.clear();
    queuedAssets.length = 0;
    activeAssetReads = 0;
  };
  const applyStaticDocument = (surfaceDocument) => {
    document.title = typeof surfaceDocument.title === "string" ? surfaceDocument.title.slice(0, 256) : "Plugin";
    document.documentElement.lang = typeof surfaceDocument.language === "string" ? surfaceDocument.language.slice(0, 64) : "en";
    if (["ltr", "rtl", "auto"].includes(surfaceDocument.direction)) document.documentElement.dir = surfaceDocument.direction;
    const template = document.createElement("template");
    template.innerHTML = surfaceDocument.body_html;
    if (!validateDOMTree(template.content)) throw new Error("static plugin document failed renderer validation");
    document.body.replaceChildren(template.content.cloneNode(true));
    for (const styleAsset of surfaceDocument.styles) {
      const style = document.createElement("style");
      style.setAttribute("nonce", scriptNonce);
      style.dataset.redevpluginAsset = styleAsset.path;
      style.textContent = styleAsset.content;
      document.head.append(style);
    }
  };
  const buildWorkerNode = (value, state, depth) => {
    state.nodes += 1;
    if (state.nodes > maxRenderNodes || depth > maxRenderDepth) throw new Error("plugin render tree exceeds limits");
    if (typeof value === "string") {
      if (value.length > maxTextLength) throw new Error("plugin render text exceeds limits");
      return document.createTextNode(value);
    }
    if (!exactKeys(value, Object.prototype.hasOwnProperty.call(value, "attributes") && Object.prototype.hasOwnProperty.call(value, "children") ? ["type", "tag", "attributes", "children"] : Object.prototype.hasOwnProperty.call(value, "attributes") ? ["type", "tag", "attributes"] : Object.prototype.hasOwnProperty.call(value, "children") ? ["type", "tag", "children"] : ["type", "tag"]) || value.type !== "element" || typeof value.tag !== "string") throw new Error("plugin render node is invalid");
    const tag = value.tag.toLowerCase();
    if (!allowedTags.has(tag)) throw new Error("plugin render tag is not allowed");
    const element = document.createElement(tag);
    if (value.attributes !== undefined) {
      if (!isRecord(value.attributes) || Object.keys(value.attributes).length > maxAttributesPerElement) throw new Error("plugin render attributes are invalid");
      for (const [name, attributeValue] of Object.entries(value.attributes)) {
        if (!validAttribute(tag, name, attributeValue)) throw new Error("plugin render attribute is not allowed");
        if (typeof attributeValue === "boolean") {
          if (attributeValue) element.setAttribute(name, "");
        } else {
          element.setAttribute(name, String(attributeValue));
        }
      }
    }
    if (value.children !== undefined) {
      if (!Array.isArray(value.children)) throw new Error("plugin render children are invalid");
      for (const child of value.children) element.append(buildWorkerNode(child, state, depth + 1));
    }
    return element;
  };
  const applyWorkerRender = (tree) => {
    const values = Array.isArray(tree) ? tree : [tree];
    const fragment = document.createDocumentFragment();
    const state = { nodes: 0 };
    for (const value of values) fragment.append(buildWorkerNode(value, state, 1));
    document.body.replaceChildren(fragment);
  };
  const actionPayload = (event, element) => {
    const payload = { type: "redevplugin.ui.action", action: element.getAttribute("data-redevplugin-action"), event: event.type };
    const target = event.target;
    if (target && typeof target.value === "string") payload.value = target.value.slice(0, maxTextLength);
    if (target && typeof target.checked === "boolean") payload.checked = target.checked;
    if (event.type === "submit" && event.target instanceof HTMLFormElement) {
      const values = {};
      let count = 0;
      for (const [name, value] of new FormData(event.target)) {
        if (typeof value !== "string" || !validIdentifier(name) || count >= maxFormFields) continue;
        values[name] = value.slice(0, maxTextLength);
        count += 1;
      }
      payload.form_data = values;
    }
    return payload;
  };
  const handleAction = (event) => {
    if (!["click", "input", "change", "submit"].includes(event.type)) return;
    if (event.type === "submit") event.preventDefault();
    const origin = event.target instanceof Element ? event.target : null;
    const element = origin ? origin.closest("[data-redevplugin-action]") : null;
    if (!element || !document.body.contains(element)) return;
    event.preventDefault();
    const action = element.getAttribute("data-redevplugin-action");
    if (!validIdentifier(action)) return;
    sendWorker(actionPayload(event, element));
  };
  for (const eventType of ["click", "input", "change", "submit"]) document.addEventListener(eventType, handleAction, true);
  const pumpAssets = () => {
    while (activeAssetReads < maxConcurrentAssetReads && queuedAssets.length > 0) {
      const asset = queuedAssets.shift();
      const requestID = "asset_request_" + (++assetSequence);
      pendingAssets.set(requestID, asset);
      activeAssetReads += 1;
      sendParent({ type: "redevplugin.surface.asset.read", request_id: requestID, binding_id: asset.binding_id, path: asset.path, sha256: asset.sha256 });
    }
  };
  const loadAssets = () => {
    queuedAssets.push(...currentDocument.assets);
    pumpAssets();
  };
  const applyAsset = async (asset, contentBase64) => {
    if (contentBase64.length !== Math.ceil(asset.size / 3) * 4) throw new Error("plugin asset encoded size mismatch");
    const binary = atob(contentBase64);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (bytes.byteLength !== asset.size) throw new Error("plugin asset size mismatch");
    if (!crypto || !crypto.subtle) throw new Error("plugin asset SHA-256 verification is unavailable");
    const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const actualDigest = "sha256:" + Array.from(digestBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (actualDigest !== asset.sha256) throw new Error("plugin asset bytes failed SHA-256 verification");
    const url = URL.createObjectURL(new Blob([bytes], { type: asset.content_type }));
    blobURLs.add(url);
    document.documentElement.style.setProperty("--redevplugin-asset-" + asset.binding_id, 'url("' + url.replaceAll('"', '%22') + '")');
    for (const element of document.querySelectorAll('[data-redevplugin-asset-binding="' + asset.binding_id + '"]')) {
      const attribute = element.getAttribute("data-redevplugin-asset-attr");
      if (attribute === "src" || attribute === "poster") element.setAttribute(attribute, url);
      element.removeAttribute("data-redevplugin-asset-binding");
      element.removeAttribute("data-redevplugin-asset-attr");
    }
  };
  const workerRuntime = () => [
    '{',
    '"use strict";',
    'const __rpTimer = setTimeout(() => close(), 30000);',
    'const __rpListener = (event) => {',
    '    const value = event.data;',
    '    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "port_roles,surface_handle,type,ui_protocol_version" || value.type !== "redevplugin.worker.initialize" || value.ui_protocol_version !== ' + JSON.stringify(protocolVersion) + ' || typeof value.surface_handle !== "string" || !Array.isArray(value.port_roles) || value.port_roles.join(",") !== "runtime_control,plugin_bridge" || !event.ports || event.ports.length !== 2) return;',
    '    clearTimeout(__rpTimer); removeEventListener("message", __rpListener);',
    '    const __rpSurfaceHandle = value.surface_handle;',
    '    const __rpControlPort = event.ports[0];',
    '    const __rpPort = event.ports[1];',
    'const __rpControlPost = __rpControlPort.postMessage.bind(__rpControlPort);',
    'const __rpControlStart = __rpControlPort.start.bind(__rpControlPort);',
    'const __rpControlClose = __rpControlPort.close.bind(__rpControlPort);',
    'const __rpGetPrototypeOf = Object.getPrototypeOf;',
    'const __rpGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;',
    'const __rpDefineProperty = Object.defineProperty;',
    'const __rpHasOwn = Object.prototype.hasOwnProperty;',
    'const __rpBlocked = () => { throw new TypeError("API is unavailable in the ReDevPlugin worker sandbox"); };',
    'const __rpSealDescriptor = (owner, name, value) => {',
    '    const descriptor = __rpGetOwnPropertyDescriptor(owner, name);',
    '    if (!descriptor) return;',
    '    if (descriptor.configurable) __rpDefineProperty(owner, name, { configurable: false, enumerable: Boolean(descriptor.enumerable), writable: false, value });',
    '    else if (Object.prototype.hasOwnProperty.call(descriptor, "value") && descriptor.writable) __rpDefineProperty(owner, name, { writable: false, value });',
    '    else if (!Object.prototype.hasOwnProperty.call(descriptor, "value") || descriptor.value !== value) throw new TypeError("Unable to seal worker API " + name);',
    '    const sealed = __rpGetOwnPropertyDescriptor(owner, name);',
    '    if (!sealed || !Object.prototype.hasOwnProperty.call(sealed, "value") || sealed.configurable || sealed.writable || sealed.value !== value) throw new TypeError("Worker API remained available: " + name);',
    '};',
    'const __rpSealChain = (target, name, value) => {',
    '    let current = target;',
    '    let found = false;',
    '    while (current) {',
    '        if (__rpHasOwn.call(current, name)) { found = true; __rpSealDescriptor(current, name, value); }',
    '        current = __rpGetPrototypeOf(current);',
    '    }',
    '    if (!found || !__rpHasOwn.call(target, name)) __rpDefineProperty(target, name, { configurable: false, enumerable: false, writable: false, value });',
    '    __rpSealDescriptor(target, name, value);',
    '};',
    'const __rpSealMessagePortMethod = (name) => {',
    '    let current = __rpGetPrototypeOf(__rpControlPort);',
    '    let found = false;',
    '    while (current) {',
    '        const descriptor = __rpGetOwnPropertyDescriptor(current, name);',
    '        if (descriptor && __rpHasOwn.call(descriptor, "value") && typeof descriptor.value === "function") { found = true; __rpSealDescriptor(current, name, descriptor.value); }',
    '        current = __rpGetPrototypeOf(current);',
    '    }',
    '    if (!found) throw new TypeError("MessagePort method is unavailable: " + name);',
    '};',
    'try {',
    '    for (const name of ["postMessage", "start", "close", "addEventListener", "removeEventListener"]) __rpSealMessagePortMethod(name);',
    '    for (const [name, value] of Object.entries({fetch:__rpBlocked,XMLHttpRequest:undefined,WebSocket:undefined,EventSource:undefined,WebTransport:undefined,Worker:undefined,SharedWorker:undefined,indexedDB:undefined,caches:undefined,RTCPeerConnection:undefined,webkitRTCPeerConnection:undefined,BroadcastChannel:undefined,importScripts:undefined,postMessage:undefined,eval:undefined,Function:undefined,Blob:undefined,File:undefined,FileReader:undefined,FileReaderSync:undefined})) __rpSealChain(globalThis, name, value);',
    '    for (const [name, value] of Object.entries({storage:undefined,sendBeacon:undefined,serviceWorker:undefined})) __rpSealChain(navigator, name, value);',
    '    const __rpFunctionPrototypes = [__rpGetPrototypeOf(function() {}), __rpGetPrototypeOf(async function() {}), __rpGetPrototypeOf(function*() {}), __rpGetPrototypeOf(async function*() {})];',
    '    for (const prototype of __rpFunctionPrototypes) __rpSealDescriptor(prototype, "constructor", undefined);',
    '} catch (error) {',
    '    try { __rpControlPost({ type: "redevplugin.worker.error", error: String(error && error.message || error).slice(0, 512) }); } catch {}',
    '    try { __rpControlClose(); } catch {}',
    '    try { __rpPort.close(); } catch {}',
    '    close();',
    '    return;',
    '}',
    'const __rpVerifyDynamicImportBlocked = async () => {',
    '    const specifier = "data:text/javascript,export default 1";',
    '    try {',
    '        await import(specifier);',
    '        return false;',
    '    } catch {',
    '        return true;',
    '    }',
    '};',
    'let __rpClaimed = false;',
    'const __rpBridge = Object.freeze({ claim() { if (__rpClaimed) return undefined; __rpClaimed = true; return Object.freeze({ surfaceHandle: __rpSurfaceHandle, port: __rpPort }); } });',
    'Object.defineProperty(globalThis, ' + JSON.stringify(workerGlobalKey) + ', { configurable: false, enumerable: false, writable: false, value: __rpBridge });',
    '__rpControlStart();',
    '__rpPort.start();',
    'let __rpFailed = false;',
    'const __rpReportFailure = (error) => { if (__rpFailed) return; __rpFailed = true; __rpControlPost({ type: "redevplugin.worker.error", error: String(error && error.message || error).slice(0, 512) }); };',
    'addEventListener("error", (event) => __rpReportFailure(event.error || event.message || "plugin worker failed"), { capture: true });',
    'addEventListener("unhandledrejection", (event) => __rpReportFailure(event.reason || "plugin worker rejected"), { capture: true });',
    'void (async () => {',
    '    try {',
    '        if (!await __rpVerifyDynamicImportBlocked()) throw new TypeError("Dynamic import escaped the ReDevPlugin worker sandbox");',
    '        __redevpluginPluginMain();',
    '        setTimeout(() => { if (!__rpFailed) __rpControlPost({ type: "redevplugin.worker.ready" }); }, 0);',
    '    } catch (error) {',
    '        __rpReportFailure(error);',
    '    }',
    '})();',
    '};',
    'addEventListener("message", __rpListener);',
    '}'
  ].join("\\n");
  const startWorker = (surfaceDocument) => {
    const source = 'const __redevpluginPluginMain = () => {\\n"use strict";\\n' + surfaceDocument.worker.content + '\\n};\\n' + workerRuntime();
    const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    blobURLs.add(url);
    worker = new Worker(url, { name: "redevplugin-surface" });
    worker.addEventListener("error", (event) => fail(event.message || "plugin worker failed to load"));
    worker.addEventListener("messageerror", () => fail("plugin worker message could not be decoded"));
    const controlChannel = new MessageChannel();
    const pluginChannel = new MessageChannel();
    workerControlPort = controlChannel.port1;
    workerControlPort.addEventListener("message", onWorkerControlMessage);
    workerControlPort.start();
    workerPort = pluginChannel.port1;
    workerPort.addEventListener("message", onWorkerMessage);
    workerPort.start();
    worker.postMessage({ type: "redevplugin.worker.initialize", surface_handle: surfaceHandle, ui_protocol_version: protocolVersion, port_roles: ["runtime_control", "plugin_bridge"] }, [controlChannel.port2, pluginChannel.port2]);
  };
  const validCall = (value) => exactKeys(value, ["type", "request"]) && value.type === "redevplugin.bridge.call" && isRecord(value.request) && Object.keys(value.request).every((key) => ["id", "method", "params"].includes(key)) && typeof value.request.id === "string" && value.request.id.length <= 128 && typeof value.request.method === "string" && /^[A-Za-z0-9._:-]{1,256}$/.test(value.request.method) && (value.request.params === undefined || isRecord(value.request.params));
  const requestID = (value, expectedKind) => {
    if (typeof value !== "string") return undefined;
    const match = /^(rpc|stream|render|operation)_([1-9][0-9]{0,15})$/.exec(value);
    if (!match || match[1] !== expectedKind) return undefined;
    const sequence = Number(match[2]);
    return Number.isSafeInteger(sequence) ? { kind: match[1], sequence } : undefined;
  };
  const acceptWorkerRequest = (id, kind) => {
    const parsed = requestID(id, kind);
    if (!parsed || parsed.sequence <= requestSequence[kind] || pendingWorkerRequests.size >= maxInFlightRequests) return false;
    requestSequence[kind] = parsed.sequence;
    pendingWorkerRequests.add(id);
    return true;
  };
  const completeWorkerRequest = (id) => pendingWorkerRequests.delete(id);
  const renderRateAllowed = () => {
    const now = performance.now();
    if (now - renderWindowStartedAt >= 1000) { renderWindowStartedAt = now; renderCount = 0; }
    if (renderCount >= maxRendersPerSecond) return false;
    renderCount += 1;
    return true;
  };
  const rejectWorkerRequest = (id, error) => sendWorker({ type: "redevplugin.bridge.response", id, ok: false, error_code: "PLUGIN_INVALID_REQUEST", error });
  const onWorkerControlMessage = (event) => {
    if (!withinLimit(event.data)) return;
    const message = event.data;
    if (exactKeys(message, ["type"]) && message.type === "redevplugin.worker.ready") {
      if (workerReady) return;
      workerReady = true;
      sendParent({ type: "redevplugin.surface.worker_ready" });
      return;
    }
    if (exactKeys(message, ["type", "error"]) && message.type === "redevplugin.worker.error" && typeof message.error === "string") {
      fail(message.error);
      return;
    }
  };
  const onWorkerMessage = (event) => {
    if (!withinLimit(event.data)) return;
    const message = event.data;
    if (validCall(message)) {
      if (!acceptWorkerRequest(message.request.id, "rpc")) return rejectWorkerRequest(message.request.id, "duplicate, replayed, or excessive plugin request");
      sendParent(message);
      return;
    }
    if (exactKeys(message, ["type", "id", "stream_handle"]) && message.type === "redevplugin.bridge.stream.read" && typeof message.id === "string" && validOpaqueHandle(message.stream_handle, "stream")) {
      if (!acceptWorkerRequest(message.id, "stream")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      sendParent(message);
      return;
    }
    if (isRecord(message) && Object.keys(message).every((key) => ["type", "id", "operation_id", "reason"].includes(key)) &&
        message.type === "redevplugin.bridge.operation.cancel" && typeof message.id === "string" &&
        validOpaqueHandle(message.operation_id, "operation") && (message.reason === undefined || (typeof message.reason === "string" && message.reason.length <= 256))) {
      if (!acceptWorkerRequest(message.id, "operation")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      sendParent(message);
      return;
    }
    if (exactKeys(message, ["type", "id", "tree"]) && message.type === "redevplugin.ui.render" && typeof message.id === "string") {
      if (!acceptWorkerRequest(message.id, "render")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      if (!renderRateAllowed()) {
        completeWorkerRequest(message.id);
        return rejectWorkerRequest(message.id, "plugin render rate limit exceeded");
      }
      try {
        applyWorkerRender(message.tree);
        completeWorkerRequest(message.id);
        sendWorker({ type: "redevplugin.bridge.response", id: message.id, ok: true });
      } catch (error) {
        completeWorkerRequest(message.id);
        sendWorker({ type: "redevplugin.bridge.response", id: message.id, ok: false, error_code: "PLUGIN_CONTRACT_MISMATCH", error: String(error && error.message || error).slice(0, 512) });
      }
      return;
    }
    if (exactKeys(message, ["type", "id"]) && message.type === "redevplugin.bridge.cancel" && typeof message.id === "string") {
      if (!pendingWorkerRequests.has(message.id)) return rejectWorkerRequest(message.id, "plugin request is not pending");
      completeWorkerRequest(message.id);
      sendParent(message);
    }
  };
  const onParentMessage = async (event) => {
    const message = event.data;
    if (!initialized) {
      if (!exactKeys(message, ["type", "frame_generation_id", "surface_handle", "document"]) || message.type !== "redevplugin.surface.initialize" || message.frame_generation_id !== frameGenerationID || !validOpaqueHandle(message.surface_handle, "surface") || !validDocument(message.document)) return fail("invalid private initialize message");
      initialized = true;
      surfaceHandle = message.surface_handle;
      currentDocument = message.document;
      try { applyStaticDocument(currentDocument); startWorker(currentDocument); }
      catch (error) { return fail(error); }
      requestAnimationFrame(() => requestAnimationFrame(() => {
        sendParent({ type: "redevplugin.surface.first_paint" });
        loadAssets();
      }));
      return;
    }
    if (message && message.type === "redevplugin.bridge.response" && typeof message.id === "string" && pendingWorkerRequests.has(message.id) && withinLimit(message)) {
      completeWorkerRequest(message.id);
      sendWorker(message);
      return;
    }
    if (message && message.type === "redevplugin.bridge.lifecycle" && isRecord(message.event) && ["ready", "visible", "hidden", "dispose"].includes(message.event.type)) {
      sendWorker(message);
      if (message.event.type === "dispose") disposeRuntime();
      return;
    }
    if (exactKeys(message, ["type", "request_id", "binding_id", "ok", "path", "sha256", "content_type", "content_base64"]) && message.type === "redevplugin.surface.asset.response" && typeof message.content_base64 === "string" && message.content_base64.length <= maxPrivateAssetBase64Length) {
      const asset = pendingAssets.get(message.request_id);
      pendingAssets.delete(message.request_id);
      if (asset) activeAssetReads = Math.max(0, activeAssetReads - 1);
      if (!asset || message.ok !== true || message.binding_id !== asset.binding_id || message.path !== asset.path || message.sha256 !== asset.sha256 || message.content_type !== asset.content_type || typeof message.content_base64 !== "string") {
        fail("plugin asset response did not match the prepared document");
        return;
      }
      try {
        await applyAsset(asset, message.content_base64);
      } catch {
        fail("plugin asset response failed renderer validation");
        return;
      }
      pumpAssets();
    }
  };
  const onWindowMessage = (event) => {
    if (accepted || event.source !== parent || !event.ports || event.ports.length !== 1) return;
    const message = event.data;
    if (!exactKeys(message, ["type", "frame_generation_id", "ui_protocol_version"]) || message.type !== "redevplugin.surface.port" || message.ui_protocol_version !== protocolVersion || !validOpaqueHandle(message.frame_generation_id, "frame")) return;
    accepted = true;
    frameGenerationID = message.frame_generation_id;
    removeEventListener("message", onWindowMessage);
    parentPort = event.ports[0];
    parentPort.addEventListener("message", onParentMessage);
    parentPort.start();
    parentPort.postMessage({ type: "redevplugin.surface.port_ack", frame_generation_id: frameGenerationID });
  };
  addEventListener("message", onWindowMessage);
})();`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${escapeHTMLAttribute(csp)}"><title>Plugin</title></head><body><script nonce="${scriptNonce}">${bootstrapScript}</script></body></html>`;
}

const pluginSurfaceHostConstructorToken = Symbol("redevplugin.surface-host.constructor");

export class PluginSurfaceHost {
  readonly element: HTMLIFrameElement;
  readonly bootstrap: PluginSurfaceHostBootstrap;
  readonly bridgeChannelId: string;
  readonly frameGenerationId: string;
  readonly surfaceHandle: string;
  #iframe: PluginSurfaceFrameLike;
  #transport: ReDevPluginSurfaceTransportInternals;
  #createMessageChannel: () => MessageChannelLike;
  #loadTimeoutMs: number;
  #requestTimeoutMs: number;
  #leaseRenewalLeadMs: number;
  #reloadLimiter: PluginSurfaceReloadLimiter;
  #confirm?: PluginConfirmationHandler;
  #onOpeningProgress?: (progress: PluginSurfaceOpeningProgress) => void;
  #onError?: (error: PluginBridgeError) => void;
  #abortController = new AbortController();
  #gatewayToken?: string;
  #leaseExpiresAtMs = 0;
  #leaseRenewAtMs = 0;
  #leaseRenewalTimer?: ReturnType<typeof setTimeout>;
  #leaseRenewalPromise?: Promise<void>;
  #assetSession?: string;
  #assetSessionID?: string;
  #document?: OpaqueSurfaceDocument;
  #assets = new Map<string, OpaqueSurfaceAsset>();
  #streamCredentials = new Map<string, StreamCredential>();
  #pendingRequestControllers = new Map<string, AbortController>();
  #activeTransportRequests = 0;
  #activeAssetReads = 0;
  #transportIdle?: Deferred<void>;
  #port?: MessagePortLike;
  #openSignals?: OpenSignals;
  #initialFrameLoad?: Deferred<void>;
  #frameLoaded = false;
  #revokePromise?: Promise<void>;
  #unregisterSurfaceScope?: () => void;
  #opened = false;
  #ready = false;
  #disposed = false;
  #onPortMessage = (event: MessageEventLike): void => {
    void this.#handlePortMessage(event);
  };
  #onFrameLoad = (): void => {
    if (this.#disposed || !this.#opened) return;
    if (!this.#frameLoaded) {
      this.#frameLoaded = true;
      this.#initialFrameLoad?.resolve();
      return;
    }
    const decision = this.#reloadLimiter.recordCrash();
    const error = new PluginBridgeError(
      "PLUGIN_BRIDGE_HANDSHAKE_FAILED",
      `Plugin iframe reloaded unexpectedly (attempt ${decision.attempt})`,
    );
    void this.#failSurface(error);
  };

  static create(options: PluginSurfaceHostOptions): PluginSurfaceHost {
    validateHostBootstrap(options.bootstrap);
    const transport = surfaceTransportInternals.get(options.hostTransport);
    if (!transport) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface host transport is invalid");
    }
    return new PluginSurfaceHost(pluginSurfaceHostConstructorToken, options, transport, createPluginSurfaceFrame());
  }

  private constructor(
    constructorToken: typeof pluginSurfaceHostConstructorToken,
    options: PluginSurfaceHostOptions,
    transport: ReDevPluginSurfaceTransportInternals,
    iframe: HTMLIFrameElement,
  ) {
    if (constructorToken !== pluginSurfaceHostConstructorToken) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface hosts must be created through PluginSurfaceHost.create()");
    }
    this.element = iframe;
    this.bootstrap = options.bootstrap;
    this.bridgeChannelId = options.bridgeChannelId ?? randomOpaqueHandle("bridge");
    this.frameGenerationId = randomOpaqueHandle("frame");
    this.surfaceHandle = randomOpaqueHandle("surface");
    this.#iframe = iframe;
    this.#transport = transport;
    this.#createMessageChannel = captureMessageChannelFactory();
    this.#loadTimeoutMs = normalizeTimeout(options.loadTimeoutMs);
    this.#requestTimeoutMs = normalizeTimeout(options.requestTimeoutMs);
    this.#leaseRenewalLeadMs = normalizeLeaseRenewalLead(options.leaseRenewalLeadMs);
    this.#reloadLimiter = options.reloadLimiter ?? new PluginSurfaceReloadLimiter();
    this.#confirm = options.confirm;
    this.#onOpeningProgress = options.onOpeningProgress;
    this.#onError = options.onError;
    hardenPluginSurfaceFrame(this.#iframe);
    this.#unregisterSurfaceScope = registerPluginSurface(
      options.surfaceScope ?? defaultPluginSurfaceScope,
      this.bootstrap.pluginInstanceId,
      () => this.#disposeLocal(),
    );
  }

  async open(): Promise<void> {
    this.#assertActive();
    if (this.#opened) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin surface host is already open");
    }
    this.#opened = true;
    const startedAt = Date.now();
    const progressTimer = setTimeout(() => {
      if (!this.#ready && !this.#disposed) {
        this.#onOpeningProgress?.({
          phase: "opening",
          elapsedMs: Math.max(openingProgressDelayMs, Date.now() - startedAt),
        });
      }
    }, openingProgressDelayMs);
    const signals: OpenSignals = { portAcknowledged: deferred<void>(), firstPaint: deferred<void>(), workerReady: deferred<void>() };
    void signals.portAcknowledged.promise.catch(() => undefined);
    void signals.firstPaint.promise.catch(() => undefined);
    void signals.workerReady.promise.catch(() => undefined);
    this.#openSignals = signals;
    const scriptNonce = randomOpaqueNonce();
    this.#frameLoaded = false;
    const initialFrameLoad = deferred<void>();
    this.#initialFrameLoad = initialFrameLoad;
    this.#iframe.addEventListener("load", this.#onFrameLoad);
    hardenPluginSurfaceFrame(this.#iframe);
    this.#iframe.srcdoc = createOpaquePluginBootstrapHTML({ scriptNonce });

    try {
      await withTimeout(
        this.#completeOpening(signals, initialFrameLoad.promise),
        this.#loadTimeoutMs,
        "Plugin surface opening timed out",
      );
    } catch (error) {
      const bridgeError = toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
      if (bridgeError.errorCode === "PLUGIN_BRIDGE_TIMEOUT") this.#reloadLimiter.recordCrash();
      this.#reportError(bridgeError);
      const revoke = this.#bestEffortRevokeSurface(false);
      this.#disposeLocal();
      await revoke;
      throw bridgeError;
    } finally {
      clearTimeout(progressTimer);
      this.#openSignals = undefined;
      this.#initialFrameLoad = undefined;
    }
  }

  async #completeOpening(signals: OpenSignals, initialFrameLoad: Promise<void>): Promise<void> {
    const [preparation] = await Promise.all([this.#prepareSurface(), initialFrameLoad]);
    this.#assertActive();
    validateSurfacePreparation(this.bootstrap, preparation);
    this.#assetSession = preparation.asset_session;
    this.#assetSessionID = preparation.asset_session_id;
    this.#document = preparation.document;
    this.#assets = new Map(preparation.document.assets.map((asset) => [asset.binding_id, asset]));

    const channel = this.#createMessageChannel();
    this.#port = channel.port1;
    this.#port.addEventListener("message", this.#onPortMessage);
    this.#port.start();
    const iframeWindow = this.#iframe.contentWindow;
    if (!iframeWindow) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin iframe window is unavailable");
    }
    iframeWindow.postMessage({
      type: "redevplugin.surface.port",
      frame_generation_id: this.frameGenerationId,
      ui_protocol_version: pluginUIProtocolVersion,
    }, "*", [channel.port2]);

    await signals.portAcknowledged.promise;
    this.#assertActive();

    const token = await this.#mintBridgeToken();
    this.#assertActive();
    this.#applyLease(token);
    this.#postToRenderer({
      type: "redevplugin.surface.initialize",
      frame_generation_id: this.frameGenerationId,
      surface_handle: this.surfaceHandle,
      document: preparation.document,
    });

    await Promise.all([signals.firstPaint.promise, signals.workerReady.promise]);
    this.#assertActive();
    this.#ready = true;
    this.#scheduleLeaseRenewal();
    this.#reloadLimiter.recordHealthyLoad();
    this.#postToRenderer({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
  }

  sendLifecycle(event: Exclude<BridgeLifecycleEvent, { type: "ready" | "dispose" }>): void {
    this.#assertReady();
    this.#postToRenderer({ type: "redevplugin.bridge.lifecycle", event });
  }

  async close(): Promise<void> {
    if (this.#disposed) return;
    const revoke = this.#revokeSurface(false);
    this.#disposeLocal();
    try {
      await revoke;
    } catch (error) {
      throw toBridgeError(error, "PLUGIN_BRIDGE_DISPOSED");
    }
  }

  dispose(): void {
    if (this.#disposed) return;
    void this.#bestEffortRevokeSurface(true);
    this.#disposeLocal();
  }

  #disposeLocal(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#unregisterSurfaceScope?.();
    this.#unregisterSurfaceScope = undefined;
    this.#ready = false;
    if (this.#leaseRenewalTimer) clearTimeout(this.#leaseRenewalTimer);
    this.#leaseRenewalTimer = undefined;
    this.#iframe.removeEventListener("load", this.#onFrameLoad);
    this.#abortController.abort();
    for (const controller of this.#pendingRequestControllers.values()) controller.abort();
    this.#pendingRequestControllers.clear();
    const disposedError = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface host was disposed");
    this.#openSignals?.firstPaint.reject(disposedError);
    this.#openSignals?.workerReady.reject(disposedError);
    this.#openSignals?.portAcknowledged.reject(disposedError);
    this.#initialFrameLoad?.reject(disposedError);
    this.#gatewayToken = undefined;
    this.#leaseExpiresAtMs = 0;
    this.#assetSession = undefined;
    this.#assetSessionID = undefined;
    this.#document = undefined;
    this.#assets.clear();
    this.#streamCredentials.clear();
    if (this.#port) {
      try {
        this.#port.postMessage({ type: "redevplugin.bridge.lifecycle", event: { type: "dispose" } });
      } catch {
        // The sandbox may already have closed its end of the channel.
      }
      this.#port.removeEventListener("message", this.#onPortMessage);
      this.#port.close();
      this.#port = undefined;
    }
    this.#iframe.srcdoc = "";
  }

  async #handlePortMessage(event: MessageEventLike): Promise<void> {
    if (this.#disposed || !messageWithinLimit(event.data)) return;
    const data = event.data;
    try {
      if (hasExactKeys(data, ["type"]) && data.type === "redevplugin.surface.first_paint") {
        this.#openSignals?.firstPaint.resolve();
        return;
      }
      if (hasExactKeys(data, ["type", "frame_generation_id"]) &&
          data.type === "redevplugin.surface.port_ack" && data.frame_generation_id === this.frameGenerationId) {
        this.#openSignals?.portAcknowledged.resolve();
        return;
      }
      if (hasExactKeys(data, ["type"]) && data.type === "redevplugin.surface.worker_ready") {
        this.#openSignals?.workerReady.resolve();
        return;
      }
      if (hasExactKeys(data, ["type", "error"]) && data.type === "redevplugin.surface.error" && typeof data.error === "string") {
        const error = new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", data.error);
        await this.#failSurface(error);
        return;
      }
      if (isBridgeCancelMessage(data)) {
        this.#pendingRequestControllers.get(data.id)?.abort();
        return;
      }
      if (isBridgeCallMessage(data)) {
        await this.#handleCall(data.request);
        return;
      }
      if (isStreamReadMessage(data)) {
        await this.#handleStreamRead(data.id, data.stream_handle);
        return;
      }
      if (isOperationCancelMessage(data)) {
        await this.#handleOperationCancel(data);
        return;
      }
      if (isAssetReadMessage(data)) {
        await this.#handleAssetRead(data);
      }
    } catch (error) {
      await this.#failSurface(toBridgeError(error, "PLUGIN_CONTRACT_MISMATCH"));
    }
  }

  async #handleCall(request: PluginBridgeRequest): Promise<void> {
    if (!this.#ready || !this.#gatewayToken) {
      this.#postError(request.id, "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin bridge call arrived before the surface became ready");
      return;
    }
    const controller = this.#registerPendingRequest(request.id);
    try {
      const result = await this.#callRPC(request, undefined, controller.signal);
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(request.id, this.#publicMethodResult(result));
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_PERMISSION_DENIED");
      if (bridgeError.errorCode === "PLUGIN_CONFIRMATION_REQUIRED") {
        await this.#handleConfirmationRequired(request, bridgeError, controller.signal);
        return;
      }
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message, bridgeError.details);
    } finally {
      this.#pendingRequestControllers.delete(request.id);
    }
  }

  async #handleConfirmationRequired(request: PluginBridgeRequest, originalError: PluginBridgeError, signal: AbortSignal): Promise<void> {
    if (!this.#confirm) {
      this.#postError(request.id, originalError.errorCode, originalError.message, originalError.details);
      return;
    }
    try {
      const confirmation = await this.#prepareConfirmation(request, signal);
      const decision = await abortableConfirmationDecision(this.#confirm({
        requestId: request.id,
        method: request.method,
        params: request.params,
        requestHash: confirmation.request_hash,
        planHash: confirmation.plan_hash,
        plan: confirmation.plan,
        confirmationTokenId: confirmation.confirmation_token_id,
        signal,
      }), signal);
      if (signal.aborted || this.#disposed) return;
      if (!confirmationDecisionAccepted(decision)) {
        await this.#rejectConfirmation(confirmation.confirmation_id, signal);
        if (signal.aborted || this.#disposed) return;
        this.#postError(request.id, "PLUGIN_CONFIRMATION_REJECTED", "Plugin method confirmation was rejected");
        return;
      }
      const result = await this.#callRPC(request, confirmation.confirmation_id, signal);
      if (!signal.aborted && !this.#disposed) this.#postResponse(request.id, this.#publicMethodResult(result));
    } catch (error) {
      if (signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_PERMISSION_DENIED");
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message, bridgeError.details);
    }
  }

  async #handleStreamRead(id: string, streamHandle: string): Promise<void> {
    const credential = this.#streamCredentials.get(streamHandle);
    if (!credential || credential.reading) {
      this.#postError(id, "PLUGIN_STREAM_TICKET_INVALID", "Plugin stream handle is invalid or already consumed");
      return;
    }
    if (credential.expiresAtMs <= Date.now()) {
      this.#postError(id, "PLUGIN_STREAM_TICKET_INVALID", "Plugin stream handle is expired");
      return;
    }
    credential.reading = true;
    const controller = this.#registerPendingRequest(id);
    try {
      const result = await this.#postJSON<PluginSurfaceStreamReadResult>(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/streams/read`,
        () => ({ stream_id: credential.streamID, stream_ticket: credential.streamTicket }),
        controller.signal,
      );
      if (!isStreamReadResult(result, credential.streamID, credential.lastSequence)) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin stream endpoint returned an invalid response");
      }
      const lastSequence = result.events.length > 0 ? result.events[result.events.length - 1].sequence : credential.lastSequence;
      if (result.done) {
        this.#streamCredentials.delete(streamHandle);
      } else {
        const expiresAtMs = Date.parse(result.next_stream_expires_at!);
        credential.streamTicket = result.next_stream_ticket!;
        credential.expiresAtMs = expiresAtMs;
        credential.lastSequence = lastSequence;
        credential.reading = false;
      }
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(id, {
        events: result.events.map(publicPluginStreamEvent),
        done: result.done,
        ...(result.done ? { terminal_status: result.terminal_status! } : {}),
        retry_after_ms: result.events.length === 0 && !result.done ? 25 : 0,
      });
    } catch (error) {
      if (streamReadFailureInvalidatesCredential(error)) {
        this.#streamCredentials.delete(streamHandle);
      } else {
        credential.reading = false;
      }
      if (controller.signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_RUNTIME_UNAVAILABLE");
      this.#postError(id, bridgeError.errorCode, bridgeError.message);
    } finally {
      this.#pendingRequestControllers.delete(id);
    }
  }

  async #handleOperationCancel(message: { id: string; operation_id: string; reason?: string }): Promise<void> {
    const controller = this.#registerPendingRequest(message.id);
    try {
      await this.#postJSON(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/operations/cancel`,
        { operation_id: message.operation_id, bridge_channel_id: this.bridgeChannelId, reason: message.reason },
        controller.signal,
      );
      this.#releaseOperationStreams(message.operation_id);
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id, undefined);
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_OPERATION_BLOCKED");
      this.#postError(message.id, bridgeError.errorCode, bridgeError.message);
    } finally {
      this.#pendingRequestControllers.delete(message.id);
    }
  }

  async #handleAssetRead(message: SurfaceAssetReadMessage): Promise<void> {
    if (this.#activeAssetReads >= maxConcurrentAssetReads) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin asset reads exceed the concurrency limit");
    }
    const asset = this.#assets.get(message.binding_id);
    if (!asset || asset.path !== message.path || asset.sha256 !== message.sha256 || !this.#assetSession || !this.#assetSessionID) {
      throw new PluginBridgeError("PLUGIN_ASSET_SESSION_INVALID", "Plugin asset request did not match the prepared surface document");
    }
    this.#activeAssetReads += 1;
    try {
      const result = await this.#postJSON<PluginSurfaceAssetReadResult>(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/assets/read`,
        () => ({
          asset_session: this.#assetSession,
          asset_session_id: this.#assetSessionID,
          binding_id: asset.binding_id,
        }),
      );
      if (!isAssetReadResult(result) || result.path !== asset.path || result.sha256 !== asset.sha256 || result.content_type !== asset.content_type) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin asset endpoint returned mismatched content");
      }
      this.#postToRenderer({
        type: "redevplugin.surface.asset.response",
        request_id: message.request_id,
        binding_id: asset.binding_id,
        ok: true,
        path: result.path,
        sha256: result.sha256,
        content_type: result.content_type,
        content_base64: result.content_base64,
      });
    } finally {
      this.#activeAssetReads -= 1;
    }
  }

  #registerPendingRequest(id: string): AbortController {
    if (this.#pendingRequestControllers.has(id) || this.#pendingRequestControllers.size >= maxPendingPluginBridgeRequests) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin request is duplicated or exceeds the pending request limit");
    }
    const controller = new AbortController();
    this.#pendingRequestControllers.set(id, controller);
    return controller;
  }

  #publicMethodResult(result: PluginTrustedMethodResult): PluginMethodResult {
    const publicResult: PluginMethodResult = {
      data: result.data,
      operation_id: result.operation_id,
      confirmation_required: result.confirmation_required,
      confirmation_token_id: result.confirmation_token_id,
      request_hash: result.request_hash,
    };
    if (result.stream_id || result.stream_ticket || result.stream_ticket_id || result.stream_expires_at) {
      if (!result.operation_id || !result.stream_id || !result.stream_ticket || !result.stream_ticket_id || !result.stream_expires_at) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin RPC returned incomplete stream credentials");
      }
      const expiresAtMs = Date.parse(result.stream_expires_at);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
        throw new PluginBridgeError("PLUGIN_STREAM_TICKET_INVALID", "Plugin RPC returned an expired stream ticket");
      }
      this.#pruneExpiredStreamCredentials();
      if (this.#streamCredentials.size >= maxRetainedPluginStreamHandles) {
        throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin surface retained too many unread stream handles");
      }
      const handle = randomOpaqueHandle("stream");
      this.#streamCredentials.set(handle, {
        streamID: result.stream_id,
        operationID: result.operation_id,
        streamTicket: result.stream_ticket,
        expiresAtMs,
        lastSequence: 0,
        reading: false,
      });
      publicResult.stream_handle = handle;
    }
    return removeUndefined(publicResult);
  }

  #pruneExpiredStreamCredentials(now = Date.now()): void {
    for (const [handle, credential] of this.#streamCredentials) {
      if (credential.expiresAtMs <= now) this.#streamCredentials.delete(handle);
    }
  }

  #releaseOperationStreams(operationID: string): void {
    for (const [handle, credential] of this.#streamCredentials) {
      if (credential.operationID === operationID) this.#streamCredentials.delete(handle);
    }
  }

  #callRPC(request: PluginBridgeRequest, confirmationID?: string, signal?: AbortSignal): Promise<PluginTrustedMethodResult> {
    return this.#postJSON<PluginTrustedMethodResult>("/_redevplugin/api/plugins/rpc", () => this.#rpcBody(request, confirmationID), signal);
  }

  #prepareConfirmation(request: PluginBridgeRequest, signal: AbortSignal): Promise<PluginConfirmationResult> {
    return this.#postJSON<PluginConfirmationResult>("/_redevplugin/api/plugins/confirm", () => this.#rpcBody(request), signal);
  }

  async #rejectConfirmation(confirmationID: string, signal: AbortSignal): Promise<void> {
    const result = await this.#postJSON<PluginConfirmationRejectionResult>(
      `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/confirmations/reject`,
      () => ({
        plugin_instance_id: this.bootstrap.pluginInstanceId,
        bridge_channel_id: this.bridgeChannelId,
        plugin_gateway_token: this.#gatewayToken,
        confirmation_id: confirmationID,
      }),
      signal,
    );
    if (!hasExactKeys(result, ["rejected"]) || result.rejected !== true) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin confirmation rejection endpoint returned an invalid response");
    }
  }

  #rpcBody(request: PluginBridgeRequest, confirmationID?: string): Record<string, unknown> {
    const body: Record<string, unknown> = {
      plugin_instance_id: this.bootstrap.pluginInstanceId,
      surface_instance_id: this.bootstrap.surfaceInstanceId,
      bridge_channel_id: this.bridgeChannelId,
      plugin_gateway_token: this.#gatewayToken,
      method: request.method,
      params: request.params,
    };
    if (confirmationID) body.confirmation_id = confirmationID;
    return body;
  }

  #prepareSurface(): Promise<PluginSurfacePreparationResult> {
    return this.#postJSON<PluginSurfacePreparationResult>(
      `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/prepare`,
      { asset_ticket: this.bootstrap.assetTicket },
    );
  }

  async #mintBridgeToken(previousGatewayToken?: string, direct = false): Promise<PluginGatewayTokenResult> {
    const handshake = this.#handshake();
    const transcript = await trustedParentBridgeHandshakeTranscriptSHA256(handshake, this.bridgeChannelId);
    const path = `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/bridge-token`;
    const body = {
      bridge_channel_id: this.bridgeChannelId,
      handshake,
      handshake_transcript_sha256: transcript,
      ...(previousGatewayToken ? { previous_plugin_gateway_token: previousGatewayToken } : {}),
    } satisfies TrustedParentBridgeTokenRequest;
    return direct ? this.#fetchJSON<PluginGatewayTokenResult>(path, body) : this.#postJSON<PluginGatewayTokenResult>(path, body);
  }

  #handshake(): TrustedParentBridgeHandshake {
    return {
      type: "redevplugin.bridge.handshake",
      plugin_id: this.bootstrap.pluginId,
      surface_id: this.bootstrap.surfaceId,
      surface_instance_id: this.bootstrap.surfaceInstanceId,
      active_fingerprint: this.bootstrap.activeFingerprint,
      bridge_nonce: this.bootstrap.bridgeNonce,
      asset_session_nonce: this.bootstrap.assetSessionNonce,
      plugin_state_version: this.bootstrap.pluginStateVersion,
      revoke_epoch: this.bootstrap.revokeEpoch,
      ui_protocol_version: pluginUIProtocolVersion,
    };
  }

  async #postJSON<T>(path: string, body: unknown | (() => unknown), signal?: AbortSignal): Promise<T> {
    if (this.#ready) {
      if (Date.now() >= this.#leaseRenewAtMs) await this.#startLeaseRenewal();
      else if (this.#leaseRenewalPromise) await this.#leaseRenewalPromise;
    }
    const requestBody = typeof body === "function" ? body() : body;
    this.#activeTransportRequests += 1;
    try {
      return await this.#fetchJSON<T>(path, requestBody, signal);
    } finally {
      this.#activeTransportRequests -= 1;
      if (this.#activeTransportRequests === 0) {
        const idle = this.#transportIdle;
        this.#transportIdle = undefined;
        idle?.resolve();
      }
    }
  }

  async #fetchJSON<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
    return this.#fetchJSONRequest<T>(path, body, { signal });
  }

  async #fetchJSONRequest<T>(
    path: string,
    body: unknown,
    options: { signal?: AbortSignal; keepalive?: boolean; independentLifecycle?: boolean } = {},
  ): Promise<T> {
    const controller = new AbortController();
    let timedOut = false;
    const abort = (): void => controller.abort();
    if ((!options.independentLifecycle && this.#abortController.signal.aborted) || options.signal?.aborted) controller.abort();
    else {
      if (!options.independentLifecycle) this.#abortController.signal.addEventListener("abort", abort, { once: true });
      options.signal?.addEventListener("abort", abort, { once: true });
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", `Plugin surface request timed out: ${path}`));
      }, this.#requestTimeoutMs);
    });
    try {
      const response = await Promise.race([
        this.#transport.fetch(this.#transport.apiBaseURL + path, {
          method: "POST",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: JSON.stringify(body),
          credentials: "same-origin",
          signal: controller.signal,
          keepalive: options.keepalive,
        }),
        timeout,
      ]);
      return await readHostEnvelope<T>(response, "PLUGIN_PERMISSION_DENIED");
    } catch (error) {
      if (timedOut) throw new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", `Plugin surface request timed out: ${path}`);
      throw error;
    } finally {
      if (timer) clearTimeout(timer);
      if (!options.independentLifecycle) this.#abortController.signal.removeEventListener("abort", abort);
      options.signal?.removeEventListener("abort", abort);
    }
  }

  #applyLease(result: PluginGatewayTokenResult): void {
    if (!isGatewayTokenResult(result)) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin gateway token endpoint returned an invalid lease");
    }
    const issuedAtMs = Date.parse(result.issued_at);
    const expiresAtMs = Date.parse(result.expires_at);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs) || expiresAtMs <= issuedAtMs || expiresAtMs <= Date.now()) {
      throw new PluginBridgeError("PLUGIN_GATEWAY_TOKEN_INVALID", "Plugin surface lease is already expired or malformed");
    }
    this.#gatewayToken = result.plugin_gateway_token;
    this.#assetSession = result.asset_session;
    this.#assetSessionID = result.asset_session_id;
    this.#leaseExpiresAtMs = expiresAtMs;
    const boundedLead = Math.min(this.#leaseRenewalLeadMs, Math.max(1, Math.floor((expiresAtMs - issuedAtMs) / 2)));
    this.#leaseRenewAtMs = expiresAtMs - boundedLead;
  }

  #scheduleLeaseRenewal(): void {
    if (this.#leaseRenewalTimer) clearTimeout(this.#leaseRenewalTimer);
    if (this.#disposed || this.#leaseRenewAtMs <= 0) return;
    this.#leaseRenewalTimer = setTimeout(() => {
      this.#leaseRenewalTimer = undefined;
      void this.#startLeaseRenewal().catch(() => undefined);
    }, Math.max(0, this.#leaseRenewAtMs - Date.now()));
  }

  #startLeaseRenewal(): Promise<void> {
    this.#assertActive();
    if (!this.#ready || !this.#gatewayToken) {
      return Promise.reject(new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin surface lease cannot renew before readiness"));
    }
    if (this.#leaseRenewalPromise) return this.#leaseRenewalPromise;
    const previousGatewayToken = this.#gatewayToken;
    const renewal = (async () => {
      await this.#waitForTransportIdle();
      this.#assertActive();
      const result = await this.#mintBridgeToken(previousGatewayToken, true);
      this.#assertActive();
      this.#applyLease(result);
      this.#scheduleLeaseRenewal();
    })();
    this.#leaseRenewalPromise = renewal
      .catch(async (error) => {
        const bridgeError = toBridgeError(error, "PLUGIN_GATEWAY_TOKEN_INVALID");
        await this.#failSurface(bridgeError);
        throw bridgeError;
      })
      .finally(() => {
        this.#leaseRenewalPromise = undefined;
      });
    return this.#leaseRenewalPromise;
  }

  async #waitForTransportIdle(): Promise<void> {
    if (this.#activeTransportRequests === 0) return;
    this.#transportIdle ??= deferred<void>();
    await this.#transportIdle.promise;
  }

  #revokeSurface(keepalive: boolean): Promise<void> {
    if (this.#revokePromise) return this.#revokePromise;
    this.#revokePromise = (async () => {
      await this.#fetchJSONRequest<Record<string, unknown>>(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/dispose`,
        { bridge_nonce: this.bootstrap.bridgeNonce },
        { keepalive, independentLifecycle: true },
      );
    })();
    return this.#revokePromise;
  }

  async #bestEffortRevokeSurface(keepalive: boolean): Promise<void> {
    try {
      await this.#revokeSurface(keepalive);
    } catch {
      // The server may already have revoked the surface after a failed prepare.
    }
  }

  async #failSurface(error: PluginBridgeError): Promise<void> {
    if (this.#disposed) return;
    this.#ready = false;
    this.#openSignals?.firstPaint.reject(error);
    this.#openSignals?.workerReady.reject(error);
    this.#reportError(error);
    const revoke = this.#bestEffortRevokeSurface(true);
    this.#disposeLocal();
    await revoke;
  }

  #postResponse(id: string, data?: unknown): void {
    this.#postToRenderer({ type: "redevplugin.bridge.response", id, ok: true, data });
  }

  #postError(id: string, errorCode: string, error: string, details?: unknown): void {
    const errorDetails = details === undefined ? undefined : normalizePluginJSONObject(details);
    this.#postToRenderer(removeUndefined({
      type: "redevplugin.bridge.response",
      id,
      ok: false,
      error_code: errorCode,
      error,
      error_details: errorDetails,
    }));
  }

  #postToRenderer(message: unknown): void {
    if (!this.#port) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin surface port is not ready");
    }
    this.#port.postMessage(message);
  }

  #reportError(error: PluginBridgeError): void {
    try {
      this.#onError?.(error);
    } catch {
      // Observers cannot weaken revocation or local teardown invariants.
    }
  }

  #assertReady(): void {
    this.#assertActive();
    if (!this.#ready || !this.#port) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin surface is not ready");
    }
  }

  #assertActive(): void {
    if (this.#disposed) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface host is disposed");
    }
  }
}

type SurfaceAssetReadMessage = {
  type: "redevplugin.surface.asset.read";
  request_id: string;
  binding_id: string;
  path: string;
  sha256: string;
};

function claimOpaquePluginBridge(): { surfaceHandle: string; port: MessagePortLike } {
  const value = (globalThis as Record<string, unknown>)[opaquePluginBridgeGlobalKey];
  if (!isRecord(value) || typeof value.claim !== "function") {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Opaque plugin worker bridge is unavailable");
  }
  const claimed = (value as unknown as WorkerBridgeGlobal).claim();
  if (!claimed || !isMessagePortLike(claimed.port) || !validOpaqueHandle(claimed.surfaceHandle, "surface")) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Opaque plugin worker bridge was already claimed");
  }
  return claimed;
}

function normalizeSurfaceHandle(value: string | undefined): string {
  if (!validOpaqueHandle(value, "surface")) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "A valid surface handle is required with an explicit bridge port");
  }
  return value;
}

function captureMessageChannelFactory(): () => MessageChannelLike {
  const Channel = (globalThis as { MessageChannel?: new () => MessageChannelLike }).MessageChannel;
  if (!Channel) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "MessageChannel is unavailable");
  }
  return () => new Channel();
}

function createPluginSurfaceFrame(): HTMLIFrameElement {
  const ownerDocument = globalThis.document;
  if (!ownerDocument || typeof ownerDocument.createElement !== "function") {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin surface host requires a browser document");
  }
  return ownerDocument.createElement("iframe");
}

function hardenPluginSurfaceFrame(frame: PluginSurfaceFrameLike): void {
  frame.setAttribute("src", "about:blank");
  frame.setAttribute("sandbox", "allow-scripts");
  frame.setAttribute("allow", deniedPluginPermissionsPolicy);
  frame.setAttribute("referrerpolicy", "no-referrer");
  if ("credentialless" in frame) frame.credentialless = true;
}

const deniedPluginPermissionsPolicy = [
  "accelerometer 'none'",
  "autoplay 'none'",
  "bluetooth 'none'",
  "camera 'none'",
  "clipboard-read 'none'",
  "clipboard-write 'none'",
  "display-capture 'none'",
  "encrypted-media 'none'",
  "fullscreen 'none'",
  "gamepad 'none'",
  "geolocation 'none'",
  "gyroscope 'none'",
  "hid 'none'",
  "magnetometer 'none'",
  "microphone 'none'",
  "midi 'none'",
  "payment 'none'",
  "picture-in-picture 'none'",
  "publickey-credentials-get 'none'",
  "screen-wake-lock 'none'",
  "serial 'none'",
  "usb 'none'",
  "xr-spatial-tracking 'none'",
].join("; ");

const openingProgressDelayMs = 300;

function randomOpaqueNonce(): string {
  const cryptoLike = globalThis.crypto;
  if (!cryptoLike?.getRandomValues) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Web Crypto random values are unavailable");
  }
  const bytes = new Uint8Array(24);
  cryptoLike.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomOpaqueHandle(prefix: string): string {
  const cryptoLike = globalThis.crypto;
  if (!cryptoLike?.getRandomValues) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Web Crypto random values are unavailable");
  }
  const bytes = new Uint8Array(18);
  cryptoLike.getRandomValues(bytes);
  return `${prefix}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function escapeHTMLAttribute(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function validateHostBootstrap(bootstrap: PluginSurfaceHostBootstrap): void {
  for (const value of [
    bootstrap.pluginId,
    bootstrap.pluginInstanceId,
    bootstrap.pluginVersion,
    bootstrap.surfaceId,
    bootstrap.surfaceInstanceId,
    bootstrap.activeFingerprint,
    bootstrap.bridgeNonce,
    bootstrap.entryPath,
    bootstrap.entrySHA256,
    bootstrap.assetTicket,
    bootstrap.assetSessionNonce,
    bootstrap.runtimeGenerationId,
  ]) {
    if (typeof value !== "string" || value.length === 0) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface bootstrap is incomplete");
    }
  }
  if (!Number.isSafeInteger(bootstrap.pluginStateVersion) || bootstrap.pluginStateVersion < 1 ||
      !Number.isSafeInteger(bootstrap.revokeEpoch) || bootstrap.revokeEpoch < 1) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface revision is invalid");
  }
}

function validateSurfacePreparation(bootstrap: PluginSurfaceHostBootstrap, preparation: PluginSurfacePreparationResult): void {
  if (!isSurfacePreparationResult(preparation)) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface prepare returned an invalid opaque document");
  }
  if (preparation.plugin_state_version !== bootstrap.pluginStateVersion || preparation.revoke_epoch !== bootstrap.revokeEpoch) {
    throw new PluginBridgeError("PLUGIN_GATEWAY_TOKEN_INVALID", "Plugin surface state changed during prepare");
  }
  if (preparation.asset_session_nonce !== bootstrap.assetSessionNonce) {
    throw new PluginBridgeError("PLUGIN_ASSET_SESSION_INVALID", "Plugin asset session nonce changed during prepare");
  }
  if (preparation.entry_path !== bootstrap.entryPath || preparation.entry_sha256 !== bootstrap.entrySHA256 ||
      preparation.document.entry_path !== bootstrap.entryPath || preparation.document.entry_sha256 !== bootstrap.entrySHA256) {
    throw new PluginBridgeError("PLUGIN_ASSET_SESSION_INVALID", "Plugin surface entry changed during prepare");
  }
}

function isSurfacePreparationResult(value: unknown): value is PluginSurfacePreparationResult {
  if (!hasExactKeys(value, [
    "asset_session",
    "asset_session_id",
    "asset_session_nonce",
    "entry_path",
    "entry_sha256",
    "plugin_state_version",
    "revoke_epoch",
    "issued_at",
    "expires_at",
    "document",
  ])) return false;
  const issuedAt = Date.parse(String(value.issued_at));
  const expiresAt = Date.parse(String(value.expires_at));
  return typeof value.asset_session === "string" && value.asset_session.length > 0 &&
    typeof value.asset_session_id === "string" && value.asset_session_id.length > 0 &&
    typeof value.asset_session_nonce === "string" && value.asset_session_nonce.length > 0 &&
    validPackagePath(value.entry_path) &&
    validSHA256(value.entry_sha256) &&
    Number.isSafeInteger(value.plugin_state_version) && Number(value.plugin_state_version) >= 1 &&
    Number.isSafeInteger(value.revoke_epoch) && Number(value.revoke_epoch) >= 1 &&
    Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && expiresAt > issuedAt &&
    isOpaqueSurfaceDocument(value.document);
}

function isOpaqueSurfaceDocument(value: unknown): value is OpaqueSurfaceDocument {
  if (!hasAllowedKeys(value, [
    "schema_version",
    "entry_path",
    "entry_sha256",
    "title",
    "language",
    "direction",
    "body_html",
    "styles",
    "worker",
    "assets",
    "critical_bytes",
  ])) return false;
  if (!Array.isArray(value.assets) || value.assets.length > maxOpaqueSurfaceLazyAssets) return false;
  let lazyBytes = 0;
  for (const asset of value.assets) {
    if (!hasExactKeys(asset, ["binding_id", "path", "sha256", "size", "content_type"]) ||
        !validOpaqueHandle(asset.binding_id, "asset") || !validPackagePath(asset.path) || !validSHA256(asset.sha256) ||
        !Number.isSafeInteger(asset.size) || Number(asset.size) < 0 || Number(asset.size) > maxOpaqueSurfaceLazyBytes ||
        typeof asset.content_type !== "string" || asset.content_type.length < 1 || asset.content_type.length > 256) {
      return false;
    }
    lazyBytes += Number(asset.size);
    if (!Number.isSafeInteger(lazyBytes) || lazyBytes > maxOpaqueSurfaceLazyBytes) return false;
  }
  return value.schema_version === opaqueSurfaceDocumentSchemaVersion &&
    validPackagePath(value.entry_path) &&
    validSHA256(value.entry_sha256) &&
    (value.title === undefined || (typeof value.title === "string" && value.title.length <= 256)) &&
    (value.language === undefined || (typeof value.language === "string" && value.language.length <= 64)) &&
    (value.direction === undefined || value.direction === "ltr" || value.direction === "rtl" || value.direction === "auto") &&
    typeof value.body_html === "string" && value.body_html.length <= 4 * 1024 * 1024 &&
    Array.isArray(value.styles) && value.styles.every((style) => hasExactKeys(style, ["path", "sha256", "content"]) && validPackagePath(style.path) && validSHA256(style.sha256) && typeof style.content === "string" && style.content.length <= 2 * 1024 * 1024) &&
    hasExactKeys(value.worker, ["path", "sha256", "type", "content"]) && validPackagePath(value.worker.path) && validSHA256(value.worker.sha256) && value.worker.type === "classic" && typeof value.worker.content === "string" && value.worker.content.length <= 4 * 1024 * 1024 &&
    new Set(value.assets.map((asset) => asset.binding_id)).size === value.assets.length &&
    new Set(value.assets.map((asset) => asset.path)).size === value.assets.length &&
    Number.isSafeInteger(value.critical_bytes) && Number(value.critical_bytes) >= 0 && Number(value.critical_bytes) <= 8 * 1024 * 1024;
}

function isBridgeCallMessage(value: unknown): value is { type: "redevplugin.bridge.call"; request: PluginBridgeRequest } {
  return hasExactKeys(value, ["type", "request"]) &&
    value.type === "redevplugin.bridge.call" &&
    hasAllowedKeys(value.request, ["id", "method", "params"]) &&
    validBridgeRequestID(value.request.id, "rpc") &&
    validMethod(value.request.method) &&
    validRPCParams(value.request.params);
}

function isStreamReadMessage(value: unknown): value is { type: "redevplugin.bridge.stream.read"; id: string; stream_handle: string } {
  return hasExactKeys(value, ["type", "id", "stream_handle"]) &&
    value.type === "redevplugin.bridge.stream.read" &&
    validBridgeRequestID(value.id, "stream") &&
    validOpaqueHandle(value.stream_handle, "stream");
}

function isOperationCancelMessage(value: unknown): value is { type: "redevplugin.bridge.operation.cancel"; id: string; operation_id: string; reason?: string } {
  return hasAllowedKeys(value, ["type", "id", "operation_id", "reason"]) &&
    value.type === "redevplugin.bridge.operation.cancel" &&
    validBridgeRequestID(value.id, "operation") &&
    validOpaqueHandle(value.operation_id, "operation") &&
    (value.reason === undefined || (typeof value.reason === "string" && value.reason.length <= 256));
}

function isBridgeCancelMessage(value: unknown): value is PluginBridgeCancelMessage {
  return hasExactKeys(value, ["type", "id"]) &&
    value.type === "redevplugin.bridge.cancel" &&
    validBridgeRequestID(value.id);
}

function isAssetReadMessage(value: unknown): value is SurfaceAssetReadMessage {
  return hasExactKeys(value, ["type", "request_id", "binding_id", "path", "sha256"]) &&
    value.type === "redevplugin.surface.asset.read" &&
    typeof value.request_id === "string" && value.request_id.length > 0 && value.request_id.length <= 128 &&
    validOpaqueHandle(value.binding_id, "asset") &&
    validPackagePath(value.path) &&
    validSHA256(value.sha256);
}

function isBridgeResponseCandidate(value: unknown): value is Record<string, unknown> & { id: string } {
  return isRecord(value) && value.type === "redevplugin.bridge.response" && typeof value.id === "string";
}

function isBridgeResponse(value: unknown): value is PluginBridgeResponse {
  if (!isBridgeResponseCandidate(value) || !validBridgeRequestID(value.id)) return false;
  if (value.ok === true) return Object.keys(value).every((key) => ["type", "id", "ok", "data"].includes(key));
  if (value.ok !== false || typeof value.error_code !== "string" || !pluginBridgeErrorCodeSet.has(value.error_code) ||
      typeof value.error !== "string" || value.error.length > 4096 ||
      !Object.keys(value).every((key) => ["type", "id", "ok", "error_code", "error", "error_details"].includes(key))) {
    return false;
  }
  if (value.error_code === "PLUGIN_CAPABILITY_ERROR") return isCapabilityBusinessErrorDetails(value.error_details);
  if (value.error_details === undefined) return true;
  try {
    return Object.keys(normalizePluginJSONObject(value.error_details)).length <= 8;
  } catch {
    return false;
  }
}

function isCapabilityBusinessErrorDetails(value: unknown): value is PluginJSONObject {
  if (!hasAllowedKeys(value, [
    "capability_id",
    "capability_version",
    "detail_schema_sha256",
    "business_error_code",
    "business_error_details",
  ])) return false;
  if (typeof value.capability_id !== "string" || !hostCapabilityIDPattern.test(value.capability_id) ||
      typeof value.capability_version !== "string" || !canonicalSemverPattern.test(value.capability_version) ||
      typeof value.detail_schema_sha256 !== "string" || !lowercaseSHA256Pattern.test(value.detail_schema_sha256) ||
      typeof value.business_error_code !== "string" || !businessErrorCodePattern.test(value.business_error_code)) {
    return false;
  }
  if (value.business_error_details === undefined) return true;
  try {
    normalizePluginJSONObject(value.business_error_details);
    return true;
  } catch {
    return false;
  }
}

function isLifecycleMessage(value: unknown): value is PluginBridgeLifecycleMessage {
  return hasExactKeys(value, ["type", "event"]) &&
    value.type === "redevplugin.bridge.lifecycle" &&
    hasExactKeys(value.event, ["type"]) &&
    (value.event.type === "ready" || value.event.type === "visible" || value.event.type === "hidden" || value.event.type === "dispose");
}

function isActionMessage(value: unknown): value is PluginUIActionEvent & { type: "redevplugin.ui.action" } {
  return hasAllowedKeys(value, ["type", "action", "event", "value", "checked", "form_data"]) &&
    value.type === "redevplugin.ui.action" &&
    validActionID(value.action) &&
    (value.event === "click" || value.event === "input" || value.event === "change" || value.event === "submit") &&
    (value.value == null || (typeof value.value === "string" && value.value.length <= 65536)) &&
    (value.checked == null || typeof value.checked === "boolean") &&
    (value.form_data == null || (isRecord(value.form_data) && Object.entries(value.form_data).every(([key, item]) => validActionID(key) && typeof item === "string" && item.length <= 65536)));
}

function isMessagePortLike(value: unknown): value is MessagePortLike {
  return isRecord(value) &&
    typeof value.postMessage === "function" &&
    typeof value.addEventListener === "function" &&
    typeof value.removeEventListener === "function" &&
    typeof value.start === "function" &&
    typeof value.close === "function";
}

function isAssetReadResult(value: unknown): value is PluginSurfaceAssetReadResult {
  return hasExactKeys(value, ["path", "sha256", "content_type", "content_base64"]) &&
    validPackagePath(value.path) && validSHA256(value.sha256) &&
    typeof value.content_type === "string" && value.content_type.length > 0 && value.content_type.length <= 256 &&
    typeof value.content_base64 === "string";
}

function isGatewayTokenResult(value: unknown): value is PluginGatewayTokenResult {
  return hasExactKeys(value, ["plugin_gateway_token", "plugin_gateway_token_id", "asset_session", "asset_session_id", "issued_at", "expires_at"]) &&
    typeof value.plugin_gateway_token === "string" && value.plugin_gateway_token.length > 0 &&
    typeof value.plugin_gateway_token_id === "string" && value.plugin_gateway_token_id.length > 0 &&
    typeof value.asset_session === "string" && value.asset_session.length > 0 &&
    typeof value.asset_session_id === "string" && value.asset_session_id.length > 0 &&
    typeof value.issued_at === "string" && typeof value.expires_at === "string";
}

function isStreamReadResult(value: unknown, expectedStreamID: string, previousSequence: number): value is PluginSurfaceStreamReadResult {
  if (!isRecord(value) || typeof value.done !== "boolean" || !Array.isArray(value.events)) return false;
  const expectedKeys = value.done
    ? ["done", "events", "terminal_status"]
    : ["done", "events", "next_stream_expires_at", "next_stream_ticket", "next_stream_ticket_id"];
  if (!hasExactKeys(value, expectedKeys)) return false;
  if (value.done) {
    if (!validPluginStreamTerminalStatus(value.terminal_status)) return false;
  } else {
    const expiresAt = Date.parse(String(value.next_stream_expires_at));
    if (typeof value.next_stream_ticket !== "string" || value.next_stream_ticket.length === 0 ||
        typeof value.next_stream_ticket_id !== "string" || value.next_stream_ticket_id.length === 0 ||
        !Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
  }
  let terminal = false;
  for (const event of value.events) {
    if (!isStreamEvent(event) || event.stream_id !== expectedStreamID || event.sequence <= previousSequence || terminal) return false;
    previousSequence = event.sequence;
    terminal = event.kind === "end" || event.kind === "error";
  }
  return true;
}

function isStreamEvent(value: unknown): value is PluginStreamEvent & { stream_id: string } {
  return hasAllowedKeys(value, ["stream_id", "sequence", "kind", "data", "error", "at"]) &&
    typeof value.stream_id === "string" &&
    Number.isSafeInteger(value.sequence) && Number(value.sequence) > 0 &&
    typeof value.kind === "string" && value.kind.length > 0 &&
    (value.data == null || typeof value.data === "string") &&
    (value.error == null || typeof value.error === "string") &&
    typeof value.at === "string";
}

function publicPluginStreamEvent(event: PluginStreamEvent & { stream_id: string }): PluginStreamEvent {
  return removeUndefined({ sequence: event.sequence, kind: event.kind, data: event.data, error: event.error, at: event.at });
}

function validPluginStreamTerminalStatus(value: unknown): value is PluginStreamTerminalStatus {
  return value === "closed" || value === "canceled" || value === "failed" ||
    value === "orphaned_after_disable" || value === "orphaned_after_uninstall";
}

function validRPCParams(value: unknown): value is Record<string, unknown> | undefined {
  if (value === undefined) return true;
  try {
    normalizePluginJSONObject(value);
    return true;
  } catch {
    return false;
  }
}

const pluginMethodPattern = new RegExp("^[-A-Za-z0-9._:]{1,256}$");
const pluginActionPattern = new RegExp("^[-A-Za-z0-9._:]{1,128}$");
const opaqueHandlePattern = new RegExp("^[-A-Za-z0-9_]{8,160}$");
const bridgeRequestIDPattern = /^(rpc|stream|render|operation)_([1-9][0-9]{0,15})$/;

function validBridgeRequestID(value: unknown, expectedKind?: "rpc" | "stream" | "render" | "operation"): value is string {
  if (typeof value !== "string") return false;
  const match = bridgeRequestIDPattern.exec(value);
  if (!match || (expectedKind && match[1] !== expectedKind)) return false;
  return Number.isSafeInteger(Number(match[2]));
}

function validMethod(value: unknown): value is string {
  return typeof value === "string" && pluginMethodPattern.test(value);
}

function validActionID(value: unknown): value is string {
  return typeof value === "string" && pluginActionPattern.test(value);
}

function validOpaqueHandle(value: unknown, prefix: string): value is string {
  return typeof value === "string" && value.startsWith(`${prefix}_`) && opaqueHandlePattern.test(value);
}

function validSHA256(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function validPackagePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && !value.startsWith("/") && !value.includes("\\") &&
    value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function normalizeSurfaceAPIBaseURL(value: string): string {
  const invalid = (): never => {
    throw new PluginBridgeError(
      "PLUGIN_CONTRACT_MISMATCH",
      "Plugin surface API base URL must be a path-only same-origin URL",
    );
  };
  if (typeof value !== "string" || value !== value.trim() || /[\u0000-\u001f\u007f\\]/.test(value) || value.includes("?") || value.includes("#")) {
    return invalid();
  }
  if (value === "") return "";
  if (hasEncodedPathSeparatorOrDot(value) || /(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) return invalid();

  let origin = "";
  let pathname: string;
  if (value.startsWith("/")) {
    if (value.startsWith("//")) return invalid();
    pathname = value;
  } else {
    const currentOrigin = (globalThis as { location?: { origin?: unknown } }).location?.origin;
    if (typeof currentOrigin !== "string" || currentOrigin === "" || currentOrigin === "null") return invalid();
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      return invalid();
    }
    if (parsed.origin !== currentOrigin || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
      return invalid();
    }
    origin = parsed.origin;
    pathname = parsed.pathname;
  }

  const segments = pathname.split("/");
  if (!pathname.startsWith("/") || segments.slice(1, -1).some((segment) => segment === "" || segment === "." || segment === "..") ||
      (segments.at(-1) !== "" && (segments.at(-1) === "." || segments.at(-1) === ".."))) {
    return invalid();
  }
  const normalizedPath = pathname === "/" ? "" : pathname.replace(/\/$/, "");
  return origin + normalizedPath;
}

function hasEncodedPathSeparatorOrDot(value: string): boolean {
  let decoded = value;
  for (let pass = 0; pass < 4; pass += 1) {
    if (/%(?:2e|2f|5c)/i.test(decoded)) return true;
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) return false;
      decoded = next;
    } catch {
      return true;
    }
  }
  return /%(?:2e|2f|5c)/i.test(decoded);
}

function isPluginRiskFlag(value: unknown): value is PluginRiskFlag {
  return isRecord(value) &&
    typeof value.id === "string" &&
    isPluginRiskSeverity(value.severity) &&
    typeof value.summary === "string" &&
    (value.description == null || typeof value.description === "string") &&
    (value.requires_confirmation == null || typeof value.requires_confirmation === "boolean") &&
    (value.requires_admin == null || typeof value.requires_admin === "boolean") &&
    (value.data_loss_risk == null || typeof value.data_loss_risk === "boolean") &&
    (value.destructive == null || typeof value.destructive === "boolean");
}

function isPluginRiskSeverity(value: unknown): value is PluginRiskSeverity {
  return value === "info" || value === "low" || value === "medium" || value === "high" || value === "critical";
}

function isPluginRiskEffect(value: unknown): value is PluginRiskEffect {
  return value === "read" || value === "write" || value === "execute" || value === "delete" || value === "admin";
}

function confirmationDecisionAccepted(decision: PluginConfirmationDecision): boolean {
  return typeof decision === "boolean" ? decision : decision.confirmed;
}

function abortableConfirmationDecision(
  decision: Promise<PluginConfirmationDecision> | PluginConfirmationDecision,
  signal: AbortSignal,
): Promise<PluginConfirmationDecision> {
  if (signal.aborted) {
    return Promise.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin confirmation was aborted"));
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback: (value: never) => void, value: unknown): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback(value as never);
    };
    const onAbort = (): void => {
      finish(reject, new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin confirmation was aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(decision).then(
      (value) => finish(resolve, value),
      (error: unknown) => finish(reject, error),
    );
  });
}

function messageWithinLimit(value: unknown): boolean {
  try {
    const normalized = normalizePluginJSONValue(value);
    return new TextEncoder().encode(JSON.stringify(normalized)).byteLength <= maxPluginBridgeMessageBytes;
  } catch {
    return false;
  }
}

function normalizePluginJSONObject(value: unknown): PluginJSONObject {
  const normalized = normalizePluginJSONValue(value);
  if (normalized === null || Array.isArray(normalized) || typeof normalized !== "object") {
    throw new TypeError("value must be a JSON object");
  }
  return normalized;
}

function normalizePluginJSONValue(
  value: unknown,
  depth = 0,
  state: { nodes: number; seen: Set<object> } = { nodes: 0, seen: new Set<object>() },
): PluginJSONValue {
  state.nodes += 1;
  if (state.nodes > 4096 || depth > 64) throw new TypeError("JSON value exceeds structural limits");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JSON numbers must be finite");
    return value;
  }
  if (typeof value !== "object" || state.seen.has(value)) throw new TypeError("value is not canonical JSON");
  state.seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizePluginJSONValue(item, depth + 1, state));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("JSON objects must be plain records");
    const result: PluginJSONObject = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new TypeError("JSON object keys must be strings");
      if (prototypeSensitivePropertyNames.has(key)) throw new TypeError("JSON object keys must not alter object prototypes");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("JSON object fields must be enumerable data properties");
      result[key] = normalizePluginJSONValue(descriptor.value, depth + 1, state);
    }
    return result;
  } finally {
    state.seen.delete(value);
  }
}

const prototypeSensitivePropertyNames = new Set(["__proto__", "constructor", "prototype"]);

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs == null) return 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("timeoutMs must be a positive finite number");
  return timeoutMs;
}

function normalizeLeaseRenewalLead(leadMs: number | undefined): number {
  if (leadMs == null) return 60_000;
  if (!Number.isFinite(leadMs) || leadMs <= 0) throw new Error("leaseRenewalLeadMs must be a positive finite number");
  return leadMs;
}

function normalizeReloadMax(maxReloads: number): number {
  if (!Number.isInteger(maxReloads) || maxReloads < 0) throw new Error("maxReloads must be a non-negative integer");
  return maxReloads;
}

function normalizeReloadWindow(windowMs: number): number {
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new Error("windowMs must be a positive finite number");
  return windowMs;
}

function normalizeNowMs(nowMs: number): number {
  if (!Number.isFinite(nowMs)) throw new Error("nowMs must be a finite number");
  return nowMs;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value?: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((innerResolve, innerReject) => {
    resolve = innerResolve as (value?: T | PromiseLike<T>) => void;
    reject = innerReject;
  });
  return { promise, resolve, reject };
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", message)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

function removeUndefined<T extends Record<string, unknown>>(value: T): T {
  for (const key of Object.keys(value)) if (value[key] === undefined) delete value[key];
  return value;
}

function toBridgeError(error: unknown, fallbackCode: string): PluginBridgeError {
  if (error instanceof PluginBridgeError) return error;
  if (error instanceof Error) return new PluginBridgeError(fallbackCode, error.message);
  return new PluginBridgeError(fallbackCode, String(error));
}

function streamReadFailureInvalidatesCredential(error: unknown): boolean {
  if (!(error instanceof PluginBridgeError)) return true;
  return streamCredentialInvalidatingErrorCodes.has(error.errorCode);
}
