import { sha256 } from "@noble/hashes/sha2.js";
import { PluginFilesClient, isPluginFileResource, isPluginFileResourceReview, validFileIORequest, type PluginFileAccessConfirmation, type PluginFileIORequest, type PluginFileIOResult } from "./files.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  PluginBridgeError,
  PluginPlatformRequestError,
  PluginTransportError,
  pluginBridgeErrorCodes,
  type PluginMutationOutcome,
} from "./errors.js";
import {
  pluginBridgeCapabilityEffect,
  type PluginBridgeCapabilityRequestOptions,
} from "./bridge-capability.js";
import {
  defaultFetch,
  hasAllowedKeys,
  hasExactKeys,
  hasRequiredKeys,
  isRecord,
  readMutationPlatformResponse,
  readPlatformResponse,
  type FetchLike,
} from "./http.js";
import {
  defaultPluginSurfaceScope,
  registerPluginSurface,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export const webSurfaceDocumentSchemaVersion = "redevplugin.web_surface.v1" as const;
export const pluginRiskPlanSchemaVersion = "redevplugin.capability.risk_plan.v1" as const;

export type PluginJSONValue = null | boolean | number | string | PluginJSONValue[] | PluginJSONObject;
export type PluginJSONObject = { [key: string]: PluginJSONValue };
export const pluginSurfaceContextSchemaVersion = "redevplugin.surface_context.v1" as const;

export type PluginSurfaceContext = Readonly<{
  schema_version: typeof pluginSurfaceContextSchemaVersion;
  revision: number;
  appearance: Readonly<{
    color_scheme: "light" | "dark";
    colors: Readonly<Record<
      "canvas" | "surface" | "surface_elevated" | "text" | "text_muted" | "border" |
      "accent" | "accent_text" | "success" | "warning" | "danger" | "focus",
      string
    >>;
  }>;
  locale: Readonly<{
    language_tag: string;
    direction: "ltr" | "rtl";
  }>;
}>;

export type PluginBridgeContextMessage = {
  type: "redevplugin.bridge.context";
  context: PluginSurfaceContext;
};

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
  management_revision: number;
  revoke_epoch: number;
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
  | {
      type: "redevplugin.bridge.response";
      id: string;
      ok: false;
      error_code: string;
      error: string;
      error_details?: PluginJSONObject;
      mutation_outcome?: PluginMutationOutcome;
    };

export type PluginBridgeCancelMessage = {
  type: "redevplugin.bridge.cancel";
  id: string;
};

export type PluginBridgeLifecycleMessage = {
  type: "redevplugin.bridge.lifecycle";
  event: BridgeLifecycleEvent;
  quiesce_id?: string;
};

export type PluginBridgeLifecycleAckMessage = {
  type: "redevplugin.bridge.lifecycle_ack";
  quiesce_id: string;
};

export const pluginSurfaceFileExportMaxBytes = 16 * 1024 * 1024;
export const pluginSurfaceFileExportMediaTypes = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/svg+xml",
  "text/plain",
] as const;

export type PluginSurfaceFileExportMediaType = (typeof pluginSurfaceFileExportMediaTypes)[number];

export type PluginFileExportRequest = {
  fileName: string;
  mediaType: PluginSurfaceFileExportMediaType;
  bytes: Uint8Array;
};

export type PluginSurfaceFileExport = Readonly<PluginFileExportRequest & { signal: AbortSignal }>;
/** The host must obtain an explicit destination/confirmation before writing exported bytes. */
export type PluginSurfaceFileExportHandler = (request: PluginSurfaceFileExport) => Promise<void> | void;

export type PluginMethodResult<T = unknown> = {
  data: T;
  execution_id?: string;
  confirmation_required?: boolean;
  confirmation_token_id?: string;
  request_hash?: string;
};

export type PluginExecutionEvent = {
  execution_id: string;
  sequence: number;
  kind: "progress" | "data" | "diagnostic" | "terminal";
  payload?: PluginJSONObject;
  error?: { code: string; message: string };
};

export type PluginExecutionEventList = { execution_id: string; events: PluginExecutionEvent[]; cursor: number };

export type PluginExecutionFailureCode =
  | "adapter_failed"
  | "contract_invalid"
  | "platform_failed"
  | "quota_exceeded"
  | "runtime_failed";

export type PluginExecutionProgress = {
  revision: number;
  phase: string;
  completed_units?: number;
  total_units?: number;
  unit?: string;
};

type PluginExecutionSnapshotActive = {
  execution_id: string;
  plugin_instance_id: string;
  kind: "operation" | "subscription";
  status: "running" | "cancel_requested";
  cursor: number;
  cancelable: boolean;
  created_at: string;
  updated_at: string;
  progress?: PluginExecutionProgress;
};

type PluginExecutionSnapshotTerminal = {
  execution_id: string;
  plugin_instance_id: string;
  kind: "operation" | "subscription";
  status: "completed" | "canceled" | "orphaned";
  cursor: number;
  cancelable: boolean;
  created_at: string;
  updated_at: string;
  terminal_at: string;
  progress?: PluginExecutionProgress;
};

type PluginExecutionSnapshotFailed = {
  execution_id: string;
  plugin_instance_id: string;
  kind: "operation" | "subscription";
  status: "failed";
  cursor: number;
  cancelable: boolean;
  created_at: string;
  updated_at: string;
  terminal_at: string;
  failure_code: PluginExecutionFailureCode;
  progress?: PluginExecutionProgress;
};

export type PluginExecutionSnapshot =
  | PluginExecutionSnapshotActive
  | PluginExecutionSnapshotTerminal
  | PluginExecutionSnapshotFailed;

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
  postMessage(message: unknown, transfer?: readonly unknown[]): void;
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
  src: string;
  contentWindow: WindowLike | null;
  credentialless?: boolean;
  setAttribute(name: string, value: string): void;
  addEventListener(type: "load", listener: () => void): void;
  removeEventListener(type: "load", listener: () => void): void;
  remove?(): void;
};

export type PluginBridgeClock = {
  schedule(callback: () => void, delayMs: number): () => void;
};
const nativeBridgeClock: PluginBridgeClock = {
  schedule(callback, delayMs) { const timer = setTimeout(callback, delayMs); return () => clearTimeout(timer); },
};

export type PluginBridgeClientOptions = {
  timeoutMs?: number;
  clock?: PluginBridgeClock;
  port?: MessagePortLike;
  surfaceHandle?: string;
};

export type PluginBridgeRequestOptions = {
  signal?: AbortSignal;
};

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  cancelTimer: () => void;
  abortCleanup?: () => void;
  kind: "json";
  identifier?: string;
};

type PendingCallOptions = {
  kind?: PendingCall["kind"];
  identifier?: string;
  cancellationKind?: "bridge" | "stream";
  mutation?: boolean;
  signal?: AbortSignal;
};

type PluginBridgeLifecycleState = "active" | "quiescing" | "quiesced" | "disposed";

type WebBridgeClaim = { surfaceHandle: string; port: MessagePortLike };

type WebBridgeGlobal = {
  claim(): WebBridgeClaim | undefined;
};

const webPluginBridgeGlobalKey = "__redevpluginWebBridge";
const maxPendingPluginBridgeRequests = 256;
const maxPluginBridgeMessageBytes = 1024 * 1024;
const maxPluginJSONStructuralNodes = 32 * 1024;
const maxSurfaceQuiesceMs = 1500;
const maxSurfaceInteractionEventsPerSecond = 120;
const pluginBridgeErrorCodeSet = new Set<string>(pluginBridgeErrorCodes);
const hostCapabilityIDPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._-]*$");
const lowercaseSHA256Pattern = new RegExp("^[0-9a-f]{64}$");
const businessErrorCodePattern = new RegExp("^[A-Z][A-Z0-9_]*$");

export class PluginBridgeClient {
  readonly files = new PluginFilesClient((request, options) => this.#fileIO(request, options));
  readonly surfaceHandle: string;
  readonly timeoutMs: number;
  #nextID = 1;
  #clock: PluginBridgeClock;
  #port: MessagePortLike;
  #pending = new Map<string, PendingCall>();
  #lifecycleHandlers = new Set<(event: BridgeLifecycleEvent) => Promise<void> | void>();
  #beforeCloseHandlers = new Set<() => boolean | Promise<boolean>>();
  #beforeClosePending = false;
  #contextHandlers = new Set<(context: PluginSurfaceContext) => void>();
  #context?: PluginSurfaceContext;
  #ready = false;
  #readyPromise: Promise<void>;
  #resolveReady!: () => void;
  #rejectReady!: (reason: unknown) => void;
  #lifecycleState: PluginBridgeLifecycleState = "active";
  #handlingLifecycle = false;
  #onMessage = (event: MessageEventLike): void => {
    void this.#handleMessage(event);
  };

  constructor(options: PluginBridgeClientOptions = {}) {
    const claimed = options.port
      ? { port: options.port, surfaceHandle: normalizeSurfaceHandle(options.surfaceHandle) }
      : claimWebPluginBridge();
    this.surfaceHandle = claimed.surfaceHandle;
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
    this.#clock = options.clock ?? nativeBridgeClock;
    this.#port = claimed.port;
    this.#readyPromise = new Promise<void>((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
    void this.#readyPromise.catch(() => undefined);
    this.#port.addEventListener("message", this.#onMessage);
    this.#port.start();
    this.#port.postMessage({ type: "redevplugin.bridge.client_ready" });
  }

  ready(): Promise<void> {
    this.#assertActive();
    return this.#ready ? Promise.resolve() : this.#readyPromise;
  }

  call<T = unknown>(
    method: string,
    params?: PluginJSONObject,
    options: PluginBridgeRequestOptions = {},
  ): Promise<T> {
    const effect = (options as PluginBridgeCapabilityRequestOptions)[pluginBridgeCapabilityEffect];
    return this.#call(method, params, options, effect === undefined || effect !== "read");
  }

  #fileIO(request: PluginFileIORequest, options: PluginBridgeRequestOptions = {}): Promise<PluginFileIOResult> {
    this.#assertActive();
    if (!validFileIORequest(request)) throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "File operation is invalid");
    const id = this.#requestID("file");
    return this.#request<PluginFileIOResult>(id, { type: "redevplugin.bridge.file_io", id, request }, { mutation: true, signal: options.signal });
  }

  #call<T>(
    method: string,
    params: PluginJSONObject | undefined,
    options: PluginBridgeRequestOptions,
    mutation: boolean,
  ): Promise<T> {
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
    }, { mutation, signal: options.signal });
  }

  executionEvents(executionID: string, afterCursor: number, options: PluginBridgeRequestOptions = {}): Promise<PluginExecutionEventList> {
    this.#assertActive();
    if (!validOpaqueHandle(executionID, "execution") || !Number.isSafeInteger(afterCursor) || afterCursor < 0) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin execution event cursor is invalid");
    }
    const id = this.#requestID("execution");
    return this.#request<PluginExecutionEventList>(id, {
      type: "redevplugin.bridge.execution.events",
      id,
      execution_id: executionID,
      after_cursor: afterCursor,
    }, { signal: options.signal });
  }

  cancelExecution(
    executionID: string,
    reason?: string,
    options: PluginBridgeRequestOptions = {},
  ): Promise<void> {
    this.#assertActive();
    if (!validOpaqueHandle(executionID, "execution") || (reason !== undefined && (typeof reason !== "string" || reason.length > 256))) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin execution cancellation is invalid");
    }
    const id = this.#requestID("execution");
    return this.#request<void>(id, removeUndefined({
      type: "redevplugin.bridge.execution.cancel",
      id,
      execution_id: executionID,
      reason,
    }), { mutation: true, signal: options.signal });
  }

  executionSnapshot(
    executionID: string,
    options: PluginBridgeRequestOptions = {},
  ): Promise<PluginExecutionSnapshot> {
    this.#assertActive();
    if (!validOpaqueHandle(executionID, "execution")) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin execution handle is invalid");
    }
    const id = this.#requestID("execution");
    return this.#request<unknown>(id, {
      type: "redevplugin.bridge.execution.query",
      id,
      execution_id: executionID,
    }, { signal: options.signal }).then((snapshot) => {
      if (!isPluginExecutionSnapshot(snapshot) || snapshot.execution_id !== executionID) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin execution snapshot is invalid");
      }
      return snapshot;
    });
  }

  context(): PluginSurfaceContext | undefined {
    this.#assertActive();
    return this.#context;
  }

  onContext(handler: (context: PluginSurfaceContext) => void): () => void {
    this.#assertActive();
    if (typeof handler !== "function") {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface context subscription is invalid");
    }
    this.#contextHandlers.add(handler);
    if (this.#context) {
      try {
        handler(this.#context);
      } catch {
        // A plugin context observer cannot disrupt bridge delivery.
      }
    }
    return () => this.#contextHandlers.delete(handler);
  }

  exportFile(request: PluginFileExportRequest, options: PluginBridgeRequestOptions = {}): Promise<void> {
    this.#assertActive();
    if (!validFileExportName(request?.fileName) || !validFileExportMediaType(request?.mediaType) ||
        !(request?.bytes instanceof Uint8Array) || request.bytes.byteLength === 0 ||
        request.bytes.byteLength > pluginSurfaceFileExportMaxBytes) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin file export request is invalid");
    }
    const id = this.#requestID("file");
    const content = Uint8Array.from(request.bytes).buffer;
    return this.#dispatchRequest<void>(id, {
      type: "redevplugin.ui.file.export",
      id,
      file_name: request.fileName,
      media_type: request.mediaType,
      content,
    }, { mutation: true, signal: options.signal }, [content]);
  }

  /** Return false when saving failed or the application still has unsaved work. */
  onBeforeClose(handler: () => boolean | Promise<boolean>): () => void {
    this.#assertActive();
    if (typeof handler !== "function" || this.#beforeCloseHandlers.size >= 32) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Application close handler is invalid or exceeds the limit");
    }
    this.#beforeCloseHandlers.add(handler);
    return () => this.#beforeCloseHandlers.delete(handler);
  }

  onLifecycle(handler: (event: BridgeLifecycleEvent) => Promise<void> | void): () => void {
    this.#assertActive();
    this.#lifecycleHandlers.add(handler);
    return () => {
      this.#lifecycleHandlers.delete(handler);
    };
  }

  dispose(): void {
    if (this.#lifecycleState === "disposed") return;
    this.#lifecycleState = "disposed";
    const disposedError = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin bridge client is disposed");
    if (!this.#ready) this.#rejectReady(disposedError);
    this.#port.removeEventListener("message", this.#onMessage);
    for (const [id, pending] of this.#pending) {
      pending.cancelTimer();
      pending.abortCleanup?.();
      pending.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", `Plugin bridge request ${id} was disposed`));
    }
    this.#pending.clear();
    this.#lifecycleHandlers.clear();
    this.#contextHandlers.clear();
    this.#beforeCloseHandlers.clear();
    this.#context = undefined;
    this.#port.close();
  }

  #request<T>(id: string, message: unknown, options: PendingCallOptions = {}): Promise<T> {
    let normalizedMessage: PluginJSONObject;
    try {
      normalizedMessage = normalizePluginJSONObject(message);
    } catch {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin bridge request must be canonical JSON");
    }
    if (new TextEncoder().encode(JSON.stringify(normalizedMessage)).byteLength > maxPluginBridgeMessageBytes) {
      throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin bridge request exceeds the message size limit");
    }
    return this.#dispatchRequest<T>(id, normalizedMessage, options);
  }

  #dispatchRequest<T>(
    id: string,
    message: unknown,
    options: PendingCallOptions,
    transfer?: readonly unknown[],
  ): Promise<T> {
    if (this.#pending.size >= maxPendingPluginBridgeRequests) {
      throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin bridge has too many pending requests");
    }
    if (options.signal?.aborted) return Promise.reject(requestCancelledError(options, false));
    let posted = false;
    const result = new Promise<T>((resolve, reject) => {
      const cancelTimer = this.#clock.schedule(() => {
        const pending = this.#takePending(id);
        if (!pending) return;
        try {
          this.#port.postMessage({ type: "redevplugin.bridge.cancel", id } satisfies PluginBridgeCancelMessage);
        } catch {
          // The request is already locally cancelled when the port closes concurrently.
        }
        pending.reject(new PluginBridgeError(
          "PLUGIN_BRIDGE_TIMEOUT",
          `Plugin bridge request ${id} timed out`,
          undefined,
          undefined,
          mutationOutcome(options, posted),
        ));
      }, this.timeoutMs);
      const onAbort = (): void => {
        const pending = this.#takePending(id);
        if (!pending) return;
        if (posted) {
          try {
            this.#port.postMessage({ type: "redevplugin.bridge.cancel", id } satisfies PluginBridgeCancelMessage);
          } catch {
            // The request is already locally cancelled when the port closes concurrently.
          }
        }
        pending.reject(requestCancelledError(options, posted));
      };
      this.#pending.set(id, {
        resolve: (value: unknown) => resolve(value as T),
        reject,
        cancelTimer,
        abortCleanup: options.signal ? () => options.signal?.removeEventListener("abort", onAbort) : undefined,
        kind: options.kind ?? "json",
        identifier: options.identifier,
      });
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
    });
    if (!this.#pending.has(id)) return result;
    try {
      this.#port.postMessage(message, transfer);
      posted = true;
    } catch {
      const pending = this.#takePending(id);
      if (pending) {
        pending.reject(new PluginBridgeError(
          "PLUGIN_BRIDGE_DISPOSED",
          `Plugin bridge request ${id} could not be posted`,
          undefined,
          undefined,
          options.mutation ? "not_committed" : undefined,
        ));
      }
    }
    return result;
  }

  #takePending(id: string): PendingCall | undefined {
    const pending = this.#pending.get(id);
    if (!pending) return undefined;
    this.#pending.delete(id);
    pending.cancelTimer();
    pending.abortCleanup?.();
    return pending;
  }

  async #handleMessage(event: MessageEventLike): Promise<void> {
    if (this.#lifecycleState === "disposed") return;
    const data = event.data;
    if (!messageWithinLimit(data)) return;
    if (isBridgeResponseCandidate(data)) {
      const pending = this.#takePending(data.id);
      if (!pending) return;
      if (!isBridgeResponse(data)) {
        pending.reject(new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin bridge response ${data.id} is invalid`));
        return;
      }
      if (data.ok && pending.kind !== "json") {
        pending.reject(new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin transfer response ${data.id} is invalid`));
      } else if (data.ok) pending.resolve(data.data);
      else pending.reject(new PluginBridgeError(data.error_code, data.error, undefined, data.error_details, data.mutation_outcome));
      return;
    }
    if (hasExactKeys(data, ["type", "close_id"]) && data.type === "redevplugin.bridge.close_request" && validOpaqueHandle(data.close_id, "close")) {
      if (this.#beforeClosePending) return;
      this.#beforeClosePending = true;
      const results = await Promise.allSettled(Array.from(this.#beforeCloseHandlers, handler => withTimeout(Promise.resolve().then(handler), Math.min(this.timeoutMs, maxSurfaceQuiesceMs), "Application close handler timed out")));
      this.#beforeClosePending = false;
      if (this.#lifecycleState === "active") this.#port.postMessage({
        type: "redevplugin.bridge.close_response", close_id: data.close_id,
        allow: results.every(result => result.status === "fulfilled" && result.value === true),
      });
      return;
    }
    if (isPluginBridgeContextMessage(data)) {
      const context = normalizePluginSurfaceContext(data.context);
      if (this.#context && context.revision <= this.#context.revision) return;
      this.#context = context;
      for (const handler of this.#contextHandlers) {
        try {
          handler(context);
        } catch {
          // A plugin context observer cannot disrupt bridge delivery.
        }
      }
      return;
    }
    if (isLifecycleMessage(data)) {
      if (data.event.type === "ready" && !this.#ready) {
        this.#ready = true;
        this.#resolveReady();
      }
      if (data.quiesce_id) this.#lifecycleState = "quiescing";
      this.#handlingLifecycle = true;
      await Promise.allSettled(Array.from(this.#lifecycleHandlers, async (handler) => {
        try {
          await handler(data.event);
        } catch {
          // A plugin lifecycle observer cannot block bounded surface teardown.
        }
      }));
      this.#handlingLifecycle = false;
      if (data.quiesce_id) {
        this.#port.postMessage({
          type: "redevplugin.bridge.lifecycle_ack",
          quiesce_id: data.quiesce_id,
        } satisfies PluginBridgeLifecycleAckMessage);
        this.#lifecycleState = "quiesced";
      }
      if (data.event.type === "dispose" && !data.quiesce_id) this.dispose();
      return;
    }

  }

  #requestID(prefix: string): string {
    return `${prefix}_${this.#nextID++}`;
  }

  #assertActive(): void {
    if (!this.#acceptsPluginWork()) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin bridge client is disposed");
    }
  }

  #acceptsPluginWork(): boolean {
    return this.#lifecycleState === "active" ||
      (this.#lifecycleState === "quiescing" && this.#handlingLifecycle);
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

export function decodePluginEventText(event: PluginExecutionEvent): string {
  const data = event.payload?.data;
  if (typeof data !== "string" || data === "") return "";
  if (typeof TextDecoder === "function" && typeof atob === "function") {
    const binary = atob(data);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  const bufferLike = (globalThis as { Buffer?: { from(value: string, encoding: "base64"): { toString(encoding: "utf8"): string } } }).Buffer;
  if (bufferLike) return bufferLike.from(data, "base64").toString("utf8");
  throw new PluginBridgeError("PLUGIN_STREAM_FAILED", "No base64 decoder is available for plugin execution event data");
}

export async function trustedParentBridgeHandshakeTranscriptSHA256(
  handshake: TrustedParentBridgeHandshake,
  bridgeChannelID: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const fields = [
    "redevplugin.bridge.handshake.v3",
    handshake.plugin_id,
    handshake.surface_id,
    handshake.surface_instance_id,
    handshake.active_fingerprint,
    handshake.bridge_nonce,
    handshake.asset_session_nonce,
    String(handshake.management_revision),
    String(handshake.revoke_epoch),
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
  return `sha256:${bytesToHex(sha256(transcript))}`;
}

export type WebSurfaceDocument = {
  schema_version: typeof webSurfaceDocumentSchemaVersion;
  origin: string;
  parent_origin: string;
  bootstrap_url: string;
  entry_url: string;
};

export type PluginSurfacePreparationResult = {
  asset_session: string;
  asset_session_id: string;
  asset_session_nonce: string;
  entry_path: string;
  entry_sha256: string;
  management_revision: number;
  revoke_epoch: number;
  issued_at: string;
  expires_at: string;
  document: WebSurfaceDocument;
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
  managementRevision: number;
  revokeEpoch: number;
  runtimeGenerationId: string;
};

export type PluginSurfaceHostContext = PluginSurfaceContext;

export type PluginSurfaceOpeningStage = "preparing" | "connecting" | "authorizing" | "initializing";
export type PluginSurfaceOpeningMilestone = "prepare" | "origin" | "entry_ready" | "port_ack" | "token" | "app_ready";

export type PluginSurfaceOpeningProgress = {
  phase: "opening";
  elapsedMs: number;
  stage: PluginSurfaceOpeningStage;
  stageElapsedMs: number;
  pendingMilestones: PluginSurfaceOpeningMilestone[];
};

export type PluginSurfaceInteractionKind = "activation" | "focus" | "wheel" | "text-selection" | "action";

export type PluginSurfaceInteractionEvent = {
  kind: PluginSurfaceInteractionKind;
  sequence: number;
  targetKey?: string;
  action?: string;
  localScroll: boolean;
  selectionActive: boolean;
};

export type PluginSurfaceHost = {
  readonly element: HTMLIFrameElement;
  readonly surfaceInstanceId: string;
  sendLifecycle(event: Exclude<BridgeLifecycleEvent, { type: "ready" | "dispose" }>): void;
  updateContext(context: PluginSurfaceContext): void;
  requestClose(): Promise<PluginSurfaceCloseResult | undefined>;
  close(): Promise<PluginSurfaceCloseResult>;
  dispose(): Promise<void>;
};

export type PreparedPluginSurfaceHost = PluginSurfaceHost & {
  readonly bootstrap: PluginSurfaceHostBootstrap;
  readonly bridgeChannelId: string;
  readonly frameGenerationId: string;
  readonly surfaceHandle: string;
  open(): Promise<void>;
};

/** Trusted host routing preparation. The signal remains active for the surface lifetime. */
export type PluginWebOriginPreparation = Readonly<{
  origin: string;
  parentOrigin: string;
  pluginInstanceId: string;
  surfaceInstanceId: string;
  signal: AbortSignal;
}>;

/** Prepare only the allocated route; return no URL, token, or alternate bootstrap. */
export type PluginWebOriginPreparationHandler = (request: PluginWebOriginPreparation) => void | Promise<void>;

export type PluginSurfaceHostOptions = {
  confirmFileAccess?: PluginFileAccessConfirmation;
  bootstrap: PluginSurfaceHostBootstrap;
  hostTransport: ReDevPluginSurfaceTransport;
  surfaceScope?: PluginSurfaceScope;
  bridgeChannelId?: string;
  loadTimeoutMs?: number;
  requestTimeoutMs?: number;
  leaseRenewalLeadMs?: number;
  reloadLimiter?: PluginSurfaceReloadLimiter;
  confirm?: PluginConfirmationHandler;
  prepareWebOrigin?: PluginWebOriginPreparationHandler;
  onOpeningProgress?: (progress: PluginSurfaceOpeningProgress) => void;
  onInteraction?: (event: PluginSurfaceInteractionEvent) => void;
  onFileExport?: PluginSurfaceFileExportHandler;
  confirmClose?: (request: { reason: "unsaved" | "unresponsive"; signal: AbortSignal }) => boolean | Promise<boolean>;
  onError?: (error: PluginBridgeError) => void;
  surfaceContext?: PluginSurfaceContext;
};

type PluginSurfaceOpeningRequest = {
  pluginInstanceId: string;
  surfaceScope: PluginSurfaceScope;
  signal?: AbortSignal;
  abortError: () => Error;
  open: () => Promise<PluginSurfaceHostOptions>;
};

type PluginSurfaceOpeningLease = {
  options: Promise<PluginSurfaceHostOptions>;
  readonly pluginInstanceId: string;
  readonly signal?: AbortSignal;
  readonly abortError: () => Error;
  owner: "opening" | "host" | "revoked" | "invalidated";
  cancelled: boolean;
  adopt(): void;
  cancel(): Promise<void>;
  invalidate(): void;
  observeInvalidation(observer: () => void): void;
  revoke(): Promise<void>;
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

function requireSurfaceTransportInternals(transport: ReDevPluginSurfaceTransport): ReDevPluginSurfaceTransportInternals {
  const internals = surfaceTransportInternals.get(transport);
  if (!internals) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface host transport is invalid");
  }
  return internals;
}

async function revokeSurfaceBootstrap(
  transport: ReDevPluginSurfaceTransportInternals,
  bootstrap: PluginSurfaceHostBootstrap,
  timeoutMs: number,
  keepalive: boolean,
): Promise<PluginSurfaceRevocationReconciliation> {
  const path = `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(bootstrap.surfaceInstanceId)}/dispose`;
  const controller = new AbortController();
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new PluginBridgeError(
        "PLUGIN_BRIDGE_TIMEOUT",
        `Plugin surface request timed out: ${path}`,
        undefined,
        undefined,
        "unknown",
      ));
    }, timeoutMs);
  });
  try {
    const response = await Promise.race([
      transport.fetch(transport.apiBaseURL + path, {
        method: "POST",
        headers: { "Accept": "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ bridge_nonce: bootstrap.bridgeNonce }),
        credentials: "same-origin",
        signal: controller.signal,
        keepalive,
      }),
      timeout,
    ]);
    const result = await readMutationPlatformResponse<unknown>(response);
    if (!isSurfaceRevocationReconciliation(result)) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface revocation reconciliation returned an invalid result", undefined, undefined, "unknown");
    }
    return result;
  } catch (error) {
    if (timedOut) {
      throw new PluginBridgeError(
        "PLUGIN_BRIDGE_TIMEOUT",
        `Plugin surface request timed out: ${path}`,
        undefined,
        undefined,
        "unknown",
      );
    }
    if (error instanceof PluginBridgeError || error instanceof PluginPlatformRequestError || error instanceof PluginTransportError) {
      throw error;
    }
    throw new PluginTransportError(`Plugin surface request failed for POST ${path}`, error, "unknown");
  } finally {
    if (timer) clearTimeout(timer);
  }
}

type PluginGatewayTokenResult = {
  plugin_gateway_token: string;
  plugin_gateway_token_id: string;
  asset_session: string;
  asset_session_id: string;
  issued_at: string;
  expires_at: string;
};

type PluginMethodConfirmationPreparation = {
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

type OpenSignals = {
  portAcknowledged: Deferred<void>;
  entryReady: Deferred<void>;
  appReady: Deferred<void>;
};

type SurfaceQuiesce = {
  id: string;
  acknowledged: Deferred<void>;
};

export type PluginSurfaceQuiesceResult = {
  outcome: "acknowledged" | "not_ready" | "timed_out";
  durationMs: number;
};

export type PluginSurfaceCloseResult = {
  quiesce: PluginSurfaceQuiesceResult;
  readonly revocation?: PluginSurfaceRevocationReconciliation;
  revokeDurationMs: number;
  totalDurationMs: number;
};

export type PluginSurfaceRevocationReconciliation = {
  disposed: true;
  state: "closed" | "absent";
  previous_state: "active" | "closed" | "absent";
  revoked: boolean;
};

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value?: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
};

class PluginSurfaceHostImplementation implements PluginSurfaceHost {
  readonly element: HTMLIFrameElement;
  readonly surfaceInstanceId: string;
  readonly bootstrap: PluginSurfaceHostBootstrap;
  readonly bridgeChannelId: string;
  #frameGenerationId: string;
  get frameGenerationId(): string { return this.#frameGenerationId; }
  readonly surfaceHandle: string;
  #iframe: PluginSurfaceFrameLike;
  #transport: ReDevPluginSurfaceTransportInternals;
  #createMessageChannel: () => MessageChannelLike;
  #bridgeReady = false;
  #applicationInitialized = false;
  #loadTimeoutMs: number;
  #requestTimeoutMs: number;
  #leaseRenewalLeadMs: number;
  #reloadLimiter: PluginSurfaceReloadLimiter;
  #confirm?: PluginConfirmationHandler;
  #confirmFileAccess?: PluginFileAccessConfirmation;
  #prepareWebOrigin?: PluginWebOriginPreparationHandler;
  #onOpeningProgress?: (progress: PluginSurfaceOpeningProgress) => void;
  #onInteraction?: (event: PluginSurfaceInteractionEvent) => void;
  #onFileExport?: PluginSurfaceFileExportHandler;
  #confirmClose?: PluginSurfaceHostOptions["confirmClose"];
  #closeDecision?: { id: string; result: Deferred<boolean>; controller: AbortController };
  #requestedClose?: Promise<PluginSurfaceCloseResult | undefined>;
  #onError?: (error: PluginBridgeError) => void;
  #lastInteractionSequence = 0;
  #interactionWindowStartedAt = 0;
  #interactionWindowCount = 0;
  #abortController = new AbortController();
  #gatewayToken?: string;
  #leaseExpiresAtMs = 0;
  #leaseRenewAtMs = 0;
  #leaseRenewalTimer?: ReturnType<typeof setTimeout>;
  #leaseRenewalPromise?: Promise<void>;
  #assetSession?: string;
  #assetSessionID?: string;
  #surfaceContext?: PluginSurfaceContext;
  #pendingRequestControllers = new Map<string, AbortController>();
  #activeTransportRequests = 0;
  #transportIdle?: Deferred<void>;
  #port?: MessagePortLike;
  #openSignals?: OpenSignals;
  #openingFailure?: PluginBridgeError;
  #openingStartedAt = 0;
  #openingStageStartedAt = 0;
  #openingStage: PluginSurfaceOpeningStage = "preparing";
  #openingPending = new Set<PluginSurfaceOpeningMilestone>();
  #quiesce?: SurfaceQuiesce;
  #document?: WebSurfaceDocument;
  #navigationPath?: string;
  #documentID?: string;
  #navigationPending = false;
  #navigationTimer?: ReturnType<typeof setTimeout>;
  #closePromise?: Promise<PluginSurfaceCloseResult>;
  #revokePromise?: Promise<PluginSurfaceRevocationReconciliation>;
  #unregisterSurfaceScope?: () => void;
  #onLocalInvalidation?: () => void;
  #opened = false;
  #ready = false;
  #disposed = false;
  #onPortMessage = (event: MessageEventLike): void => {
    void this.#handlePortMessage(event);
  };
  #onEntryMessage = (event: MessageEvent): void => {
    if (this.#disposed || !this.#document || event.source !== this.#iframe.contentWindow || event.origin !== this.#document.origin) return;
    if (hasExactKeys(event.data, ["type", "entry_path", "document_id"]) && event.data.type === "redevplugin.surface.entry_ready" && typeof event.data.entry_path === "string" && validOpaqueHandle(event.data.document_id, "document")) {
      const path = event.data.entry_path;
      if (!path.startsWith("/") || path.startsWith("//") || path.length > 2048 || path.includes("\\") || new URL(path, this.#document.origin).origin !== this.#document.origin) return;
      if (event.data.document_id === this.#documentID) return;
      if (this.#documentID && !this.#ready && !this.#navigationPending) {
        void this.#failSurface(new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Application navigated before its connection completed; reopen the application"));
        return;
      }
      if (this.#ready) this.#beginNavigation();
      this.#documentID = event.data.document_id;
      this.#navigationPath = path;
      if (this.#navigationPending) { void this.#resumeNavigation(); return; }
      this.#openingPending.delete("entry_ready");
      this.#openSignals?.entryReady.resolve();
    } else if (hasExactKeys(event.data, ["type", "error"]) && event.data.type === "redevplugin.surface.entry_error" && typeof event.data.error === "string") {
      this.#openSignals?.entryReady.reject(new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", event.data.error));
    }
  };

  constructor(
    options: PluginSurfaceHostOptions,
    transport: ReDevPluginSurfaceTransportInternals,
    iframe: HTMLIFrameElement,
  ) {
    this.element = iframe;
    this.bootstrap = options.bootstrap;
    this.surfaceInstanceId = options.bootstrap.surfaceInstanceId;
    this.bridgeChannelId = options.bridgeChannelId ?? randomOpaqueHandle("bridge");
    this.#frameGenerationId = randomOpaqueHandle("frame");
    this.surfaceHandle = randomOpaqueHandle("surface");
    this.#iframe = iframe;
    this.#transport = transport;
    this.#createMessageChannel = captureMessageChannelFactory();
    this.#loadTimeoutMs = normalizeTimeout(options.loadTimeoutMs);
    this.#requestTimeoutMs = normalizeTimeout(options.requestTimeoutMs);
    this.#leaseRenewalLeadMs = normalizeLeaseRenewalLead(options.leaseRenewalLeadMs);
    this.#reloadLimiter = options.reloadLimiter ?? new PluginSurfaceReloadLimiter();
    this.#confirm = options.confirm;
    this.#confirmFileAccess = options.confirmFileAccess;
    this.#prepareWebOrigin = options.prepareWebOrigin;
    this.#onOpeningProgress = options.onOpeningProgress;
    this.#onInteraction = options.onInteraction;
    this.#onFileExport = options.onFileExport;
    this.#confirmClose = options.confirmClose;
    this.#onError = options.onError;
    this.#surfaceContext = options.surfaceContext === undefined ? undefined : normalizePluginSurfaceContext(options.surfaceContext);
    hardenPluginSurfaceFrame(this.#iframe);
    this.#unregisterSurfaceScope = registerPluginSurface(
      options.surfaceScope ?? defaultPluginSurfaceScope,
      this.bootstrap.pluginInstanceId,
      () => this.#disposeLocal(),
      () => this.#invalidateLocal(),
    );
  }

  async open(): Promise<void> {
    this.#assertActive();
    if (this.#opened) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin surface host is already open");
    }
    this.#opened = true;
    this.#openingFailure = undefined;
    this.#openingStartedAt = performance.now();
    this.#setOpeningStage("preparing", ["prepare"]);
    const progressTimer = setInterval(() => {
      if (!this.#ready && !this.#disposed) {
        const progress = this.#openingProgress();
        this.#reportOpeningProgress({ ...progress, elapsedMs: Math.max(openingProgressDelayMs, progress.elapsedMs) });
      }
    }, openingProgressDelayMs);
    const signals: OpenSignals = {
      portAcknowledged: deferred<void>(),
      entryReady: deferred<void>(),
      appReady: deferred<void>(),
    };
    void signals.portAcknowledged.promise.catch(() => undefined);
    void signals.entryReady.promise.catch(() => undefined);
    void signals.appReady.promise.catch(() => undefined);
    this.#openSignals = signals;
    globalThis.addEventListener("message", this.#onEntryMessage);
    hardenPluginSurfaceFrame(this.#iframe);

    try {
      await withTimeout(
        this.#completeOpening(signals),
        this.#loadTimeoutMs,
        "Plugin surface opening timed out",
      );
    } catch (error) {
      let bridgeError = this.#openingFailure ?? toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
      if (bridgeError.errorCode === "PLUGIN_BRIDGE_TIMEOUT") {
        bridgeError = new PluginBridgeError(bridgeError.errorCode, bridgeError.message, undefined, this.#openingProgress(), bridgeError.mutationOutcome);
        this.#reloadLimiter.recordCrash();
      }
      this.#reportError(bridgeError);
      const revoke = this.#revokeSurface(false);
      this.#disposeLocal();
      await revoke;
      throw bridgeError;
    } finally {
      clearInterval(progressTimer);
      this.#openingPending.clear();
      this.#openSignals = undefined;
      this.#openingFailure = undefined;
    }
  }

  async #completeOpening(signals: OpenSignals): Promise<void> {
    const preparation = await this.#prepareSurface();
    this.#assertActive();
    validateSurfacePreparation(this.bootstrap, preparation);
    if (preparation.document.parent_origin !== globalThis.location.origin) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Web surface parent origin does not match this host");
    }
    this.#assetSession = preparation.asset_session;
    this.#assetSessionID = preparation.asset_session_id;
    this.#document = preparation.document;
    if (this.#prepareWebOrigin) {
      this.#setOpeningStage("connecting", ["origin"]);
      await abortableWebOriginPreparation(this.#prepareWebOrigin(Object.freeze({
        origin: preparation.document.origin,
        parentOrigin: preparation.document.parent_origin,
        pluginInstanceId: this.bootstrap.pluginInstanceId,
        surfaceInstanceId: this.surfaceInstanceId,
        signal: this.#abortController.signal,
      })), this.#abortController.signal);
      this.#assertActive();
    }
    this.#setOpeningStage("connecting", ["entry_ready"]);
    this.#iframe.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
    this.#iframe.src = preparation.document.bootstrap_url;
    await signals.entryReady.promise;
    this.#assertActive();
    await this.#connectApplication(signals, this.#navigationPath ?? new URL(preparation.document.entry_url).pathname);
  }

  async #connectApplication(signals: OpenSignals, entryPath: string): Promise<void> {
    const preparation = { document: this.#document! };
    this.#setOpeningStage("connecting", ["port_ack"]);
    const channel = this.#createMessageChannel();
    this.#port = channel.port1;
    const activePort = this.#port;
    this.#onPortMessage = event => { if (this.#port === activePort) void this.#handlePortMessage(event); };
    this.#port.addEventListener("message", this.#onPortMessage);
    this.#port.start();
    const iframeWindow = this.#iframe.contentWindow;
    if (!iframeWindow) {
      throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Plugin iframe window is unavailable");
    }
    iframeWindow.postMessage({
      type: "redevplugin.surface.port",
      frame_generation_id: this.frameGenerationId,
      document_id: this.#documentID,
    }, preparation.document.origin, [channel.port2]);

    await signals.portAcknowledged.promise;
    this.#assertActive();

    this.#setOpeningStage("authorizing", ["token"]);
    if (this.#leaseRenewalPromise) await this.#leaseRenewalPromise;
    const token = await this.#mintBridgeToken(this.#gatewayToken);
    this.#assertActive();
    this.#applyLease(token);
    this.#setOpeningStage("initializing", ["app_ready"]);
    this.#postToApplication(removeUndefined({
      type: "redevplugin.surface.initialize",
      frame_generation_id: this.frameGenerationId,
      surface_handle: this.surfaceHandle,
      entry_path: entryPath,
      context: this.#surfaceContext,
    }));
    this.#applicationInitialized = true;
    this.#bridgeReady = true;
    this.#postToApplication({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });

    await signals.appReady.promise;
    this.#assertActive();
    this.#bridgeReady = true;
    this.#ready = true;
    this.#scheduleLeaseRenewal();
    this.#postToApplication({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });
    this.#reloadLimiter.recordHealthyLoad();
  }

  #beginNavigation(): void {
    if (this.#disposed || this.#navigationPending) return;
    if (!this.#ready && this.#openSignals) {
      void this.#failSurface(new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Application navigated before its connection completed; reopen the application"));
      return;
    }
    this.#navigationPending = true;
    clearTimeout(this.#leaseRenewalTimer);
    this.#leaseRenewalTimer = undefined;
    this.#ready = false;
    this.#bridgeReady = false;
    this.#applicationInitialized = false;
    this.#lastInteractionSequence = 0;
    this.#frameGenerationId = randomOpaqueHandle("frame");
    for (const controller of this.#pendingRequestControllers.values()) controller.abort();
    this.#pendingRequestControllers.clear();
    this.#cancelCloseDecision();
    this.#port?.removeEventListener("message", this.#onPortMessage);
    this.#port?.close();
    this.#port = undefined;
    this.#navigationTimer = setTimeout(() => {
      void this.#failSurface(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", "Application document did not reconnect"));
    }, this.#loadTimeoutMs);
  }

  async #resumeNavigation(): Promise<void> {
    if (!this.#navigationPending || this.#disposed) return;
    this.#navigationPending = false;
    clearTimeout(this.#navigationTimer);
    this.#navigationTimer = undefined;
    const signals: OpenSignals = { entryReady: deferred<void>(), portAcknowledged: deferred<void>(), appReady: deferred<void>() };
    for (const signal of Object.values(signals)) void signal.promise.catch(() => undefined);
    this.#openSignals = signals;
    try {
      await withTimeout(this.#connectApplication(signals, this.#navigationPath!), this.#loadTimeoutMs, "Application document reconnection timed out");
    } catch (error) {
      const failure = this.#openingFailure ?? toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
      this.#reportError(failure);
      await this.#failSurface(failure);
    } finally { if (this.#openSignals === signals) this.#openSignals = undefined; }
  }

  sendLifecycle(event: Exclude<BridgeLifecycleEvent, { type: "ready" | "dispose" }>): void {
    this.#assertReady();
    this.#postToApplication({ type: "redevplugin.bridge.lifecycle", event });
  }

  updateContext(context: PluginSurfaceContext): void {
    this.#assertActive();
    const normalized = normalizePluginSurfaceContext(context);
    if (this.#surfaceContext && normalized.revision <= this.#surfaceContext.revision) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface context revision must increase monotonically");
    }
    this.#surfaceContext = normalized;
    if (this.#port && this.#applicationInitialized) {
      this.#postToApplication({ type: "redevplugin.surface.context", frame_generation_id: this.frameGenerationId, surface_handle: this.surfaceHandle, context: normalized });
    }
  }

  /** User-initiated close. Cancellation leaves the live application and lease intact. */
  requestClose(): Promise<PluginSurfaceCloseResult | undefined> {
    if (this.#requestedClose) return this.#requestedClose;
    const pending = this.#requestClose();
    this.#requestedClose = pending;
    void pending.finally(() => { if (this.#requestedClose === pending) this.#requestedClose = undefined; }).catch(() => undefined);
    return pending;
  }

  async #requestClose(): Promise<PluginSurfaceCloseResult | undefined> {
    if (this.#disposed) return this.close();
    if (!this.#ready) return undefined;
    const generation = this.#frameGenerationId;
    const decision = { id: randomOpaqueHandle("close"), result: deferred<boolean>(), controller: new AbortController() };
    this.#closeDecision = decision;
    try {
      let allow = false;
      let reason: "unsaved" | "unresponsive" = "unsaved";
      try {
        this.#postToApplication({ type: "redevplugin.bridge.close_request", close_id: decision.id });
        allow = await withTimeout(decision.result.promise, Math.min(this.#requestTimeoutMs, maxSurfaceQuiesceMs), "Application close decision timed out");
      } catch { reason = "unresponsive"; }
      if (decision.controller.signal.aborted || generation !== this.#frameGenerationId) return undefined;
      if (!allow && this.#confirmClose) {
        try { allow = confirmationDecisionAccepted(await abortableConfirmationDecision(this.#confirmClose({ reason, signal: decision.controller.signal }), decision.controller.signal)); }
        catch { allow = false; }
      }
      if (!allow || decision.controller.signal.aborted || generation !== this.#frameGenerationId) return undefined;
      return this.close();
    } finally {
      if (this.#closeDecision === decision) this.#closeDecision = undefined;
    }
  }

  #cancelCloseDecision(): void {
    const decision = this.#closeDecision;
    this.#closeDecision = undefined;
    decision?.controller.abort();
    decision?.result.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Application close decision was cancelled"));
  }

  close(): Promise<PluginSurfaceCloseResult> {
    this.#cancelCloseDecision();
    if (this.#disposed) {
      const result: PluginSurfaceCloseResult = {
        quiesce: { outcome: "not_ready", durationMs: 0 },
        revocation: { disposed: true, state: "closed", previous_state: "closed", revoked: false },
        revokeDurationMs: 0,
        totalDurationMs: 0,
      };
      return this.#revokeSurface(false).then((revocation) => ({ ...result, revocation }));
    }
    if (this.#closePromise) return this.#closePromise;
    const closing = this.#closeSurface();
    this.#closePromise = closing;
    void closing.catch(() => {
      if (this.#closePromise === closing) this.#closePromise = undefined;
    });
    return closing;
  }

  dispose(): Promise<void> {
    if (this.#disposed) return this.#revokeSurface(true).then(() => undefined);
    const revoke = this.#revokeSurface(true);
    void revoke.catch(() => undefined);
    this.#disposeLocal();
    return revoke.then(() => undefined);
  }

  observeLocalInvalidation(observer: () => void): void {
    this.#onLocalInvalidation = observer;
    if (this.#disposed) observer();
  }

  async #closeSurface(): Promise<PluginSurfaceCloseResult> {
    const startedAt = performance.now();
    const quiesce = await this.#quiesceSurface();
    if (this.#disposed) {
      const revocation = this.#revokePromise ? await this.#revokePromise : { disposed: true, state: "closed", previous_state: "closed", revoked: false } as const;
      return { quiesce, revocation, revokeDurationMs: 0, totalDurationMs: performance.now() - startedAt };
    }
    const revokeStartedAt = performance.now();
    const revoke = this.#revokeSurface(false);
    this.#disposeLocal();
    try {
      const revocation = await revoke;
      return {
        quiesce,
        revocation,
        revokeDurationMs: performance.now() - revokeStartedAt,
        totalDurationMs: performance.now() - startedAt,
      };
    } catch (error) {
      throw toBridgeError(error, "PLUGIN_BRIDGE_DISPOSED");
    }
  }

  #disposeLocal(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    clearTimeout(this.#navigationTimer);
    this.#navigationPending = false;
    this.#unregisterSurfaceScope?.();
    this.#unregisterSurfaceScope = undefined;
    this.#ready = false;
    this.#bridgeReady = false;
    this.#applicationInitialized = false;
    if (this.#leaseRenewalTimer) clearTimeout(this.#leaseRenewalTimer);
    this.#leaseRenewalTimer = undefined;
    globalThis.removeEventListener("message", this.#onEntryMessage);
    this.#abortController.abort();
    for (const controller of this.#pendingRequestControllers.values()) controller.abort();
    this.#pendingRequestControllers.clear();
    const disposedError = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface host was disposed");
    this.#openSignals?.entryReady.reject(disposedError);
    this.#openSignals?.appReady.reject(disposedError);
    this.#openSignals?.portAcknowledged.reject(disposedError);
    this.#cancelCloseDecision();
    this.#quiesce?.acknowledged.reject(disposedError);
    this.#quiesce = undefined;
    this.#gatewayToken = undefined;
    this.#leaseExpiresAtMs = 0;
    this.#assetSession = undefined;
    this.#assetSessionID = undefined;
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
    this.#iframe.setAttribute("sandbox", "allow-scripts allow-forms");
    this.#iframe.src = "about:blank";
  }

  #invalidateLocal(): void {
    this.#disposeLocal();
    this.#iframe.remove?.();
    try {
      this.#onLocalInvalidation?.();
    } catch {
      // Slot state observers cannot weaken local session containment.
    }
  }

  async #handlePortMessage(event: MessageEventLike): Promise<void> {
    if (this.#disposed) return;
    const data = event.data;
    try {
      if (isSurfaceFileExportCandidate(data)) {
        await this.#handleFileExport(data);
        return;
      }
      if (!messageWithinLimit(data)) return;
      if (hasExactKeys(data, ["type", "frame_generation_id"]) &&
          data.type === "redevplugin.surface.port_ack" && data.frame_generation_id === this.frameGenerationId) {
        this.#openingPending.delete("port_ack");
        this.#openSignals?.portAcknowledged.resolve();
        return;
      }
      if (hasExactKeys(data, ["type", "frame_generation_id"]) && data.type === "redevplugin.surface.app_ready" && data.frame_generation_id === this.frameGenerationId) {
        this.#openingPending.delete("app_ready");
        this.#openSignals?.appReady.resolve();
        return;
      }
      if (hasExactKeys(data, ["type", "frame_generation_id"]) && data.type === "redevplugin.surface.navigation" && data.frame_generation_id === this.frameGenerationId) {
        this.#beginNavigation();
        return;
      }
      if (hasExactKeys(data, ["type", "close_id", "allow"]) && data.type === "redevplugin.bridge.close_response" && typeof data.allow === "boolean" && data.close_id === this.#closeDecision?.id) {
        this.#closeDecision?.result.resolve(data.allow);
        return;
      }
      if (isSurfaceInteractionMessage(data)) {
        this.#handleInteraction(data);
        return;
      }
      if (hasExactKeys(data, ["type", "quiesce_id"]) && data.type === "redevplugin.surface.quiesce_ack" && validOpaqueHandle(data.quiesce_id, "quiesce") && data.quiesce_id === this.#quiesce?.id) {
        this.#quiesce.acknowledged.resolve();
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
      if (hasExactKeys(data, ["type", "id", "request", "frame_generation_id", "surface_handle"]) && data.type === "redevplugin.surface.file_io" && validBridgeRequestID(data.id, "file") && validFileIORequest(data.request)) {
        if (data.frame_generation_id !== this.frameGenerationId || data.surface_handle !== this.surfaceHandle) return;
        await this.#handleFileIO(data.id, data.request);
        return;
      }
      if (isExecutionCancelMessage(data)) {
        await this.#handleExecutionCancel(data);
        return;
      }
      if (isExecutionQueryMessage(data)) {
        await this.#handleExecutionQuery(data);
        return;
      }
      if (isExecutionEventsMessage(data)) {
        await this.#handleExecutionEvents(data);
        return;
      }

    } catch (error) {
      await this.#failSurface(toBridgeError(error, "PLUGIN_CONTRACT_MISMATCH"));
    }
  }

  #handleInteraction(message: SurfaceInteractionMessage): void {
    if (!this.#ready || message.frame_generation_id !== this.frameGenerationId || message.surface_handle !== this.surfaceHandle) return;
    if (message.sequence <= this.#lastInteractionSequence) return;
    this.#lastInteractionSequence = message.sequence;
    const now = performance.now();
    if (now - this.#interactionWindowStartedAt >= 1000) {
      this.#interactionWindowStartedAt = now;
      this.#interactionWindowCount = 0;
    }
    this.#interactionWindowCount += 1;
    if (this.#interactionWindowCount > maxSurfaceInteractionEventsPerSecond) return;
    const interaction: PluginSurfaceInteractionEvent = {
      kind: message.kind,
      sequence: message.sequence,
      localScroll: message.local_scroll,
      selectionActive: message.selection_active,
      ...(message.target_key === null ? {} : { targetKey: message.target_key }),
      ...(message.action === null ? {} : { action: message.action }),
    };
    try {
      this.#onInteraction?.(interaction);
    } catch {
      // Interaction observers cannot alter the surface lifecycle.
    }
  }

  async #handleFileExport(message: SurfaceFileExportCandidate): Promise<void> {
    if (!validBridgeRequestID(message.id, "file")) return;
    if (!isSurfaceFileExportMessage(message)) {
      this.#postError(message.id, "PLUGIN_INVALID_REQUEST", "Plugin file export request is invalid");
      return;
    }
    if (!this.#bridgeReady || !this.#ready) {
      this.#postError(message.id, "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Plugin file export arrived before the surface became ready");
      return;
    }
    if (message.frame_generation_id !== this.frameGenerationId || message.surface_handle !== this.surfaceHandle) return;
    if (!this.#onFileExport) {
      this.#postError(message.id, "PLUGIN_FEATURE_NOT_CONFIGURED", "Plugin file export is not configured by the host");
      return;
    }
    const controller = this.#registerPendingRequest(message.id);
    try {
      await this.#onFileExport({
        fileName: message.file_name,
        mediaType: message.media_type,
        bytes: new Uint8Array(message.content),
        signal: controller.signal,
      });
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id);
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_ADAPTER_FAILURE");
      this.#postError(message.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    } finally {
      if (this.#pendingRequestControllers.get(message.id) === controller) this.#pendingRequestControllers.delete(message.id);
    }
  }

  async #handleCall(request: PluginBridgeRequest): Promise<void> {
    if ((!this.#bridgeReady && !this.#quiesce) || !this.#gatewayToken) {
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
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    } finally {
      if (this.#pendingRequestControllers.get(request.id) === controller) this.#pendingRequestControllers.delete(request.id);
    }
  }

  async #handleFileIO(id: string, request: PluginFileIORequest): Promise<void> {
    if (!this.#ready || !this.#bridgeReady || !this.#gatewayToken) { this.#postError(id, "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "File operation arrived before the surface became ready"); return; }
    if (request.operation === "select" && !this.#confirmFileAccess) { this.#postError(id, "PLUGIN_FEATURE_NOT_CONFIGURED", "File access confirmation is not configured"); return; }
    const controller = this.#registerPendingRequest(id);
    let reviewID: string | undefined;
    let approvalSent = false;
    try {
      let result = await this.#postMutationJSON<PluginFileIOResult>("/_redevplugin/api/plugins/file-resources/surface-io", () => ({ plugin_instance_id: this.bootstrap.pluginInstanceId, surface_instance_id: this.bootstrap.surfaceInstanceId, bridge_channel_id: this.bridgeChannelId, plugin_gateway_token: this.#gatewayToken, ...request }), controller.signal);
      if (request.operation === "select" && result.canceled !== true) {
        if (!isPluginFileResourceReview(result.review) || result.review.plugin_instance_id !== this.bootstrap.pluginInstanceId) throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "File review is invalid");
        reviewID = result.review.review_id;
        const approved = await abortableConfirmationDecision(this.#confirmFileAccess!({ ...result.review, signal: controller.signal }), controller.signal);
        if (controller.signal.aborted || this.#disposed) return;
        if (!confirmationDecisionAccepted(approved)) {
          await this.#postMutationJSON("/_redevplugin/api/plugins/file-resources/cancel", { plugin_instance_id: this.bootstrap.pluginInstanceId, review_id: reviewID }, controller.signal);
          reviewID = undefined;
          result = { canceled: true };
        } else {
          approvalSent = true;
          const resource = await this.#postMutationJSON<unknown>("/_redevplugin/api/plugins/file-resources/approve", { plugin_instance_id: this.bootstrap.pluginInstanceId, review_id: reviewID }, controller.signal);
          if (!isPluginFileResource(resource)) throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Approved file resource is invalid");
          reviewID = undefined;
          result = { resource };
        }
      }
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(id, result);
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
      const failure = toBridgeError(error, "PLUGIN_INTERNAL_FAILURE");
      this.#postError(id, failure.errorCode, failure.message, failure.details, failure.mutationOutcome);
    } finally {
      if (reviewID && !approvalSent) {
        try { await this.#fetchJSONRequest("/_redevplugin/api/plugins/file-resources/cancel", { plugin_instance_id: this.bootstrap.pluginInstanceId, review_id: reviewID }, { mutation: true, independentLifecycle: true }); } catch { /* Expired reviews are reclaimed by Host maintenance. */ }
      }
      if (this.#pendingRequestControllers.get(id) === controller) this.#pendingRequestControllers.delete(id);
    }
  }

  async #handleConfirmationRequired(request: PluginBridgeRequest, originalError: PluginBridgeError, signal: AbortSignal): Promise<void> {
    if (!this.#confirm) {
      this.#postError(request.id, originalError.errorCode, originalError.message, originalError.details, originalError.mutationOutcome);
      return;
    }
    try {
      const confirmation = await this.#preparePluginMethodConfirmation(request, signal);
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
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    }
  }

  async #handleExecutionCancel(message: { id: string; execution_id: string; reason?: string }): Promise<void> {
    const controller = this.#registerPendingRequest(message.id);
    try {
      await this.#postMutationJSON(
        `/_redevplugin/api/plugins/executions/${encodeURIComponent(message.execution_id)}/cancel`,
        { reason: message.reason },
        controller.signal,
      );
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id, undefined);
	    } catch (error) {
	      if (controller.signal.aborted || this.#disposed) return;
	      const bridgeError = toBridgeError(error, "PLUGIN_EXECUTION_BLOCKED");
	      this.#postError(message.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
	    } finally {
      if (this.#pendingRequestControllers.get(message.id) === controller) this.#pendingRequestControllers.delete(message.id);
    }
  }

  async #handleExecutionQuery(message: { id: string; execution_id: string }): Promise<void> {
    const controller = this.#registerPendingRequest(message.id);
    try {
      const snapshot = await this.#postJSON<unknown>(
        `/_redevplugin/api/plugins/executions/${encodeURIComponent(message.execution_id)}/query`,
        {},
        controller.signal,
      );
      if (!isPluginExecutionSnapshot(snapshot) || snapshot.execution_id !== message.execution_id) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin execution snapshot endpoint returned an invalid response");
      }
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id, snapshot);
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
	      const bridgeError = toBridgeError(error, "PLUGIN_EXECUTION_NOT_FOUND");
      this.#postError(message.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    } finally {
      if (this.#pendingRequestControllers.get(message.id) === controller) this.#pendingRequestControllers.delete(message.id);
    }
  }

  async #handleExecutionEvents(message: { id: string; execution_id: string; after_cursor: number }): Promise<void> {
    const controller = this.#registerPendingRequest(message.id);
    try {
      const result = await this.#postJSON<unknown>(
        `/_redevplugin/api/plugins/executions/${encodeURIComponent(message.execution_id)}/events/query`,
        { after_cursor: message.after_cursor },
        controller.signal,
      );
      if (!isPluginExecutionEventList(result, message.execution_id, message.after_cursor)) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin execution event endpoint returned an invalid response");
      }
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id, result);
    } catch (error) {
      if (controller.signal.aborted || this.#disposed) return;
	      const bridgeError = toBridgeError(error, "PLUGIN_EXECUTION_NOT_FOUND");
      this.#postError(message.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    } finally {
      if (this.#pendingRequestControllers.get(message.id) === controller) this.#pendingRequestControllers.delete(message.id);
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

  #publicMethodResult(result: PluginMethodResult): PluginMethodResult {
    return removeUndefined({
      data: result.data,
      execution_id: result.execution_id,
      confirmation_required: result.confirmation_required,
      confirmation_token_id: result.confirmation_token_id,
      request_hash: result.request_hash,
    });
  }

  #callRPC(request: PluginBridgeRequest, confirmationID?: string, signal?: AbortSignal): Promise<PluginMethodResult> {
    return this.#postMutationJSON<PluginMethodResult>("/_redevplugin/api/plugins/rpc", () => this.#rpcBody(request, confirmationID), signal);
  }

  #preparePluginMethodConfirmation(request: PluginBridgeRequest, signal: AbortSignal): Promise<PluginMethodConfirmationPreparation> {
    return this.#postMutationJSON<PluginMethodConfirmationPreparation>("/_redevplugin/api/plugins/confirmations/prepare", () => this.#rpcBody(request), signal);
  }

  async #rejectConfirmation(confirmationID: string, signal: AbortSignal): Promise<void> {
    const result = await this.#postMutationJSON<PluginConfirmationRejectionResult>(
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
    return this.#postMutationJSON<PluginSurfacePreparationResult>(
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
    return direct ? this.#fetchMutationJSON<PluginGatewayTokenResult>(path, body) : this.#postMutationJSON<PluginGatewayTokenResult>(path, body);
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
      management_revision: this.bootstrap.managementRevision,
      revoke_epoch: this.bootstrap.revokeEpoch,
    };
  }

  async #postJSON<T>(path: string, body: unknown | (() => unknown), signal?: AbortSignal): Promise<T> {
    return this.#requestJSON<T>(path, body, false, signal);
  }

  async #postMutationJSON<T>(path: string, body: unknown | (() => unknown), signal?: AbortSignal): Promise<T> {
    return this.#requestJSON<T>(path, body, true, signal);
  }

  async #requestJSON<T>(path: string, body: unknown | (() => unknown), mutation: boolean, signal?: AbortSignal): Promise<T> {
    if (this.#bridgeReady) {
      if (Date.now() >= this.#leaseRenewAtMs) await this.#startLeaseRenewal();
      else if (this.#leaseRenewalPromise) await this.#leaseRenewalPromise;
    }
    const requestBody = typeof body === "function" ? body() : body;
    this.#activeTransportRequests += 1;
    try {
      return mutation
        ? await this.#fetchMutationJSON<T>(path, requestBody, signal)
        : await this.#fetchJSON<T>(path, requestBody, signal);
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

  async #fetchMutationJSON<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
    return this.#fetchJSONRequest<T>(path, body, { signal, mutation: true });
  }

  async #fetchJSONRequest<T>(
    path: string,
    body: unknown,
    options: { signal?: AbortSignal; keepalive?: boolean; independentLifecycle?: boolean; mutation?: boolean } = {},
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
        reject(new PluginBridgeError(
          "PLUGIN_BRIDGE_TIMEOUT",
          `Plugin surface request timed out: ${path}`,
          undefined,
          undefined,
          options.mutation ? "unknown" : undefined,
        ));
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
      return options.mutation ? await readMutationPlatformResponse<T>(response) : await readPlatformResponse<T>(response);
    } catch (error) {
      if (timedOut) {
        throw new PluginBridgeError(
          "PLUGIN_BRIDGE_TIMEOUT",
          `Plugin surface request timed out: ${path}`,
          undefined,
          undefined,
          options.mutation ? "unknown" : undefined,
        );
      }
      if (error instanceof PluginBridgeError || error instanceof PluginPlatformRequestError || error instanceof PluginTransportError) {
        throw error;
      }
      throw new PluginTransportError(`Plugin surface request failed for POST ${path}`, error, options.mutation ? "unknown" : undefined);
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
    if (this.#disposed || !this.#ready || this.#leaseRenewAtMs <= 0) return;
    this.#leaseRenewalTimer = setTimeout(() => {
      this.#leaseRenewalTimer = undefined;
      void this.#startLeaseRenewal().catch(() => undefined);
    }, Math.max(0, this.#leaseRenewAtMs - Date.now()));
  }

  #startLeaseRenewal(): Promise<void> {
    this.#assertActive();
    if (!this.#bridgeReady || !this.#gatewayToken) {
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

  #revokeSurface(keepalive: boolean): Promise<PluginSurfaceRevocationReconciliation> {
    if (this.#revokePromise) return this.#revokePromise;
    const revocation = revokeSurfaceBootstrap(
      this.#transport,
      this.bootstrap,
      this.#requestTimeoutMs,
      keepalive,
    );
    this.#revokePromise = revocation;
    void revocation.catch(() => {
      if (this.#revokePromise === revocation) this.#revokePromise = undefined;
    });
    return revocation;
  }

  async #quiesceSurface(): Promise<PluginSurfaceQuiesceResult> {
    const startedAt = performance.now();
    if (!this.#ready || !this.#port || this.#quiesce) {
      return { outcome: "not_ready", durationMs: performance.now() - startedAt };
    }
    const quiesce: SurfaceQuiesce = {
      id: randomOpaqueHandle("quiesce"),
      acknowledged: deferred<void>(),
    };
    void quiesce.acknowledged.promise.catch(() => undefined);
    this.#quiesce = quiesce;
    this.#ready = false;
    try {
      this.#postToApplication({
        type: "redevplugin.bridge.lifecycle",
        event: { type: "dispose" },
        quiesce_id: quiesce.id,
      } satisfies PluginBridgeLifecycleMessage);
      await withTimeout(
        quiesce.acknowledged.promise,
        Math.min(this.#requestTimeoutMs, maxSurfaceQuiesceMs),
        "Plugin surface quiesce timed out",
      );
      return { outcome: "acknowledged", durationMs: performance.now() - startedAt };
    } catch {
      const error = new PluginBridgeError("PLUGIN_SURFACE_QUIESCE_TIMEOUT", "Plugin surface quiesce timed out");
      this.#reportError(error);
      return { outcome: "timed_out", durationMs: performance.now() - startedAt };
    } finally {
      if (this.#quiesce === quiesce) this.#quiesce = undefined;
    }
  }

  async #failSurface(error: PluginBridgeError): Promise<void> {
    if (this.#disposed) return;
    const opening = !this.#ready && this.#openSignals !== undefined;
    this.#ready = false;
    this.#bridgeReady = false;
    this.#applicationInitialized = false;
    const terminalError = opening ? (this.#openingFailure ??= error) : error;
    this.#openSignals?.portAcknowledged.reject(terminalError);
    this.#openSignals?.entryReady.reject(terminalError);
    this.#openSignals?.appReady.reject(terminalError);
    if (!opening) this.#reportError(terminalError);
    const revoke = this.#revokeSurface(true);
    this.#disposeLocal();
    await revoke;
  }

  #postResponse(id: string, data?: unknown): void {
    const response = removeUndefined({ type: "redevplugin.bridge.response", id, ok: true, data });
    if (!messageWithinLimit(response)) {
      this.#postError(id, "PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin response exceeds the bridge message limit");
      return;
    }
    this.#postToApplication(response);
  }

  #postError(
    id: string,
    errorCode: string,
    error: string,
    details?: unknown,
    mutationOutcome?: PluginMutationOutcome,
  ): void {
    const errorDetails = details === undefined ? undefined : normalizePluginJSONObject(details);
    const response = removeUndefined({
      type: "redevplugin.bridge.response",
      id,
      ok: false,
      error_code: errorCode,
      error,
      error_details: errorDetails,
      mutation_outcome: mutationOutcome,
    });
    if (!messageWithinLimit(response)) {
      this.#postToApplication(removeUndefined({
        type: "redevplugin.bridge.response",
        id,
        ok: false,
        error_code: "PLUGIN_JSON_LIMIT_EXCEEDED",
        error: "Plugin error response exceeds the bridge message limit",
        mutation_outcome: mutationOutcome,
      }));
      return;
    }
    this.#postToApplication(response);
  }

  #postToApplication(message: unknown): void {
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

  #setOpeningStage(stage: PluginSurfaceOpeningStage, pending: PluginSurfaceOpeningMilestone[]): void {
    this.#openingStage = stage;
    this.#openingStageStartedAt = performance.now();
    this.#openingPending = new Set(pending);
  }

  #openingProgress(): PluginSurfaceOpeningProgress {
    const now = performance.now();
    return {
      phase: "opening",
      elapsedMs: Math.max(0, Math.floor(now - this.#openingStartedAt)),
      stage: this.#openingStage,
      stageElapsedMs: Math.max(0, Math.floor(now - this.#openingStageStartedAt)),
      pendingMilestones: [...this.#openingPending],
    };
  }

  #reportOpeningProgress(progress: PluginSurfaceOpeningProgress): void {
    try {
      this.#onOpeningProgress?.(progress);
    } catch {
      // Observers cannot weaken opening, revocation, or local teardown invariants.
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

export function createPreparedPluginSurfaceHost(options: PluginSurfaceHostOptions): PreparedPluginSurfaceHost {
  return createPluginSurfaceHostImplementation(options);
}

function createPluginSurfaceHostImplementation(options: PluginSurfaceHostOptions): PluginSurfaceHostImplementation {
  validateHostBootstrap(options.bootstrap);
  const transport = requireSurfaceTransportInternals(options.hostTransport);
  return new PluginSurfaceHostImplementation(options, transport, createPluginSurfaceFrame());
}

export type PluginSurfaceSlotState = "empty" | "opening" | "ready" | "error" | "disposed";

export type PluginSurfaceSlotOptions = {
  stage: HTMLElement;
  onStateChange?: (state: PluginSurfaceSlotState, error?: PluginBridgeError) => void;
  onSurfaceClosed?: (result: PluginSurfaceCloseResult) => void;
};

type PluginSurfaceSlotInternals = {
  open(request: PluginSurfaceOpeningRequest): Promise<PluginSurfaceHost>;
  openPrepared(options: PluginSurfaceHostOptions | PromiseLike<PluginSurfaceHostOptions>): Promise<PluginSurfaceHost>;
};

const surfaceSlotInternals = new WeakMap<PluginSurfaceSlot, PluginSurfaceSlotInternals>();

class PluginSurfaceCleanupError extends Error {
  override readonly cause: unknown;

  constructor(cause: unknown) {
    super("Plugin surface cleanup failed", { cause });
    this.name = "PluginSurfaceCleanupError";
    this.cause = cause;
  }
}

export function openPluginSurfaceInSlot(
  slot: PluginSurfaceSlot,
  request: PluginSurfaceOpeningRequest,
): Promise<PluginSurfaceHost> {
  const internals = surfaceSlotInternals.get(slot);
  if (!internals) throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface slot is invalid");
  return internals.open(request);
}

export function openPreparedPluginSurfaceInSlot(
  slot: PluginSurfaceSlot,
  options: PluginSurfaceHostOptions | PromiseLike<PluginSurfaceHostOptions>,
): Promise<PluginSurfaceHost> {
  const internals = surfaceSlotInternals.get(slot);
  if (!internals) throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface slot is invalid");
  return internals.openPrepared(options);
}

function createPluginSurfaceOpeningLease(request: PluginSurfaceOpeningRequest): PluginSurfaceOpeningLease {
  let unregister = (): void => undefined;
  let revokePromise: Promise<void> | undefined;
  let removeAbortListener = (): void => undefined;
  let invalidationObserver = (): void => undefined;
  const lease: PluginSurfaceOpeningLease = {
    options: Promise.resolve(undefined as never),
    pluginInstanceId: request.pluginInstanceId,
    signal: request.signal,
    abortError: request.abortError,
    owner: "opening",
    cancelled: false,
    adopt() {
      if (lease.owner !== "opening" || lease.cancelled) {
        throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface opening was cancelled before adoption");
      }
      lease.owner = "host";
      unregister();
      removeAbortListener();
    },
    cancel() {
      lease.cancelled = true;
      if (lease.owner === "host") return Promise.resolve();
      return lease.revoke();
    },
    invalidate() {
      lease.cancelled = true;
      if (lease.owner === "host" || lease.owner === "invalidated") return;
      lease.owner = "invalidated";
      unregister();
      removeAbortListener();
      invalidationObserver();
    },
    observeInvalidation(observer) {
      invalidationObserver = observer;
      if (lease.owner === "invalidated") observer();
    },
    revoke() {
      if (lease.owner === "invalidated") return Promise.resolve();
      if (lease.owner === "host") {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface ownership was already adopted");
      }
      lease.cancelled = true;
      lease.owner = "revoked";
      unregister();
      removeAbortListener();
      revokePromise ??= lease.options.then(async (options) => {
        await revokeSurfaceBootstrap(
          requireSurfaceTransportInternals(options.hostTransport),
          options.bootstrap,
          normalizeTimeout(options.requestTimeoutMs),
          false,
        );
      }, () => undefined);
      return revokePromise;
    },
  };
  unregister = registerPluginSurface(
    request.surfaceScope,
    request.pluginInstanceId,
    () => lease.cancel(),
    () => lease.invalidate(),
  );
  if (lease.owner === "invalidated") {
    lease.options = Promise.reject(new PluginBridgeError(
      "PLUGIN_BRIDGE_DISPOSED",
      "Plugin surface scope is invalidated",
    ));
  } else {
    try {
      lease.options = Promise.resolve(request.open());
    } catch (error) {
      lease.options = Promise.reject(error);
    }
  }
  void lease.options.catch(() => {
    if (lease.owner !== "opening") return;
    lease.owner = "revoked";
    unregister();
    removeAbortListener();
  });
  if (request.signal) {
    const onAbort = (): void => {
      void lease.cancel().catch(() => undefined);
    };
    request.signal.addEventListener("abort", onAbort, { once: true });
    removeAbortListener = () => request.signal?.removeEventListener("abort", onAbort);
    if (request.signal.aborted) onAbort();
  }
  return lease;
}

export class PluginSurfaceSlot {
  readonly element: HTMLElement;
  #onStateChange?: PluginSurfaceSlotOptions["onStateChange"];
  #onSurfaceClosed?: PluginSurfaceSlotOptions["onSurfaceClosed"];
  #active?: PluginSurfaceHostImplementation;
  #opening?: PluginSurfaceHostImplementation;
  #transitionController?: AbortController;
  #tail: Promise<void> = Promise.resolve();
  #disposed = false;
  #retired = new WeakMap<PluginSurfaceHostImplementation, Promise<PluginSurfaceCloseResult>>();
  #pendingRetirements = new Set<PluginSurfaceHostImplementation>();
  #disposePromise?: Promise<void>;

  static create(options: PluginSurfaceSlotOptions): PluginSurfaceSlot {
    if (!options.stage || typeof options.stage.append !== "function" || !options.stage.dataset) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface slot requires an HTML stage");
    }
    return new PluginSurfaceSlot(options);
  }

  private constructor(options: PluginSurfaceSlotOptions) {
    this.element = options.stage;
    this.#onStateChange = options.onStateChange;
    this.#onSurfaceClosed = options.onSurfaceClosed;
    surfaceSlotInternals.set(this, {
      open: (request) => {
        this.#assertActive();
        return this.#openLease(createPluginSurfaceOpeningLease(request));
      },
      openPrepared: (preparedOptions) => this.#queueOpening(Promise.resolve(preparedOptions)),
    });
    this.#setState("empty");
  }

  #openLease(lease: PluginSurfaceOpeningLease): Promise<PluginSurfaceHost> {
    return this.#queueOpening(lease.options, lease);
  }

  #queueOpening(
    resolvedOptions: Promise<PluginSurfaceHostOptions>,
    lease?: PluginSurfaceOpeningLease,
  ): Promise<PluginSurfaceHostImplementation> {
    this.#assertActive();
    void resolvedOptions.catch(() => undefined);
    this.#transitionController?.abort();
    const controller = new AbortController();
    this.#transitionController = controller;
    this.#setState("opening");
    lease?.observeInvalidation(() => {
      if (this.#transitionController !== controller) return;
      controller.abort();
      this.#setState("empty");
    });
    const transition = this.#tail.then(
      () => this.#openSurface(resolvedOptions, controller, lease),
      async (error) => {
        await this.#revokeOpening(lease);
        throw error;
      },
    );
    this.#tail = transition.then(
      () => undefined,
      (error) => error instanceof PluginSurfaceCleanupError ? Promise.reject(error) : undefined,
    );
    void this.#tail.catch(() => undefined);
    return transition.catch((error: unknown) => {
      if (error instanceof PluginSurfaceCleanupError) throw error.cause;
      throw error;
    });
  }

  async #openSurface(
    options: Promise<PluginSurfaceHostOptions>,
    controller: AbortController,
    lease: PluginSurfaceOpeningLease | undefined,
  ): Promise<PluginSurfaceHostImplementation> {
    let resolvedOptions: PluginSurfaceHostOptions;
    try {
      resolvedOptions = await options;
    } catch (error) {
      if (!this.#disposed && this.#transitionController === controller && !this.#openingCancelled(controller, lease)) {
        this.#setState("error", toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED"));
      } else {
        this.#setCancelledState(controller);
      }
      throw error;
    }

    if (lease && resolvedOptions.bootstrap.pluginInstanceId !== lease.pluginInstanceId) {
      await this.#revokeOpening(lease);
      throw new PluginBridgeError(
        "PLUGIN_CONTRACT_MISMATCH",
        "Plugin surface bootstrap identity does not match the opening lease",
      );
    }

    if (this.#openingCancelled(controller, lease)) {
      await this.#revokeOpening(lease);
      this.#setCancelledState(controller);
      throw this.#openingCancellationError(lease);
    }

    const previous = this.#active;
    this.#active = undefined;
    if (previous) {
      try {
        await this.#awaitRetirement(previous);
      } catch (error) {
        await this.#revokeOpening(lease);
        throw error;
      }
    }

    if (this.#openingCancelled(controller, lease)) {
      await this.#revokeOpening(lease);
      this.#setCancelledState(controller);
      throw this.#openingCancellationError(lease);
    }

    let host: PluginSurfaceHostImplementation;
    try {
      host = createPluginSurfaceHostImplementation(resolvedOptions);
    } catch (error) {
      await this.#revokeOpening(lease);
      if (!this.#disposed && this.#transitionController === controller) {
        this.#setState("error", toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED"));
      }
      throw error;
    }
    host.observeLocalInvalidation(() => {
      if (this.#active === host) this.#active = undefined;
      if (this.#opening === host) this.#opening = undefined;
      if (this.#transitionController === controller) controller.abort();
      host.element.remove();
      if (!this.#disposed) this.#setState("empty");
    });
    this.#adoptOpening(lease);
    this.#opening = host;
    setSurfacePresentation(host.element, "opening");
    this.element.append(host.element);
    try {
      await this.#openHostUntilCancelled(host, controller, lease);
      if (this.#openingCancelled(controller, lease) || this.#opening !== host) {
        await this.#awaitRetirement(host);
        this.#setCancelledState(controller);
        throw this.#openingCancellationError(lease);
      }
      this.#opening = undefined;
      this.#active = host;
      setSurfacePresentation(host.element, "ready");
      this.#setState("ready");
      return host;
    } catch (error) {
      await this.#awaitRetirement(host);
      if (!this.#disposed && this.#transitionController === controller && !this.#openingCancelled(controller, lease)) {
        const bridgeError = toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
        this.#setState("error", bridgeError);
      }
      throw error;
    }
  }

  /** Ask before removing a user-owned application; forced scope invalidation bypasses this. */
  requestClose(): Promise<PluginSurfaceCloseResult | undefined> {
    this.#assertActive();
    return this.#tail.then(async () => {
      if (this.#disposed) return undefined;
      const host = this.#active;
      if (!host) return undefined;
      const result = await host.requestClose();
      if (!result) return undefined;
      if (this.#active === host) {
        this.#active = undefined;
        if (!this.#disposed) this.#setState("empty");
      }
      host.element.remove();
      try { this.#onSurfaceClosed?.(result); } catch { /* Presentation observers do not own revocation. */ }
      return result;
    });
  }

  async close(): Promise<PluginSurfaceCloseResult | undefined> {
    this.#assertActive();
    this.#transitionController?.abort();
    this.#transitionController = undefined;
    this.#setState("empty");
    const closing = this.#tail.then(
      () => this.#closeCurrentSurface(),
      () => this.#closeCurrentSurface(),
    );
    this.#tail = closing.then(
      () => undefined,
      () => undefined,
    );
    void this.#tail.catch(() => undefined);
    return this.#unwrapCleanupError(closing);
  }

  dispose(): Promise<void> {
    if (this.#disposePromise) return this.#disposePromise;
    this.#disposed = true;
    this.#transitionController?.abort();
    this.#transitionController = undefined;
    this.#setState("disposed");
    const disposal = this.#tail.then(
      () => this.#closeCurrentSurface().then(() => undefined),
      () => this.#closeCurrentSurface().then(() => undefined),
    );
    const disposePromise = this.#unwrapCleanupError(disposal);
    this.#disposePromise = disposePromise;
    void disposePromise.catch(() => {
      if (this.#disposePromise === disposePromise) this.#disposePromise = undefined;
    });
    this.#tail = disposal.then(
      () => undefined,
      () => undefined,
    );
    void this.#tail.catch(() => undefined);
    return disposePromise;
  }

  async #closeCurrentSurface(): Promise<PluginSurfaceCloseResult | undefined> {
    const hosts = new Set([
      ...this.#pendingRetirements,
      ...[this.#active, this.#opening].filter((host): host is PluginSurfaceHostImplementation => host !== undefined),
    ]);
    this.#active = undefined;
    this.#opening = undefined;
    let result: PluginSurfaceCloseResult | undefined;
    const failures: unknown[] = [];
    for (const host of hosts) {
      try {
        const closed = await this.#retire(host);
        result ??= closed;
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) throw new AggregateError(failures, "Plugin surface slot cleanup failed");
    return result;
  }

  #retire(host: PluginSurfaceHostImplementation): Promise<PluginSurfaceCloseResult> {
    const existing = this.#retired.get(host);
    if (existing) return existing;
    this.#pendingRetirements.add(host);
    setSurfacePresentation(host.element, "retiring");
    const closing = Promise.resolve().then(async () => {
      try {
        const result = await host.close();
        try {
          this.#onSurfaceClosed?.(result);
        } catch {
          // Observers cannot turn a completed revocation into a cleanup failure.
        }
        return result;
      } finally {
        host.element.remove();
      }
    });
    this.#retired.set(host, closing);
    void closing.then(
      () => {
        this.#pendingRetirements.delete(host);
        if (this.#retired.get(host) === closing) this.#retired.delete(host);
      },
      () => {
        if (this.#retired.get(host) === closing) this.#retired.delete(host);
      },
    );
    return closing;
  }

  async #awaitRetirement(host: PluginSurfaceHostImplementation): Promise<PluginSurfaceCloseResult> {
    try {
      return await this.#retire(host);
    } catch (error) {
      throw new PluginSurfaceCleanupError(error);
    }
  }

  async #openHostUntilCancelled(
    host: PluginSurfaceHostImplementation,
    controller: AbortController,
    lease: PluginSurfaceOpeningLease | undefined,
  ): Promise<void> {
    const signals = [controller.signal, lease?.signal].filter((signal): signal is AbortSignal => signal !== undefined);
    let cancel!: () => void;
    const cancelled = new Promise<never>((_resolve, reject) => {
      cancel = (): void => {
        void this.#awaitRetirement(host).then(
          () => reject(this.#openingCancellationError(lease)),
          reject,
        );
      };
      for (const signal of signals) signal.addEventListener("abort", cancel, { once: true });
      if (signals.some((signal) => signal.aborted)) cancel();
    });
    try {
      await Promise.race([host.open(), cancelled]);
    } finally {
      for (const signal of signals) signal.removeEventListener("abort", cancel);
    }
  }

  #openingCancelled(controller: AbortController, lease: PluginSurfaceOpeningLease | undefined): boolean {
    return this.#disposed || controller.signal.aborted || lease?.cancelled === true || lease?.signal?.aborted === true;
  }

  #openingCancellationError(lease: PluginSurfaceOpeningLease | undefined): Error {
    if (lease?.signal?.aborted) return lease.abortError();
    return new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface opening was superseded");
  }

  #setCancelledState(controller: AbortController): void {
    if (!this.#disposed && this.#transitionController === controller) this.#setState("empty");
  }

  #adoptOpening(lease: PluginSurfaceOpeningLease | undefined): void {
    lease?.adopt();
  }

  async #revokeOpening(lease: PluginSurfaceOpeningLease | undefined): Promise<void> {
    if (!lease || lease.owner === "host") return;
    try {
      await lease.revoke();
    } catch (error) {
      throw new PluginSurfaceCleanupError(error);
    }
  }

  async #unwrapCleanupError<T>(result: Promise<T>): Promise<T> {
    try {
      return await result;
    } catch (error) {
      if (error instanceof PluginSurfaceCleanupError) throw error.cause;
      throw error;
    }
  }

  #setState(state: PluginSurfaceSlotState, error?: PluginBridgeError): void {
    this.element.dataset.redevpluginSurfaceState = state;
    try {
      this.#onStateChange?.(state, error);
    } catch {
      // Observers cannot alter the slot lifecycle state machine.
    }
  }

  #assertActive(): void {
    if (this.#disposed) throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface slot is disposed");
  }
}

function setSurfacePresentation(
  element: HTMLIFrameElement,
  state: "opening" | "ready" | "retiring",
): void {
  const ready = state === "ready";
  element.hidden = state === "retiring";
  element.inert = !ready;
  element.setAttribute("aria-hidden", ready ? "false" : "true");
  element.style.visibility = "";
  element.style.opacity = state === "opening" ? "0" : "";
  element.style.pointerEvents = ready ? "" : "none";
}


type SurfaceInteractionMessage = {
  type: "redevplugin.surface.interaction";
  frame_generation_id: string;
  surface_handle: string;
  sequence: number;
  kind: PluginSurfaceInteractionKind;
  target_key: string | null;
  action: string | null;
  local_scroll: boolean;
  selection_active: boolean;
};

type SurfaceFileExportCandidate = Record<string, unknown> & {
  type: "redevplugin.surface.file.export";
  id: string;
};

type SurfaceFileExportMessage = SurfaceFileExportCandidate & {
  frame_generation_id: string;
  surface_handle: string;
  file_name: string;
  media_type: PluginSurfaceFileExportMediaType;
  content: ArrayBuffer;
};

function isSurfaceFileExportCandidate(value: unknown): value is SurfaceFileExportCandidate {
  return isRecord(value) && value.type === "redevplugin.surface.file.export" && typeof value.id === "string";
}

function isSurfaceFileExportMessage(value: SurfaceFileExportCandidate): value is SurfaceFileExportMessage {
  return hasExactKeys(value, [
    "type", "frame_generation_id", "surface_handle", "id", "file_name", "media_type", "content",
  ]) && validOpaqueHandle(value.frame_generation_id, "frame") && validOpaqueHandle(value.surface_handle, "surface") &&
    validBridgeRequestID(value.id, "file") && validFileExportName(value.file_name) &&
    validFileExportMediaType(value.media_type) && value.content instanceof ArrayBuffer &&
    value.content.byteLength > 0 && value.content.byteLength <= pluginSurfaceFileExportMaxBytes;
}

function isSurfaceInteractionMessage(value: unknown): value is SurfaceInteractionMessage {
  if (!hasExactKeys(value, [
    "type", "frame_generation_id", "surface_handle", "sequence", "kind", "target_key", "action", "local_scroll", "selection_active",
  ])) return false;
  return value.type === "redevplugin.surface.interaction" &&
    validOpaqueHandle(value.frame_generation_id, "frame") &&
    validOpaqueHandle(value.surface_handle, "surface") &&
    typeof value.sequence === "number" && Number.isSafeInteger(value.sequence) && value.sequence > 0 &&
    ["activation", "focus", "wheel", "text-selection", "action"].includes(String(value.kind)) &&
    (value.target_key === null || validUIIdentifier(value.target_key)) &&
    (value.action === null || validActionID(value.action)) &&
    typeof value.local_scroll === "boolean" && typeof value.selection_active === "boolean" &&
    (value.kind === "action" ? value.action !== null : value.action === null) &&
    (value.kind === "wheel" || value.local_scroll === false) &&
    (value.kind === "text-selection" || value.selection_active === false);
}

function isSurfaceRevocationReconciliation(value: unknown): value is PluginSurfaceRevocationReconciliation {
  if (!hasExactKeys(value, ["disposed", "state", "previous_state", "revoked"])) return false;
  return value.disposed === true && ["closed", "absent"].includes(String(value.state)) &&
    ["active", "closed", "absent"].includes(String(value.previous_state)) &&
    typeof value.revoked === "boolean" &&
    (value.revoked ? value.state === "closed" && value.previous_state === "active" : true);
}

function claimWebPluginBridge(): { surfaceHandle: string; port: MessagePortLike } {
  const value = (globalThis as Record<string, unknown>)[webPluginBridgeGlobalKey];
  if (!isRecord(value) || typeof value.claim !== "function") {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Web application bridge is unavailable");
  }
  const claimed = (value as unknown as WebBridgeGlobal).claim();
  if (!claimed || !isMessagePortLike(claimed.port) || !validOpaqueHandle(claimed.surfaceHandle, "surface")) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", "Web application bridge was already claimed");
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
  frame.setAttribute("sandbox", "allow-scripts allow-forms");
  frame.setAttribute("allow", deniedPluginPermissionsPolicy);
  frame.setAttribute("referrerpolicy", "no-referrer");

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


function randomOpaqueHandle(prefix: string): string {
  const cryptoLike = globalThis.crypto;
  if (!cryptoLike?.getRandomValues) {
    throw new PluginBridgeError("PLUGIN_BRIDGE_HANDSHAKE_FAILED", "Web Crypto random values are unavailable");
  }
  const bytes = new Uint8Array(18);
  cryptoLike.getRandomValues(bytes);
  return `${prefix}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
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
  if (!Number.isSafeInteger(bootstrap.managementRevision) || bootstrap.managementRevision < 1 ||
      !Number.isSafeInteger(bootstrap.revokeEpoch) || bootstrap.revokeEpoch < 1) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface revision is invalid");
  }
}

function validateSurfacePreparation(bootstrap: PluginSurfaceHostBootstrap, preparation: PluginSurfacePreparationResult): void {
  if (!isSurfacePreparationResult(preparation)) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface prepare returned an invalid Web document");
  }
  if (preparation.management_revision !== bootstrap.managementRevision || preparation.revoke_epoch !== bootstrap.revokeEpoch) {
    throw new PluginBridgeError("PLUGIN_GATEWAY_TOKEN_INVALID", "Plugin surface state changed during prepare");
  }
  if (preparation.asset_session_nonce !== bootstrap.assetSessionNonce) {
    throw new PluginBridgeError("PLUGIN_ASSET_SESSION_INVALID", "Plugin asset session nonce changed during prepare");
  }
  if (preparation.entry_path !== bootstrap.entryPath || preparation.entry_sha256 !== bootstrap.entrySHA256) {
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
    "management_revision",
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
    Number.isSafeInteger(value.management_revision) && Number(value.management_revision) >= 1 &&
    Number.isSafeInteger(value.revoke_epoch) && Number(value.revoke_epoch) >= 1 &&
    Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && expiresAt > issuedAt &&
    isWebSurfaceDocument(value.document);
}

export function isWebSurfaceDocument(value: unknown): value is WebSurfaceDocument {
  if (!hasExactKeys(value, ["schema_version", "origin", "parent_origin", "bootstrap_url", "entry_url"]) || value.schema_version !== webSurfaceDocumentSchemaVersion) return false;
  try {
    if ([value.origin, value.parent_origin, value.bootstrap_url, value.entry_url].some(v => typeof v !== "string")) return false;
    const origin = new URL(String(value.origin)), parent = new URL(String(value.parent_origin));
    const bootstrap = new URL(String(value.bootstrap_url)), entry = new URL(String(value.entry_url));
    const validOrigin = (u: URL, raw: unknown) => u.origin === raw && !u.username && !u.password && (u.protocol === "https:" || (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname.endsWith(".localhost"))));
    return validOrigin(origin, value.origin) && validOrigin(parent, value.parent_origin) && origin.hostname !== parent.hostname &&
      bootstrap.origin === origin.origin && !bootstrap.username && !bootstrap.password && bootstrap.pathname === "/_redevplugin_web/bootstrap" && !bootstrap.search && /^#[a-f0-9]{64}$/.test(bootstrap.hash) &&
      entry.origin === origin.origin && !entry.username && !entry.password && !entry.search && !entry.hash && !entry.pathname.startsWith("/_redevplugin_web/");
  } catch { return false; }
}

function isPluginBridgeContextMessage(value: unknown): value is PluginBridgeContextMessage {
  return hasExactKeys(value, ["type", "context"]) && value.type === "redevplugin.bridge.context" && isPluginSurfaceContext(value.context);
}

function isPluginSurfaceContext(value: unknown): value is PluginSurfaceContext {
  if (!isRecord(value) || !hasExactKeys(value, ["schema_version", "revision", "appearance", "locale"]) || value.schema_version !== pluginSurfaceContextSchemaVersion ||
      !Number.isSafeInteger(value.revision) || Number(value.revision) < 1) return false;
  const appearance = value.appearance;
  const locale = value.locale;
  if (!isRecord(appearance) || !hasExactKeys(appearance, ["color_scheme", "colors"]) ||
      (appearance.color_scheme !== "light" && appearance.color_scheme !== "dark") || !isRecord(appearance.colors)) return false;
  const colors = appearance.colors;
  if (!hasExactKeys(colors, surfaceContextColorKeys) || surfaceContextColorKeys.some((key) => !validSurfaceContextColor(colors[key])) ||
      !isRecord(locale) || !hasExactKeys(locale, ["language_tag", "direction"]) || typeof locale.language_tag !== "string" ||
      locale.language_tag.length < 2 || locale.language_tag.length > 64 || (locale.direction !== "ltr" && locale.direction !== "rtl")) return false;
  try {
    return typeof Intl === "undefined" || Intl.getCanonicalLocales(locale.language_tag).length === 1;
  } catch {
    return false;
  }
}

const surfaceContextColorKeys = ["canvas", "surface", "surface_elevated", "text", "text_muted", "border", "accent", "accent_text", "success", "warning", "danger", "focus"] as const;
const surfaceContextColorPattern = new RegExp("^#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?$");
const operationProgressPhasePattern = new RegExp("^[A-Za-z0-9._:-]{1,128}$");
const operationProgressUnitPattern = new RegExp("^[A-Za-z0-9._:-]{1,64}$");

function validSurfaceContextColor(value: unknown): value is string {
  return typeof value === "string" && surfaceContextColorPattern.test(value);
}

export function normalizePluginSurfaceContext(value: unknown): PluginSurfaceContext {
  if (!isPluginSurfaceContext(value)) {
    throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin surface context is invalid");
  }
  const languageTag = Intl.getCanonicalLocales(value.locale.language_tag)[0];
  const colors = Object.fromEntries(surfaceContextColorKeys.map((key) => [key, String(value.appearance.colors[key]).toLowerCase()])) as PluginSurfaceContext["appearance"]["colors"];
  return Object.freeze({
    schema_version: pluginSurfaceContextSchemaVersion,
    revision: Number(value.revision),
    appearance: Object.freeze({ color_scheme: value.appearance.color_scheme, colors: Object.freeze(colors) }),
    locale: Object.freeze({ language_tag: languageTag, direction: value.locale.direction }),
  });
}

function isBridgeCallMessage(value: unknown): value is { type: "redevplugin.bridge.call"; request: PluginBridgeRequest } {
  return hasExactKeys(value, ["type", "request"]) &&
    value.type === "redevplugin.bridge.call" &&
    hasAllowedKeys(value.request, ["id", "method", "params"]) &&
    validBridgeRequestID(value.request.id, "rpc") &&
    validMethod(value.request.method) &&
    validRPCParams(value.request.params);
}

function isExecutionCancelMessage(value: unknown): value is { type: "redevplugin.bridge.execution.cancel"; id: string; execution_id: string; reason?: string } {
  return hasAllowedKeys(value, ["type", "id", "execution_id", "reason"]) &&
    value.type === "redevplugin.bridge.execution.cancel" &&
    validBridgeRequestID(value.id, "execution") &&
    validOpaqueHandle(value.execution_id, "execution") &&
    (value.reason === undefined || (typeof value.reason === "string" && value.reason.length <= 256));
}

function isExecutionQueryMessage(value: unknown): value is { type: "redevplugin.bridge.execution.query"; id: string; execution_id: string } {
  return hasExactKeys(value, ["type", "id", "execution_id"]) && value.type === "redevplugin.bridge.execution.query" &&
    validBridgeRequestID(value.id, "execution") && validOpaqueHandle(value.execution_id, "execution");
}

function isExecutionEventsMessage(value: unknown): value is { type: "redevplugin.bridge.execution.events"; id: string; execution_id: string; after_cursor: number } {
  return hasExactKeys(value, ["type", "id", "execution_id", "after_cursor"]) && value.type === "redevplugin.bridge.execution.events" &&
    validBridgeRequestID(value.id, "execution") && validOpaqueHandle(value.execution_id, "execution") &&
    Number.isSafeInteger(value.after_cursor) && Number(value.after_cursor) >= 0;
}

function isPluginExecutionSnapshot(value: unknown): value is PluginExecutionSnapshot {
  if (!isRecord(value) || !validOpaqueHandle(value.execution_id, "execution") || typeof value.plugin_instance_id !== "string" ||
      (value.kind !== "operation" && value.kind !== "subscription") || typeof value.cancelable !== "boolean" ||
      !Number.isSafeInteger(value.cursor) || Number(value.cursor) < 0 || !validDateTime(value.created_at) || !validDateTime(value.updated_at)) return false;
  const common = ["execution_id", "plugin_instance_id", "kind", "status", "cursor", "cancelable", "created_at", "updated_at"];
  const withProgress = (keys: string[]): boolean => hasAllowedKeys(value, [...keys, "progress"]) && (value.progress === undefined || validOperationProgress(value.progress));
  if (value.status === "running" || value.status === "cancel_requested") return withProgress(common);
  if (["completed", "canceled", "orphaned"].includes(String(value.status))) {
    return withProgress([...common, "terminal_at"]) && validDateTime(value.terminal_at);
  }
  return value.status === "failed" && withProgress([...common, "terminal_at", "failure_code"]) &&
    validDateTime(value.terminal_at) && ["adapter_failed", "contract_invalid", "platform_failed", "quota_exceeded", "runtime_failed"].includes(String(value.failure_code));
}

function validOperationProgress(value: unknown): value is PluginExecutionProgress {
  if (!isRecord(value) || !hasAllowedKeys(value, ["revision", "phase", "completed_units", "total_units", "unit"]) ||
      !Number.isSafeInteger(value.revision) || Number(value.revision) < 1 || typeof value.phase !== "string" || !operationProgressPhasePattern.test(value.phase) ||
      (value.unit !== undefined && (typeof value.unit !== "string" || !operationProgressUnitPattern.test(value.unit))) ||
      (value.completed_units !== undefined && (!Number.isSafeInteger(value.completed_units) || Number(value.completed_units) < 0)) ||
      (value.total_units !== undefined && (!Number.isSafeInteger(value.total_units) || Number(value.total_units) < 0)) ||
      (value.completed_units === undefined) !== (value.total_units === undefined)) return false;
  return value.completed_units === undefined || Number(value.completed_units) <= Number(value.total_units);
}

function validDateTime(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && Number.isFinite(Date.parse(value));
}

function isPluginExecutionEventList(value: unknown, executionID: string, afterCursor: number): value is PluginExecutionEventList {
  if (!isRecord(value) || !hasRequiredKeys(value, ["execution_id", "events", "cursor"]) || value.execution_id !== executionID ||
      !Array.isArray(value.events) || !Number.isSafeInteger(value.cursor) || Number(value.cursor) < afterCursor) return false;
  let cursor = afterCursor;
  for (const event of value.events) {
    if (!isRecord(event) || !hasRequiredKeys(event, ["execution_id", "sequence", "kind"]) ||
        event.execution_id !== executionID || !Number.isSafeInteger(event.sequence) || Number(event.sequence) <= cursor ||
        !["progress", "data", "diagnostic", "terminal"].includes(String(event.kind)) ||
        (event.payload !== undefined && !isRecord(event.payload)) ||
        (event.error !== undefined && (!isRecord(event.error) || !hasRequiredKeys(event.error, ["code", "message"]) ||
          typeof event.error.code !== "string" || typeof event.error.message !== "string"))) return false;
    cursor = Number(event.sequence);
  }
  return Number(value.cursor) === cursor;
}

function isBridgeCancelMessage(value: unknown): value is PluginBridgeCancelMessage {
  return hasExactKeys(value, ["type", "id"]) &&
    value.type === "redevplugin.bridge.cancel" &&
    validBridgeRequestID(value.id);
}

function isBridgeResponseCandidate(value: unknown): value is Record<string, unknown> & { id: string } {
  return isRecord(value) && value.type === "redevplugin.bridge.response" && typeof value.id === "string";
}

function isBridgeResponse(value: unknown): value is PluginBridgeResponse {
  if (!isBridgeResponseCandidate(value) || !validBridgeRequestID(value.id)) return false;
  if (value.ok === true) return true;
  if (value.ok !== false || typeof value.error_code !== "string" || !pluginBridgeErrorCodeSet.has(value.error_code) ||
      typeof value.error !== "string" || value.error.length > 4096 ||
      (value.mutation_outcome !== undefined && value.mutation_outcome !== "committed" &&
        value.mutation_outcome !== "not_committed" && value.mutation_outcome !== "unknown")) {
    return false;
  }
  if (value.error_code === "PLUGIN_CAPABILITY_ERROR") return isCapabilityBusinessErrorDetails(value.error_details);
  if (value.error_code === "PLUGIN_WORKER_ERROR") return isWorkerErrorDetails(value.error_details);
  if (value.error_code === "PLUGIN_FILE_OPERATION_FAILED") return hasExactKeys(value.error_details, ["file_error_code", "file_retryable"]) && typeof value.error_details.file_retryable === "boolean" && ["INVALID_ARGUMENT", "PERMISSION_DENIED", "NOT_FOUND", "NOT_EMPTY", "ALREADY_EXISTS", "RESOURCE_CLOSED", "RESOURCE_LIMIT", "CROSS_DEVICE", "MOUNT_UNAVAILABLE", "RUNTIME_UNAVAILABLE", "CANCELED", "TIMEOUT", "IO_ERROR"].includes(String(value.error_details.file_error_code));
  if (value.error_details === undefined) return true;
  try {
    return Object.keys(normalizePluginJSONObject(value.error_details)).length <= 8;
  } catch {
    return false;
  }
}

function isWorkerErrorDetails(value: unknown): value is PluginJSONObject {
  return hasExactKeys(value, ["worker_error_code", "worker_error_message", "worker_error_origin"]) &&
    typeof value.worker_error_code === "string" && businessErrorCodePattern.test(value.worker_error_code) &&
    typeof value.worker_error_message === "string" && value.worker_error_message.length > 0 && value.worker_error_message.length <= 4096 &&
    (value.worker_error_origin === "runtime" || value.worker_error_origin === "hostcall" || value.worker_error_origin === "plugin");
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
      typeof value.capability_version !== "string" || !isCanonicalSemver(value.capability_version) ||
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

function isCanonicalSemver(value: string): boolean {
  if (value.length < 5 || value.length > 255) return false;
  const plus = value.indexOf("+");
  if (plus !== value.lastIndexOf("+") || plus === value.length - 1) return false;
  const withoutBuild = plus < 0 ? value : value.slice(0, plus);
  if (plus >= 0 && !validSemverIdentifiers(value.slice(plus + 1), false)) return false;

  const dash = withoutBuild.indexOf("-");
  if (dash === withoutBuild.length - 1) return false;
  const core = dash < 0 ? withoutBuild : withoutBuild.slice(0, dash);
  if (dash >= 0 && !validSemverIdentifiers(withoutBuild.slice(dash + 1), true)) return false;
  const coreIdentifiers = core.split(".");
  return coreIdentifiers.length === 3 && coreIdentifiers.every(validSemverNumericIdentifier);
}

function validSemverIdentifiers(value: string, rejectNumericLeadingZero: boolean): boolean {
  const identifiers = value.split(".");
  return identifiers.every((identifier) => {
    if (identifier.length === 0) return false;
    let numeric = true;
    for (let index = 0; index < identifier.length; index += 1) {
      const code = identifier.charCodeAt(index);
      const digit = code >= 48 && code <= 57;
      const upper = code >= 65 && code <= 90;
      const lower = code >= 97 && code <= 122;
      if (!digit && !upper && !lower && code !== 45) return false;
      numeric = numeric && digit;
    }
    return !rejectNumericLeadingZero || !numeric || identifier.length === 1 || identifier[0] !== "0";
  });
}

function validSemverNumericIdentifier(value: string): boolean {
  if (value.length === 0 || (value.length > 1 && value[0] === "0")) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

function isLifecycleMessage(value: unknown): value is PluginBridgeLifecycleMessage {
  return hasAllowedKeys(value, ["type", "event", "quiesce_id"]) &&
    value.type === "redevplugin.bridge.lifecycle" &&
    hasExactKeys(value.event, ["type"]) &&
    (value.event.type === "ready" || value.event.type === "visible" || value.event.type === "hidden" || value.event.type === "dispose") &&
    (value.quiesce_id === undefined || (value.event.type === "dispose" && validOpaqueHandle(value.quiesce_id, "quiesce")));
}

function isMessagePortLike(value: unknown): value is MessagePortLike {
  return isRecord(value) &&
    typeof value.postMessage === "function" &&
    typeof value.addEventListener === "function" &&
    typeof value.removeEventListener === "function" &&
    typeof value.start === "function" &&
    typeof value.close === "function";
}

function isGatewayTokenResult(value: unknown): value is PluginGatewayTokenResult {
  return hasExactKeys(value, ["plugin_gateway_token", "plugin_gateway_token_id", "asset_session", "asset_session_id", "issued_at", "expires_at"]) &&
    typeof value.plugin_gateway_token === "string" && value.plugin_gateway_token.length > 0 &&
    typeof value.plugin_gateway_token_id === "string" && value.plugin_gateway_token_id.length > 0 &&
    typeof value.asset_session === "string" && value.asset_session.length > 0 &&
    typeof value.asset_session_id === "string" && value.asset_session_id.length > 0 &&
    typeof value.issued_at === "string" && typeof value.expires_at === "string";
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
const pluginUIIdentifierPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
const opaqueHandlePattern = new RegExp("^[-A-Za-z0-9_]{8,160}$");
const bridgeRequestIDPattern = /^(rpc|execution|file)_([1-9][0-9]{0,15})$/;

function validBridgeRequestID(value: unknown, expectedKind?: "rpc" | "execution" | "file"): value is string {
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

function validUIIdentifier(value: unknown): value is string {
  return typeof value === "string" && pluginUIIdentifierPattern.test(value);
}

function validFileExportName(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || value.trim() !== value ||
      value === "." || value === ".." || new TextEncoder().encode(value).byteLength > 255) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 47 || code === 92 || code === 127) return false;
  }
  return true;
}

function validFileExportMediaType(value: unknown): value is PluginSurfaceFileExportMediaType {
  return pluginSurfaceFileExportMediaTypes.includes(value as PluginSurfaceFileExportMediaType);
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

function streamReadAbortedError(): PluginBridgeError {
  return new PluginBridgeError("PLUGIN_STREAM_CANCELLED", "Plugin stream read was aborted");
}

function mutationOutcome(options: PendingCallOptions, posted: boolean): PluginMutationOutcome | undefined {
  if (!options.mutation) return undefined;
  return posted ? "unknown" : "not_committed";
}

function requestCancelledError(options: PendingCallOptions, posted: boolean): PluginBridgeError {
  if (options.cancellationKind === "stream") return streamReadAbortedError();
  return new PluginBridgeError(
    "PLUGIN_BRIDGE_CANCELLED",
    "Plugin bridge request was cancelled",
    undefined,
    undefined,
    mutationOutcome(options, posted),
  );
}

function abortableWebOriginPreparation(operation: void | Promise<void>, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const onAbort = (): void => reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Web origin preparation was aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(operation).then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
    if (signal.aborted) onAbort();
  });
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
  if (state.nodes > maxPluginJSONStructuralNodes || depth > 64) throw new TypeError("JSON value exceeds structural limits");
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

function toBridgeError(error: unknown, defaultCode: string): PluginBridgeError {
  if (error instanceof PluginBridgeError) return error;
  if (error instanceof PluginPlatformRequestError) {
    return new PluginBridgeError(error.errorCode, error.message, undefined, error.details, error.mutationOutcome);
  }
  if (error instanceof PluginTransportError) {
    return new PluginBridgeError(defaultCode, error.message, undefined, undefined, error.mutationOutcome);
  }
  if (error instanceof Error) return new PluginBridgeError(defaultCode, error.message);
  return new PluginBridgeError(defaultCode, String(error));
}
