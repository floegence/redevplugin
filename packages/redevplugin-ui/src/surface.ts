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
import { pluginUIProtocolVersion } from "./contracts.gen.js";
import {
  opaqueSurfaceAllowedTags,
  opaqueSurfaceGlobalAttributes,
  opaqueSurfaceRenderLimits,
  opaqueSurfaceSafeInputTypes,
  opaqueSurfaceTagAttributes,
} from "./opaque-surface-policy.gen.js";
import {
  defaultFetch,
  hasAllowedKeys,
  hasExactKeys,
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
import {
  PluginUIReconcileError,
  reconcileValidatedPluginUITrees,
  validatePluginUITree,
  type PluginUIElementVNode,
  type PluginUIVNode,
} from "./ui-reconciler.js";

export type {
  PluginUIAttributeValue,
  PluginUIElementVNode,
  PluginUIPatchOperation,
  PluginUIVNode,
} from "./ui-reconciler.js";

export const opaqueSurfaceDocumentSchemaVersion = "redevplugin.opaque_surface_document.v3" as const;
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
  management_revision: number;
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

export type PluginUIActionEvent = {
  action: string;
  event: "click" | "input" | "change" | "submit" | "escape";
  targetKey: string;
  editRevision: number;
  isComposing: boolean;
  value?: string;
  checked?: boolean;
  form_data?: Record<string, string>;
};

export type PluginCanvasSurface = {
  canvas: OffscreenCanvas;
  canvasId: string;
  cssWidth: number;
  cssHeight: number;
  devicePixelRatio: number;
};

export type PluginCanvasAccessibilityState = {
  label: string;
  description: string;
};

export type PluginCanvasFocusEvent = {
  type: "focus" | "blur";
};

export type PluginCanvasResizeEvent = {
  type: "resize";
  cssWidth: number;
  cssHeight: number;
  devicePixelRatio: number;
};

export type PluginCanvasKeyEvent = {
  type: "key";
  event: "keydown" | "keyup";
  code: string;
  key: string;
  repeat: boolean;
  altKey: boolean;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
};

export type PluginCanvasPointerEvent = {
  type: "pointer";
  event: "pointerdown" | "pointermove" | "pointerup" | "pointercancel";
  pointerId: number;
  pointerType: "mouse" | "pen" | "touch" | "unknown";
  buttons: number;
  button: number;
  x: number;
  y: number;
  pressure: number;
};

export type PluginCanvasInputEvent = PluginCanvasFocusEvent | PluginCanvasResizeEvent | PluginCanvasKeyEvent | PluginCanvasPointerEvent;

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

type PrivatePluginStreamReadResult = PluginStreamReadResult & { delivery_id?: string };

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

export type PluginBridgeRequestOptions = {
  signal?: AbortSignal;
};

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
  abortCleanup?: () => void;
  kind: "json" | "canvas" | "asset";
  identifier?: string;
};

type PendingCallOptions = {
  kind?: PendingCall["kind"];
  identifier?: string;
  cancellationKind?: "bridge" | "stream";
  mutation?: boolean;
  signal?: AbortSignal;
};

type PendingRender = {
  tree: PluginUIElementVNode;
  waiters: Array<{ resolve: () => void; reject: (reason: unknown) => void }>;
};

type PluginBridgeLifecycleState = "active" | "quiescing" | "quiesced" | "disposed";

type WorkerBridgeClaim = { surfaceHandle: string; port: MessagePortLike };

type WorkerBridgeGlobal = {
  claim(): WorkerBridgeClaim | undefined;
};

const opaquePluginBridgeGlobalKey = "__redevpluginWorkerBridge";
const maxPendingPluginBridgeRequests = 256;
const maxPluginBridgeMessageBytes = opaqueSurfaceRenderLimits.max_message_bytes;
const maxRetainedPluginStreamHandles = 128;
const maxPluginJSONStructuralNodes = 32 * 1024;
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
  "PLUGIN_MANAGEMENT_REVISION_MISMATCH",
  "PLUGIN_STREAM_CANCELLED",
  "PLUGIN_STREAM_TICKET_INVALID",
  "PLUGIN_TOKEN_EXPIRED",
  "PLUGIN_TOKEN_REPLAY",
]);
const maxOpaqueSurfaceLazyAssets = 128;
const maxOpaqueSurfaceLazyBytes = 32 * 1024 * 1024;
const maxConcurrentAssetReads = 4;
const maxSurfaceQuiesceMs = 1500;
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
  #canvasInputHandlers = new Map<string, Set<(event: PluginCanvasInputEvent) => void>>();
  #lifecycleHandlers = new Set<(event: BridgeLifecycleEvent) => Promise<void> | void>();
  #ready = false;
  #readyPromise: Promise<void>;
  #resolveReady!: () => void;
  #rejectReady!: (reason: unknown) => void;
  #lifecycleState: PluginBridgeLifecycleState = "active";
  #handlingLifecycle = false;
  #renderRevision = 0;
  #committedTree?: PluginUIElementVNode;
  #pendingRender?: PendingRender;
  #renderLoop?: Promise<void>;
  #controlEditRevisions = new Map<string, number>();
  #pendingStreamDeliveries = new Map<string, { deliveryID: string; result: PluginStreamReadResult }>();
  #streamReadTails = new Map<string, Promise<PluginStreamReadResult>>();
  #onMessage = (event: MessageEventLike): void => {
    void this.#handleMessage(event);
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

  call<T = unknown>(
    method: string,
    params?: PluginJSONObject,
    options: PluginBridgeRequestOptions = {},
  ): Promise<T> {
    const effect = (options as PluginBridgeCapabilityRequestOptions)[pluginBridgeCapabilityEffect];
    return this.#call(method, params, options, effect === undefined || effect !== "read");
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

  readStream(streamHandle: string, options: PluginBridgeRequestOptions = {}): Promise<PluginStreamReadResult> {
    this.#assertActive();
    if (!validOpaqueHandle(streamHandle, "stream")) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin stream handle is invalid");
    }
    const previous = this.#streamReadTails.get(streamHandle);
    const read = (previous ? previous.catch(() => undefined) : Promise.resolve()).then(() => {
      this.#assertActive();
      if (options.signal?.aborted) throw streamReadAbortedError();
      return this.#readStream(streamHandle, options.signal);
    });
    this.#streamReadTails.set(streamHandle, read);
    void read.finally(() => {
      if (this.#streamReadTails.get(streamHandle) === read) this.#streamReadTails.delete(streamHandle);
    }).catch(() => undefined);
    return abortableStreamRead(read, options.signal);
  }

  async #readStream(streamHandle: string, signal?: AbortSignal): Promise<PluginStreamReadResult> {
    const pending = this.#pendingStreamDeliveries.get(streamHandle);
    if (pending) {
      await this.#acknowledgeStream(streamHandle, pending.deliveryID, signal);
      this.#pendingStreamDeliveries.delete(streamHandle);
      return pending.result;
    }
    const id = this.#requestID("stream");
    const privateResult = await this.#request<PrivatePluginStreamReadResult>(id, {
      type: "redevplugin.bridge.stream.read",
      id,
      stream_handle: streamHandle,
    }, { cancellationKind: "stream", signal });
    const { delivery_id: deliveryID, ...result } = privateResult;
    if (!deliveryID) return result;
    this.#pendingStreamDeliveries.set(streamHandle, { deliveryID, result });
    await this.#acknowledgeStream(streamHandle, deliveryID, signal);
    this.#pendingStreamDeliveries.delete(streamHandle);
    return result;
  }

  async #acknowledgeStream(streamHandle: string, deliveryID: string, signal?: AbortSignal): Promise<void> {
    const id = this.#requestID("stream_ack");
    await this.#request<void>(id, {
      type: "redevplugin.bridge.stream.ack",
      id,
      stream_handle: streamHandle,
      delivery_id: deliveryID,
    }, { cancellationKind: "stream", signal });
  }

  cancelOperation(
    operationID: string,
    reason?: string,
    options: PluginBridgeRequestOptions = {},
  ): Promise<void> {
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
    }), { mutation: true, signal: options.signal });
  }

  render(tree: PluginUIVNode): Promise<void> {
    this.#assertActive();
    let validated: PluginUIElementVNode;
    try {
      validated = validatePluginUITree(tree);
    } catch (error) {
      throw new PluginBridgeError(
        "PLUGIN_UI_PROTOCOL_VIOLATION",
        error instanceof Error ? error.message : "Plugin UI tree is invalid",
      );
    }
    return new Promise<void>((resolve, reject) => {
      const waiters = this.#pendingRender?.waiters ?? [];
      waiters.push({ resolve, reject });
      this.#pendingRender = { tree: validated, waiters };
      this.#startRenderLoop();
    });
  }

  openCanvas(canvasId: string): Promise<PluginCanvasSurface> {
    this.#assertActive();
    if (!validUIIdentifier(canvasId)) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin canvas identifier is invalid");
    }
    const id = this.#requestID("canvas");
    return this.#request<PluginCanvasSurface>(id, {
      type: "redevplugin.ui.canvas.open",
      id,
      canvas_id: canvasId,
    }, { kind: "canvas", identifier: canvasId });
  }

  updateCanvasAccessibility(canvasId: string, state: PluginCanvasAccessibilityState): Promise<void> {
    this.#assertActive();
    if (!validUIIdentifier(canvasId) || !validCanvasAccessibilityState(state)) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin canvas accessibility state is invalid");
    }
    const id = this.#requestID("canvas");
    return this.#request<void>(id, {
      type: "redevplugin.ui.canvas.accessibility",
      id,
      canvas_id: canvasId,
      label: state.label,
      description: state.description,
    });
  }

  loadImageAsset(assetId: string): Promise<ImageBitmap> {
    this.#assertActive();
    if (!validUIIdentifier(assetId)) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin image asset identifier is invalid");
    }
    const id = this.#requestID("asset");
    return this.#request<ImageBitmap>(id, {
      type: "redevplugin.ui.asset.image.open",
      id,
      asset_id: assetId,
    }, { kind: "asset", identifier: assetId });
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

  onCanvasInput(canvasId: string, handler: (event: PluginCanvasInputEvent) => void): () => void {
    this.#assertActive();
    if (!validUIIdentifier(canvasId) || typeof handler !== "function") {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin canvas input subscription is invalid");
    }
    const handlers = this.#canvasInputHandlers.get(canvasId) ?? new Set();
    handlers.add(handler);
    this.#canvasInputHandlers.set(canvasId, handlers);
    return () => {
      handlers.delete(handler);
      if (handlers.size === 0) this.#canvasInputHandlers.delete(canvasId);
    };
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
      clearTimeout(pending.timer);
      pending.abortCleanup?.();
      pending.reject(new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", `Plugin bridge request ${id} was disposed`));
    }
    this.#pending.clear();
    this.#pendingStreamDeliveries.clear();
    this.#actionHandlers.clear();
    this.#canvasInputHandlers.clear();
    this.#lifecycleHandlers.clear();
    for (const waiter of this.#pendingRender?.waiters ?? []) waiter.reject(disposedError);
    this.#pendingRender = undefined;
    this.#controlEditRevisions.clear();
    this.#port.close();
  }

  async #drainRenders(): Promise<void> {
    while (this.#pendingRender && this.#acceptsPluginWork()) {
      const pending = this.#pendingRender;
      this.#pendingRender = undefined;
      const id = this.#requestID("render");
      const nextRevision = this.#renderRevision + 1;
      try {
        if (!this.#committedTree) {
          await this.#request<void>(id, {
            type: "redevplugin.ui.mount",
            id,
            revision: 1,
            tree: pending.tree,
          });
        } else {
          const operations = reconcileValidatedPluginUITrees(this.#committedTree, pending.tree, {
            controlEditRevisions: this.#controlEditRevisions,
          });
          if (operations.length > 0) {
            await this.#request<void>(id, {
              type: "redevplugin.ui.patch",
              id,
              base_revision: this.#renderRevision,
              revision: nextRevision,
              operations,
            });
            this.#renderRevision = nextRevision;
          }
        }
        this.#committedTree = pending.tree;
        if (this.#renderRevision === 0) this.#renderRevision = 1;
        for (const waiter of pending.waiters) waiter.resolve();
      } catch (error) {
        const bridgeError = error instanceof PluginUIReconcileError
          ? new PluginBridgeError("PLUGIN_UI_PROTOCOL_VIOLATION", error.message)
          : error;
        for (const waiter of pending.waiters) waiter.reject(bridgeError);
        const queued = this.#pendingRender as PendingRender | undefined;
        for (const waiter of queued?.waiters ?? []) waiter.reject(bridgeError);
        this.#pendingRender = undefined;
        throw bridgeError;
      }
    }
    if (this.#pendingRender) {
      const error = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin UI cannot render after quiescing starts");
      for (const waiter of this.#pendingRender.waiters) waiter.reject(error);
      this.#pendingRender = undefined;
    }
  }

  #startRenderLoop(): void {
    if (this.#renderLoop) return;
    this.#renderLoop = this.#drainRenders()
      .catch(() => undefined)
      .finally(() => {
        this.#renderLoop = undefined;
        if (this.#pendingRender) this.#startRenderLoop();
      });
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
    if (this.#pending.size >= maxPendingPluginBridgeRequests) {
      throw new PluginBridgeError("PLUGIN_JSON_LIMIT_EXCEEDED", "Plugin bridge has too many pending requests");
    }
    if (options.signal?.aborted) return Promise.reject(requestCancelledError(options, false));
    let posted = false;
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
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
        timer,
        abortCleanup: options.signal ? () => options.signal?.removeEventListener("abort", onAbort) : undefined,
        kind: options.kind ?? "json",
        identifier: options.identifier,
      });
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
    });
    if (!this.#pending.has(id)) return result;
    try {
      this.#port.postMessage(normalizedMessage);
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
    clearTimeout(pending.timer);
    pending.abortCleanup?.();
    return pending;
  }

  async #handleMessage(event: MessageEventLike): Promise<void> {
    if (this.#lifecycleState === "disposed") return;
    const data = event.data;
    if (isCanvasReadyCandidate(data)) {
      const pending = this.#takePending(data.id);
      if (!pending) return;
      if (pending.kind !== "canvas" || pending.identifier !== data.canvas_id || !isCanvasReadyMessage(data)) {
        pending.reject(new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin canvas response ${data.id} is invalid`));
        return;
      }
      pending.resolve({
        canvas: data.canvas,
        canvasId: data.canvas_id,
        cssWidth: data.css_width,
        cssHeight: data.css_height,
        devicePixelRatio: data.device_pixel_ratio,
      } satisfies PluginCanvasSurface);
      return;
    }
    if (isImageReadyCandidate(data)) {
      const pending = this.#takePending(data.id);
      if (!pending) return;
      if (pending.kind !== "asset" || pending.identifier !== data.asset_id || !isImageReadyMessage(data)) {
        pending.reject(new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin image response ${data.id} is invalid`));
        return;
      }
      pending.resolve(data.image);
      return;
    }
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
    if (isActionMessage(data)) {
      this.#controlEditRevisions.set(data.target_key, data.edit_revision);
      const action = publicActionEvent(data);
      for (const handler of this.#actionHandlers.get(data.action) ?? []) handler(action);
      return;
    }
    const canvasInput = publicCanvasInputMessage(data);
    if (canvasInput) {
      for (const handler of this.#canvasInputHandlers.get(canvasInput.canvasId) ?? []) handler(canvasInput.event);
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
    "redevplugin.bridge.handshake.v3",
    handshake.plugin_id,
    handshake.surface_id,
    handshake.surface_instance_id,
    handshake.active_fingerprint,
    handshake.bridge_nonce,
    handshake.asset_session_nonce,
    String(handshake.management_revision),
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
  logical_ids: string[];
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
  management_revision: number;
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
  managementRevision: number;
  revokeEpoch: number;
  runtimeGenerationId: string;
};

export type PluginSurfaceOpeningProgress = {
  phase: "opening";
  elapsedMs: number;
};

export type PluginSurfaceHost = {
  readonly element: HTMLIFrameElement;
  readonly surfaceInstanceId: string;
  sendLifecycle(event: Exclude<BridgeLifecycleEvent, { type: "ready" | "dispose" }>): void;
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
  owner: "opening" | "host" | "revoked";
  cancelled: boolean;
  adopt(): void;
  cancel(): Promise<void>;
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
): Promise<void> {
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
    await readMutationPlatformResponse<Record<string, unknown>>(response);
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

type PluginSurfaceAssetReadResult = {
  path: string;
  sha256: string;
  content_type: string;
  content_base64: string;
};

type PluginSurfaceStreamReadResult = {
  delivery_id?: string;
  read_id: string;
  events: Array<PluginStreamEvent & { stream_id: string }>;
  done: boolean;
  terminal_status?: PluginStreamTerminalStatus;
};

type PluginSurfaceStreamAcknowledgementResult = { acknowledged: true };

type PendingStreamDelivery = {
  deliveryID: string;
  lastSequence: number;
  done: boolean;
  response: PrivatePluginStreamReadResult;
};

type StreamCredential = {
  streamID: string;
  operationID: string;
  streamTicket: string;
  expiresAtMs: number;
  lastSequence: number;
  readID: string;
  reading: boolean;
  acknowledging: boolean;
  completed: boolean;
  pending?: PendingStreamDelivery;
  lastAcknowledgedDeliveryID?: string;
};

type OpenSignals = {
  portAcknowledged: Deferred<void>;
  firstPaint: Deferred<void>;
  workerReady: Deferred<void>;
  firstCommit: Deferred<void>;
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
  revokeDurationMs: number;
  totalDurationMs: number;
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
  const maxPatchOperations = ${opaqueSurfaceRenderLimits.max_patch_operations};
  const maxAttributesPerElement = ${opaqueSurfaceRenderLimits.max_attributes_per_element};
  const maxTextLength = ${opaqueSurfaceRenderLimits.max_text_length};
  const maxAttributeValueLength = ${opaqueSurfaceRenderLimits.max_attribute_value_length};
  const maxFormFields = ${opaqueSurfaceRenderLimits.max_form_fields};
  const maxCanvasCount = ${opaqueSurfaceRenderLimits.max_canvas_count};
  const maxCanvasDimension = ${opaqueSurfaceRenderLimits.max_canvas_dimension};
  const maxCanvasTotalPixels = ${opaqueSurfaceRenderLimits.max_canvas_total_pixels};
  const maxCanvasPointerEventsPerSecond = ${opaqueSurfaceRenderLimits.max_canvas_pointer_events_per_second};
  const maxImageCount = ${opaqueSurfaceRenderLimits.max_image_count};
  const maxImageDimension = ${opaqueSurfaceRenderLimits.max_image_dimension};
  const maxImageTotalPixels = ${opaqueSurfaceRenderLimits.max_image_total_pixels};
  const workerHeartbeatIntervalMs = ${opaqueSurfaceRenderLimits.worker_heartbeat_interval_ms};
  const workerHeartbeatTimeoutMs = ${opaqueSurfaceRenderLimits.worker_heartbeat_timeout_ms};
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
    if (state.nodes > ${maxPluginJSONStructuralNodes} || depth > 64) return false;
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
  const validResourceIdentifier = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
  const validOpaqueHandle = (value, prefix) => typeof value === "string" && value.startsWith(prefix + "_") && /^[A-Za-z0-9_-]{8,160}$/.test(value);
  const validDeliveryID = (value) => typeof value === "string" && /^delivery_[A-Za-z0-9_-]{8,128}$/.test(value);
  const validDigest = (value) => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
  const validPath = (value) => typeof value === "string" && value.length > 0 && value.length <= 512 && !value.startsWith("/") && !value.includes("\\\\") && !value.split("/").some((part) => !part || part === "." || part === "..");
  const validAttribute = (tag, name, value) => {
    const lower = name.toLowerCase();
    if (lower.startsWith("on") || lower === "style" || lower === "src" || lower === "srcset" || lower === "href" || lower === "srcdoc" || lower === "action" || lower === "formaction") return false;
    if (!globalAttributes.has(lower) && !lower.startsWith("aria-") && !(tagAttributes[tag] && tagAttributes[tag].has(lower))) return false;
    if (!["string", "number", "boolean"].includes(typeof value)) return false;
    if (lower === "data-redevplugin-action" && !validIdentifier(String(value))) return false;
    if (lower === "data-redevplugin-escape-action" && !validIdentifier(String(value))) return false;
    if (lower === "data-redevplugin-asset-binding" && !validOpaqueHandle(String(value), "asset")) return false;
    if (lower === "data-redevplugin-asset-attr" && !["src", "poster"].includes(String(value))) return false;
    if (lower === "data-redevplugin-canvas" && (tag !== "canvas" || !validResourceIdentifier(String(value)))) return false;
    if (tag === "canvas" && (lower === "width" || lower === "height") && (!/^[1-9][0-9]{0,4}$/.test(String(value)) || Number(value) > maxCanvasDimension)) return false;
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
  const validAsset = (value) => exactKeys(value, ["binding_id", "logical_ids", "path", "sha256", "size", "content_type"]) && validOpaqueHandle(value.binding_id, "asset") && Array.isArray(value.logical_ids) && value.logical_ids.length > 0 && value.logical_ids.length <= 16 && value.logical_ids.every(validResourceIdentifier) && new Set(value.logical_ids).size === value.logical_ids.length && validPath(value.path) && validDigest(value.sha256) && Number.isSafeInteger(value.size) && value.size >= 0 && value.size <= maxLazyAssetBytes && typeof value.content_type === "string" && value.content_type.length > 0 && value.content_type.length <= 256;
  const validDocument = (value) => isRecord(value) && Object.keys(value).every((key) => ["schema_version", "entry_path", "entry_sha256", "title", "language", "direction", "body_html", "styles", "worker", "assets", "critical_bytes"].includes(key)) && value.schema_version === documentSchema && validPath(value.entry_path) && validDigest(value.entry_sha256) && (value.title === undefined || (typeof value.title === "string" && value.title.length <= 256)) && (value.language === undefined || (typeof value.language === "string" && value.language.length <= 64)) && (value.direction === undefined || ["ltr", "rtl", "auto"].includes(value.direction)) && typeof value.body_html === "string" && value.body_html.length <= 4194304 && Array.isArray(value.styles) && value.styles.every(validStyle) && validWorker(value.worker) && Array.isArray(value.assets) && value.assets.length <= maxLazyAssetCount && value.assets.every(validAsset) && new Set(value.assets.map((asset) => asset.binding_id)).size === value.assets.length && new Set(value.assets.map((asset) => asset.path)).size === value.assets.length && new Set(value.assets.flatMap((asset) => asset.logical_ids)).size === value.assets.reduce((total, asset) => total + asset.logical_ids.length, 0) && value.assets.reduce((total, asset) => total + asset.size, 0) <= maxLazyAssetBytes && Number.isSafeInteger(value.critical_bytes) && value.critical_bytes >= 0 && value.critical_bytes <= maxCriticalDocumentBytes;
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
  let workerHeartbeatSequence = 0;
  let workerHeartbeatPendingID;
  let workerHeartbeatTimer;
  let workerHeartbeatTimeout;
  let pendingQuiesceID;
  const pendingWorkerRequests = new Set();
  const requestSequence = { rpc: 0, stream: 0, stream_ack: 0, render: 0, operation: 0, canvas: 0, asset: 0 };
  let renderWindowStartedAt = 0;
  let renderCount = 0;
  let uiRevision = 0;
  let uiGraph = new Map();
  let uiNodes = new Map();
  const controlEdits = new Map();
  let lastAutofocusIdentity = "";
  const pendingAssets = new Map();
  const queuedAssets = [];
  let activeAssetReads = 0;
  let assetSequence = 0;
  const blobURLs = new Set();
  const assetByLogicalID = new Map();
  const verifiedAssetBytes = new Map();
  const imageAssetDimensions = new Map();
  const imageAssetTypes = new Map();
  const pendingImageRequests = new Map();
  const activeImageDecodes = new Set();
  const imageReservations = new Map();
  let retainedImageCount = 0;
  let retainedImagePixels = 0;
  const canvasRuntimes = new Map();

  const sendParent = (message) => {
    if (parentPort && withinLimit(message)) parentPort.postMessage(message);
  };
  const sendWorker = (message) => {
    if (workerPort && withinLimit(message)) workerPort.postMessage(message);
  };
  const sendWorkerTransfer = (message, transfer) => {
    if (workerPort) workerPort.postMessage(message, transfer);
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
    if (workerHeartbeatTimer) clearTimeout(workerHeartbeatTimer);
    if (workerHeartbeatTimeout) clearTimeout(workerHeartbeatTimeout);
    workerHeartbeatTimer = undefined;
    workerHeartbeatTimeout = undefined;
    workerHeartbeatPendingID = undefined;
    workerReady = false;
    for (const runtime of canvasRuntimes.values()) runtime.dispose();
    canvasRuntimes.clear();
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
    pendingImageRequests.clear();
    activeImageDecodes.clear();
    imageReservations.clear();
    imageAssetDimensions.clear();
    imageAssetTypes.clear();
    retainedImageCount = 0;
    retainedImagePixels = 0;
    verifiedAssetBytes.clear();
    assetByLogicalID.clear();
  };
  const terminateQuiescedWorker = () => {
    if (workerHeartbeatTimer) clearTimeout(workerHeartbeatTimer);
    if (workerHeartbeatTimeout) clearTimeout(workerHeartbeatTimeout);
    workerHeartbeatTimer = undefined;
    workerHeartbeatTimeout = undefined;
    workerHeartbeatPendingID = undefined;
    workerReady = false;
    if (workerControlPort) {
      workerControlPort.close();
      workerControlPort = undefined;
    }
    if (workerPort) {
      workerPort.close();
      workerPort = undefined;
    }
    if (worker) {
      worker.terminate();
      worker = undefined;
    }
    pendingWorkerRequests.clear();
  };
  const validateCanvasIdentifiers = (root) => {
    const identifiers = new Set();
    let totalPixels = 0;
    for (const canvas of root.querySelectorAll("canvas[data-redevplugin-canvas]")) {
      const identifier = canvas.getAttribute("data-redevplugin-canvas");
      if (!validResourceIdentifier(identifier) || identifiers.has(identifier)) throw new Error("plugin canvas identifiers are invalid or ambiguous");
      identifiers.add(identifier);
      if (identifiers.size > maxCanvasCount) throw new Error("plugin document exceeds the canvas count limit");
      const width = Number(canvas.getAttribute("width") || 300);
      const height = Number(canvas.getAttribute("height") || 150);
      if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width <= 0 || height <= 0 || width > maxCanvasDimension || height > maxCanvasDimension) {
        throw new Error("plugin canvas dimensions are invalid");
      }
      totalPixels += width * height;
      if (totalPixels > maxCanvasTotalPixels) throw new Error("plugin document exceeds the canvas pixel budget");
    }
  };
  const applyStaticDocument = (surfaceDocument) => {
    for (const asset of surfaceDocument.assets) {
      for (const logicalID of asset.logical_ids) assetByLogicalID.set(logicalID, asset);
    }
    document.title = typeof surfaceDocument.title === "string" ? surfaceDocument.title.slice(0, 256) : "Plugin";
    document.documentElement.lang = typeof surfaceDocument.language === "string" ? surfaceDocument.language.slice(0, 64) : "en";
    if (["ltr", "rtl", "auto"].includes(surfaceDocument.direction)) document.documentElement.dir = surfaceDocument.direction;
    const template = document.createElement("template");
    template.innerHTML = surfaceDocument.body_html;
    if (!validateDOMTree(template.content)) throw new Error("static plugin document failed renderer validation");
    validateCanvasIdentifiers(template.content);
    document.body.replaceChildren(template.content.cloneNode(true));
    for (const styleAsset of surfaceDocument.styles) {
      const style = document.createElement("style");
      style.setAttribute("nonce", scriptNonce);
      style.dataset.redevpluginAsset = styleAsset.path;
      style.textContent = styleAsset.content;
      document.head.append(style);
    }
  };
  const applyWorkerAttribute = (element, tag, name, attributeValue) => {
    const lower = name.toLowerCase();
    if (!validAttribute(tag, name, attributeValue)) throw new Error("plugin render attribute is not allowed");
    if (lower === "value" && "value" in element) element.value = String(attributeValue);
    if (lower === "checked" && "checked" in element) element.checked = attributeValue === true;
    if (lower === "autofocus") {
      if (attributeValue !== false) element.setAttribute("data-redevplugin-renderer-autofocus", "");
      else element.removeAttribute("data-redevplugin-renderer-autofocus");
      return;
    }
    if (typeof attributeValue === "boolean") {
      const serialized = lower.startsWith("aria-") ? String(attributeValue) : "";
      if (attributeValue || serialized) element.setAttribute(name, serialized);
      else element.removeAttribute(name);
      return;
    }
    element.setAttribute(name, String(attributeValue));
  };
  const buildWorkerSubtree = (value, state, depth, parentKey, graph = new Map(), nodes = new Map()) => {
    state.nodes += 1;
    if (state.nodes > maxRenderNodes || depth > maxRenderDepth || !isRecord(value) || typeof value.key !== "string" ||
        !validResourceIdentifier(value.key) || graph.has(value.key)) {
      throw new Error("plugin render tree exceeds limits or contains an invalid key");
    }
    if (value.type === "text") {
      if (!exactKeys(value, ["type", "key", "text"]) || typeof value.text !== "string" || value.text.length > maxTextLength) {
        throw new Error("plugin render text node is invalid");
      }
      const node = document.createTextNode(value.text);
      graph.set(value.key, {
        key: value.key,
        type: "text",
        text: value.text,
        parentKey,
        prevKey: null,
        nextKey: null,
        firstChildKey: null,
        lastChildKey: null,
        height: 1,
        heightDirty: false,
      });
      nodes.set(value.key, node);
      return { node, graph, nodes };
    }
    if (!Object.keys(value).every((key) => ["type", "key", "tag", "attributes", "children"].includes(key)) ||
        value.type !== "element" || typeof value.tag !== "string") {
      throw new Error("plugin render node is invalid");
    }
    const tag = value.tag.toLowerCase();
    if (!allowedTags.has(tag)) throw new Error("plugin render tag is not allowed");
    const attributes = {};
    if (value.attributes !== undefined) {
      if (!isRecord(value.attributes) || Object.keys(value.attributes).length > maxAttributesPerElement) throw new Error("plugin render attributes are invalid");
      for (const [name, attributeValue] of Object.entries(value.attributes)) {
        if (!validAttribute(tag, name, attributeValue)) throw new Error("plugin render attribute is not allowed");
        attributes[name] = attributeValue;
      }
    }
    if (value.children !== undefined && !Array.isArray(value.children)) throw new Error("plugin render children are invalid");
    const element = document.createElement(tag);
    element.setAttribute("data-redevplugin-key", value.key);
    for (const [name, attributeValue] of Object.entries(attributes)) applyWorkerAttribute(element, tag, name, attributeValue);
    const record = {
      key: value.key,
      type: "element",
      tag,
      attributes,
      parentKey,
      prevKey: null,
      nextKey: null,
      firstChildKey: null,
      lastChildKey: null,
      height: 1,
      heightDirty: false,
    };
    graph.set(value.key, record);
    nodes.set(value.key, element);
    let previousKey = null;
    for (const child of value.children || []) {
      const built = buildWorkerSubtree(child, state, depth + 1, value.key, graph, nodes);
      const childRecord = graph.get(child.key);
      childRecord.prevKey = previousKey;
      if (previousKey) graph.get(previousKey).nextKey = child.key;
      else record.firstChildKey = child.key;
      record.lastChildKey = child.key;
      record.height = Math.max(record.height, childRecord.height + 1);
      previousKey = child.key;
      element.append(built.node);
    }
    return { node: element, graph, nodes };
  };
  const renderElementIdentity = (element) => ({
    tag: element.tagName,
    id: element.getAttribute("id") || "",
    name: element.getAttribute("name") || "",
    action: element.getAttribute("data-redevplugin-action") || "",
    escapeAction: element.getAttribute("data-redevplugin-escape-action") || "",
    ariaLabel: element.getAttribute("aria-label") || "",
    value: element.tagName === "BUTTON" || element.tagName === "OPTION" ? element.getAttribute("value") || "" : "",
  });
  const sameRenderElementIdentity = (left, right) => left.tag === right.tag && left.id === right.id && left.name === right.name && left.action === right.action && left.escapeAction === right.escapeAction && left.ariaLabel === right.ariaLabel && left.value === right.value;
  const captureRenderState = () => {
    const active = document.activeElement instanceof Element && document.body.contains(document.activeElement) ? document.activeElement : undefined;
    let selection;
    if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
      selection = { start: active.selectionStart, end: active.selectionEnd, direction: active.selectionDirection };
    }
    return {
      activeIdentity: active ? renderElementIdentity(active) : undefined,
      selection,
      activeScrollTop: active instanceof HTMLElement ? active.scrollTop : 0,
      activeScrollLeft: active instanceof HTMLElement ? active.scrollLeft : 0,
      documentScrollTop: document.documentElement.scrollTop,
      documentScrollLeft: document.documentElement.scrollLeft,
      bodyScrollTop: document.body.scrollTop,
      bodyScrollLeft: document.body.scrollLeft,
    };
  };
  const restoreRenderState = (snapshot) => {
    const autofocus = document.body.querySelector("[data-redevplugin-renderer-autofocus]");
    const autofocusIdentity = autofocus instanceof Element ? JSON.stringify(renderElementIdentity(autofocus)) : "";
    if (autofocus instanceof Element) autofocus.removeAttribute("data-redevplugin-renderer-autofocus");
    let target;
    if (autofocus instanceof HTMLElement && !autofocus.hasAttribute("disabled") && autofocusIdentity !== lastAutofocusIdentity) {
      target = autofocus;
      lastAutofocusIdentity = autofocusIdentity;
    } else {
      if (!autofocusIdentity) lastAutofocusIdentity = "";
      if (snapshot.activeIdentity) {
        for (const candidate of document.body.querySelectorAll(snapshot.activeIdentity.tag.toLowerCase())) {
          if (sameRenderElementIdentity(renderElementIdentity(candidate), snapshot.activeIdentity)) {
            target = candidate;
            break;
          }
        }
      }
    }
    if (target instanceof HTMLElement && !target.hasAttribute("disabled")) {
      try { target.focus({ preventScroll: true }); } catch { target.focus(); }
      target.scrollTop = snapshot.activeScrollTop;
      target.scrollLeft = snapshot.activeScrollLeft;
      if (snapshot.selection && (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
        const length = target.value.length;
        const start = Math.min(snapshot.selection.start ?? length, length);
        const end = Math.min(snapshot.selection.end ?? start, length);
        try { target.setSelectionRange(start, end, snapshot.selection.direction || "none"); } catch {}
      }
    }
    document.documentElement.scrollTop = snapshot.documentScrollTop;
    document.documentElement.scrollLeft = snapshot.documentScrollLeft;
    document.body.scrollTop = snapshot.bodyScrollTop;
    document.body.scrollLeft = snapshot.bodyScrollLeft;
  };
  const transferredCanvasKey = (key) => {
    const element = uiNodes.get(key);
    if (!(element instanceof HTMLCanvasElement)) return false;
    for (const runtime of canvasRuntimes.values()) if (runtime.canvas === element) return true;
    return false;
  };
  const editableControlAttribute = (tag, name) => {
    const normalized = name.toLowerCase();
    return (normalized === "value" && ["input", "textarea", "select", "option"].includes(tag)) ||
      (normalized === "checked" && tag === "input");
  };
  const createGraphOverlay = (base) => {
    const changed = new Map();
    const deleted = new Set();
    let count = base.size;
    const get = (key) => changed.has(key) ? changed.get(key) : deleted.has(key) ? undefined : base.get(key);
    const edit = (key) => {
      const current = get(key);
      if (!current) throw new Error("plugin UI patch target does not exist");
      if (changed.has(key)) return current;
      const copy = { ...current, ...(current.attributes ? { attributes: { ...current.attributes } } : {}) };
      changed.set(key, copy);
      return copy;
    };
    const add = (record) => {
      if (get(record.key)) throw new Error("plugin UI insertion duplicates a key");
      changed.set(record.key, { ...record, ...(record.attributes ? { attributes: { ...record.attributes } } : {}) });
      count += 1;
    };
    const remove = (key) => {
      if (!get(key)) throw new Error("plugin UI removal target does not exist");
      changed.delete(key);
      if (base.has(key)) deleted.add(key);
      count -= 1;
    };
    const commit = () => {
      for (const key of deleted) base.delete(key);
      for (const [key, record] of changed) base.set(key, record);
    };
    return { get, edit, add, remove, commit, count: () => count };
  };
  const graphDepth = (graph, key) => {
    let depth = 0;
    let cursor = graph.get(key);
    const seen = new Set();
    while (cursor) {
      if (seen.has(cursor.key)) throw new Error("plugin UI graph contains a cycle");
      seen.add(cursor.key);
      depth += 1;
      cursor = cursor.parentKey ? graph.get(cursor.parentKey) : undefined;
    }
    return depth;
  };
  const graphSubtreeKeys = (graph, rootKey) => {
    const keys = [];
    const stack = [rootKey];
    while (stack.length > 0) {
      const key = stack.pop();
      const record = key && graph.get(key);
      if (!record) throw new Error("plugin UI graph is inconsistent");
      keys.push(key);
      const children = [];
      let childKey = record.firstChildKey;
      while (childKey) {
        const child = graph.get(childKey);
        if (!child || child.parentKey !== key) throw new Error("plugin UI child graph is inconsistent");
        children.push(childKey);
        childKey = child.nextKey;
      }
      stack.push(...children.reverse());
    }
    return keys;
  };
  const graphSubtreeHeight = (graph, rootKey) => {
    const record = graph.get(rootKey);
    if (!record) throw new Error("plugin UI graph is inconsistent");
    if (!record.heightDirty) return record.height;
    let height = 1;
    let childKey = record.firstChildKey;
    while (childKey) {
      const child = graph.get(childKey);
      if (!child || child.parentKey !== rootKey) throw new Error("plugin UI child graph is inconsistent");
      height = Math.max(height, graphSubtreeHeight(graph, childKey) + 1);
      childKey = child.nextKey;
    }
    const edited = graph.edit(rootKey);
    edited.height = height;
    edited.heightDirty = false;
    return height;
  };
  const graphParentChainContains = (graph, rootKey, targetKey) => {
    let cursor = graph.get(rootKey);
    const seen = new Set();
    while (cursor) {
      if (cursor.key === targetKey) return true;
      if (seen.has(cursor.key)) throw new Error("plugin UI graph contains a cycle");
      seen.add(cursor.key);
      cursor = cursor.parentKey ? graph.get(cursor.parentKey) : undefined;
    }
    return false;
  };
  const graphSubtreeHasTransferredCanvas = (graph, rootKey) => {
    for (const runtime of canvasRuntimes.values()) {
      const key = runtime.canvas.getAttribute("data-redevplugin-key");
      if (!key) continue;
      let cursor = graph.get(key);
      const seen = new Set();
      while (cursor) {
        if (cursor.key === rootKey) return true;
        if (seen.has(cursor.key)) throw new Error("plugin UI graph contains a cycle");
        seen.add(cursor.key);
        cursor = cursor.parentKey ? graph.get(cursor.parentKey) : undefined;
      }
    }
    return false;
  };
  const markGraphHeightDirty = (graph, key) => {
    let cursorKey = key;
    const seen = new Set();
    while (cursorKey) {
      if (seen.has(cursorKey)) throw new Error("plugin UI graph contains a cycle");
      seen.add(cursorKey);
      const record = graph.edit(cursorKey);
      record.heightDirty = true;
      cursorKey = record.parentKey;
    }
  };
  const detachGraphNode = (graph, key) => {
    const record = graph.edit(key);
    if (!record.parentKey) throw new Error("plugin UI root cannot be detached");
    const parentKey = record.parentKey;
    const parent = graph.edit(parentKey);
    if (record.prevKey) graph.edit(record.prevKey).nextKey = record.nextKey;
    else parent.firstChildKey = record.nextKey;
    if (record.nextKey) graph.edit(record.nextKey).prevKey = record.prevKey;
    else parent.lastChildKey = record.prevKey;
    record.parentKey = undefined;
    record.prevKey = null;
    record.nextKey = null;
    markGraphHeightDirty(graph, parentKey);
  };
  const attachGraphNode = (graph, key, parentKey, beforeKey) => {
    const record = graph.edit(key);
    const parent = graph.edit(parentKey);
    if (parent.type !== "element" || record.parentKey) throw new Error("plugin UI insertion parent is invalid");
    let previousKey = parent.lastChildKey;
    if (beforeKey !== null) {
      if (beforeKey === key) throw new Error("plugin UI anchor cannot target the moved node");
      const before = graph.get(beforeKey);
      if (!before || before.parentKey !== parentKey) throw new Error("plugin UI anchor is invalid");
      previousKey = before.prevKey;
      graph.edit(beforeKey).prevKey = key;
    } else {
      parent.lastChildKey = key;
    }
    if (previousKey) graph.edit(previousKey).nextKey = key;
    else parent.firstChildKey = key;
    record.parentKey = parentKey;
    record.prevKey = previousKey;
    record.nextKey = beforeKey;
    if (beforeKey === null) parent.lastChildKey = key;
    markGraphHeightDirty(graph, parentKey);
  };
  const validatePatch = (operations) => {
    if (!Array.isArray(operations) || operations.length > maxPatchOperations) throw new Error("plugin UI patch exceeds limits");
    const graph = createGraphOverlay(uiGraph);
    const plan = [];
    for (const operation of operations) {
      if (!isRecord(operation) || typeof operation.type !== "string") throw new Error("plugin UI patch operation is invalid");
      if (operation.type === "set_text") {
        if (!exactKeys(operation, ["type", "target_key", "text"]) || !validResourceIdentifier(operation.target_key) ||
            typeof operation.text !== "string" || operation.text.length > maxTextLength) throw new Error("plugin UI text patch is invalid");
        const target = graph.edit(operation.target_key);
        if (target.type !== "text") throw new Error("plugin UI text patch target is invalid");
        target.text = operation.text;
        plan.push(operation);
      } else if (operation.type === "patch_attributes") {
        if (!exactKeys(operation, ["type", "target_key", "set", "remove"]) || !validResourceIdentifier(operation.target_key) ||
            !isRecord(operation.set) || Object.keys(operation.set).length > maxAttributesPerElement || !Array.isArray(operation.remove) ||
            operation.remove.length > maxAttributesPerElement || new Set(operation.remove).size !== operation.remove.length ||
            operation.remove.some((name) => typeof name !== "string")) throw new Error("plugin UI attribute patch is invalid");
        const target = graph.edit(operation.target_key);
        if (target.type !== "element" || transferredCanvasKey(target.key) || Object.keys(operation.set).some((name) => editableControlAttribute(target.tag, name)) ||
            operation.remove.some((name) => editableControlAttribute(target.tag, name))) throw new Error("plugin UI attribute patch target is invalid");
        target.attributes ||= {};
        for (const [name, value] of Object.entries(operation.set)) {
          if (!validAttribute(target.tag, name, value)) throw new Error("plugin UI attribute patch is not allowed");
          target.attributes[name] = value;
        }
        for (const name of operation.remove) delete target.attributes[name];
        plan.push(operation);
      } else if (operation.type === "patch_control") {
        if (!Object.keys(operation).every((key) => ["type", "target_key", "edit_revision", "value", "checked"].includes(key)) ||
            !validResourceIdentifier(operation.target_key) || !Number.isSafeInteger(operation.edit_revision) || operation.edit_revision < 0 ||
            (operation.value === undefined && operation.checked === undefined) ||
            (operation.value !== undefined && operation.value !== null && typeof operation.value !== "string") ||
            (operation.checked !== undefined && operation.checked !== null && typeof operation.checked !== "boolean")) throw new Error("plugin UI control patch is invalid");
        const target = graph.edit(operation.target_key);
        if (target.type !== "element" || !["input", "textarea", "select", "option"].includes(target.tag)) throw new Error("plugin UI control patch target is invalid");
        target.attributes ||= {};
        if (operation.value !== undefined) operation.value === null ? delete target.attributes.value : target.attributes.value = operation.value;
        if (operation.checked !== undefined) operation.checked === null ? delete target.attributes.checked : target.attributes.checked = operation.checked;
        plan.push(operation);
      } else if (operation.type === "insert_child") {
        if (!exactKeys(operation, ["type", "parent_key", "before_key", "node"]) || !validResourceIdentifier(operation.parent_key) ||
            (operation.before_key !== null && !validResourceIdentifier(operation.before_key))) throw new Error("plugin UI insertion is invalid");
        const parent = graph.get(operation.parent_key);
        if (!parent || parent.type !== "element") throw new Error("plugin UI insertion target is invalid");
        const state = { nodes: 0 };
        const built = buildWorkerSubtree(operation.node, state, graphDepth(graph, operation.parent_key) + 1, undefined);
        if (graph.count() + state.nodes > maxRenderNodes) throw new Error("plugin UI insertion exceeds node limits");
        for (const record of built.graph.values()) graph.add(record);
        attachGraphNode(graph, operation.node.key, operation.parent_key, operation.before_key);
        plan.push({ ...operation, built });
      } else if (operation.type === "remove_child") {
        if (!exactKeys(operation, ["type", "target_key"]) || !validResourceIdentifier(operation.target_key)) throw new Error("plugin UI removal is invalid");
        const target = graph.get(operation.target_key);
        if (!target || !target.parentKey) throw new Error("plugin UI removal target is invalid");
        if (graphSubtreeHasTransferredCanvas(graph, operation.target_key)) throw new Error("transferred canvas cannot be removed");
        const removedKeys = graphSubtreeKeys(graph, operation.target_key);
        detachGraphNode(graph, operation.target_key);
        for (const key of removedKeys) graph.remove(key);
        plan.push({ ...operation, removedKeys });
      } else if (operation.type === "move_child") {
        if (!exactKeys(operation, ["type", "target_key", "parent_key", "before_key"]) || !validResourceIdentifier(operation.target_key) ||
            !validResourceIdentifier(operation.parent_key) || (operation.before_key !== null && !validResourceIdentifier(operation.before_key))) {
          throw new Error("plugin UI move is invalid");
        }
        const target = graph.get(operation.target_key);
        const parent = graph.get(operation.parent_key);
        if (!target || !target.parentKey || !parent || parent.type !== "element" ||
            graphParentChainContains(graph, operation.parent_key, operation.target_key) ||
            graphSubtreeHasTransferredCanvas(graph, operation.target_key)) throw new Error("plugin UI move target is invalid");
        if (graphDepth(graph, operation.parent_key) + graphSubtreeHeight(graph, operation.target_key) > maxRenderDepth) {
          throw new Error("plugin UI move exceeds depth limits");
        }
        detachGraphNode(graph, operation.target_key);
        attachGraphNode(graph, operation.target_key, operation.parent_key, operation.before_key);
        plan.push(operation);
      } else {
        throw new Error("plugin UI patch operation type is unsupported");
      }
    }
    return { graph, plan };
  };
  const applyPatchOperation = (operation) => {
    const parent = operation.parent_key && uiNodes.get(operation.parent_key);
    const target = operation.target_key && uiNodes.get(operation.target_key);
    if (operation.type === "set_text") {
      target.nodeValue = operation.text;
    } else if (operation.type === "patch_attributes") {
      for (const name of operation.remove) {
        target.removeAttribute(name);
        if (name.toLowerCase() === "autofocus") target.removeAttribute("data-redevplugin-renderer-autofocus");
      }
      for (const [name, value] of Object.entries(operation.set)) applyWorkerAttribute(target, target.tagName.toLowerCase(), name, value);
    } else if (operation.type === "patch_control") {
      const edit = controlEdits.get(operation.target_key) || { revision: 0, isComposing: false };
      if (edit.revision !== operation.edit_revision || edit.isComposing) return;
      if (operation.value !== undefined && "value" in target) target.value = operation.value === null ? "" : operation.value;
      if (operation.checked !== undefined && "checked" in target) target.checked = operation.checked === true;
    } else if (operation.type === "insert_child") {
      const before = operation.before_key === null ? null : uiNodes.get(operation.before_key);
      parent.insertBefore(operation.built.node, before || null);
      for (const [key, node] of operation.built.nodes) uiNodes.set(key, node);
    } else if (operation.type === "remove_child") {
      for (const key of operation.removedKeys) uiNodes.delete(key);
      target.remove();
    } else if (operation.type === "move_child") {
      const before = operation.before_key === null ? null : uiNodes.get(operation.before_key);
      parent.insertBefore(target, before || null);
    }
  };
  const onAnimationFrame = (commit) => new Promise((resolve, reject) => requestAnimationFrame(() => {
    try { commit(); resolve(); } catch (error) { reject(error); }
  }));
  const mountWorkerTree = async (tree) => {
    if (uiRevision !== 0) throw new Error("plugin UI mount may only occur once");
    const built = buildWorkerSubtree(tree, { nodes: 0 }, 1, undefined);
    const root = built.node;
    if (!(root instanceof Element)) throw new Error("plugin UI root must be an element");
    validateCanvasIdentifiers(root);
    const renderState = captureRenderState();
    await onAnimationFrame(() => {
      document.body.replaceChildren(root);
      restoreRenderState(renderState);
    });
    uiGraph = built.graph;
    uiNodes = built.nodes;
    uiRevision = 1;
    sendParent({ type: "redevplugin.surface.first_commit" });
  };
  const patchWorkerTree = async (baseRevision, revision, operations) => {
    if (uiRevision < 1 || baseRevision !== uiRevision || revision !== baseRevision + 1) throw new Error("plugin UI patch revision is invalid");
    const validated = validatePatch(operations);
    const renderState = captureRenderState();
    await onAnimationFrame(() => {
      for (const operation of validated.plan) applyPatchOperation(operation);
      validated.graph.commit();
      restoreRenderState(renderState);
    });
    uiRevision = revision;
  };
  const actionPayload = (event, element, eventType = event.type) => {
    const target = event.target instanceof Element ? event.target.closest("[data-redevplugin-key]") : element;
    const targetKey = target?.getAttribute("data-redevplugin-key") || element.getAttribute("data-redevplugin-key");
    if (!validResourceIdentifier(targetKey)) throw new Error("plugin UI action target is invalid");
    const edit = controlEdits.get(targetKey) || { revision: 0, isComposing: false };
    if (eventType === "input" || eventType === "change") edit.revision += 1;
    edit.isComposing = Boolean(event.isComposing || edit.isComposing);
    controlEdits.set(targetKey, edit);
    const payload = {
      type: "redevplugin.ui.action",
      action: element.getAttribute("data-redevplugin-action"),
      event: eventType,
      target_key: targetKey,
      edit_revision: edit.revision,
      is_composing: edit.isComposing,
    };
    const eventTarget = event.target;
    if (eventTarget && typeof eventTarget.value === "string") payload.value = eventTarget.value.slice(0, maxTextLength);
    if (eventTarget && typeof eventTarget.checked === "boolean") payload.checked = eventTarget.checked;
    if (eventType === "submit" && element.tagName === "FORM") {
      const values = {};
      let count = 0;
      for (const [name, value] of new FormData(element)) {
        if (typeof value !== "string" || !validIdentifier(name) || count >= maxFormFields) continue;
        values[name] = value.slice(0, maxTextLength);
        count += 1;
      }
      payload.form_data = values;
    }
    return payload;
  };
  document.addEventListener("compositionstart", (event) => {
    const element = event.target instanceof Element ? event.target.closest("[data-redevplugin-key]") : null;
    const key = element?.getAttribute("data-redevplugin-key");
    if (!validResourceIdentifier(key)) return;
    const edit = controlEdits.get(key) || { revision: 0, isComposing: false };
    edit.isComposing = true;
    controlEdits.set(key, edit);
  }, true);
  document.addEventListener("compositionend", (event) => {
    const element = event.target instanceof Element ? event.target.closest("[data-redevplugin-key]") : null;
    const key = element?.getAttribute("data-redevplugin-key");
    if (!validResourceIdentifier(key)) return;
    const edit = controlEdits.get(key) || { revision: 0, isComposing: true };
    edit.isComposing = false;
    controlEdits.set(key, edit);
  }, true);
  const handleAction = (event) => {
    if (pendingQuiesceID) return;
    if (!["click", "input", "change", "submit"].includes(event.type)) return;
    const origin = event.target instanceof Element ? event.target : null;
    const element = origin ? origin.closest("[data-redevplugin-action]") : null;
    if (!element || !document.body.contains(element)) return;
    if (element.tagName === "FORM" && event.type !== "submit") {
      const submitButton = origin ? origin.closest("button") : null;
      const buttonType = submitButton && element.contains(submitButton) ? (submitButton.getAttribute("type") || "submit").toLowerCase() : "";
      if (event.type === "click" && buttonType === "submit") {
        event.preventDefault();
        sendWorker(actionPayload(event, element, "submit"));
      }
      return;
    }
    if (event.type === "submit" || (event.type === "click" && element.tagName === "BUTTON")) event.preventDefault();
    const action = element.getAttribute("data-redevplugin-action");
    if (!validIdentifier(action)) return;
    sendWorker(actionPayload(event, element));
  };
  for (const eventType of ["click", "input", "change", "submit"]) document.addEventListener(eventType, handleAction, true);
  const focusableModalElements = (modal) => Array.from(modal.querySelectorAll('button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'))
    .filter((element) => element instanceof HTMLElement && element.tabIndex >= 0 && element.getClientRects().length > 0);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Tab" && !event.defaultPrevented && !event.repeat) {
      const modal = document.body.querySelector('[role="dialog"][aria-modal="true"]');
      if (modal instanceof HTMLElement) {
        const focusable = focusableModalElements(modal);
        if (focusable.length === 0) {
          event.preventDefault();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        const target = event.shiftKey
          ? (active === first || !modal.contains(active) ? last : undefined)
          : (active === last || !modal.contains(active) ? first : undefined);
        if (target instanceof HTMLElement) {
          event.preventDefault();
          event.stopPropagation();
          try { target.focus({ preventScroll: true }); } catch { target.focus(); }
        }
      }
      return;
    }
    if (event.key !== "Escape" || event.defaultPrevented || event.repeat) return;
    const origin = event.target instanceof Element ? event.target : document.activeElement instanceof Element ? document.activeElement : null;
    const owner = origin ? origin.closest("[data-redevplugin-escape-action]") : null;
    const action = owner?.getAttribute("data-redevplugin-escape-action");
    if (!owner || !document.body.contains(owner) || !validIdentifier(action)) return;
    event.preventDefault();
    event.stopPropagation();
    const targetKey = owner.getAttribute("data-redevplugin-key");
    if (!validResourceIdentifier(targetKey)) return;
    const edit = controlEdits.get(targetKey) || { revision: 0, isComposing: false };
    sendWorker({
      type: "redevplugin.ui.action",
      action,
      event: "escape",
      target_key: targetKey,
      edit_revision: edit.revision,
      is_composing: edit.isComposing,
    });
  }, true);
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
  const failTransferRequest = (id, error) => {
    pendingImageRequests.delete(id);
    activeImageDecodes.delete(id);
    const reservedPixels = imageReservations.get(id);
    if (reservedPixels !== undefined) {
      imageReservations.delete(id);
      retainedImageCount = Math.max(0, retainedImageCount - 1);
      retainedImagePixels = Math.max(0, retainedImagePixels - reservedPixels);
    }
    completeWorkerRequest(id);
    sendWorker({ type: "redevplugin.bridge.response", id, ok: false, error_code: "PLUGIN_CONTRACT_MISMATCH", error: String(error).slice(0, 512) });
  };
  const imageType = (contentType) => String(contentType).split(";", 1)[0].trim().toLowerCase();
  const bytesMatch = (bytes, offset, values) => values.every((value, index) => bytes[offset + index] === value);
  const asciiMatches = (bytes, offset, value) => Array.from(value).every((character, index) => bytes[offset + index] === character.charCodeAt(0));
  const detectRasterImageType = (bytes) => {
    if (bytes.length >= 8 && bytesMatch(bytes, 0, [137, 80, 78, 71, 13, 10, 26, 10])) return "image/png";
    if (bytes.length >= 2 && bytesMatch(bytes, 0, [255, 216])) return "image/jpeg";
    if (bytes.length >= 6 && (asciiMatches(bytes, 0, "GIF87a") || asciiMatches(bytes, 0, "GIF89a"))) return "image/gif";
    if (bytes.length >= 12 && asciiMatches(bytes, 0, "RIFF") && asciiMatches(bytes, 8, "WEBP")) return "image/webp";
    return "";
  };
  const uint16BE = (bytes, offset) => (bytes[offset] << 8) | bytes[offset + 1];
  const uint16LE = (bytes, offset) => bytes[offset] | (bytes[offset + 1] << 8);
  const uint24LE = (bytes, offset) => bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
  const uint32BE = (bytes, offset) => ((bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
  const readImageDimensions = (bytes, contentType) => {
    const type = imageType(contentType);
    let width = 0;
    let height = 0;
    if (type === "image/png") {
      if (bytes.length < 24 || !bytesMatch(bytes, 0, [137, 80, 78, 71, 13, 10, 26, 10]) || !asciiMatches(bytes, 12, "IHDR")) throw new Error("PNG dimensions are invalid");
      width = uint32BE(bytes, 16);
      height = uint32BE(bytes, 20);
    } else if (type === "image/gif") {
      if (bytes.length < 10 || (!asciiMatches(bytes, 0, "GIF87a") && !asciiMatches(bytes, 0, "GIF89a"))) throw new Error("GIF dimensions are invalid");
      width = uint16LE(bytes, 6);
      height = uint16LE(bytes, 8);
    } else if (type === "image/jpeg") {
      if (bytes.length < 4 || !bytesMatch(bytes, 0, [255, 216])) throw new Error("JPEG dimensions are invalid");
      let offset = 2;
      const startOfFrame = new Set([192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207]);
      while (offset + 4 <= bytes.length) {
        if (bytes[offset] !== 255) throw new Error("JPEG marker sequence is invalid");
        while (offset < bytes.length && bytes[offset] === 255) offset += 1;
        const marker = bytes[offset++];
        if (marker === 217 || marker === 218) break;
        if (marker === 1 || (marker >= 208 && marker <= 215)) continue;
        if (offset + 2 > bytes.length) break;
        const length = uint16BE(bytes, offset);
        if (length < 2 || offset + length > bytes.length) throw new Error("JPEG segment length is invalid");
        if (startOfFrame.has(marker)) {
          if (length < 7) throw new Error("JPEG frame dimensions are invalid");
          height = uint16BE(bytes, offset + 3);
          width = uint16BE(bytes, offset + 5);
          break;
        }
        offset += length;
      }
    } else if (type === "image/webp") {
      if (bytes.length < 30 || !asciiMatches(bytes, 0, "RIFF") || !asciiMatches(bytes, 8, "WEBP")) throw new Error("WebP dimensions are invalid");
      if (asciiMatches(bytes, 12, "VP8X")) {
        width = uint24LE(bytes, 24) + 1;
        height = uint24LE(bytes, 27) + 1;
      } else if (asciiMatches(bytes, 12, "VP8L") && bytes[20] === 47) {
        width = 1 + bytes[21] + ((bytes[22] & 63) << 8);
        height = 1 + (bytes[22] >> 6) + (bytes[23] << 2) + ((bytes[24] & 15) << 10);
      } else if (asciiMatches(bytes, 12, "VP8 ") && bytesMatch(bytes, 23, [157, 1, 42])) {
        width = uint16LE(bytes, 26) & 0x3fff;
        height = uint16LE(bytes, 28) & 0x3fff;
      }
    } else {
      throw new Error("plugin raster image type is unsupported");
    }
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width <= 0 || height <= 0 || width > maxImageDimension || height > maxImageDimension) {
      throw new Error("decoded image dimensions exceed the renderer budget");
    }
    return { width, height, pixels: width * height };
  };
  const retainImagePixels = (pixels) => {
    if (!Number.isSafeInteger(pixels) || pixels <= 0 || retainedImageCount >= maxImageCount || retainedImagePixels + pixels > maxImageTotalPixels) {
      throw new Error("decoded image assets exceed the renderer pixel budget");
    }
    retainedImageCount += 1;
    retainedImagePixels += pixels;
  };
  const deliverImageAsset = async (id, assetID, asset) => {
    if (!pendingImageRequests.has(id)) pendingImageRequests.set(id, { assetID, asset });
    const bytes = verifiedAssetBytes.get(asset.binding_id);
    if (!bytes) {
      return;
    }
    if (activeImageDecodes.has(id)) return;
    activeImageDecodes.add(id);
    let image;
    try {
      const rasterType = imageAssetTypes.get(asset.binding_id) || imageType(asset.content_type);
      const dimensions = imageAssetDimensions.get(asset.binding_id) || readImageDimensions(bytes, rasterType);
      retainImagePixels(dimensions.pixels);
      imageReservations.set(id, dimensions.pixels);
      image = await createImageBitmap(new Blob([bytes], { type: rasterType }));
      if (!pendingWorkerRequests.has(id) || !pendingImageRequests.has(id)) {
        image.close();
        const reservedPixels = imageReservations.get(id);
        if (reservedPixels !== undefined) {
          imageReservations.delete(id);
          retainedImageCount = Math.max(0, retainedImageCount - 1);
          retainedImagePixels = Math.max(0, retainedImagePixels - reservedPixels);
        }
        activeImageDecodes.delete(id);
        return;
      }
      if (!image || image.width !== dimensions.width || image.height !== dimensions.height) throw new Error("decoded image dimensions changed after validation");
      pendingImageRequests.delete(id);
      activeImageDecodes.delete(id);
      sendWorkerTransfer({ type: "redevplugin.ui.asset.image.ready", id, asset_id: assetID, image, width: image.width, height: image.height }, [image]);
      imageReservations.delete(id);
      completeWorkerRequest(id);
    } catch (error) {
      try { image && image.close(); } catch {}
      failTransferRequest(id, error && error.message || "plugin image asset could not be decoded");
    }
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
    const declaredType = imageType(asset.content_type);
    const rasterType = detectRasterImageType(bytes);
    if (rasterType || (declaredType.startsWith("image/") && declaredType !== "image/svg+xml")) {
      const validatedType = rasterType || declaredType;
      const dimensions = readImageDimensions(bytes, validatedType);
      retainImagePixels(dimensions.pixels);
      imageAssetDimensions.set(asset.binding_id, dimensions);
      imageAssetTypes.set(asset.binding_id, validatedType);
    }
    verifiedAssetBytes.set(asset.binding_id, bytes);
    const url = URL.createObjectURL(new Blob([bytes], { type: rasterType || asset.content_type }));
    blobURLs.add(url);
    document.documentElement.style.setProperty("--redevplugin-asset-" + asset.binding_id, 'url("' + url.replaceAll('"', '%22') + '")');
    for (const element of document.querySelectorAll('[data-redevplugin-asset-binding="' + asset.binding_id + '"]')) {
      const attribute = element.getAttribute("data-redevplugin-asset-attr");
      if (attribute === "src" || attribute === "poster") element.setAttribute(attribute, url);
      element.removeAttribute("data-redevplugin-asset-binding");
      element.removeAttribute("data-redevplugin-asset-attr");
    }
    for (const [id, pending] of pendingImageRequests) {
      if (pending.asset.binding_id === asset.binding_id) void deliverImageAsset(id, pending.assetID, pending.asset);
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
    'const __rpControlAddEventListener = __rpControlPort.addEventListener.bind(__rpControlPort);',
    'const __rpGetPrototypeOf = Object.getPrototypeOf;',
    'const __rpGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;',
    'const __rpDefineProperty = Object.defineProperty;',
    'const __rpHasOwn = Object.prototype.hasOwnProperty;',
    'const __rpObjectKeys = Object.keys;',
    'const __rpApply = Reflect.apply;',
    'const __rpNumberIsSafeInteger = Number.isSafeInteger.bind(Number);',
    'const __rpOffscreenCanvas = globalThis.OffscreenCanvas;',
    'const __rpCanvasPrototype = __rpOffscreenCanvas && __rpOffscreenCanvas.prototype;',
    'const __rpTrackedCanvases = [];',
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
    'const __rpTrackCanvas = (canvas) => {',
    '    for (let index = 0; index < __rpTrackedCanvases.length; index += 1) if (__rpTrackedCanvases[index] === canvas) return;',
    '    if (__rpTrackedCanvases.length >= ' + JSON.stringify(maxCanvasCount) + ') throw new RangeError("plugin canvas count exceeds the worker budget");',
    '    __rpTrackedCanvases.push(canvas);',
    '};',
    'const __rpInstallCanvasBudget = () => {',
    '    if (!__rpCanvasPrototype) return;',
    '    const widthDescriptor = __rpGetOwnPropertyDescriptor(__rpCanvasPrototype, "width");',
    '    const heightDescriptor = __rpGetOwnPropertyDescriptor(__rpCanvasPrototype, "height");',
    '    const contextDescriptor = __rpGetOwnPropertyDescriptor(__rpCanvasPrototype, "getContext");',
    '    if (!widthDescriptor || !heightDescriptor || typeof widthDescriptor.get !== "function" || typeof widthDescriptor.set !== "function" || typeof heightDescriptor.get !== "function" || typeof heightDescriptor.set !== "function" || !contextDescriptor || typeof contextDescriptor.value !== "function") throw new TypeError("OffscreenCanvas descriptors are unavailable");',
    '    const readWidth = (canvas) => __rpApply(widthDescriptor.get, canvas, []);',
    '    const readHeight = (canvas) => __rpApply(heightDescriptor.get, canvas, []);',
    '    const validateResize = (canvas, axis, value) => {',
    '        if (!__rpNumberIsSafeInteger(value) || value <= 0 || value > ' + JSON.stringify(maxCanvasDimension) + ') throw new RangeError("plugin canvas resize exceeds the worker dimension budget");',
    '        __rpTrackCanvas(canvas);',
    '        let pixels = 0;',
    '        for (let index = 0; index < __rpTrackedCanvases.length; index += 1) {',
    '            const current = __rpTrackedCanvases[index];',
    '            const width = current === canvas && axis === "width" ? value : readWidth(current);',
    '            const height = current === canvas && axis === "height" ? value : readHeight(current);',
    '            pixels += width * height;',
    '            if (pixels > ' + JSON.stringify(maxCanvasTotalPixels) + ') throw new RangeError("plugin canvas resize exceeds the worker pixel budget");',
    '        }',
    '    };',
    '    __rpDefineProperty(__rpCanvasPrototype, "width", { configurable: false, enumerable: Boolean(widthDescriptor.enumerable), get() { return readWidth(this); }, set(value) { validateResize(this, "width", value); __rpApply(widthDescriptor.set, this, [value]); } });',
    '    __rpDefineProperty(__rpCanvasPrototype, "height", { configurable: false, enumerable: Boolean(heightDescriptor.enumerable), get() { return readHeight(this); }, set(value) { validateResize(this, "height", value); __rpApply(heightDescriptor.set, this, [value]); } });',
    '    __rpDefineProperty(__rpCanvasPrototype, "getContext", { configurable: false, enumerable: Boolean(contextDescriptor.enumerable), writable: false, value(type, ...options) { if (type !== "2d") throw new TypeError("only 2d canvas contexts are available"); __rpTrackCanvas(this); return __rpApply(contextDescriptor.value, this, [type, ...options]); } });',
    '    __rpSealDescriptor(__rpCanvasPrototype, "constructor", undefined);',
    '    __rpSealDescriptor(__rpCanvasPrototype, "convertToBlob", __rpBlocked);',
    '    __rpSealDescriptor(__rpCanvasPrototype, "transferToImageBitmap", __rpBlocked);',
    '};',
    'try {',
    '    for (const name of ["postMessage", "start", "close", "addEventListener", "removeEventListener"]) __rpSealMessagePortMethod(name);',
    '    __rpInstallCanvasBudget();',
    '    for (const [name, value] of Object.entries({fetch:__rpBlocked,XMLHttpRequest:undefined,WebSocket:undefined,EventSource:undefined,WebTransport:undefined,Worker:undefined,SharedWorker:undefined,indexedDB:undefined,caches:undefined,RTCPeerConnection:undefined,webkitRTCPeerConnection:undefined,BroadcastChannel:undefined,importScripts:undefined,postMessage:undefined,eval:undefined,Function:undefined,Blob:undefined,File:undefined,FileReader:undefined,FileReaderSync:undefined,OffscreenCanvas:undefined,ImageBitmap:undefined,createImageBitmap:undefined})) __rpSealChain(globalThis, name, value);',
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
    'const __rpControlListener = (event) => {',
    '    const message = event.data;',
    '    if (!message || typeof message !== "object" || Array.isArray(message)) return;',
    '    const keys = __rpObjectKeys(message).sort();',
    '    if (keys.length !== 2 || keys[0] !== "ping_id" || keys[1] !== "type" || message.type !== "redevplugin.worker.ping" || typeof message.ping_id !== "string" || !/^ping_[1-9][0-9]{0,15}$/.test(message.ping_id)) return;',
    '    __rpControlPost({ type: "redevplugin.worker.pong", ping_id: message.ping_id });',
    '};',
    '__rpControlAddEventListener("message", __rpControlListener);',
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
    const match = /^(rpc|stream|stream_ack|render|operation|canvas|asset)_([1-9][0-9]{0,15})$/.exec(value);
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
  const findCanvas = (canvasID) => {
    for (const element of document.querySelectorAll("canvas[data-redevplugin-canvas]")) {
      if (element.getAttribute("data-redevplugin-canvas") === canvasID) return element;
    }
    return undefined;
  };
  const updateCanvasAccessibility = (id, canvasID, label, description) => {
    const runtime = canvasRuntimes.get(canvasID);
    if (!runtime || typeof label !== "string" || label.length < 1 || label.length > 256 || typeof description !== "string" || description.length > 1024) {
      completeWorkerRequest(id);
      return rejectWorkerRequest(id, "plugin canvas accessibility state is invalid");
    }
    if (!runtime.description) {
      const status = document.createElement("span");
      status.id = "redevplugin-canvas-description-" + canvasID.replace(/[^A-Za-z0-9_-]/g, "-");
      status.style.position = "absolute";
      status.style.width = "1px";
      status.style.height = "1px";
      status.style.padding = "0";
      status.style.margin = "-1px";
      status.style.overflow = "hidden";
      status.style.clip = "rect(0, 0, 0, 0)";
      status.style.whiteSpace = "nowrap";
      status.style.border = "0";
      runtime.canvas.insertAdjacentElement("afterend", status);
      runtime.canvas.setAttribute("aria-describedby", status.id);
      runtime.description = status;
    }
    runtime.canvas.setAttribute("aria-label", label);
    runtime.description.textContent = description;
    completeWorkerRequest(id);
    sendWorker({ type: "redevplugin.bridge.response", id, ok: true });
  };
  const canvasMetrics = (canvas) => {
    const rect = canvas.getBoundingClientRect();
    const cssWidth = Math.ceil(rect.width || canvas.width || 1);
    const cssHeight = Math.ceil(rect.height || canvas.height || 1);
    const devicePixelRatio = Math.min(4, Math.max(0.5, Number(globalThis.devicePixelRatio) || 1));
    if (!Number.isSafeInteger(cssWidth) || !Number.isSafeInteger(cssHeight) || cssWidth <= 0 || cssHeight <= 0 || cssWidth > maxCanvasDimension || cssHeight > maxCanvasDimension) {
      throw new Error("plugin canvas dimensions exceed the renderer budget");
    }
    const pixelCount = Math.ceil(cssWidth * devicePixelRatio) * Math.ceil(cssHeight * devicePixelRatio);
    return { cssWidth, cssHeight, devicePixelRatio, pixelCount };
  };
  const openCanvas = (id, canvasID) => {
    const canvas = findCanvas(canvasID);
    if (!canvas || canvasRuntimes.has(canvasID) || typeof canvas.transferControlToOffscreen !== "function" || typeof ResizeObserver !== "function") {
      completeWorkerRequest(id);
      return rejectWorkerRequest(id, "plugin canvas is missing, already transferred, or unsupported");
    }
    if (canvas.tabIndex < 0) canvas.tabIndex = 0;
    let pointerWindowStartedAt = 0;
    let pointerEvents = 0;
    const listeners = [];
    const listen = (type, handler) => {
      canvas.addEventListener(type, handler, { passive: false });
      listeners.push([type, handler]);
    };
    const sendInput = (event) => sendWorker({ type: "redevplugin.ui.canvas.input", canvas_id: canvasID, event });
    const sendResize = () => {
      const metrics = canvasMetrics(canvas);
      const runtime = canvasRuntimes.get(canvasID);
      let totalPixels = metrics.pixelCount;
      for (const [identifier, active] of canvasRuntimes) {
        if (identifier !== canvasID) totalPixels += active.pixelCount;
      }
      if (totalPixels > maxCanvasTotalPixels) throw new Error("plugin canvases exceed the renderer pixel budget");
      if (runtime) runtime.pixelCount = metrics.pixelCount;
      sendInput({ type: "resize", css_width: metrics.cssWidth, css_height: metrics.cssHeight, device_pixel_ratio: metrics.devicePixelRatio });
      return metrics;
    };
    const handlePointer = (event) => {
      const now = performance.now();
      if (now - pointerWindowStartedAt >= 1000) { pointerWindowStartedAt = now; pointerEvents = 0; }
      if (event.type === "pointermove") {
        if (pointerEvents >= maxCanvasPointerEventsPerSecond) return;
        pointerEvents += 1;
      }
      event.preventDefault();
      if (event.type === "pointerdown") {
        try { canvas.focus({ preventScroll: true }); } catch { canvas.focus(); }
        try { canvas.setPointerCapture(event.pointerId); } catch {}
      }
      if (event.type === "pointerup" || event.type === "pointercancel") {
        try { canvas.releasePointerCapture(event.pointerId); } catch {}
      }
      const rect = canvas.getBoundingClientRect();
      sendInput({
        type: "pointer",
        event: event.type,
        pointer_id: Math.max(0, Number.isSafeInteger(event.pointerId) ? event.pointerId : 0),
        pointer_type: ["mouse", "pen", "touch"].includes(event.pointerType) ? event.pointerType : "unknown",
        buttons: Math.min(31, Math.max(0, Number.isSafeInteger(event.buttons) ? event.buttons : 0)),
        button: Math.min(4, Math.max(-1, Number.isSafeInteger(event.button) ? event.button : -1)),
        x: Math.min(32768, Math.max(-16384, event.clientX - rect.left)),
        y: Math.min(32768, Math.max(-16384, event.clientY - rect.top)),
        pressure: Math.min(1, Math.max(0, Number.isFinite(event.pressure) ? event.pressure : 0)),
      });
    };
    const handleKey = (event) => {
      event.preventDefault();
      sendInput({
        type: "key",
        event: event.type,
        code: String(event.code || "").slice(0, 64),
        key: String(event.key || "").slice(0, 64),
        repeat: Boolean(event.repeat),
        alt_key: Boolean(event.altKey),
        ctrl_key: Boolean(event.ctrlKey),
        meta_key: Boolean(event.metaKey),
        shift_key: Boolean(event.shiftKey),
      });
    };
    for (const type of ["pointerdown", "pointermove", "pointerup", "pointercancel"]) listen(type, handlePointer);
    for (const type of ["keydown", "keyup"]) listen(type, handleKey);
    listen("focus", () => sendInput({ type: "focus" }));
    listen("blur", () => sendInput({ type: "blur" }));
    const observer = new ResizeObserver(() => {
      try { sendResize(); }
      catch (error) { fail(error && error.message || "plugin canvas resize exceeded renderer limits"); }
    });
    observer.observe(canvas);
    const runtime = { canvas, description: undefined, dispose: undefined, pixelCount: 0 };
    const dispose = () => {
      observer.disconnect();
      for (const [type, handler] of listeners) canvas.removeEventListener(type, handler);
      runtime.description?.remove();
    };
    runtime.dispose = dispose;
    try {
      const offscreen = canvas.transferControlToOffscreen();
      const metrics = canvasMetrics(canvas);
      let totalPixels = metrics.pixelCount;
      for (const runtime of canvasRuntimes.values()) totalPixels += runtime.pixelCount;
      if (canvasRuntimes.size >= maxCanvasCount || totalPixels > maxCanvasTotalPixels) throw new Error("plugin canvas resources exceed renderer limits");
      runtime.pixelCount = metrics.pixelCount;
      canvasRuntimes.set(canvasID, runtime);
      completeWorkerRequest(id);
      sendWorkerTransfer({ type: "redevplugin.ui.canvas.ready", id, canvas_id: canvasID, canvas: offscreen, css_width: metrics.cssWidth, css_height: metrics.cssHeight, device_pixel_ratio: metrics.devicePixelRatio }, [offscreen]);
      sendResize();
    } catch (error) {
      dispose();
      completeWorkerRequest(id);
      rejectWorkerRequest(id, String(error && error.message || "plugin canvas transfer failed").slice(0, 512));
    }
  };
  const scheduleWorkerHeartbeat = () => {
    if (workerHeartbeatTimer) clearTimeout(workerHeartbeatTimer);
    workerHeartbeatTimer = undefined;
    if (!workerReady || !workerControlPort || workerHeartbeatPendingID) return;
    workerHeartbeatTimer = setTimeout(() => {
      workerHeartbeatTimer = undefined;
      if (!workerReady || !workerControlPort || workerHeartbeatPendingID) return;
      const pingID = "ping_" + (++workerHeartbeatSequence);
      workerHeartbeatPendingID = pingID;
      try {
        workerControlPort.postMessage({ type: "redevplugin.worker.ping", ping_id: pingID });
      } catch {
        fail("plugin worker heartbeat could not be sent");
        return;
      }
      workerHeartbeatTimeout = setTimeout(() => {
        workerHeartbeatTimeout = undefined;
        if (workerHeartbeatPendingID !== pingID) return;
        workerHeartbeatPendingID = undefined;
        fail("plugin worker heartbeat timed out");
      }, workerHeartbeatTimeoutMs);
    }, workerHeartbeatIntervalMs);
  };
  const onWorkerControlMessage = (event) => {
    if (!withinLimit(event.data)) return;
    const message = event.data;
    if (exactKeys(message, ["type"]) && message.type === "redevplugin.worker.ready") {
      if (workerReady) return;
      workerReady = true;
      sendParent({ type: "redevplugin.surface.worker_ready" });
      scheduleWorkerHeartbeat();
      return;
    }
    if (exactKeys(message, ["type", "ping_id"]) && message.type === "redevplugin.worker.pong" && message.ping_id === workerHeartbeatPendingID) {
      if (workerHeartbeatTimeout) clearTimeout(workerHeartbeatTimeout);
      workerHeartbeatTimeout = undefined;
      workerHeartbeatPendingID = undefined;
      scheduleWorkerHeartbeat();
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
    if (exactKeys(message, ["type", "quiesce_id"]) && message.type === "redevplugin.bridge.lifecycle_ack" && validOpaqueHandle(message.quiesce_id, "quiesce") && message.quiesce_id === pendingQuiesceID) {
      pendingQuiesceID = undefined;
      sendParent({ type: "redevplugin.surface.quiesce_ack", quiesce_id: message.quiesce_id });
      terminateQuiescedWorker();
      return;
    }
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
    if (exactKeys(message, ["type", "id", "stream_handle", "delivery_id"]) && message.type === "redevplugin.bridge.stream.ack" &&
        requestID(message.id, "stream_ack") && validOpaqueHandle(message.stream_handle, "stream") && validDeliveryID(message.delivery_id)) {
      if (!acceptWorkerRequest(message.id, "stream_ack")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
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
    if (exactKeys(message, ["type", "id", "canvas_id"]) && message.type === "redevplugin.ui.canvas.open" && typeof message.id === "string" && validResourceIdentifier(message.canvas_id)) {
      if (!acceptWorkerRequest(message.id, "canvas")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      openCanvas(message.id, message.canvas_id);
      return;
    }
    if (exactKeys(message, ["type", "id", "canvas_id", "label", "description"]) && message.type === "redevplugin.ui.canvas.accessibility" && typeof message.id === "string" && validResourceIdentifier(message.canvas_id)) {
      if (!acceptWorkerRequest(message.id, "canvas")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      updateCanvasAccessibility(message.id, message.canvas_id, message.label, message.description);
      return;
    }
    if (exactKeys(message, ["type", "id", "asset_id"]) && message.type === "redevplugin.ui.asset.image.open" && typeof message.id === "string" && validResourceIdentifier(message.asset_id)) {
      if (!acceptWorkerRequest(message.id, "asset")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      const asset = assetByLogicalID.get(message.asset_id);
      if (!asset || !String(asset.content_type).toLowerCase().startsWith("image/") || String(asset.content_type).toLowerCase() === "image/svg+xml") {
        completeWorkerRequest(message.id);
        return rejectWorkerRequest(message.id, "plugin image asset is not declared");
      }
      void deliverImageAsset(message.id, message.asset_id, asset);
      return;
    }
    if (exactKeys(message, ["type", "id", "revision", "tree"]) && message.type === "redevplugin.ui.mount" &&
        typeof message.id === "string" && message.revision === 1) {
      if (!acceptWorkerRequest(message.id, "render")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      if (!renderRateAllowed()) {
        completeWorkerRequest(message.id);
        return rejectWorkerRequest(message.id, "plugin render rate limit exceeded");
      }
      void mountWorkerTree(message.tree).then(() => {
        completeWorkerRequest(message.id);
        sendWorker({ type: "redevplugin.bridge.response", id: message.id, ok: true });
      }, (error) => fail(error && error.message || "plugin UI mount violated the protocol"));
      return;
    }
    if (exactKeys(message, ["type", "id", "base_revision", "revision", "operations"]) && message.type === "redevplugin.ui.patch" &&
        typeof message.id === "string" && Number.isSafeInteger(message.base_revision) && Number.isSafeInteger(message.revision)) {
      if (!acceptWorkerRequest(message.id, "render")) return rejectWorkerRequest(message.id, "duplicate, replayed, or excessive plugin request");
      if (!renderRateAllowed()) {
        completeWorkerRequest(message.id);
        return rejectWorkerRequest(message.id, "plugin render rate limit exceeded");
      }
      void patchWorkerTree(message.base_revision, message.revision, message.operations).then(() => {
        completeWorkerRequest(message.id);
        sendWorker({ type: "redevplugin.bridge.response", id: message.id, ok: true });
      }, (error) => fail(error && error.message || "plugin UI patch violated the protocol"));
      return;
    }
    if (exactKeys(message, ["type", "id"]) && message.type === "redevplugin.bridge.cancel" && typeof message.id === "string") {
      if (!pendingWorkerRequests.has(message.id)) return rejectWorkerRequest(message.id, "plugin request is not pending");
      if (pendingImageRequests.has(message.id)) {
        pendingImageRequests.delete(message.id);
        completeWorkerRequest(message.id);
        return;
      }
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
    if (message && message.type === "redevplugin.bridge.lifecycle" && isRecord(message.event) && ["ready", "visible", "hidden", "dispose"].includes(message.event.type) && Object.keys(message).every((key) => ["type", "event", "quiesce_id"].includes(key)) && (message.quiesce_id === undefined || (message.event.type === "dispose" && validOpaqueHandle(message.quiesce_id, "quiesce")))) {
      pendingQuiesceID = message.quiesce_id;
      sendWorker(message);
      if (message.event.type === "dispose" && !message.quiesce_id) disposeRuntime();
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

class PluginSurfaceHostImplementation implements PluginSurfaceHost {
  readonly element: HTMLIFrameElement;
  readonly surfaceInstanceId: string;
  readonly bootstrap: PluginSurfaceHostBootstrap;
  readonly bridgeChannelId: string;
  readonly frameGenerationId: string;
  readonly surfaceHandle: string;
  #iframe: PluginSurfaceFrameLike;
  #transport: ReDevPluginSurfaceTransportInternals;
  #createMessageChannel: () => MessageChannelLike;
  #bridgeReady = false;
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
  #quiesce?: SurfaceQuiesce;
  #initialFrameLoad?: Deferred<void>;
  #frameLoaded = false;
  #closePromise?: Promise<PluginSurfaceCloseResult>;
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

  constructor(
    options: PluginSurfaceHostOptions,
    transport: ReDevPluginSurfaceTransportInternals,
    iframe: HTMLIFrameElement,
  ) {
    this.element = iframe;
    this.bootstrap = options.bootstrap;
    this.surfaceInstanceId = options.bootstrap.surfaceInstanceId;
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
        this.#reportOpeningProgress({
          phase: "opening",
          elapsedMs: Math.max(openingProgressDelayMs, Date.now() - startedAt),
        });
      }
    }, openingProgressDelayMs);
    const signals: OpenSignals = {
      portAcknowledged: deferred<void>(),
      firstPaint: deferred<void>(),
      workerReady: deferred<void>(),
      firstCommit: deferred<void>(),
    };
    void signals.portAcknowledged.promise.catch(() => undefined);
    void signals.firstPaint.promise.catch(() => undefined);
    void signals.workerReady.promise.catch(() => undefined);
    void signals.firstCommit.promise.catch(() => undefined);
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
      const revoke = this.#revokeSurface(false);
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
    this.#bridgeReady = true;
    this.#scheduleLeaseRenewal();
    this.#postToRenderer({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } });

    await signals.firstCommit.promise;
    this.#assertActive();
    this.#ready = true;
    this.#reloadLimiter.recordHealthyLoad();
  }

  sendLifecycle(event: Exclude<BridgeLifecycleEvent, { type: "ready" | "dispose" }>): void {
    this.#assertReady();
    this.#postToRenderer({ type: "redevplugin.bridge.lifecycle", event });
  }

  close(): Promise<PluginSurfaceCloseResult> {
    if (this.#disposed) {
      const result: PluginSurfaceCloseResult = {
        quiesce: { outcome: "not_ready", durationMs: 0 },
        revokeDurationMs: 0,
        totalDurationMs: 0,
      };
      return this.#revokePromise ? this.#revokePromise.then(() => result) : Promise.resolve(result);
    }
    if (this.#closePromise) return this.#closePromise;
    this.#closePromise = this.#closeSurface();
    return this.#closePromise;
  }

  dispose(): Promise<void> {
    if (this.#disposed) return this.#revokePromise ?? Promise.resolve();
    const revoke = this.#revokeSurface(true);
    void revoke.catch(() => undefined);
    this.#disposeLocal();
    return revoke;
  }

  async #closeSurface(): Promise<PluginSurfaceCloseResult> {
    const startedAt = performance.now();
    const quiesce = await this.#quiesceSurface();
    if (this.#disposed) {
      return { quiesce, revokeDurationMs: 0, totalDurationMs: performance.now() - startedAt };
    }
    const revokeStartedAt = performance.now();
    const revoke = this.#revokeSurface(false);
    this.#disposeLocal();
    try {
      await revoke;
    } catch (error) {
      throw toBridgeError(error, "PLUGIN_BRIDGE_DISPOSED");
    }
    return {
      quiesce,
      revokeDurationMs: performance.now() - revokeStartedAt,
      totalDurationMs: performance.now() - startedAt,
    };
  }

  #disposeLocal(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#unregisterSurfaceScope?.();
    this.#unregisterSurfaceScope = undefined;
    this.#ready = false;
    this.#bridgeReady = false;
    if (this.#leaseRenewalTimer) clearTimeout(this.#leaseRenewalTimer);
    this.#leaseRenewalTimer = undefined;
    this.#iframe.removeEventListener("load", this.#onFrameLoad);
    this.#abortController.abort();
    for (const controller of this.#pendingRequestControllers.values()) controller.abort();
    this.#pendingRequestControllers.clear();
    const disposedError = new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "Plugin surface host was disposed");
    this.#openSignals?.firstPaint.reject(disposedError);
    this.#openSignals?.workerReady.reject(disposedError);
    this.#openSignals?.firstCommit.reject(disposedError);
    this.#openSignals?.portAcknowledged.reject(disposedError);
    this.#initialFrameLoad?.reject(disposedError);
    this.#quiesce?.acknowledged.reject(disposedError);
    this.#quiesce = undefined;
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
      if (hasExactKeys(data, ["type"]) && data.type === "redevplugin.surface.first_commit") {
        this.#openSignals?.firstCommit.resolve();
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
      if (isStreamReadMessage(data)) {
        await this.#handleStreamRead(data.id, data.stream_handle);
        return;
      }
      if (isStreamAcknowledgeMessage(data)) {
        await this.#handleStreamAcknowledge(data.id, data.stream_handle, data.delivery_id);
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
      this.#pendingRequestControllers.delete(request.id);
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

  async #handleStreamRead(id: string, streamHandle: string): Promise<void> {
    const credential = this.#streamCredentials.get(streamHandle);
    if (!credential || credential.completed || credential.reading || credential.acknowledging) {
      this.#postError(id, "PLUGIN_STREAM_TICKET_INVALID", "Plugin stream handle is invalid, completed, or busy");
      return;
    }
    if (credential.expiresAtMs <= Date.now()) {
      this.#postError(id, "PLUGIN_STREAM_TICKET_INVALID", "Plugin stream handle is expired");
      return;
    }
    if (credential.pending) {
      this.#postResponse(id, credential.pending.response);
      return;
    }
    credential.reading = true;
    const controller = this.#registerPendingRequest(id);
    try {
      const readPath = `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/streams/read`;
      const readBody = (): unknown => ({ stream_id: credential.streamID, stream_ticket: credential.streamTicket, read_id: credential.readID });
      let result: PluginSurfaceStreamReadResult;
      try {
        result = await this.#postJSON<PluginSurfaceStreamReadResult>(readPath, readBody, controller.signal);
      } catch (error) {
        if (!retryableStreamReadTransportFailure(error) || controller.signal.aborted || this.#disposed) throw error;
        result = await this.#postJSON<PluginSurfaceStreamReadResult>(readPath, readBody, controller.signal);
      }
      if (!isStreamReadResult(result, credential.streamID, credential.readID, credential.lastSequence)) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin stream endpoint returned an invalid response");
      }
      const lastSequence = result.events.length > 0 ? result.events[result.events.length - 1].sequence : credential.lastSequence;
      const events = result.events.map(publicPluginStreamEvent);
      const response: PrivatePluginStreamReadResult = result.done
        ? { delivery_id: result.delivery_id, events, done: true, terminal_status: result.terminal_status!, retry_after_ms: 0 }
        : { delivery_id: result.delivery_id, events, done: false, retry_after_ms: events.length === 0 ? 25 : 0 };
      if (result.delivery_id) {
        credential.pending = {
          deliveryID: result.delivery_id,
          lastSequence,
          done: result.done,
          response,
        };
      }
      credential.reading = false;
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(id, response);
    } catch (error) {
      const bridgeError = toBridgeError(error, "PLUGIN_RUNTIME_UNAVAILABLE");
      if (streamReadFailureInvalidatesCredential(bridgeError)) {
        this.#streamCredentials.delete(streamHandle);
      } else {
        credential.reading = false;
      }
      if (controller.signal.aborted || this.#disposed) return;
      this.#postError(id, bridgeError.errorCode, bridgeError.message);
    } finally {
      this.#pendingRequestControllers.delete(id);
    }
  }

  async #handleStreamAcknowledge(id: string, streamHandle: string, deliveryID: string): Promise<void> {
    const credential = this.#streamCredentials.get(streamHandle);
    if (!credential || credential.reading || credential.acknowledging) {
      this.#postError(id, "PLUGIN_STREAM_DELIVERY_INVALID", "Plugin stream delivery is invalid or busy", undefined, "not_committed");
      return;
    }
    if (credential.lastAcknowledgedDeliveryID === deliveryID) {
      this.#postResponse(id, undefined);
      return;
    }
    if (!credential.pending || credential.pending.deliveryID !== deliveryID) {
      this.#postError(id, "PLUGIN_STREAM_DELIVERY_INVALID", "Plugin stream delivery does not match the pending batch", undefined, "not_committed");
      return;
    }
    credential.acknowledging = true;
    const controller = this.#registerPendingRequest(id);
    try {
      const result = await this.#postMutationJSON<PluginSurfaceStreamAcknowledgementResult>(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/streams/ack`,
        () => ({
          stream_id: credential.streamID,
          stream_ticket: credential.streamTicket,
          delivery_id: deliveryID,
        }),
        controller.signal,
      );
      if (!hasExactKeys(result, ["acknowledged"]) || result.acknowledged !== true) {
        throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin stream acknowledgement endpoint returned an invalid response", undefined, undefined, "unknown");
      }
      const pending = credential.pending;
      credential.lastAcknowledgedDeliveryID = deliveryID;
      credential.lastSequence = pending.lastSequence;
      credential.pending = undefined;
      credential.readID = randomOpaqueHandle("read");
      credential.completed = pending.done;
      credential.acknowledging = false;
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(id, undefined);
    } catch (error) {
      credential.acknowledging = false;
      if (controller.signal.aborted || this.#disposed) return;
      const bridgeError = toBridgeError(error, "PLUGIN_STREAM_DELIVERY_INVALID");
      this.#postError(id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
    } finally {
      this.#pendingRequestControllers.delete(id);
    }
  }

  async #handleOperationCancel(message: { id: string; operation_id: string; reason?: string }): Promise<void> {
    const controller = this.#registerPendingRequest(message.id);
    try {
      await this.#postMutationJSON(
        `/_redevplugin/api/plugins/surfaces/${encodeURIComponent(this.bootstrap.surfaceInstanceId)}/operations/cancel`,
        { operation_id: message.operation_id, bridge_channel_id: this.bridgeChannelId, reason: message.reason },
        controller.signal,
      );
      this.#releaseOperationStreams(message.operation_id);
      if (!controller.signal.aborted && !this.#disposed) this.#postResponse(message.id, undefined);
	    } catch (error) {
	      if (controller.signal.aborted || this.#disposed) return;
	      const bridgeError = toBridgeError(error, "PLUGIN_OPERATION_BLOCKED");
	      this.#postError(message.id, bridgeError.errorCode, bridgeError.message, bridgeError.details, bridgeError.mutationOutcome);
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
        readID: randomOpaqueHandle("read"),
        reading: false,
        acknowledging: false,
        completed: false,
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
    return this.#postMutationJSON<PluginTrustedMethodResult>("/_redevplugin/api/plugins/rpc", () => this.#rpcBody(request, confirmationID), signal);
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
      ui_protocol_version: pluginUIProtocolVersion,
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
    if (this.#disposed || this.#leaseRenewAtMs <= 0) return;
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

  #revokeSurface(keepalive: boolean): Promise<void> {
    if (this.#revokePromise) return this.#revokePromise;
    this.#revokePromise = revokeSurfaceBootstrap(
      this.#transport,
      this.bootstrap,
      this.#requestTimeoutMs,
      keepalive,
    );
    return this.#revokePromise;
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
      this.#postToRenderer({
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
    this.#ready = false;
    this.#bridgeReady = false;
    this.#openSignals?.firstPaint.reject(error);
    this.#openSignals?.workerReady.reject(error);
    this.#reportError(error);
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
    this.#postToRenderer(response);
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
      this.#postToRenderer(removeUndefined({
        type: "redevplugin.bridge.response",
        id,
        ok: false,
        error_code: "PLUGIN_JSON_LIMIT_EXCEEDED",
        error: "Plugin error response exceeds the bridge message limit",
        mutation_outcome: mutationOutcome,
      }));
      return;
    }
    this.#postToRenderer(response);
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
    revoke() {
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
  unregister = registerPluginSurface(request.surfaceScope, request.pluginInstanceId, () => lease.cancel());
  try {
    lease.options = Promise.resolve(request.open());
  } catch (error) {
    lease.options = Promise.reject(error);
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
      if (!this.#disposed && this.#transitionController === controller && !controller.signal.aborted) {
        this.#setState("error", toBridgeError(error, "PLUGIN_BRIDGE_HANDSHAKE_FAILED"));
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
    this.#adoptOpening(lease);
    this.#opening = host;
    setSurfaceInteractive(host.element, false);
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
      setSurfaceInteractive(host.element, true);
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

  async close(): Promise<PluginSurfaceCloseResult | undefined> {
    this.#assertActive();
    this.#transitionController?.abort();
    this.#transitionController = undefined;
    this.#setState("empty");
    const closing = this.#tail.then(() => this.#closeCurrentSurface());
    this.#tail = closing.then(
      () => undefined,
      (error) => error instanceof PluginSurfaceCleanupError ? Promise.reject(error) : undefined,
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
    const disposal = this.#tail.then(async () => {
      await this.#closeCurrentSurface();
    });
    this.#disposePromise = this.#unwrapCleanupError(disposal);
    void this.#disposePromise.catch(() => undefined);
    this.#tail = disposal.then(
      () => undefined,
      (error) => error instanceof PluginSurfaceCleanupError ? Promise.reject(error) : undefined,
    );
    void this.#tail.catch(() => undefined);
    return this.#disposePromise;
  }

  async #closeCurrentSurface(): Promise<PluginSurfaceCloseResult | undefined> {
    const hosts = new Set([this.#active, this.#opening].filter((host): host is PluginSurfaceHostImplementation => host !== undefined));
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
    setSurfaceInteractive(host.element, false);
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

function setSurfaceInteractive(element: HTMLIFrameElement, interactive: boolean): void {
  element.hidden = !interactive;
  element.inert = !interactive;
  element.setAttribute("aria-hidden", interactive ? "false" : "true");
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
  if (!Number.isSafeInteger(bootstrap.managementRevision) || bootstrap.managementRevision < 1 ||
      !Number.isSafeInteger(bootstrap.revokeEpoch) || bootstrap.revokeEpoch < 1) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface revision is invalid");
  }
}

function validateSurfacePreparation(bootstrap: PluginSurfaceHostBootstrap, preparation: PluginSurfacePreparationResult): void {
  if (!isSurfacePreparationResult(preparation)) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Plugin surface prepare returned an invalid opaque document");
  }
  if (preparation.management_revision !== bootstrap.managementRevision || preparation.revoke_epoch !== bootstrap.revokeEpoch) {
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
  const logicalIDs = new Set<string>();
  for (const asset of value.assets) {
    if (!hasExactKeys(asset, ["binding_id", "logical_ids", "path", "sha256", "size", "content_type"]) ||
        !validOpaqueHandle(asset.binding_id, "asset") || !validPackagePath(asset.path) || !validSHA256(asset.sha256) ||
        !Array.isArray(asset.logical_ids) || asset.logical_ids.length < 1 || asset.logical_ids.length > 16 ||
        asset.logical_ids.some((logicalID) => !validUIIdentifier(logicalID) || logicalIDs.has(logicalID)) ||
        !Number.isSafeInteger(asset.size) || Number(asset.size) < 0 || Number(asset.size) > maxOpaqueSurfaceLazyBytes ||
        typeof asset.content_type !== "string" || asset.content_type.length < 1 || asset.content_type.length > 256) {
      return false;
    }
    for (const logicalID of asset.logical_ids) logicalIDs.add(logicalID);
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

function isStreamAcknowledgeMessage(value: unknown): value is { type: "redevplugin.bridge.stream.ack"; id: string; stream_handle: string; delivery_id: string } {
  return hasExactKeys(value, ["type", "id", "stream_handle", "delivery_id"]) &&
    value.type === "redevplugin.bridge.stream.ack" &&
    validBridgeRequestID(value.id, "stream_ack") &&
    validOpaqueHandle(value.stream_handle, "stream") &&
    validDeliveryID(value.delivery_id);
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
      !Object.keys(value).every((key) => ["type", "id", "ok", "error_code", "error", "error_details", "mutation_outcome"].includes(key)) ||
      (value.mutation_outcome !== undefined && value.mutation_outcome !== "not_committed" && value.mutation_outcome !== "unknown")) {
    return false;
  }
  if (value.error_code === "PLUGIN_CAPABILITY_ERROR") return isCapabilityBusinessErrorDetails(value.error_details);
  if (value.error_code === "PLUGIN_WORKER_ERROR") return isWorkerErrorDetails(value.error_details);
  if (value.error_details === undefined) return true;
  try {
    return Object.keys(normalizePluginJSONObject(value.error_details)).length <= 8;
  } catch {
    return false;
  }
}

function validCanvasAccessibilityState(value: unknown): value is PluginCanvasAccessibilityState {
  return hasExactKeys(value, ["label", "description"]) &&
    typeof value.label === "string" && value.label.length > 0 && value.label.length <= 256 &&
    typeof value.description === "string" && value.description.length <= 1024;
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
  return hasAllowedKeys(value, ["type", "event", "quiesce_id"]) &&
    value.type === "redevplugin.bridge.lifecycle" &&
    hasExactKeys(value.event, ["type"]) &&
    (value.event.type === "ready" || value.event.type === "visible" || value.event.type === "hidden" || value.event.type === "dispose") &&
    (value.quiesce_id === undefined || (value.event.type === "dispose" && validOpaqueHandle(value.quiesce_id, "quiesce")));
}

type PluginUIActionMessage = {
  type: "redevplugin.ui.action";
  action: string;
  event: PluginUIActionEvent["event"];
  target_key: string;
  edit_revision: number;
  is_composing: boolean;
  value?: string;
  checked?: boolean;
  form_data?: Record<string, string>;
};

function isActionMessage(value: unknown): value is PluginUIActionMessage {
  return hasAllowedKeys(value, ["type", "action", "event", "target_key", "edit_revision", "is_composing", "value", "checked", "form_data"]) &&
    value.type === "redevplugin.ui.action" &&
    validActionID(value.action) &&
    (value.event === "click" || value.event === "input" || value.event === "change" || value.event === "submit" || value.event === "escape") &&
    validUIIdentifier(value.target_key) && Number.isSafeInteger(value.edit_revision) && Number(value.edit_revision) >= 0 &&
    typeof value.is_composing === "boolean" &&
    (value.value == null || (typeof value.value === "string" && value.value.length <= 65536)) &&
    (value.checked == null || typeof value.checked === "boolean") &&
    (value.form_data == null || (isRecord(value.form_data) && Object.entries(value.form_data).every(([key, item]) => validActionID(key) && typeof item === "string" && item.length <= 65536)));
}

function publicActionEvent(value: PluginUIActionMessage): PluginUIActionEvent {
  return removeUndefined({
    action: value.action,
    event: value.event,
    targetKey: value.target_key,
    editRevision: value.edit_revision,
    isComposing: value.is_composing,
    value: value.value,
    checked: value.checked,
    form_data: value.form_data,
  });
}

type PluginCanvasReadyMessage = {
  type: "redevplugin.ui.canvas.ready";
  id: string;
  canvas_id: string;
  canvas: OffscreenCanvas;
  css_width: number;
  css_height: number;
  device_pixel_ratio: number;
};

type PluginImageReadyMessage = {
  type: "redevplugin.ui.asset.image.ready";
  id: string;
  asset_id: string;
  image: ImageBitmap;
  width: number;
  height: number;
};

function isCanvasReadyCandidate(value: unknown): value is { type: "redevplugin.ui.canvas.ready"; id: string; canvas_id: string } & Record<string, unknown> {
  return isRecord(value) && value.type === "redevplugin.ui.canvas.ready" && typeof value.id === "string" && typeof value.canvas_id === "string";
}

function isCanvasReadyMessage(value: unknown): value is PluginCanvasReadyMessage {
  return hasExactKeys(value, ["type", "id", "canvas_id", "canvas", "css_width", "css_height", "device_pixel_ratio"]) &&
    value.type === "redevplugin.ui.canvas.ready" && validBridgeRequestID(value.id, "canvas") && validUIIdentifier(value.canvas_id) &&
    isOffscreenCanvasLike(value.canvas) && validSurfaceDimension(value.css_width) && validSurfaceDimension(value.css_height) &&
    validDevicePixelRatio(value.device_pixel_ratio);
}

function isImageReadyCandidate(value: unknown): value is { type: "redevplugin.ui.asset.image.ready"; id: string; asset_id: string } & Record<string, unknown> {
  return isRecord(value) && value.type === "redevplugin.ui.asset.image.ready" && typeof value.id === "string" && typeof value.asset_id === "string";
}

function isImageReadyMessage(value: unknown): value is PluginImageReadyMessage {
  return hasExactKeys(value, ["type", "id", "asset_id", "image", "width", "height"]) &&
    value.type === "redevplugin.ui.asset.image.ready" && validBridgeRequestID(value.id, "asset") && validUIIdentifier(value.asset_id) &&
    isImageBitmapLike(value.image) && Number.isInteger(value.width) && Number(value.width) > 0 && Number(value.width) <= opaqueSurfaceRenderLimits.max_image_dimension &&
    Number.isInteger(value.height) && Number(value.height) > 0 && Number(value.height) <= opaqueSurfaceRenderLimits.max_image_dimension &&
    value.image.width === value.width && value.image.height === value.height;
}

function publicCanvasInputMessage(value: unknown): { canvasId: string; event: PluginCanvasInputEvent } | undefined {
  if (!hasExactKeys(value, ["type", "canvas_id", "event"]) || value.type !== "redevplugin.ui.canvas.input" ||
      !validUIIdentifier(value.canvas_id) || !isRecord(value.event)) return undefined;
  const event = value.event;
  if (hasExactKeys(event, ["type"]) && (event.type === "focus" || event.type === "blur")) {
    return { canvasId: value.canvas_id, event: { type: event.type } };
  }
  if (hasExactKeys(event, ["type", "css_width", "css_height", "device_pixel_ratio"]) && event.type === "resize" &&
      validSurfaceDimension(event.css_width) && validSurfaceDimension(event.css_height) && validDevicePixelRatio(event.device_pixel_ratio)) {
    return {
      canvasId: value.canvas_id,
      event: { type: "resize", cssWidth: event.css_width, cssHeight: event.css_height, devicePixelRatio: event.device_pixel_ratio },
    };
  }
  if (hasExactKeys(event, ["type", "event", "code", "key", "repeat", "alt_key", "ctrl_key", "meta_key", "shift_key"]) &&
      event.type === "key" && (event.event === "keydown" || event.event === "keyup") &&
      typeof event.code === "string" && event.code.length <= 64 && typeof event.key === "string" && event.key.length <= 64 &&
      typeof event.repeat === "boolean" && typeof event.alt_key === "boolean" && typeof event.ctrl_key === "boolean" &&
      typeof event.meta_key === "boolean" && typeof event.shift_key === "boolean") {
    return {
      canvasId: value.canvas_id,
      event: {
        type: "key",
        event: event.event,
        code: event.code,
        key: event.key,
        repeat: event.repeat,
        altKey: event.alt_key,
        ctrlKey: event.ctrl_key,
        metaKey: event.meta_key,
        shiftKey: event.shift_key,
      },
    };
  }
  if (hasExactKeys(event, ["type", "event", "pointer_id", "pointer_type", "buttons", "button", "x", "y", "pressure"]) &&
      event.type === "pointer" && ["pointerdown", "pointermove", "pointerup", "pointercancel"].includes(String(event.event)) &&
      Number.isInteger(event.pointer_id) && Number(event.pointer_id) >= 0 &&
      ["mouse", "pen", "touch", "unknown"].includes(String(event.pointer_type)) &&
      Number.isInteger(event.buttons) && Number(event.buttons) >= 0 && Number(event.buttons) <= 31 &&
      Number.isInteger(event.button) && Number(event.button) >= -1 && Number(event.button) <= 4 &&
      validCanvasCoordinate(event.x) && validCanvasCoordinate(event.y) &&
      typeof event.pressure === "number" && Number.isFinite(event.pressure) && event.pressure >= 0 && event.pressure <= 1) {
    return {
      canvasId: value.canvas_id,
      event: {
        type: "pointer",
        event: event.event as PluginCanvasPointerEvent["event"],
        pointerId: Number(event.pointer_id),
        pointerType: event.pointer_type as PluginCanvasPointerEvent["pointerType"],
        buttons: Number(event.buttons),
        button: Number(event.button),
        x: event.x,
        y: event.y,
        pressure: event.pressure,
      },
    };
  }
  return undefined;
}

function isOffscreenCanvasLike(value: unknown): value is OffscreenCanvas {
  return isRecord(value) && Number.isInteger(value.width) && Number(value.width) > 0 && Number(value.width) <= opaqueSurfaceRenderLimits.max_canvas_dimension &&
    Number.isInteger(value.height) && Number(value.height) > 0 && Number(value.height) <= opaqueSurfaceRenderLimits.max_canvas_dimension && typeof value.getContext === "function";
}

function isImageBitmapLike(value: unknown): value is ImageBitmap {
  return isRecord(value) && Number.isInteger(value.width) && Number(value.width) > 0 && Number(value.width) <= opaqueSurfaceRenderLimits.max_image_dimension &&
    Number.isInteger(value.height) && Number(value.height) > 0 && Number(value.height) <= opaqueSurfaceRenderLimits.max_image_dimension && typeof value.close === "function";
}

function validSurfaceDimension(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 && value <= opaqueSurfaceRenderLimits.max_canvas_dimension;
}

function validDevicePixelRatio(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0.5 && value <= 4;
}

function validCanvasCoordinate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= -16384 && value <= 32768;
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

function isStreamReadResult(value: unknown, expectedStreamID: string, expectedReadID: string, previousSequence: number): value is PluginSurfaceStreamReadResult {
  if (!isRecord(value) || typeof value.done !== "boolean" || !Array.isArray(value.events)) return false;
  const hasDelivery = value.events.length > 0 || value.done;
  const expectedKeys = value.done
    ? ["delivery_id", "done", "events", "read_id", "terminal_status"]
    : hasDelivery
      ? ["delivery_id", "done", "events", "read_id"]
      : ["done", "events", "read_id"];
  if (!hasExactKeys(value, expectedKeys)) return false;
  if (value.read_id !== expectedReadID || (hasDelivery && !validDeliveryID(value.delivery_id))) return false;
  if (value.done) {
    if (!validPluginStreamTerminalStatus(value.terminal_status)) return false;
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
const pluginUIIdentifierPattern = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
const opaqueHandlePattern = new RegExp("^[-A-Za-z0-9_]{8,160}$");
const bridgeRequestIDPattern = /^(rpc|stream|stream_ack|render|operation|canvas|asset)_([1-9][0-9]{0,15})$/;

function validBridgeRequestID(value: unknown, expectedKind?: "rpc" | "stream" | "stream_ack" | "render" | "operation" | "canvas" | "asset"): value is string {
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

function validOpaqueHandle(value: unknown, prefix: string): value is string {
  return typeof value === "string" && value.startsWith(`${prefix}_`) && opaqueHandlePattern.test(value);
}

function validDeliveryID(value: unknown): value is string {
  return typeof value === "string" && /^delivery_[A-Za-z0-9_-]{8,128}$/.test(value);
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

function abortableStreamRead(
  read: Promise<PluginStreamReadResult>,
  signal?: AbortSignal,
): Promise<PluginStreamReadResult> {
  if (!signal) return read;
  if (signal.aborted) return Promise.reject(streamReadAbortedError());
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback: (value: never) => void, value: unknown): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback(value as never);
    };
    const onAbort = (): void => finish(reject, streamReadAbortedError());
    signal.addEventListener("abort", onAbort, { once: true });
    read.then(
      (value) => finish(resolve, value),
      (error: unknown) => finish(reject, error),
    );
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

function streamReadFailureInvalidatesCredential(error: unknown): boolean {
  if (!(error instanceof PluginBridgeError)) return true;
  return streamCredentialInvalidatingErrorCodes.has(error.errorCode);
}

function retryableStreamReadTransportFailure(error: unknown): boolean {
  return error instanceof PluginTransportError ||
    (error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_TIMEOUT");
}
