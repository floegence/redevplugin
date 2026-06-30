export type BridgeLifecycleEvent =
  | { type: "ready" }
  | { type: "visible" }
  | { type: "hidden" }
  | { type: "dispose" };

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

  constructor(errorCode: string, message: string) {
    super(message);
    this.name = "PluginBridgeError";
    this.errorCode = errorCode;
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

export type PluginConfirmationResult = {
  confirmation_token: string;
  confirmation_token_id: string;
  request_hash: string;
  expires_at?: string;
};

type HostEnvelope<T> =
  | { ok: true; data?: T }
  | { ok: false; error?: string; error_code?: string };

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
      const result = await this.#callRPC(request, confirmation.confirmation_token);
      this.#postToIframe({ type: "redevplugin.bridge.response", id: request.id, ok: true, data: result });
    } catch (error) {
      const bridgeError = toBridgeError(error, "PLUGIN_PERMISSION_DENIED");
      this.#postError(request.id, bridgeError.errorCode, bridgeError.message);
    }
  }

  #callRPC(request: PluginBridgeRequest, confirmationToken?: string): Promise<PluginMethodResult> {
    return this.#postJSON<PluginMethodResult>(`/_redevplugin/api/plugins/rpc`, this.#rpcBody(request, confirmationToken));
  }

  #prepareConfirmation(request: PluginBridgeRequest): Promise<PluginConfirmationResult> {
    return this.#postJSON<PluginConfirmationResult>(`/_redevplugin/api/plugins/confirm`, this.#rpcBody(request));
  }

  #rpcBody(request: PluginBridgeRequest, confirmationToken?: string): Record<string, unknown> {
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
    if (confirmationToken) {
      body.confirmation_token = confirmationToken;
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
    const raw = await response.json();
    if (!isHostEnvelope(raw)) {
      throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin platform endpoint returned an invalid envelope with HTTP ${response.status}`);
    }
    if (!raw.ok) {
      const errorCode = raw.error_code ?? "PLUGIN_PERMISSION_DENIED";
      const message = raw.error ?? `Plugin platform endpoint failed with HTTP ${response.status}`;
      if (errorCode === "PLUGIN_CONFIRMATION_REQUIRED") {
        throw new PluginConfirmationRequiredError(errorCode, message);
      }
      throw new PluginBridgeError(errorCode, message);
    }
    return raw.data as T;
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

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs == null) {
    return 30_000;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive finite number");
  }
  return timeoutMs;
}

function defaultFetch(): FetchLike {
  const fetchLike = (globalThis as { fetch?: FetchLike }).fetch;
  if (!fetchLike) {
    throw new Error("fetch is required when globalThis.fetch is unavailable");
  }
  return fetchLike.bind(globalThis) as FetchLike;
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
  return value.error == null || typeof value.error === "string";
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
