export type BridgeLifecycleEvent =
  | { type: "ready" }
  | { type: "visible" }
  | { type: "hidden" }
  | { type: "dispose" };

export type PluginBridgeHandshake = {
  type: "redeven.plugin.handshake";
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
  | { type: "redeven.plugin.response"; id: string; ok: true; data?: unknown }
  | { type: "redeven.plugin.response"; id: string; ok: false; error_code: string; error: string };

export type PluginBridgeCallMessage = {
  type: "redeven.plugin.call";
  request: PluginBridgeRequest;
};

export type PluginBridgeLifecycleMessage = {
  type: "redeven.plugin.lifecycle";
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
};

export class PluginBridgeError extends Error {
  readonly errorCode: string;

  constructor(errorCode: string, message: string) {
    super(message);
    this.name = "PluginBridgeError";
    this.errorCode = errorCode;
  }
}

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
      type: "redeven.plugin.handshake",
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
    const message: PluginBridgeCallMessage = { type: "redeven.plugin.call", request };
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

function normalizeTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs == null) {
    return 30_000;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive finite number");
  }
  return timeoutMs;
}

function isBridgeResponse(value: unknown): value is PluginBridgeResponse {
  if (!isRecord(value) || value.type !== "redeven.plugin.response" || typeof value.id !== "string") {
    return false;
  }
  if (value.ok === true) {
    return true;
  }
  return value.ok === false && typeof value.error_code === "string" && typeof value.error === "string";
}

function isLifecycleMessage(value: unknown): value is PluginBridgeLifecycleMessage {
  if (!isRecord(value) || value.type !== "redeven.plugin.lifecycle" || !isRecord(value.event)) {
    return false;
  }
  return value.event.type === "ready" || value.event.type === "visible" || value.event.type === "hidden" || value.event.type === "dispose";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
