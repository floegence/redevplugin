import { PluginBridgeClient, type MessagePortLike, type MessageEventLike, type PluginJSONObject, type PluginSurfaceContext, type PluginBridgeClientOptions, type PluginBridgeClock } from "./surface.js";
import { PluginBridgeError } from "./errors.js";

/** Business/bridge fixture only. It does not certify Host permissions or WASM execution. */
export type PluginTestCall = {
  method: string;
  input?: PluginJSONObject;
  cancelled: boolean;
  resolve(value: unknown): void;
  reject(error: Error): void;
};
export type PluginTestHarnessOptions = {
  context?: PluginSurfaceContext;
  clock?: PluginBridgeClock;
  call?: (method: string, input?: PluginJSONObject) => unknown | Promise<unknown>;
};

class FixturePort implements MessagePortLike {
  listeners = new Set<(event: MessageEventLike) => void>();
  closed = false;
  constructor(readonly dispatch: (message: unknown) => void) {}
  postMessage(message: unknown): void { if (this.closed) throw new Error("Fixture port is closed"); queueMicrotask(() => { if (!this.closed) this.dispatch(message); }); }
  addEventListener(_type: "message", listener: (event: MessageEventLike) => void): void { this.listeners.add(listener); }
  removeEventListener(_type: "message", listener: (event: MessageEventLike) => void): void { this.listeners.delete(listener); }
  start(): void {}
  close(): void { this.closed = true; this.listeners.clear(); }
  emit(data: unknown): void { if (!this.closed) for (const listener of this.listeners) listener({ origin: "null", data }); }
}

export function createPluginTestContext(languageTag = "en-US", revision = 1): PluginSurfaceContext {
  return { schema_version: "redevplugin.surface_context.v1", revision, appearance: { color_scheme: "dark", colors: {
    canvas: "#101010", surface: "#181818", surface_elevated: "#202020", text: "#ffffff", text_muted: "#aaaaaa", border: "#444444", accent: "#66aaff", accent_text: "#000000", success: "#44cc88", warning: "#ffcc44", danger: "#ff6677", focus: "#88bbff",
  } }, locale: { language_tag: languageTag, direction: "ltr" } };
}

/** A deterministic transport adapter around the actual production bridge client. */
export function createPluginTestHarness(options: PluginTestHarnessOptions = {}) {
  const calls: PluginTestCall[] = [], pending = new Map<string, PluginTestCall>();
  const clients = new Set<PluginBridgeClient>();
  let disposed = false;
  let context = options.context ?? createPluginTestContext();
  const port = new FixturePort(message => {
    const value = message as { type: string; id?: string; request?: { id: string; method: string; params?: PluginJSONObject } };
    if (value.type === "redevplugin.bridge.cancel") { const call = pending.get(value.id!); if (call) call.cancelled = true; pending.delete(value.id!); return; }
    if (value.type !== "redevplugin.bridge.call" || !value.request) return;
    const request = value.request;
    if (calls.length >= 1024) { port.emit({ type: "redevplugin.bridge.response", id: request.id, ok: false, error_code: "PLUGIN_INVALID_REQUEST", error: "Fixture call history exceeds 1024 entries" }); return; }
    const finish = (response: Record<string, unknown>): void => { if (!pending.delete(request.id)) return; port.emit({ type: "redevplugin.bridge.response", id: request.id, ...response }); };
    const call: PluginTestCall = { method: request.method, input: request.params, cancelled: false,
      resolve: value => finish({ ok: true, data: value }),
      reject: failure => finish({ ok: false, error_code: failure instanceof PluginBridgeError ? failure.errorCode : "PLUGIN_CAPABILITY_ERROR", error: failure.message }),
    };
    calls.push(call); pending.set(request.id, call);
    if (options.call) void Promise.resolve().then(() => options.call!(call.method, call.input)).then(call.resolve, failure => call.reject(failure instanceof Error ? failure : new Error(String(failure))));
  });
  class BridgeClient extends PluginBridgeClient {
    constructor(clientOptions: PluginBridgeClientOptions = {}) {
      if (clients.size || disposed) throw new Error("A fixture owns exactly one bridge client");
      super({ clock: options.clock, ...clientOptions, port, surfaceHandle: "surface_author_fixture" }); clients.add(this);
      queueMicrotask(() => { port.emit({ type: "redevplugin.bridge.context", context }); port.emit({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } }); });
    }
  }
  return {
    mode: "fixture" as const, BridgeClient, calls,
    context(next: PluginSurfaceContext): void { context = next; port.emit({ type: "redevplugin.bridge.context", context }); },
    dispose(): void { disposed = true; for (const client of clients) client.dispose(); clients.clear(); port.close(); pending.clear(); },
  };
}

/** Virtual time affects only consumers explicitly given this clock, never global timers. */
export function createPluginTestClock(initialTimeMs = 0) {
  if (!Number.isFinite(initialTimeMs) || initialTimeMs < 0) throw new Error("Fixture time must be nonnegative and finite");
  let now = initialTimeMs, nextID = 0, advancing = false;
  const tasks = new Map<number, { at: number; callback: () => void }>();
  const clock: PluginBridgeClock = {
    schedule(callback, delayMs) {
      if (!Number.isFinite(delayMs) || delayMs < 0 || typeof callback !== "function" || tasks.size >= 10000) throw new Error("Invalid fixture timer");
      const id = ++nextID; tasks.set(id, { at: now + delayMs, callback });
      return () => { tasks.delete(id); };
    },
  };
  return {
    clock, get now() { return now; }, get pending() { return tasks.size; },
    async advanceBy(milliseconds: number): Promise<void> {
      if (!Number.isFinite(milliseconds) || milliseconds < 0 || !Number.isFinite(now + milliseconds) || advancing) throw new Error("Invalid or concurrent fixture clock advance");
      advancing = true;
      const target = now + milliseconds;
      try {
        for (let count = 0; ; count++) {
          await Promise.resolve();
          const next = [...tasks.entries()].filter(([, task]) => task.at <= target).sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
          if (!next) break;
          if (count >= 10000) throw new Error("Fixture timer loop exceeded its bound");
          tasks.delete(next[0]); now = next[1].at; next[1].callback();
        }
        now = target;
      } finally { advancing = false; }
    },
    dispose(): void { tasks.clear(); },
  };
}
