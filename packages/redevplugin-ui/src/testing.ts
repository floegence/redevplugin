import { PluginBridgeClient, type MessagePortLike, type MessageEventLike, type PluginJSONObject, type PluginUIElementVNode, type PluginSurfaceContext, type PluginUIActionEvent, type PluginBridgeClientOptions } from "./surface.js";
import { PluginBridgeError } from "./errors.js";

/** Business/bridge fixture only. It does not certify Host permissions or WASM execution. */
export type PluginTestCall = {
  method: string;
  input?: PluginJSONObject;
  tree?: PluginUIElementVNode;
  cancelled: boolean;
  resolve(value: unknown): void;
  reject(error: Error): void;
};
export type PluginTestHarnessOptions = {
  context?: PluginSurfaceContext;
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
  let tree: PluginUIElementVNode | undefined, disposed = false;
  let context = options.context ?? createPluginTestContext();
  const port = new FixturePort(message => {
    const value = message as { type: string; id?: string; request?: { id: string; method: string; params?: PluginJSONObject } };
    if (value.type === "redevplugin.bridge.cancel") { const call = pending.get(value.id!); if (call) call.cancelled = true; pending.delete(value.id!); return; }
    if (value.type === "redevplugin.ui.mount" || value.type === "redevplugin.ui.patch") {
      port.emit({ type: "redevplugin.bridge.response", id: value.id, ok: true }); return;
    }
    if (value.type !== "redevplugin.bridge.call" || !value.request) return;
    const request = value.request;
    if (calls.length >= 1024) { port.emit({ type: "redevplugin.bridge.response", id: request.id, ok: false, error_code: "PLUGIN_INVALID_REQUEST", error: "Fixture call history exceeds 1024 entries" }); return; }
    const finish = (response: Record<string, unknown>): void => { if (!pending.delete(request.id)) return; port.emit({ type: "redevplugin.bridge.response", id: request.id, ...response }); };
    const call: PluginTestCall = { method: request.method, input: request.params, tree, cancelled: false,
      resolve: value => finish({ ok: true, data: value }),
      reject: failure => finish({ ok: false, error_code: failure instanceof PluginBridgeError ? failure.errorCode : "PLUGIN_CAPABILITY_ERROR", error: failure.message }),
    };
    calls.push(call); pending.set(request.id, call);
    if (options.call) void Promise.resolve().then(() => options.call!(call.method, call.input)).then(call.resolve, failure => call.reject(failure instanceof Error ? failure : new Error(String(failure))));
  });
  class BridgeClient extends PluginBridgeClient {
    constructor(clientOptions: PluginBridgeClientOptions = {}) {
      if (clients.size || disposed) throw new Error("A fixture owns exactly one bridge client");
      super({ ...clientOptions, port, surfaceHandle: "surface_author_fixture" }); clients.add(this);
      queueMicrotask(() => { port.emit({ type: "redevplugin.bridge.context", context }); port.emit({ type: "redevplugin.bridge.lifecycle", event: { type: "ready" } }); });
    }
    override async render(next: PluginUIElementVNode): Promise<void> { await super.render(next); tree = structuredClone(next); }
  }
  return {
    mode: "fixture" as const, BridgeClient, calls,
    get tree() { return tree; },
    context(next: PluginSurfaceContext): void { context = next; port.emit({ type: "redevplugin.bridge.context", context }); },
    action(action: string, event: Partial<PluginUIActionEvent> = {}): void {
      port.emit({ type: "redevplugin.ui.action", action, event: event.event ?? "click", target_key: event.targetKey ?? "fixture-target", edit_revision: event.editRevision ?? 0, is_composing: event.isComposing ?? false, ...(event.value !== undefined ? { value: event.value } : {}), ...(event.checked !== undefined ? { checked: event.checked } : {}), ...(event.form_data ? { form_data: event.form_data } : {}) });
    },
    dispose(): void { disposed = true; for (const client of clients) client.dispose(); clients.clear(); port.close(); pending.clear(); },
  };
}
