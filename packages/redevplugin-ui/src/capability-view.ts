import type { PluginBridgeClient, PluginJSONValue } from "./plugin.js";

export interface CapabilityViewMount {
  readonly container: HTMLElement;
  readonly bridge: PluginBridgeClient;
  readonly input: PluginJSONValue;
  readonly signal: AbortSignal;
}

export interface CapabilityView {
  dispose(): void;
}

export interface CapabilityViewModule {
  mount(options: CapabilityViewMount): CapabilityView | Promise<CapabilityView>;
}

export interface MountCapabilityViewOptions {
  readonly bindingID: string;
  readonly bridge: PluginBridgeClient;
  readonly input: PluginJSONValue;
  readonly signal?: AbortSignal;
}

interface ViewManifest {
  schema_version: "redevplugin.capability_view.v1";
  module: string;
  styles: string[];
}

const validPath = (value: unknown): value is string => typeof value === "string"
  && value.length > 0 && value.length <= 512 && /^[A-Za-z0-9/._@+-]+$/.test(value)
  && value.split("/").every(part => part.length > 0 && !part.startsWith("."));

/** Validates the host's versioned descriptor before loading any executable bytes. */
export function parseCapabilityViewManifest(value: unknown): ViewManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid capability view");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 3 || record.schema_version !== "redevplugin.capability_view.v1"
    || !validPath(record.module) || !Array.isArray(record.styles) || record.styles.length > 1024 || !record.styles.every(validPath)
    || new Set(record.styles).size !== record.styles.length) throw new Error("Invalid capability view");
  return { schema_version: record.schema_version, module: record.module, styles: [...record.styles] };
}

/**
 * Mounts the host's official view inside this plugin's existing sandbox. The
 * shared view receives exactly the plugin bridge, never a host session token.
 * Disposing presentation does not cancel work accepted by the capability.
 */
export async function mountCapabilityView(container: HTMLElement, options: MountCapabilityViewOptions): Promise<CapabilityView> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.bindingID)) throw new Error("Invalid capability binding");
  const controller = new AbortController();
  const abort = () => controller.abort(options.signal?.reason);
  options.signal?.throwIfAborted();
  options.signal?.addEventListener("abort", abort, { once: true });
  const host = container.ownerDocument.createElement("div");
  host.style.cssText = "display:flex;flex:1;min-height:0;min-width:0;height:100%;width:100%";
  const shadow = host.attachShadow({ mode: "open" });
  const content = container.ownerDocument.createElement("div");
  content.style.cssText = host.style.cssText;
  const base = new URL(`/_redevplugin_web/capability-views/${options.bindingID}/`, container.ownerDocument.location.href);
  let mounted: CapabilityView | undefined;
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    options.signal?.removeEventListener("abort", abort);
    try { mounted?.dispose(); } finally { host.remove(); }
  };
  controller.signal.addEventListener("abort", dispose, { once: true });
  try {
    const response = await fetch(new URL("view.json", base), { signal: controller.signal, credentials: "same-origin", redirect: "error" });
    if (!response.ok) throw new Error("Capability view unavailable");
    const manifest = parseCapabilityViewManifest(await response.json());
    const styles = manifest.styles.map(name => {
      const link = container.ownerDocument.createElement("link");
      link.rel = "stylesheet";
      link.href = new URL(name, base).href;
      const loaded = new Promise<void>((resolve, reject) => {
        link.onload = () => resolve();
        link.onerror = () => reject(new Error("Capability view stylesheet unavailable"));
        controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
      });
      shadow.append(link);
      return loaded;
    });
    shadow.append(content);
    container.append(host);
    const [module] = await Promise.all([import(/* @vite-ignore */ new URL(manifest.module, base).href), ...styles]);
    controller.signal.throwIfAborted();
    if (typeof module.mount !== "function") throw new Error("Invalid capability view module");
    mounted = await (module as CapabilityViewModule).mount({ container: content, bridge: options.bridge, input: options.input, signal: controller.signal });
    if (!mounted || typeof mounted.dispose !== "function") throw new Error("Invalid capability view instance");
    if (disposed) {
      mounted.dispose();
      controller.signal.throwIfAborted();
    }
    return { dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}
