import {
  PluginBridgeError,
  type FetchLike,
  type FetchResponseLike,
  type PluginPlatformClientOptions,
  type PluginRecord,
} from "./index.js";

export type PluginImportLocalPackageRequest = {
  package_base64: string;
  plugin_instance_id?: string;
};

export type PluginUpdateLocalPackageRequest = {
  plugin_instance_id: string;
  package_base64: string;
};

type HostEnvelope<T> =
  | { ok: true; data?: T }
  | { ok: false; data?: unknown; error?: string; error_code?: string; error_details?: Record<string, unknown> };

export class PluginLocalImportClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #ownerSessionHashHeader?: string;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#ownerSessionHashHeader = options.ownerSessionHashHeader;
  }

  importLocalPackage(request: PluginImportLocalPackageRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/local-import/install", request);
  }

  updateLocalPackage(request: PluginUpdateLocalPackageRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/local-import/update", request);
  }

  async #postJSON<T>(path: string, body: unknown): Promise<T> {
    const response = await this.#fetch(this.#apiBaseURL + path, {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    return readHostEnvelope<T>(response);
  }

  #headers(): Record<string, string> {
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };
    if (this.#ownerSessionHashHeader) {
      headers["X-ReDevPlugin-Owner-Session-Hash"] = this.#ownerSessionHashHeader;
    }
    return headers;
  }
}

function defaultFetch(): FetchLike {
  const fetchLike = (globalThis as { fetch?: FetchLike }).fetch;
  if (!fetchLike) {
    throw new Error("fetch is required when globalThis.fetch is unavailable");
  }
  return fetchLike.bind(globalThis) as FetchLike;
}

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

async function readHostEnvelope<T>(response: FetchResponseLike): Promise<T> {
  const raw = await response.json();
  if (!isHostEnvelope(raw)) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Plugin platform endpoint returned an invalid envelope with HTTP ${response.status}`);
  }
  const envelope = raw as HostEnvelope<T>;
  if (response.ok && envelope.ok) {
    return envelope.data as T;
  }
  if (envelope.ok) {
    throw new PluginBridgeError("PLUGIN_PLATFORM_REQUEST_FAILED", `Plugin platform request failed with HTTP ${response.status}`, envelope.data);
  }
  const errorCode = envelope.error_code ?? "PLUGIN_PLATFORM_REQUEST_FAILED";
  const message = envelope.error ?? "Plugin platform request failed";
  throw new PluginBridgeError(errorCode, message, envelope.data, envelope.error_details ?? envelope.data);
}

function isHostEnvelope(value: unknown): value is HostEnvelope<unknown> {
  if (!isRecord(value) || typeof value.ok !== "boolean") {
    return false;
  }
  if (value.ok) {
    return true;
  }
  return (
    (value.error === undefined || typeof value.error === "string") &&
    (value.error_code === undefined || typeof value.error_code === "string") &&
    (value.error_details === undefined || isRecord(value.error_details))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
