import { PluginBridgeError } from "./errors.js";

export type FetchLike = (input: string, init: FetchInitLike) => Promise<FetchResponseLike>;

export type FetchInitLike = {
  method: string;
  headers: Record<string, string>;
  body?: string;
  credentials?: "same-origin" | "include" | "omit";
  signal?: AbortSignal;
  keepalive?: boolean;
};

export type FetchResponseLike = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

export type HostEnvelope<T> =
  | { ok: true; data?: T }
  | { ok: false; data?: unknown; error?: string; error_code?: string; error_details?: Record<string, unknown> };

export function defaultFetch(): FetchLike {
  const fetchLike = (globalThis as { fetch?: FetchLike }).fetch;
  if (!fetchLike) {
    throw new Error("fetch is required when globalThis.fetch is unavailable");
  }
  return fetchLike.bind(globalThis) as FetchLike;
}

export function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

export async function readHostEnvelope<T>(response: FetchResponseLike, fallbackCode: string): Promise<T> {
  const raw = await response.json();
  if (!isHostEnvelope(raw)) {
    throw new PluginBridgeError(
      "PLUGIN_CONTRACT_MISMATCH",
      `Plugin platform endpoint returned an invalid envelope with HTTP ${response.status}`,
    );
  }
  if (!raw.ok) {
    throw new PluginBridgeError(
      raw.error_code ?? fallbackCode,
      raw.error ?? `Plugin platform endpoint failed with HTTP ${response.status}`,
      raw.data,
      raw.error_details ?? raw.data,
    );
  }
  return raw.data as T;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function hasAllowedKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).every((key) => keys.includes(key));
}

function isHostEnvelope(value: unknown): value is HostEnvelope<unknown> {
  if (!isRecord(value) || typeof value.ok !== "boolean") {
    return false;
  }
  if (value.ok) {
    return true;
  }
  return (value.error == null || typeof value.error === "string") &&
    (value.error_code == null || typeof value.error_code === "string") &&
    (value.error_details == null || isRecord(value.error_details));
}
