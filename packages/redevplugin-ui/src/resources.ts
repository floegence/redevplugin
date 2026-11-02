import type { PluginJSONValue } from "./surface.js";

export type PluginResourceOptions = { signal?: AbortSignal };
export type PluginResourceOutcome = "not_committed" | "committed" | "unknown";
export class PluginResourceError extends Error {
  constructor(readonly code: string, readonly mutationOutcome: PluginResourceOutcome, readonly retryable = false) {
    super(code === "CONFLICT" ? "This resource changed. Reload before saving." : "Plugin resource request failed: " + code);
    this.name = "PluginResourceError";
  }
}
export interface PluginStorageUsage {
  usage_bytes: number;
  quota_bytes: number;
  usage_files: number;
  quota_files: number;
}
export interface PluginResourcePage<T> { entries: T[]; next_cursor?: string; usage: PluginStorageUsage }
export interface PluginKVEntry { key: string; size_bytes: number; updated_at: string }
export interface PluginPrivateFileEntry { path: string; dir: boolean; size_bytes?: number; updated_at: string }
export interface PluginSettingsSnapshot<T> { values: T; values_revision: number; schema_version: number; scope: "user" | "environment" }
export type PluginSQLiteValue = null | string | number | Uint8Array;

async function* snapshots<T>(resource: string, args: Record<string, unknown>, options: PluginResourceOptions & { cursor?: string }): AsyncIterableIterator<{ snapshot: T | undefined; cursor: string }> {
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  let cursor = options.cursor;
  try {
    while (!signal.aborted) {
      const value = await request<{ changed: boolean; found?: boolean; cursor: string; snapshot?: T }>(resource, { ...args, operation: "watch", cursor }, false, { signal });
      if (!value || typeof value.changed !== "boolean" || typeof value.cursor !== "string" || (value.changed && (typeof value.found !== "boolean" || !("snapshot" in value)))) throw new PluginResourceError("INVALID_RESPONSE", "not_committed");
      cursor = value.cursor;
      if (value.changed) yield { snapshot: value.found ? value.snapshot : undefined, cursor };
    }
  } finally { controller.abort(); }
}

export interface PluginResourceDescription {
  can_read: boolean;
  can_write: boolean;
  storage: { store_id: string; kind: "kv" | "files" | "sqlite"; scope: "user" | "environment"; operations: string[] }[];
  settings: string[] | null;
  limits: { control_bytes: number; value_bytes: number; page_entries: number; transaction_statements: number; operation_timeout_ms: number; watch_timeout_ms: number; stream_timeout_ms: number; concurrency_per_surface: number; concurrency_per_host: number; websocket_message_bytes: number };
}
/** Declared ceilings and session limits are not a grant or an availability promise. */
export function describePluginResources(options: PluginResourceOptions = {}): Promise<PluginResourceDescription> {
  return request("describe", {}, false, options);
}

// Bounded decoding applies to control responses; file bodies use streaming APIs.
async function responseJSON(response: Response): Promise<unknown> {
  if (!response.body) throw new Error("Missing response body");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "", size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024 * 1024) throw new Error("Control response exceeds limit");
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } catch (error) { await reader.cancel().catch(() => undefined); throw error; }
  finally { reader.releaseLock(); }
}
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function safeCount(value: unknown): boolean { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0; }
function validData(resource: string, args: Record<string, unknown>, value: unknown): boolean {
  if (!object(value)) return false;
  const operation = args.operation;
  if (operation === "watch") return typeof value.changed === "boolean" && typeof value.cursor === "string";
  if (resource === "storage.kv") {
    if (operation === "get") return typeof value.value_base64 === "string" && typeof value.etag === "string";
    if (operation === "put") return typeof value.etag === "string";
    if (operation === "batch") return object(value.etags) && Object.values(value.etags).every(item => typeof item === "string");
  }
  if (resource === "storage.files" && operation === "read") return typeof value.data_base64 === "string";
  if (operation === "list") return Array.isArray(value.entries) && value.entries.length <= 100 && value.entries.every(object) && object(value.usage) && Object.values(value.usage).every(safeCount) && (value.next_cursor === undefined || typeof value.next_cursor === "string");
  if (resource === "settings") return object(value.values) && safeCount(value.values_revision) && safeCount(value.schema_version) && (value.scope === "user" || value.scope === "environment");
  if (resource === "storage.sqlite") {
    if (operation === "query") return Array.isArray(value.columns) && value.columns.every(item => typeof item === "string") && Array.isArray(value.rows) && value.rows.length <= 100 && value.rows.every(row => Array.isArray(row) && row.length === (value.columns as unknown[]).length && row.every(object));
    if (operation === "exec") return safeCount(value.rows_affected) && typeof value.last_insert_id === "number" && Number.isSafeInteger(value.last_insert_id);
  }
  if (resource === "describe") return typeof value.can_read === "boolean" && typeof value.can_write === "boolean" && Array.isArray(value.storage) && object(value.limits);
  return true;
}

async function request<T>(resource: string, args: Record<string, unknown>, writes: boolean, options: PluginResourceOptions): Promise<T> {
  options.signal?.throwIfAborted();
  const body = JSON.stringify({ resource, arguments: args });
  if (new TextEncoder().encode(body).byteLength > 96 * 1024) throw new PluginResourceError("RESOURCE_LIMIT", "not_committed");
  let response: Response;
  try {
    response = await fetch(new URL("/_redevplugin_web/resource", globalThis.location.origin), { method: "POST", headers: { "Content-Type": "application/json" }, body, credentials: "same-origin", redirect: "error", cache: "no-store", signal: options.signal });
  } catch {
    throw new PluginResourceError("TRANSPORT_FAILED", writes ? "unknown" : "not_committed");
  }
  let value: unknown;
  try { value = await responseJSON(response); } catch { throw new PluginResourceError("INVALID_RESPONSE", writes ? "unknown" : "not_committed"); }
  if (!value || typeof value !== "object") throw new PluginResourceError("INVALID_RESPONSE", writes ? "unknown" : "not_committed");
  const envelope = value as Record<string, unknown>;
  if (response.ok && envelope.ok === true && validData(resource, args, envelope.data)) return envelope.data as T;
  const error = envelope.error as Record<string, unknown> | undefined;
  if (error && typeof error.code === "string" && ["unknown", "committed", "not_committed"].includes(String(error.mutation_outcome))) {
    throw new PluginResourceError(error.code, error.mutation_outcome as PluginResourceOutcome, error.retryable === true);
  }
  throw new PluginResourceError("INVALID_RESPONSE", writes ? "unknown" : "not_committed");
}
function identifier(id: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(id)) throw new TypeError("Invalid store identifier");
  return id;
}
function encode(data: Uint8Array): string {
  let text = "";
  for (let offset = 0; offset < data.length; offset += 8192) text += String.fromCharCode(...data.subarray(offset, offset + 8192));
  return btoa(text);
}
function decode(data: string): Uint8Array { return Uint8Array.from(atob(data), char => char.charCodeAt(0)); }
function sqliteValue(value: PluginSQLiteValue): Record<string, unknown> {
  if (value === null) return { null: true };
  if (value instanceof Uint8Array) return { blob_base64: encode(value) };
  if (typeof value === "string") return { text: value };
  if (!Number.isFinite(value)) throw new TypeError("SQLite values must be finite");
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) throw new TypeError("SQLite integer exceeds JavaScript precision");
  return Number.isInteger(value) ? { int: value } : { float: value };
}
function fromSQLite(value: Record<string, unknown>): PluginSQLiteValue {
  if (value.null === true) return null;
  if (typeof value.text === "string") return value.text;
  if (typeof value.blob_base64 === "string") return decode(value.blob_base64);
  if (typeof value.int === "number" && Number.isSafeInteger(value.int)) return value.int;
  if (typeof value.float === "number" && Number.isFinite(value.float)) return value.float;
  throw new PluginResourceError("INVALID_RESPONSE", "not_committed");
}

/** Direct private storage, using this Surface's signed ceiling and live session. */
export function pluginKV<T extends PluginJSONValue = PluginJSONValue>(storeId: string) {
  const store_id = identifier(storeId);
  return Object.freeze({
    async *watch(key: string, options: PluginResourceOptions & { cursor?: string } = {}): AsyncIterableIterator<{ value: T | undefined; cursor: string }> {
      for await (const item of snapshots<{ value_base64: string }>("storage.kv", { store_id, key }, options)) {
        yield { value: item.snapshot ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decode(item.snapshot.value_base64))) as T : undefined, cursor: item.cursor };
      }
    },
    batch(mutations: ({ key: string; value: T; expectedETag?: string } | { key: string; delete: true; expectedETag?: string })[], options: PluginResourceOptions = {}): Promise<{ etags: Record<string, string>; usage: PluginStorageUsage }> {
      if (!mutations.length || mutations.length > 64) throw new TypeError("A batch requires 1 to 64 mutations");
      return request("storage.kv", { operation: "batch", store_id, mutations: mutations.map(item => ({ key: item.key, expected_etag: item.expectedETag, ...("delete" in item ? { delete: true } : { value_base64: encode(new TextEncoder().encode(JSON.stringify(item.value))) }) })) }, true, options);
    },
    async read(key: string, options: PluginResourceOptions = {}): Promise<{ value: T; etag: string } | undefined> {
      try {
        const value = await request<{ value_base64: string; etag: string }>("storage.kv", { operation: "get", store_id, key, max_bytes: 64 * 1024 }, false, options);
        return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decode(value.value_base64))) as T, etag: value.etag };
      } catch (error) { if (error instanceof PluginResourceError && error.code === "NOT_FOUND") return undefined; throw error; }
    },
    async put(key: string, value: T, options: PluginResourceOptions & { expectedETag?: string } = {}): Promise<{ etag: string }> {
      return request("storage.kv", { operation: "put", store_id, key, expected_etag: options.expectedETag, value_base64: encode(new TextEncoder().encode(JSON.stringify(value))) }, true, options);
    },
    async delete(key: string, options: PluginResourceOptions & { expectedETag?: string } = {}): Promise<void> {
      await request("storage.kv", { operation: "delete", store_id, key, expected_etag: options.expectedETag }, true, options);
    },
    list(options: PluginResourceOptions & { prefix?: string; cursor?: string; limit?: number } = {}): Promise<PluginResourcePage<PluginKVEntry>> {
      return request("storage.kv", { operation: "list", store_id, prefix: options.prefix ?? "", cursor: options.cursor ?? "", max_entries: options.limit ?? 100 }, false, options);
    },
  });
}

export function pluginFiles(storeId: string) {
  const store_id = identifier(storeId);
  return Object.freeze({
    async readable(path: string, options: PluginResourceOptions = {}): Promise<ReadableStream<Uint8Array>> {
      options.signal?.throwIfAborted();
      const endpoint = fileEndpoint(store_id, path, "read");
      const response = await fetch(endpoint, { method: "POST", credentials: "same-origin", redirect: "error", cache: "no-store", signal: options.signal });
      if (!response.ok || !response.body) throw new PluginResourceError("STREAM_UNAVAILABLE", "not_committed");
      return response.body;
    },
    /** Replaces the file atomically. Transport failures never trigger a replay. */
    async writeFrom(path: string, source: Blob | ReadableStream<Uint8Array>, options: PluginResourceOptions = {}): Promise<number> {
      options.signal?.throwIfAborted();
      try {
        const response = await fetch(fileEndpoint(store_id, path, "write"), { method: "POST", body: source, credentials: "same-origin", redirect: "error", cache: "no-store", signal: options.signal,
          ...(source instanceof ReadableStream ? { duplex: "half" } : {}),
        } as RequestInit);
        const result: unknown = await responseJSON(response);
        if (result && typeof result === "object") {
          const value = result as Record<string, unknown>;
          if (response.ok && value.ok === true && Number.isSafeInteger(value.count) && Number(value.count) >= 0) return Number(value.count);
          const error = value.error as Record<string, unknown> | undefined;
          if (error && typeof error.code === "string" && ["not_committed", "committed", "unknown"].includes(String(error.mutation_outcome))) throw new PluginResourceError(error.code, error.mutation_outcome as PluginResourceOutcome, error.retryable === true);
        }
        throw new PluginResourceError("INVALID_RESPONSE", "unknown");
      } catch (error) { if (error instanceof PluginResourceError) throw error; throw new PluginResourceError("TRANSPORT_FAILED", "unknown"); }
    },
    async read(path: string, options: PluginResourceOptions = {}): Promise<Uint8Array> {
      const value = await request<{ data_base64: string }>("storage.files", { operation: "read", store_id, path, max_bytes: 64 * 1024 }, false, options);
      return decode(value.data_base64);
    },
    async write(path: string, data: Uint8Array, options: PluginResourceOptions = {}): Promise<void> {
      await request("storage.files", { operation: "write", store_id, path, data_base64: encode(data) }, true, options);
    },
    async delete(path: string, options: PluginResourceOptions & { recursive?: boolean } = {}): Promise<void> {
      await request("storage.files", { operation: "delete", store_id, path, recursive: options.recursive ?? false }, true, options);
    },
    list(options: PluginResourceOptions & { path?: string; cursor?: string; limit?: number } = {}): Promise<PluginResourcePage<PluginPrivateFileEntry>> {
      return request("storage.files", { operation: "list", store_id, path: options.path ?? "", cursor: options.cursor ?? "", max_entries: options.limit ?? 100 }, false, options);
    },
  });
}
function fileEndpoint(store: string, path: string, direction: "read" | "write"): URL {
  if (!path || path.length > 4096) throw new TypeError("Invalid private file path");
  const url = new URL("/_redevplugin_web/private-file-transfer", globalThis.location.origin);
  url.searchParams.set("store_id", store); url.searchParams.set("path", path); url.searchParams.set("direction", direction);
  return url;
}
export function pluginDatabase(storeId: string, database = "") {
  const store_id = identifier(storeId);
  return Object.freeze({
    async query(sql: string, args: PluginSQLiteValue[] = [], options: PluginResourceOptions & { limit?: number } = {}): Promise<{ columns: string[]; rows: PluginSQLiteValue[][] }> {
      const result = await request<{ columns: string[]; rows: Record<string, unknown>[][] }>("storage.sqlite", { operation: "query", store_id, database, sql, args: args.map(sqliteValue), max_rows: options.limit ?? 100, max_response_bytes: 64 * 1024, timeout_ms: 5000 }, false, options);
      return { columns: result.columns, rows: result.rows.map(row => row.map(fromSQLite)) };
    },
    async transaction(statements: { sql: string; args?: PluginSQLiteValue[] }[], options: PluginResourceOptions = {}): Promise<{ rows_affected: number; last_insert_id: number }> {
      if (!statements.length || statements.length > 64) throw new TypeError("A transaction requires 1 to 64 statements");
      return request("storage.sqlite", { operation: "exec", store_id, database, statements: statements.map(item => ({ sql: item.sql, args: (item.args ?? []).map(sqliteValue) })), timeout_ms: 5000 }, true, options);
    },
    async exec(sql: string, args: PluginSQLiteValue[] = [], options: PluginResourceOptions = {}): Promise<{ rows_affected: number; last_insert_id: number }> {
      return request("storage.sqlite", { operation: "exec", store_id, database, sql, args: args.map(sqliteValue), timeout_ms: 5000 }, true, options);
    },
  });
}
export function pluginSettings<T extends Record<string, PluginJSONValue>>(scope: "user" | "environment" = "user") {
  return Object.freeze({
    watch(options: PluginResourceOptions & { cursor?: string } = {}): AsyncIterableIterator<{ snapshot: PluginSettingsSnapshot<T> | undefined; cursor: string }> {
      return snapshots("settings", { scope }, options);
    },
    get(options: PluginResourceOptions = {}): Promise<PluginSettingsSnapshot<T>> { return request("settings", { operation: "get", scope }, false, options); },
    patch(expectedRevision: number, set: Partial<T>, remove: (keyof T)[] = [], options: PluginResourceOptions = {}): Promise<PluginSettingsSnapshot<T>> {
      return request("settings", { operation: "patch", scope, expected_values_revision: expectedRevision, set, remove }, true, options);
    },
  });
}
