import type { components } from "./openapi.gen.js";
import { PluginBridgeError, pluginMutationOutcome } from "./errors.js";
import { hasAllowedKeys, hasExactKeys, isRecord } from "./http.js";
import type { PluginBridgeRequestOptions } from "./surface.js";

type Schemas = components["schemas"];
export type PluginFileResource = Schemas["FileResource"];
export type PluginFileResourceReview = Schemas["FileResourceReview"];
export type PluginFileSelectionOptions = Schemas["FileSelectionOptions"];
export type PluginFileIORequest = Schemas["FileIORequest"];
export type PluginFileIOResult = Schemas["FileIOResult"];
export type PluginFileOpenOptions = Extract<PluginFileIORequest, { operation: "fs.open" }>["arguments"]["options"];
export type PluginFileAccessConfirmation = (review: Readonly<PluginFileResourceReview & { signal: AbortSignal }>) => boolean | Promise<boolean>;
export type PluginFileStat = { uri: string; kind: "file" | "directory"; size: bigint; mode: number; modified_unix_ms: number; created_unix_ms?: number };
export type PluginDirectoryEntry = { name: string; uri: string; kind: "file" | "directory" | "symlink" | "other" };
type FileCall = (request: PluginFileIORequest, options?: PluginBridgeRequestOptions) => Promise<PluginFileIOResult>;
const chunkBytes = 65536;

function invalid(message: string): never { throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", message); }
function handle(value: unknown): string {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value) || BigInt(value) > 9223372036854775807n) return invalid("File handle is invalid");
  return value;
}
function uri(value: string): string {
  if (!validURI(value)) throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Selected file URI is invalid");
  return value;
}

export function isPluginFileResourceReview(value: unknown): value is PluginFileResourceReview {
  return hasExactKeys(value, ["review_id", "plugin_instance_id", "name", "kind", "recursive", "writable", "review_expires_at", "resource_expires_at"]) &&
    typeof value.review_id === "string" && /^[0-9a-f]{64}$/.test(value.review_id) &&
    typeof value.plugin_instance_id === "string" && value.plugin_instance_id.length > 0 && value.plugin_instance_id.length <= 256 &&
    typeof value.name === "string" && value.name.length > 0 && [...value.name].length <= 255 &&
    (value.kind === "file" || value.kind === "directory") && typeof value.recursive === "boolean" && (value.kind !== "file" || !value.recursive) && typeof value.writable === "boolean" &&
    typeof value.review_expires_at === "string" && Number.isFinite(Date.parse(value.review_expires_at)) &&
    typeof value.resource_expires_at === "string" && Number.isFinite(Date.parse(value.resource_expires_at));
}

export function isPluginFileResource(value: unknown): value is PluginFileResource {
  return hasExactKeys(value, ["resource_id", "uri", "name", "kind", "recursive", "writable", "revision", "expires_at", "status"]) &&
    typeof value.resource_id === "string" && /^selected-[0-9a-f]{64}$/.test(value.resource_id) && value.uri === `redevfs://${value.resource_id}/` &&
    typeof value.name === "string" && value.name.length > 0 && [...value.name].length <= 255 && (value.kind === "file" || value.kind === "directory") &&
    typeof value.recursive === "boolean" && (value.kind !== "file" || !value.recursive) && typeof value.writable === "boolean" && Number.isSafeInteger(value.revision) && Number(value.revision) >= 1 &&
    typeof value.expires_at === "string" && Number.isFinite(Date.parse(value.expires_at)) &&
    ["active", "revoked", "expired", "unavailable"].includes(String(value.status));
}

/** Thin client over the Host's selected-resource authority and shared I/O table. */
export class PluginFilesClient {
  constructor(private readonly call: FileCall) {}

  async select(selection: PluginFileSelectionOptions, options?: PluginBridgeRequestOptions): Promise<PluginFileResource | null> {
    const result = await this.call({ operation: "select", arguments: selection }, options);
    if (hasExactKeys(result, ["canceled"]) && result.canceled === true) return null;
    if (!hasExactKeys(result, ["resource"]) || !isPluginFileResource(result.resource)) return invalid("File selection response is invalid");
    return result.resource;
  }

  async open(resourceURI: string, flags: PluginFileOpenOptions = { read: true }, options?: PluginBridgeRequestOptions): Promise<PluginFileHandle> {
    const result = await this.call({ operation: "fs.open", arguments: { uri: uri(resourceURI), options: flags } }, options);
    return new PluginFileHandle(this.call, handle(result.handle));
  }

  async stat(resourceURI: string, options?: PluginBridgeRequestOptions): Promise<PluginFileStat> {
    const result = await this.call({ operation: "fs.stat", arguments: { uri: uri(resourceURI) } }, options);
    const value: unknown = result.value;
    if (!hasExactKeys(result, ["value"]) || !isRecord(value) || !hasAllowedKeys(value, ["uri", "kind", "size", "mode", "modified_unix_ms", "created_unix_ms"]) || !sameFileURI(value.uri, resourceURI) || !["file", "directory"].includes(String(value.kind)) || typeof value.size !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value.size) || BigInt(value.size) > 9223372036854775807n || !boundedInteger(value.mode, 0, 4294967295) || !Number.isSafeInteger(value.modified_unix_ms) || (value.created_unix_ms !== undefined && !Number.isSafeInteger(value.created_unix_ms))) return invalid("File stat response is invalid");
    return { ...value, size: BigInt(value.size) } as PluginFileStat;
  }

  async *entries(resourceURI: string, options?: PluginBridgeRequestOptions): AsyncGenerator<PluginDirectoryEntry> {
    const opened = await this.call({ operation: "fs.read_dir.open", arguments: { uri: uri(resourceURI) } }, options);
    const id = handle(opened.handle);
    let finished = false;
    let failed = false;
    try {
      for (;;) {
        const result = await this.call({ operation: "read_dir.next", arguments: { handle: id, limit: 128 } }, options);
        const value: unknown = result.value;
        if (!hasExactKeys(value, ["entries", "eof"]) || !Array.isArray(value.entries) || value.entries.length > 128 || typeof value.eof !== "boolean") return invalid("Directory page is invalid");
        for (const entry of value.entries) {
          if (!hasExactKeys(entry, ["name", "uri", "kind"]) || typeof entry.name !== "string" || typeof entry.uri !== "string" || !["file", "directory", "symlink", "other"].includes(String(entry.kind))) return invalid("Directory entry is invalid");
          yield entry as PluginDirectoryEntry;
        }
        if (value.eof) { finished = true; return; }
        if (value.entries.length === 0) return invalid("Directory made no progress");
      }
    } catch (error) { failed = true; throw error; }
    finally {
      if (!finished) {
        try { await this.call({ operation: "close", arguments: { handle: id } }); }
        catch (error) { if (!failed) throw error; }
      }
    }
  }

  async mkdir(resourceURI: string, recursive = false, options?: PluginBridgeRequestOptions): Promise<void> {
    await this.call({ operation: "fs.mkdir", arguments: { uri: uri(resourceURI), recursive } }, options);
  }
  async remove(resourceURI: string, recursive = false, options?: PluginBridgeRequestOptions): Promise<void> {
    await this.call({ operation: "fs.remove", arguments: { uri: uri(resourceURI), recursive } }, options);
  }
  async rename(from: string, to: string, overwrite = false, options?: PluginBridgeRequestOptions): Promise<void> {
    await this.call({ operation: "fs.rename", arguments: { from: uri(from), to: uri(to), overwrite } }, options);
  }
  async copy(from: string, to: string, overwrite = false, options?: PluginBridgeRequestOptions): Promise<void> {
    await this.call({ operation: "fs.copy", arguments: { from: uri(from), to: uri(to), overwrite } }, options);
  }
}

export class PluginFileHandle {
  #closed = false;
  constructor(private readonly call: FileCall, private readonly id: string) {}
  #active(): void { if (this.#closed) throw new PluginBridgeError("PLUGIN_BRIDGE_DISPOSED", "File handle is closed"); }

  async read(length = chunkBytes, options?: PluginBridgeRequestOptions): Promise<{ bytes: Uint8Array; eof: boolean }> {
    this.#active();
    if (!Number.isSafeInteger(length) || length < 1 || length > chunkBytes) throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Read length must be between 1 and 65536");
    const result = await this.call({ operation: "read", arguments: { handle: this.id, length } }, options);
    if (!hasExactKeys(result, ["data", "count", "eof"]) || typeof result.data !== "string" || typeof result.eof !== "boolean" || !Number.isSafeInteger(result.count)) return invalid("File read response is invalid");
    let decoded: string;
    try { decoded = atob(result.data); } catch { return invalid("File data is invalid"); }
    if (decoded.length !== result.count || decoded.length > length || btoa(decoded) !== result.data) return invalid("File read length is invalid");
    return { bytes: Uint8Array.from(decoded, c => c.charCodeAt(0)), eof: result.eof };
  }

  async write(bytes: Uint8Array, options?: PluginBridgeRequestOptions): Promise<number> {
    this.#active();
    let written = 0;
    for (let offset = 0; offset < bytes.byteLength; offset += chunkBytes) {
      const part = bytes.subarray(offset, offset + chunkBytes);
      let binary = ""; for (const byte of part) binary += String.fromCharCode(byte);
      try {
        const result = await this.call({ operation: "write", arguments: { handle: this.id, data: btoa(binary) } }, options);
        if (!hasExactKeys(result, ["count"]) || result.count !== part.length) {
          throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "File write length is invalid", undefined, undefined, "unknown");
        }
        written += result.count;
      } catch (error) {
        if (written > 0 || pluginMutationOutcome(error) !== "not_committed") throw new PluginFileWriteError(written, error);
        throw error;
      }
    }
    return written;
  }

  async seek(offset: bigint, whence: 0 | 1 | 2 = 0, options?: PluginBridgeRequestOptions): Promise<bigint> {
    this.#active();
    const result = await this.call({ operation: "seek", arguments: { handle: this.id, offset: offset.toString(), whence } }, options);
    if (!hasExactKeys(result, ["offset"]) || typeof result.offset !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(result.offset) || BigInt(result.offset) > 9223372036854775807n) return invalid("File offset is invalid");
    return BigInt(result.offset);
  }
  async sync(options?: PluginBridgeRequestOptions): Promise<void> { this.#active(); await this.call({ operation: "sync", arguments: { handle: this.id } }, options); }
  async close(): Promise<void> {
    if (this.#closed) return;
    await this.call({ operation: "close", arguments: { handle: this.id } });
    this.#closed = true;
  }
}

/** A rejected write may have changed the file. bytesWritten counts acknowledged bytes only. */
export class PluginFileWriteError extends PluginBridgeError {
  override readonly cause: unknown;
  constructor(readonly bytesWritten: number, cause: unknown) {
    super(cause instanceof PluginBridgeError ? cause.errorCode : "PLUGIN_FILE_OPERATION_FAILED", "File write did not finish; inspect the file before retrying", undefined, cause instanceof PluginBridgeError ? cause.details : undefined, "unknown");
    this.name = "PluginFileWriteError";
    this.cause = cause;
  }
}

function validURI(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 4096 || !/^redevfs:\/\/selected-[0-9a-f]{64}\//.test(value)) return false;
  const path = value.slice(value.indexOf("/", 10) + 1);
  if (path === "") return true;
  try {
    return path.split("/").every(part => {
      if (/[?#]/.test(part)) return false;
      const decoded = decodeURIComponent(part);
      return decoded !== "" && decoded !== "." && decoded !== ".." && !/[\\/\u0000]/.test(decoded);
    });
  } catch { return false; }
}
function sameFileURI(actual: unknown, expected: string): boolean {
  if (!validURI(actual) || !validURI(expected)) return false;
  const normalized = (value: string) => value.split("/").map(part => decodeURIComponent(part).normalize("NFC")).join("/");
  return normalized(actual) === normalized(expected);
}
function boundedInteger(value: unknown, min: number, max: number): boolean { return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max; }
function decimal(value: unknown, signed = false): boolean {
  return typeof value === "string" && (signed ? /^(0|-?[1-9][0-9]{0,18})$/ : /^[1-9][0-9]{0,18}$/).test(value) && BigInt(value) <= 9223372036854775807n && BigInt(value) >= (signed ? -9223372036854775808n : 1n);
}
function base64(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 87384) return false;
  try { const raw = atob(value); return raw.length <= chunkBytes && btoa(raw) === value; } catch { return false; }
}
export function validFileIORequest(value: unknown): value is PluginFileIORequest {
  if (!hasExactKeys(value, ["operation", "arguments"]) || !isRecord(value.arguments)) return false;
  const a = value.arguments;
  const keys = (required: string[], optional: string[] = []) => required.every(key => Object.hasOwn(a, key)) && hasAllowedKeys(a, [...required, ...optional]);
  const flags = (...names: string[]) => names.every(name => a[name] === undefined || typeof a[name] === "boolean");
  switch (value.operation) {
    case "select": return keys(["kind"], ["recursive", "writable"]) && ["file", "directory"].includes(String(a.kind)) && flags("recursive", "writable") && (a.kind !== "file" || !a.recursive);
    case "fs.open": {
      if (!keys(["uri", "options"]) || !validURI(a.uri) || !isRecord(a.options) || !hasAllowedKeys(a.options, ["read", "write", "create", "create_new", "truncate", "append", "mode"])) return false;
      const o = a.options;
      return ["read", "write", "create", "create_new", "truncate", "append"].every(key => o[key] === undefined || typeof o[key] === "boolean") && (o.mode === undefined || boundedInteger(o.mode, 0, 511));
    }
    case "fs.stat": return keys(["uri"], ["follow_symlinks"]) && validURI(a.uri) && flags("follow_symlinks");
    case "fs.read_dir.open": return keys(["uri"]) && validURI(a.uri);
    case "fs.mkdir": return keys(["uri"], ["recursive", "mode"]) && validURI(a.uri) && flags("recursive") && (a.mode === undefined || boundedInteger(a.mode, 0, 511));
    case "fs.remove": return keys(["uri"], ["recursive"]) && validURI(a.uri) && flags("recursive");
    case "fs.rename": case "fs.copy": return keys(["from", "to"], ["overwrite"]) && validURI(a.from) && validURI(a.to) && flags("overwrite");
    case "fs.set_times": return keys(["uri", "accessed_unix_ms", "modified_unix_ms"]) && validURI(a.uri) && Number.isSafeInteger(a.accessed_unix_ms) && Number.isSafeInteger(a.modified_unix_ms);
    case "read": return keys(["handle", "length"]) && decimal(a.handle) && boundedInteger(a.length, 1, chunkBytes);
    case "write": return keys(["handle", "data"]) && decimal(a.handle) && base64(a.data);
    case "seek": return keys(["handle", "offset"], ["whence"]) && decimal(a.handle) && decimal(a.offset, true) && (a.whence === undefined || boundedInteger(a.whence, 0, 2));
    case "close": case "sync": return keys(["handle"]) && decimal(a.handle);
    case "read_dir.next": return keys(["handle", "limit"]) && decimal(a.handle) && boundedInteger(a.limit, 1, 256);
    default: return false;
  }
}
