import {
  PluginPlatformRequestError,
  PluginTransportError,
  pluginPlatformErrorCodes,
  type PluginPlatformErrorCode,
} from "./errors.js";
import type { components as PluginPlatformComponents } from "./openapi.gen.js";

export type FetchLike = (input: string, init: FetchInitLike) => Promise<FetchResponseLike>;

export type FetchInitLike = {
  method: string;
  headers: Record<string, string>;
  body?: BodyInit;
  credentials?: "same-origin" | "include" | "omit";
  signal?: AbortSignal;
  keepalive?: boolean;
};

export type FetchResponseLike = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

export type PlatformResponse<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: PluginPlatformComponents["schemas"]["PlatformError"];
    };

export type MutationPlatformResponse<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: PluginPlatformComponents["schemas"]["MutationPlatformError"];
    };

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

export async function readPlatformResponse<T>(response: FetchResponseLike): Promise<T> {
  return readResponse<T>(response, false);
}

export async function readMutationPlatformResponse<T>(response: FetchResponseLike): Promise<T> {
  return readResponse<T>(response, true);
}

async function readResponse<T>(response: FetchResponseLike, mutation: boolean): Promise<T> {
  let raw: unknown;
  try {
    raw = await response.json();
  } catch (cause) {
    throw new PluginTransportError(
      `Plugin platform endpoint returned invalid JSON with HTTP ${response.status}`,
      cause,
      mutation ? "unknown" : undefined,
    );
  }
  if (!isPlatformResponse<T>(raw, mutation)) {
    throw new PluginTransportError(
      `Plugin platform endpoint returned an invalid envelope with HTTP ${response.status}`,
      new PluginPlatformRequestError("PLUGIN_CONTRACT_MISMATCH", "Invalid platform response envelope"),
      mutation ? "unknown" : undefined,
    );
  }
  if (raw.ok) {
    if (!response.ok || response.status !== 200) {
      throw new PluginTransportError(
        `Plugin platform endpoint returned a success envelope with HTTP ${response.status}`,
        new PluginPlatformRequestError("PLUGIN_CONTRACT_MISMATCH", "HTTP status does not match the platform response envelope"),
        mutation ? "unknown" : undefined,
      );
    }
    return raw.data;
  }
  if (response.ok || response.status === 200) {
    throw new PluginTransportError(
      `Plugin platform endpoint returned an error envelope with HTTP ${response.status}`,
      new PluginPlatformRequestError("PLUGIN_CONTRACT_MISMATCH", "HTTP status does not match the platform response envelope"),
      mutation ? "unknown" : undefined,
    );
  }
  {
    throw new PluginPlatformRequestError(
      raw.error.code,
      raw.error.message || `Plugin platform endpoint failed with HTTP ${response.status}`,
      raw.error.details,
      "mutation_outcome" in raw.error ? raw.error.mutation_outcome : undefined,
    );
  }
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

function isPlatformResponse<T>(value: unknown, mutation: boolean): value is PlatformResponse<T> | MutationPlatformResponse<T> {
  if (!isRecord(value) || typeof value.ok !== "boolean") return false;
  if (value.ok) {
    return hasExactKeys(value, ["ok", "data"]);
  }
  if (!hasExactKeys(value, ["ok", "error"]) || !isRecord(value.error)) return false;
  const errorKeys = mutation ? ["code", "message", "details", "mutation_outcome"] : ["code", "message", "details"];
  if (!hasExactKeys(value.error, errorKeys) ||
      !isPluginPlatformErrorCode(value.error.code) ||
      typeof value.error.message !== "string" || value.error.message.trim().length === 0 ||
      Array.from(value.error.message).length > 4096 ||
      !isPlatformErrorDetails(value.error.code, value.error.details)) return false;
  return !mutation || value.error.mutation_outcome === "not_committed" || value.error.mutation_outcome === "unknown";
}

const packageValidationErrorCodes = [
  "PLUGIN_MANIFEST_INVALID",
  "PLUGIN_PACKAGE_INVALID",
  "PLUGIN_PACKAGE_TOO_LARGE",
  "PLUGIN_PACKAGE_PATH_FORBIDDEN",
] as const;

const jsonLimitReasons = ["payload_bytes", "json_depth", "prototype_key", "number_precision"] as const;

const packageValidationReasons = [
  "manifest_missing", "manifest_field", "manifest_decode", "zip_invalid", "file_count", "duplicate_entry",
  "ambiguous_entry", "non_regular_entry", "invalid_utf8_path", "non_nfc_path", "symlink_entry",
  "directory_entry", "entry_bytes", "path_length", "compression_ratio", "total_uncompressed_bytes",
  "entry_open_failed", "entry_read_failed", "entry_close_failed", "entry_size_mismatch",
  "unsupported_signature_entry", "manifest_artifact", "package_asset_security", "package_artifact_boundary",
  "entry_path", "manifest_canonical_json", "canonical_hash", "package_signature", "empty_path",
  "slash_separator", "non_canonical_path", "path_traversal", "hidden_path", "external_icon_path",
  "unsupported_icon_format", "missing_icon_asset", "icon_magic_mismatch", "query_or_fragment",
] as const;

function isPluginPlatformErrorCode(value: unknown): value is PluginPlatformErrorCode {
  return typeof value === "string" && (pluginPlatformErrorCodes as readonly string[]).includes(value);
}

function isPlatformErrorDetails(code: PluginPlatformErrorCode, value: unknown): value is Record<string, unknown> {
  if (code === "PLUGIN_MANAGEMENT_REVISION_MISMATCH") {
    return hasExactKeys(value, ["plugin_instance_id", "expected_management_revision", "actual_management_revision"]) &&
      typeof value.plugin_instance_id === "string" && value.plugin_instance_id.length > 0 &&
      Number.isSafeInteger(value.expected_management_revision) && Number(value.expected_management_revision) >= 1 &&
      Number.isSafeInteger(value.actual_management_revision) && Number(value.actual_management_revision) >= 1;
  }
  if (code === "PLUGIN_AUTHORIZATION_REVISION_MISMATCH") {
    return hasExactKeys(value, [
      "plugin_instance_id",
      "expected_policy_revision",
      "actual_policy_revision",
      "expected_management_revision",
      "actual_management_revision",
      "expected_revoke_epoch",
      "actual_revoke_epoch",
    ]) &&
      typeof value.plugin_instance_id === "string" && value.plugin_instance_id.length > 0 &&
      Number.isSafeInteger(value.expected_policy_revision) && Number(value.expected_policy_revision) >= 1 &&
      Number.isSafeInteger(value.actual_policy_revision) && Number(value.actual_policy_revision) >= 1 &&
      Number.isSafeInteger(value.expected_management_revision) && Number(value.expected_management_revision) >= 1 &&
      Number.isSafeInteger(value.actual_management_revision) && Number(value.actual_management_revision) >= 1 &&
      Number.isSafeInteger(value.expected_revoke_epoch) && Number(value.expected_revoke_epoch) >= 0 &&
      Number.isSafeInteger(value.actual_revoke_epoch) && Number(value.actual_revoke_epoch) >= 0;
  }
  if (code === "PLUGIN_BINDING_REVISION_MISMATCH") {
    return hasExactKeys(value, ["plugin_instance_id", "expected_binding_revision", "actual_binding_revision"]) &&
      typeof value.plugin_instance_id === "string" && value.plugin_instance_id.length > 0 &&
      Number.isSafeInteger(value.expected_binding_revision) && Number(value.expected_binding_revision) >= 1 &&
      Number.isSafeInteger(value.actual_binding_revision) && Number(value.actual_binding_revision) >= 1;
  }
  if (code === "PLUGIN_VALUES_REVISION_MISMATCH") {
    return hasExactKeys(value, ["plugin_instance_id", "expected_values_revision", "actual_values_revision"]) &&
      typeof value.plugin_instance_id === "string" && value.plugin_instance_id.length > 0 &&
      Number.isSafeInteger(value.expected_values_revision) && Number(value.expected_values_revision) >= 1 &&
      Number.isSafeInteger(value.actual_values_revision) && Number(value.actual_values_revision) >= 1;
  }
  if (code === "PLUGIN_CAPABILITY_ERROR") {
    return hasAllowedKeys(value, ["capability_id", "capability_version", "detail_schema_sha256", "business_error_code", "business_error_details"]) &&
      hasRequiredKeys(value, ["capability_id", "capability_version", "detail_schema_sha256", "business_error_code"]) &&
      typeof value.capability_id === "string" && value.capability_id.length > 0 &&
      typeof value.capability_version === "string" && value.capability_version.length > 0 &&
      typeof value.detail_schema_sha256 === "string" && /^[0-9a-f]{64}$/.test(value.detail_schema_sha256) &&
      typeof value.business_error_code === "string" && /^[A-Z][A-Z0-9_]*$/.test(value.business_error_code) &&
      (value.business_error_details === undefined || isRecord(value.business_error_details));
  }
  if (code === "PLUGIN_WORKER_ERROR") {
    return hasExactKeys(value, ["worker_error_code", "worker_error_message", "worker_error_origin"]) &&
      typeof value.worker_error_code === "string" && /^[A-Z][A-Z0-9_]*$/.test(value.worker_error_code) &&
      typeof value.worker_error_message === "string" && value.worker_error_message.length > 0 &&
      Array.from(value.worker_error_message).length <= 4096 &&
      ["runtime", "hostcall", "plugin"].includes(String(value.worker_error_origin));
  }
  if (code === "PLUGIN_JSON_LIMIT_EXCEEDED") {
    return hasExactKeys(value, ["reason"]) &&
      typeof value.reason === "string" && (jsonLimitReasons as readonly string[]).includes(value.reason);
  }
  if ((packageValidationErrorCodes as readonly string[]).includes(code)) {
    return hasAllowedKeys(value, ["reason", "path", "pointer"]) &&
      hasRequiredKeys(value, ["reason"]) &&
      typeof value.reason === "string" && (packageValidationReasons as readonly string[]).includes(value.reason) &&
      (value.path === undefined || typeof value.path === "string") &&
      (value.pointer === undefined || typeof value.pointer === "string");
  }
  return hasExactKeys(value, []);
}

function hasRequiredKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((key) => Object.hasOwn(value, key));
}
