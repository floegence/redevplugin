import { securitySummarySchemas, type ExternalPackageSecuritySummary } from "./security-summary.gen.js";

type Schema = {
  ref?: string; type?: string; const?: unknown; enum?: readonly unknown[];
  properties?: Readonly<Record<string, Schema>>; required?: readonly string[];
  additionalProperties?: boolean; items?: Schema; uniqueItems?: boolean;
  minItems?: number; maxItems?: number; minLength?: number; maxLength?: number;
  minimum?: number; maximum?: number; pattern?: string;
};
const schemas: Readonly<Record<string, Schema>> = securitySummarySchemas;

/** Validate verifier evidence and return a detached value in canonical field order. */
export function normalizeSecuritySummary(value: unknown): ExternalPackageSecuritySummary {
  return normalize(value, schemas.ExternalPackageSecuritySummary, "security_summary") as ExternalPackageSecuritySummary;
}

/** Encode the complete declaration payload, excluding only its own digest. */
export function canonicalSecuritySummaryJSON(value: unknown): string {
  const payload = Object.fromEntries(Object.entries(normalizeSecuritySummary(value)).filter(([key]) => key !== "summary_sha256"));
  return goJSON(payload);
}

export async function securitySummarySHA256(value: unknown): Promise<string> {
  return sha256(canonicalSecuritySummaryJSON(value));
}

export async function capabilityContractSetSHA256(value: unknown): Promise<string> {
  return sha256(goJSON(normalizeSecuritySummary(value).capability_contracts));
}

function normalize(value: unknown, schema: Schema, path: string): unknown {
  if (schema.ref) return normalize(value, schemas[schema.ref], path);
  const invalid = (): never => { throw new TypeError(`${path} does not match the security summary contract`); };
  if (schema.const !== undefined && value !== schema.const) invalid();
  if (schema.enum && !schema.enum.includes(value)) invalid();
  if (schema.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return invalid();
    const input = value as Record<string, unknown>;
    const properties = schema.properties!;
    for (const key of Object.keys(input)) if (!Object.hasOwn(properties, key)) invalid();
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(properties)) {
      if (!Object.hasOwn(input, key)) {
        if (schema.required?.includes(key)) invalid();
      } else result[key] = normalize(input[key], child, `${path}.${key}`);
    }
    return result;
  }
  if (schema.type === "array") {
    if (!Array.isArray(value)) return invalid();
    if (schema.minItems !== undefined && value.length < schema.minItems || schema.maxItems !== undefined && value.length > schema.maxItems) invalid();
    const result = Array.from(value, (item, index) => normalize(item, schema.items!, `${path}[${index}]`));
    if (schema.uniqueItems && new Set(result.map(item => JSON.stringify(item))).size !== result.length) invalid();
    return result;
  }
  if (schema.type === "string") {
    if (typeof value !== "string" || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) return invalid();
    const length = [...value].length;
    if (schema.minLength !== undefined && length < schema.minLength || schema.maxLength !== undefined && length > schema.maxLength) invalid();
    if (schema.pattern && new RegExp(schema.pattern, "u").exec(value)?.[0] !== value) invalid();
  } else if (schema.type === "integer") {
    if (typeof value !== "number" || !Number.isSafeInteger(value)) return invalid();
    if (schema.minimum !== undefined && value < schema.minimum || schema.maximum !== undefined && value > schema.maximum) invalid();
  } else if (schema.type === "boolean" && typeof value !== "boolean") invalid();
  return value;
}

// Match encoding/json's HTML-safe strings, including JavaScript line separators.
function goJSON(value: unknown): string {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/gu, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
async function sha256(value: string): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return `sha256:${Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("")}`;
}
