import { parseDocument } from "yaml";

const DEFAULT_MAX_BYTES = 64 * 1024;

export function parseStrictJSON(raw, label, maxBytes = DEFAULT_MAX_BYTES) {
  const bytes = toBuffer(raw, label);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || bytes.length === 0 || bytes.length > maxBytes) {
    throw new Error(`${label} must contain 1..${maxBytes} bytes`);
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new Error(`${label} must not contain a UTF-8 byte-order mark`);
  }
  const text = decodeUTF8(bytes, label);
  const document = parseDocument(text, {
    schema: "json",
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    throw new Error(`${label} contains duplicate or invalid JSON keys: ${document.errors[0].message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not one strict JSON document: ${error.message}`);
  }
}

function decodeUTF8(raw, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8: ${error.message}`);
  }
}

function toBuffer(raw, label) {
  if (Buffer.isBuffer(raw)) return raw;
  if (typeof raw === "string") return Buffer.from(raw, "utf8");
  if (raw instanceof Uint8Array) return Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  throw new TypeError(`${label} must be bytes or a string`);
}
