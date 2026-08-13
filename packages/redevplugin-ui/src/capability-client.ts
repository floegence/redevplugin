import { PluginBridgeError } from "./errors.js";
import { callPluginBridgeCapability } from "./bridge-capability.js";
import { decodePluginEventText } from "./surface.js";
import type {
  PluginBridgeClient,
  PluginBridgeRequestOptions,
  PluginJSONObject,
  PluginExecutionEvent as PluginRawExecutionEvent,
  PluginExecutionEventList as PluginRawExecutionEventList,
  PluginExecutionSnapshot,
} from "./surface.js";

export type PluginCapabilitySchema = Readonly<Record<string, unknown>>;
export type PluginCapabilityEffect = "read" | "write" | "execute" | "delete" | "admin";

type PluginCapabilityMethodContract = {
  method: string;
  effect: PluginCapabilityEffect;
  requestSchema: PluginCapabilitySchema;
  responseSchema: PluginCapabilitySchema;
};

export type PluginCapabilitySyncContract = PluginCapabilityMethodContract & {
  execution: "sync";
};

export type PluginCapabilityOperationContract<Cancelable extends boolean = boolean> = PluginCapabilityMethodContract & {
  execution: "operation";
  cancelable: Cancelable;
};

export type PluginCapabilityStreamContract = PluginCapabilityMethodContract & {
  execution: "subscription";
  eventTypeName: string;
  eventSchema: PluginCapabilitySchema;
};

export type PluginCapabilityBusinessErrorSpec = {
  detail_schema_sha256: string;
  schema: PluginCapabilitySchema | null;
};

export type PluginExecutionWaitOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
  pollIntervalMs?: number;
};

export type PluginExecutionTerminalStatus = {
  [Status in Extract<PluginExecutionSnapshot["status"], "completed" | "failed" | "canceled" | "orphaned">]: {
    status: Status;
    snapshot: Extract<PluginExecutionSnapshot, { status: Status }>;
  }
}[Extract<PluginExecutionSnapshot["status"], "completed" | "failed" | "canceled" | "orphaned">];

type PluginExecutionObservation = {
  snapshot(options?: PluginBridgeRequestOptions): Promise<PluginExecutionSnapshot>;
  wait(options?: PluginExecutionWaitOptions): Promise<PluginExecutionTerminalStatus>;
};

export type PluginExecution<T, Cancelable extends boolean = true> = PluginExecutionObservation & {
  data: T;
  execution_id: string;
} & (Cancelable extends true ? {
  cancel(reason?: string, options?: PluginBridgeRequestOptions): Promise<void>;
} : Record<never, never>);

export type PluginCapabilityStreamEvent<Event> = Omit<PluginRawExecutionEvent, "payload" | "error"> & {
  data: Event;
};

export type PluginCapabilityStreamReadResult<Event> =
  | { events: PluginCapabilityStreamEvent<Event>[]; done: false; cursor: number }
  | { events: PluginCapabilityStreamEvent<Event>[]; done: true; cursor: number };

export type PluginStream<Initial, Event> = PluginExecutionObservation & {
  data: Initial;
  execution_id: string;
  read(options?: PluginBridgeRequestOptions): Promise<PluginCapabilityStreamReadResult<Event>>;
  cancel(reason?: string, options?: PluginBridgeRequestOptions): Promise<void>;
  [Symbol.asyncIterator](): AsyncIterableIterator<PluginCapabilityStreamEvent<Event>>;
};

export async function callCapabilitySync<Request extends object, Response>(
  bridge: PluginBridgeClient,
  contract: PluginCapabilitySyncContract,
  request: Request,
  options: PluginBridgeRequestOptions = {},
): Promise<Response> {
  const params = validateRequest(request, contract.requestSchema);
  const result = parseSyncResult(
    contract.method,
    await callPluginBridgeCapability<unknown>(bridge, contract.method, params, contract.effect, options),
  );
  return validateResponse(contract.method, result.data, contract.responseSchema);
}

export async function callCapabilityOperation<Request extends object, Response, Cancelable extends boolean = true>(
  bridge: PluginBridgeClient,
  contract: PluginCapabilityOperationContract<Cancelable>,
  request: Request,
  options: PluginBridgeRequestOptions = {},
): Promise<PluginExecution<Response, Cancelable>> {
  const params = validateRequest(request, contract.requestSchema);
  const result = parseOperationResult(
    contract.method,
    await callPluginBridgeCapability<unknown>(bridge, contract.method, params, contract.effect, options),
  );
  let data: Response;
  try {
    data = validateResponse(contract.method, result.data, contract.responseSchema);
  } catch (error) {
    if (contract.cancelable) await cancelAfterResponseMismatch(bridge, result.execution_id, error);
    throw error;
  }
  const observation = executionObservation(bridge, result.execution_id);
  return Object.freeze({
    data: data!,
    execution_id: result.execution_id,
    ...observation,
    ...(contract.cancelable ? {
      cancel: (reason?: string, cancelOptions?: PluginBridgeRequestOptions) =>
        bridge.cancelExecution(result.execution_id, reason, cancelOptions),
    } : {}),
  }) as PluginExecution<Response, Cancelable>;
}

export async function callCapabilityStream<Request extends object, Response, Event>(
  bridge: PluginBridgeClient,
  contract: PluginCapabilityStreamContract,
  request: Request,
  options: PluginBridgeRequestOptions = {},
): Promise<PluginStream<Response, Event>> {
  const params = validateRequest(request, contract.requestSchema);
  const result = parseStreamResult(
    contract.method,
    await callPluginBridgeCapability<unknown>(bridge, contract.method, params, contract.effect, options),
  );
  let data: Response;
  try {
    data = validateResponse(contract.method, result.data, contract.responseSchema);
  } catch (error) {
    return cancelAfterResponseMismatch(bridge, result.execution_id, error);
  }
  let settled = false;
  let cursor = 0;
  const read = async (options: PluginBridgeRequestOptions = {}) => {
    try {
      const batch = decodeCapabilityStreamBatch<Event>(
        contract.method,
        await bridge.executionEvents(result.execution_id, cursor, options),
        contract.eventTypeName,
        contract.eventSchema,
      );
      cursor = batch.cursor;
      if (batch.done) settled = true;
      return batch;
    } catch (error) {
      if (options.signal?.aborted && error instanceof PluginBridgeError && error.errorCode === "PLUGIN_STREAM_CANCELLED") {
        throw error;
      }
      if (error instanceof PluginBridgeError && error.errorCode === "PLUGIN_STREAM_FAILED") {
        settled = true;
        throw error;
      }
      settled = true;
      return cancelAfterStreamMismatch(bridge, result.execution_id, error);
    }
  };
  const cancel = async (reason?: string, cancelOptions: PluginBridgeRequestOptions = {}) => {
    if (settled) return;
    await bridge.cancelExecution(result.execution_id, reason, cancelOptions);
    settled = true;
  };
  const observation = executionObservation(bridge, result.execution_id);
  return Object.freeze({
    data: data!,
    execution_id: result.execution_id,
    ...observation,
    read,
    cancel,
    async *[Symbol.asyncIterator](): AsyncIterableIterator<PluginCapabilityStreamEvent<Event>> {
      try {
        while (true) {
          const batch = await read();
          for (const event of batch.events) yield event;
          if (batch.done) return;
          if (batch.events.length === 0) await new Promise((resolve) => setTimeout(resolve, 250));
        }
      } finally {
        if (!settled) await cancel("stream_iterator_closed");
      }
    },
  });
}

function executionObservation(bridge: PluginBridgeClient, executionID: string): PluginExecutionObservation {
  const snapshot = (options: PluginBridgeRequestOptions = {}) => bridge.executionSnapshot(executionID, options);
  const wait = async (options: PluginExecutionWaitOptions = {}): Promise<PluginExecutionTerminalStatus> => {
    const timeoutMs = options.timeoutMs ?? 120_000;
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 600_000) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin operation wait timeout must be between 1 second and 10 minutes");
    }
    if (options.signal?.aborted) throw operationWaitAborted();
    let pollIntervalMs = options.pollIntervalMs ?? 1_000;
    if (!Number.isFinite(pollIntervalMs)) {
      throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Plugin operation poll interval is invalid");
    }
    pollIntervalMs = Math.max(500, Math.min(10_000, pollIntervalMs));
    const deadline = Date.now() + timeoutMs;
    while (true) {
      let current: PluginExecutionSnapshot;
      try {
        current = await operationSnapshotUntilDeadline(snapshot, deadline, options.signal);
      } catch (error) {
        if (options.signal?.aborted) throw operationWaitAborted();
        throw error;
      }
      switch (current.status) {
      case "completed":
      case "failed":
      case "canceled":
      case "orphaned":
        return { status: current.status, snapshot: current } as PluginExecutionTerminalStatus;
      default:
        await operationWaitDelay(pollIntervalMs, deadline, options.signal);
        pollIntervalMs = Math.min(10_000, Math.ceil(pollIntervalMs * 1.5));
      }
    }
  };
  return { snapshot, wait };
}

async function operationSnapshotUntilDeadline(
  snapshot: (options?: PluginBridgeRequestOptions) => Promise<PluginExecutionSnapshot>,
  deadline: number,
  signal?: AbortSignal,
): Promise<PluginExecutionSnapshot> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", "Plugin operation observation timed out");
  const controller = new AbortController();
  let timedOut = false;
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, remaining);
  try {
    return await snapshot({ signal: controller.signal });
  } catch (error) {
    if (signal?.aborted) throw operationWaitAborted();
    if (timedOut) throw new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", "Plugin operation observation timed out");
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function operationWaitAborted(): PluginBridgeError {
  return new PluginBridgeError("PLUGIN_BRIDGE_CANCELLED", "Plugin operation observation was cancelled");
}

function operationWaitDelay(delayMs: number, deadline: number, signal?: AbortSignal): Promise<void> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return Promise.reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", "Plugin operation observation timed out"));
  const duration = Math.min(delayMs, remaining);
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: PluginBridgeError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else if (Date.now() >= deadline) reject(new PluginBridgeError("PLUGIN_BRIDGE_TIMEOUT", "Plugin operation observation timed out"));
      else resolve();
    };
    const timer = setTimeout(() => finish(), duration);
    const onAbort = () => finish(operationWaitAborted());
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function decodeCapabilityStreamBatch<Event>(
  method: string,
  batch: PluginRawExecutionEventList,
  eventTypeName: string,
  eventSchema: PluginCapabilitySchema,
): PluginCapabilityStreamReadResult<Event> {
  const events: PluginCapabilityStreamEvent<Event>[] = [];
  let done = false;
  for (const event of batch.events) {
    if (event.kind === "terminal") {
      const status = event.payload?.status;
      if (status !== "completed" && status !== "canceled" && status !== "failed" && status !== "orphaned") {
        throw contractMismatch(method, "stream terminal event has an invalid status");
      }
      done = true;
      if (status === "failed" || status === "orphaned") {
        throw new PluginBridgeError("PLUGIN_STREAM_FAILED", `Plugin stream terminated with status ${status}`, undefined, {
          execution_id: event.execution_id,
          status,
          failure_code: event.error?.code,
        });
      }
      continue;
    }
    events.push(decodeCapabilityStreamEvent<Event>(method, event, eventTypeName, eventSchema));
  }
  return { events, done, cursor: batch.cursor };
}

function decodeCapabilityStreamEvent<Event>(
  method: string,
  event: PluginRawExecutionEvent,
  eventTypeName: string,
  eventSchema: PluginCapabilitySchema,
): PluginCapabilityStreamEvent<Event> {
  if (event.kind !== "data" || event.error !== undefined || event.payload?.event_type !== eventTypeName || typeof event.payload.data !== "string") {
    throw contractMismatch(method, "stream event envelope does not match its published contract");
  }
  let value: unknown;
  try {
    value = JSON.parse(decodePluginEventText(event));
  } catch {
    throw contractMismatch(method, "stream event is not canonical JSON");
  }
  if (!validateValue(value, eventSchema, new Set())) {
    throw contractMismatch(method, "stream event does not match its published contract");
  }
  return Object.freeze({
    sequence: event.sequence,
    execution_id: event.execution_id,
    kind: event.kind,
    data: value as Event,
  });
}

function parseSyncResult(method: string, value: unknown): { data: unknown } {
  if (!hasExactKeys(value, ["data"])) throw contractMismatch(method, "returned an invalid sync result envelope");
  return value;
}

function parseOperationResult(method: string, value: unknown): { data: unknown; execution_id: string } {
  if (!hasExactKeys(value, ["data", "execution_id"]) || !validOpaqueIdentifier(value.execution_id, "execution")) {
    throw contractMismatch(method, "returned an invalid operation result envelope");
  }
  return { data: value.data, execution_id: value.execution_id };
}

function parseStreamResult(method: string, value: unknown): { data: unknown; execution_id: string } {
  if (!hasExactKeys(value, ["data", "execution_id"]) || !validOpaqueIdentifier(value.execution_id, "execution")) {
    throw contractMismatch(method, "returned an invalid subscription result envelope");
  }
  return { data: value.data, execution_id: value.execution_id };
}

async function cancelAfterResponseMismatch(bridge: PluginBridgeClient, executionID: string, mismatch: unknown): Promise<never> {
  try {
    await bridge.cancelExecution(executionID, "response_contract_mismatch");
  } catch (cleanupError) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Capability response failed validation and its live operation could not be cancelled", undefined, {
      execution_id: executionID,
      cleanup_error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
    });
  }
  throw mismatch;
}

async function cancelAfterStreamMismatch(bridge: PluginBridgeClient, executionID: string, mismatch: unknown): Promise<never> {
  try {
    await bridge.cancelExecution(executionID, "stream_contract_mismatch");
  } catch (cleanupError) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Capability stream failed validation and its live operation could not be cancelled", undefined, {
      execution_id: executionID,
      cleanup_error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
    });
  }
  throw mismatch;
}

export function isCapabilityBusinessError(
  error: unknown,
  capabilityID: string,
  capabilityVersion: string,
  detailSchemas: Readonly<Record<string, PluginCapabilityBusinessErrorSpec>>,
): error is PluginBridgeError & { readonly details: PluginJSONObject } {
  if (!(error instanceof PluginBridgeError) || error.errorCode !== "PLUGIN_CAPABILITY_ERROR" || !isRecord(error.details)) {
    return false;
  }
  if (!Object.keys(error.details).every((key) =>
    key === "capability_id" || key === "capability_version" || key === "detail_schema_sha256" ||
    key === "business_error_code" || key === "business_error_details"
  )) {
    return false;
  }
  if (error.details.capability_id !== capabilityID || error.details.capability_version !== capabilityVersion) return false;
  const code = error.details.business_error_code;
  if (typeof code !== "string" || !Object.hasOwn(detailSchemas, code)) return false;
  const specification = detailSchemas[code];
  if (error.details.detail_schema_sha256 !== specification.detail_schema_sha256) return false;
  const schema = specification.schema;
  if (schema === null) return error.details.business_error_details === undefined;
  return isRecord(schema) && validateValue(error.details.business_error_details, schema, new Set());
}

function validateRequest(request: unknown, schema: PluginCapabilitySchema): PluginJSONObject {
  if (!validateValue(request, schema, new Set())) {
    throw new PluginBridgeError("PLUGIN_INVALID_REQUEST", "Capability request does not match its published contract");
  }
  return request as PluginJSONObject;
}

function validateResponse<Response>(method: string, value: unknown, schema: PluginCapabilitySchema): Response {
  if (!validateValue(value, schema, new Set())) {
    throw contractMismatch(method, "response does not match its published contract");
  }
  return value as Response;
}

function validateValue(value: unknown, schema: PluginCapabilitySchema, seen: Set<unknown>): boolean {
  if (Array.isArray(schema.oneOf)) {
    let matches = 0;
    for (const branch of schema.oneOf) {
      if (!isRecord(branch)) return false;
      if (validateValue(value, branch, seen)) matches += 1;
    }
    return matches === 1;
  }
  const type = schema.type;
  if (typeof type !== "string") return false;
  if (value !== null && typeof value === "object") {
    if (seen.has(value)) return false;
    seen.add(value);
  }
  try {
    switch (type) {
      case "object":
        return validateObject(value, schema, seen);
      case "array":
        return validateArray(value, schema, seen);
      case "string":
        return validateString(value, schema);
      case "integer":
        return typeof value === "number" && Number.isSafeInteger(value) && validateNumber(value, schema);
      case "number":
        return typeof value === "number" && Number.isFinite(value) && validateNumber(value, schema);
      case "boolean":
        return typeof value === "boolean" && validateConst(value, schema);
      case "null":
        return value === null;
      default:
        return false;
    }
  } finally {
    if (value !== null && typeof value === "object") seen.delete(value);
  }
}

function validateObject(value: unknown, schema: PluginCapabilitySchema, seen: Set<unknown>): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (schema.additionalProperties !== false || (schema.properties !== undefined && !isRecord(schema.properties))) return false;
  const object = value as Record<string, unknown>;
  const properties = (schema.properties ?? {}) as Record<string, unknown>;
  const required = Array.isArray(schema.required) ? schema.required : [];
  if (required.some((name) => typeof name !== "string" || !Object.hasOwn(object, name))) return false;
  const keys = Object.keys(object);
  if (keys.some((key) => prototypeSensitivePropertyNames.has(key)) ||
      Object.keys(properties).some((key) => prototypeSensitivePropertyNames.has(key))) return false;
  if (!integerBound(keys.length, schema.minProperties, schema.maxProperties)) return false;
  for (const key of keys) {
    const child = properties[key];
    if (!isRecord(child) || !validateValue(object[key], child, seen)) return false;
  }
  return true;
}

function validateArray(value: unknown, schema: PluginCapabilitySchema, seen: Set<unknown>): boolean {
  if (!Array.isArray(value) || !isRecord(schema.items)) return false;
  if (!integerBound(value.length, schema.minItems, schema.maxItems)) return false;
  if (schema.uniqueItems === true) {
    const canonical = value.map(canonicalJSONKey);
    if (new Set(canonical).size !== canonical.length) return false;
  }
  return value.every((item) => validateValue(item, schema.items as PluginCapabilitySchema, seen));
}

function validateString(value: unknown, schema: PluginCapabilitySchema): boolean {
  if (typeof value !== "string" || !integerBound(Array.from(value).length, schema.minLength, schema.maxLength) || !validateConst(value, schema)) {
    return false;
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return false;
  if (typeof schema.pattern === "string") {
    try {
      if (!isPortablePattern(schema.pattern)) return false;
      const match = new RegExp(schema.pattern, "u").exec(value);
      if (match === null || match.index !== 0 || match[0].length !== value.length) return false;
    } catch {
      return false;
    }
  }
  if (typeof schema.format === "string" && !validateStringFormat(value, schema.format)) return false;
  return true;
}

function validateStringFormat(value: string, format: string): boolean {
  switch (format) {
    case "date-time":
      return validateDateTime(value);
    case "uuid":
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
    case "hostname":
      return validateHostname(value);
    case "ipv4":
      return validateIPv4(value);
    case "ipv6":
      return validateIPv6(value);
    default:
      return false;
  }
}

function validateDateTime(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (match === null || Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59) return false;
  const month = Number(match[2]);
  const day = Number(match[3]);
  const offset = match[7];
  if (offset !== "Z") {
    const offsetHours = Number(offset.slice(1, 3));
    const offsetMinutes = Number(offset.slice(4, 6));
    if (offsetHours > 23 || offsetMinutes > 59) return false;
  }
  return Number.isFinite(Date.parse(value)) && month >= 1 && month <= 12 && day >= 1 && day <= new Date(Date.UTC(Number(match[1]), month, 0)).getUTCDate();
}

function validateHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253 || value.endsWith(".")) return false;
  return value.split(".").every((label) =>
    label.length >= 1 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)
  );
}

function validateIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) =>
    /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255
  );
}

function validateIPv6(value: string): boolean {
  if (value.length === 0 || value.includes(":::")) return false;
  const compression = value.indexOf("::");
  if (compression !== value.lastIndexOf("::")) return false;
  const [leftRaw, rightRaw = ""] = compression >= 0 ? value.split("::") : [value, ""];
  const left = leftRaw === "" ? [] : leftRaw.split(":");
  const right = rightRaw === "" ? [] : rightRaw.split(":");
  const parseSide = (parts: string[], allowIPv4: boolean): number | null => {
    let groups = 0;
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      if (part.includes(".")) {
        if (!allowIPv4 || index !== parts.length - 1 || !validateIPv4(part)) return null;
        groups += 2;
      } else {
        if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) return null;
        groups += 1;
      }
    }
    return groups;
  };
  const leftGroups = parseSide(left, right.length === 0);
  const rightGroups = parseSide(right, true);
  if (leftGroups === null || rightGroups === null) return false;
  const groups = leftGroups + rightGroups;
  return compression >= 0 ? groups < 8 : groups === 8;
}

function validateNumber(value: number, schema: PluginCapabilitySchema): boolean {
  if (!validateConst(value, schema)) return false;
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return false;
  if (typeof schema.minimum === "number" && value < schema.minimum) return false;
  if (typeof schema.maximum === "number" && value > schema.maximum) return false;
  if (typeof schema.exclusiveMinimum === "number" && value <= schema.exclusiveMinimum) return false;
  if (typeof schema.exclusiveMaximum === "number" && value >= schema.exclusiveMaximum) return false;
  if (typeof schema.multipleOf === "number" && !isJSONMultipleOf(value, schema.multipleOf)) return false;
  return true;
}

function isJSONMultipleOf(value: number, divisor: number): boolean {
  if (!Number.isFinite(divisor) || divisor <= 0) return false;
  const left = decimalCoefficient(value);
  const right = decimalCoefficient(divisor);
  if (left === null || right === null || right.coefficient === 0n) return false;
  let numerator = left.coefficient;
  let denominator = right.coefficient;
  const difference = right.scale - left.scale;
  if (difference > 0) numerator *= 10n ** BigInt(difference);
  if (difference < 0) denominator *= 10n ** BigInt(-difference);
  return numerator % denominator === 0n;
}

function decimalCoefficient(value: number): { coefficient: bigint; scale: number } | null {
  if (!Number.isFinite(value)) return null;
  let text = String(value).toLowerCase();
  let sign = 1n;
  if (text.startsWith("-")) {
    sign = -1n;
    text = text.slice(1);
  }
  let exponent = 0;
  const exponentIndex = text.indexOf("e");
  if (exponentIndex >= 0) {
    exponent = Number(text.slice(exponentIndex + 1));
    if (!Number.isSafeInteger(exponent)) return null;
    text = text.slice(0, exponentIndex);
  }
  let scale = 0;
  const decimalIndex = text.indexOf(".");
  if (decimalIndex >= 0) {
    scale = text.length - decimalIndex - 1;
    text = text.slice(0, decimalIndex) + text.slice(decimalIndex + 1);
  }
  text = text.replace(/^0+/, "") || "0";
  if (!/^[0-9]+$/.test(text)) return null;
  return { coefficient: BigInt(text) * sign, scale: scale - exponent };
}

function isPortablePattern(pattern: string): boolean {
  if (!pattern.startsWith("^") || !pattern.endsWith("$") || pattern.length < 3) return false;
  const body = pattern.slice(1, -1);
  let index = 0;
  let atoms = 0;
  while (index < body.length) {
    const current = body[index];
    if (current === "[") {
      const end = body.indexOf("]", index + 1);
      if (end < 0 || end === index + 1 || !/^[A-Za-z0-9._~:/-]+$/.test(body.slice(index + 1, end))) return false;
      index = end + 1;
    } else if (current === "\\") {
      if (index + 1 >= body.length || !".\\-".includes(body[index + 1])) return false;
      index += 2;
    } else {
      if (!/^[A-Za-z0-9_~:/-]$/.test(current)) return false;
      index += 1;
    }
    atoms += 1;
    if (index >= body.length) continue;
    if ("+*?".includes(body[index])) {
      index += 1;
      continue;
    }
    if (body[index] === "{") {
      const end = body.indexOf("}", index + 1);
      if (end < 0 || !/^(?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)?)?$/.test(body.slice(index + 1, end))) return false;
      index = end + 1;
    }
  }
  return atoms > 0;
}

function canonicalJSONKey(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSONKey).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSONKey(record[key])}`).join(",")}}`;
}

function validateConst(value: unknown, schema: PluginCapabilitySchema): boolean {
  return !Object.hasOwn(schema, "const") || Object.is(value, schema.const);
}

function integerBound(value: number, minimum: unknown, maximum: unknown): boolean {
  if (typeof minimum === "number" && (!Number.isSafeInteger(minimum) || value < minimum)) return false;
  if (typeof maximum === "number" && (!Number.isSafeInteger(maximum) || value > maximum)) return false;
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys<T extends string>(value: unknown, keys: readonly T[]): value is Record<T, unknown> {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validOpaqueIdentifier(value: unknown, prefix: "execution"): value is string {
  return typeof value === "string" && value.startsWith(`${prefix}_`) && value.length >= 8 && value.length <= 160 && /^[-A-Za-z0-9_]+$/.test(value);
}

const prototypeSensitivePropertyNames = new Set(["__proto__", "constructor", "prototype"]);

function contractMismatch(method: string, detail: string): PluginBridgeError {
  return new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", `Capability method ${method} ${detail}`);
}
