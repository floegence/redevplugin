import { PluginBridgeError } from "./errors.js";
import { observePluginExecution, type PluginExecution } from "./capability-client.js";
import type { PluginBridgeClient, PluginBridgeRequestOptions, PluginJSONObject, PluginExecutionEvent, PluginMethodResult } from "./surface.js";

export type PluginActionContract = Readonly<{ method: string; execution: "sync" | "operation" | "subscription"; cancelable: boolean }>;
export type PluginActionStream<T> = PluginExecution<T> & {
  read(options?: PluginBridgeRequestOptions): Promise<{ events: PluginExecutionEvent[]; cursor: number }>;
};

function result<T>(value: PluginMethodResult<T>, execution: PluginActionContract["execution"]): PluginMethodResult<T> {
  if (!value || typeof value !== "object" || !("data" in value) || value.confirmation_required ||
      (execution !== "sync" && (typeof value.execution_id !== "string" || !value.execution_id.startsWith("execution_")))) {
    throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Action returned an invalid execution envelope");
  }
  return value;
}

/** Calls the manifest route. Host validation remains authoritative for both schemas. */
export async function callPluginActionSync<T>(bridge: PluginBridgeClient, contract: PluginActionContract, request: PluginJSONObject, options: PluginBridgeRequestOptions = {}): Promise<T> {
  if (contract.execution !== "sync") throw new TypeError("Expected a synchronous action");
  return result(await bridge.call<PluginMethodResult<T>>(contract.method, request, options), "sync").data;
}

export async function callPluginActionOperation<T, Cancelable extends boolean>(bridge: PluginBridgeClient, contract: PluginActionContract & { cancelable: Cancelable }, request: PluginJSONObject, options: PluginBridgeRequestOptions = {}): Promise<PluginExecution<T, Cancelable>> {
  if (contract.execution !== "operation") throw new TypeError("Expected an operation action");
  const value = result(await bridge.call<PluginMethodResult<T>>(contract.method, request, options), "operation");
  const id = value.execution_id!;
  return Object.freeze({ data: value.data, execution_id: id, ...observePluginExecution(bridge, id),
    ...(contract.cancelable ? { cancel: (reason?: string, opts?: PluginBridgeRequestOptions) => bridge.cancelExecution(id, reason, opts) } : {}),
  }) as PluginExecution<T, Cancelable>;
}

/** A cursor is a resume position, never authority to read another execution. */
export function observePluginActionEvents(bridge: PluginBridgeClient, executionID: string, after = 0) {
  if (!Number.isSafeInteger(after) || after < 0) throw new TypeError("Invalid execution cursor");
  const observation = observePluginExecution(bridge, executionID);
  let cursor = after;
  let reading = false;
  return Object.freeze({ ...observation,
    async read(options: PluginBridgeRequestOptions = {}): Promise<{ events: PluginExecutionEvent[]; cursor: number }> {
      if (reading) throw new TypeError("Wait for the current event read before starting another");
      reading = true;
      try {
        const batch = await bridge.executionEvents(executionID, cursor, options);
        if (batch.execution_id !== executionID || !Number.isSafeInteger(batch.cursor) || batch.cursor < cursor || !Array.isArray(batch.events)) {
          throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Invalid execution event cursor");
        }
        let last = cursor;
        for (const event of batch.events) {
          if (event.execution_id !== executionID || !Number.isSafeInteger(event.sequence) || event.sequence <= last || event.sequence > batch.cursor) {
            throw new PluginBridgeError("PLUGIN_CONTRACT_MISMATCH", "Invalid execution event sequence");
          }
          last = event.sequence;
        }
        cursor = batch.cursor;
        return { events: batch.events, cursor };
      } finally { reading = false; }
    },
  });
}

export async function callPluginActionStream<T>(bridge: PluginBridgeClient, contract: PluginActionContract, request: PluginJSONObject, options: PluginBridgeRequestOptions = {}): Promise<PluginActionStream<T>> {
  if (contract.execution !== "subscription") throw new TypeError("Expected a subscription action");
  const value = result(await bridge.call<PluginMethodResult<T>>(contract.method, request, options), "subscription");
  const id = value.execution_id!;
  return Object.freeze({ data: value.data, execution_id: id, ...observePluginActionEvents(bridge, id),
    cancel: (reason?: string, opts?: PluginBridgeRequestOptions) => bridge.cancelExecution(id, reason, opts),
  });
}
