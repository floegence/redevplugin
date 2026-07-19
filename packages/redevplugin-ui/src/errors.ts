export {
  pluginBridgeErrorCodes,
  pluginClientErrorCodes,
  pluginPlatformErrorCodes,
  runtimeProcessFailureCodes,
} from "./error-codes.gen.js";
import {
  pluginBridgeErrorCodes,
  pluginClientErrorCodes,
  pluginPlatformErrorCodes,
  runtimeProcessFailureCodes,
} from "./error-codes.gen.js";

export type PluginPlatformErrorCode = typeof pluginPlatformErrorCodes[number];
export type PluginBridgeErrorCode = typeof pluginBridgeErrorCodes[number];
export type PluginClientErrorCode = typeof pluginClientErrorCodes[number];
export type RuntimeProcessFailureCode = typeof runtimeProcessFailureCodes[number];

export type PluginMutationOutcome = "not_committed" | "unknown";

export class PluginPlatformRequestError extends Error {
  readonly errorCode: PluginPlatformErrorCode;
  readonly details: Record<string, unknown>;
  readonly mutationOutcome?: PluginMutationOutcome;

  constructor(
    errorCode: PluginPlatformErrorCode,
    message: string,
    details: Record<string, unknown> = {},
    mutationOutcome?: PluginMutationOutcome,
  ) {
    super(message);
    this.name = "PluginPlatformRequestError";
    this.errorCode = errorCode;
    this.details = details;
    this.mutationOutcome = mutationOutcome;
  }
}

export class PluginTransportError extends Error {
  readonly mutationOutcome?: PluginMutationOutcome;
  override readonly cause: unknown;

  constructor(message: string, cause: unknown, mutationOutcome?: PluginMutationOutcome) {
    super(message, { cause });
    this.name = "PluginTransportError";
    this.cause = cause;
    this.mutationOutcome = mutationOutcome;
  }
}

export class PluginBridgeError extends Error {
  readonly errorCode: string;
  readonly data?: unknown;
  readonly details?: unknown;
  readonly mutationOutcome?: PluginMutationOutcome;

  constructor(
    errorCode: string,
    message: string,
    data?: unknown,
    details?: unknown,
    mutationOutcome?: PluginMutationOutcome,
  ) {
    super(message);
    this.name = "PluginBridgeError";
    this.errorCode = errorCode;
    this.data = data;
    this.details = details ?? data;
    this.mutationOutcome = mutationOutcome;
  }
}

export function pluginMutationOutcome(error: unknown): PluginMutationOutcome | undefined {
  if (error instanceof PluginPlatformRequestError ||
      error instanceof PluginTransportError ||
      error instanceof PluginBridgeError) {
    return error.mutationOutcome;
  }
  return undefined;
}

export class PluginMutationLifecycleError extends AggregateError {
  readonly mutationOutcome?: PluginMutationOutcome;

  constructor(message: string, mutationError: unknown, lifecycleErrors: readonly unknown[]) {
    super([mutationError, ...lifecycleErrors], message, { cause: mutationError });
    this.name = "PluginMutationLifecycleError";
    this.mutationOutcome = pluginMutationOutcome(mutationError);
  }
}
