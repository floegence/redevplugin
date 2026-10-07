import { callCapabilitySync, type PluginCapabilitySyncContract } from "./capability-client.js";
import type { PluginBridgeClient, PluginBridgeRequestOptions } from "./surface.js";

export type PluginProcessResourceLimits = Readonly<{
  output_buffer_bytes?: number;
  max_runtime_ms?: number;
}>;

export type PluginProcessStartRequest = Readonly<{
  program: string;
  argv?: readonly string[];
  cwd?: string;
  environment?: Readonly<Record<string, string>>;
  environment_removals?: readonly string[];
  secret_references?: Readonly<Record<string, string>>;
  client_key: string;
  resource_limits?: PluginProcessResourceLimits;
}>;

export type PluginProcessStatus = Readonly<{
  handle: string;
  client_key: string;
  state: "starting" | "running" | "exited" | string;
  exit_code?: number;
  termination_reason?: string;
}>;

export type PluginProcessReadResult = Readonly<{
  data_base64: string;
  cursor: number;
  eof: boolean;
  process_exit: boolean;
  stream_gap: boolean;
  dropped_bytes?: number;
}>;

export type PluginProcessExitResult = Readonly<{
  exit_code?: number;
  termination_reason: string;
}>;

export type PluginProcessMethodContracts = Readonly<{
  start: PluginCapabilitySyncContract;
  attach: PluginCapabilitySyncContract;
  status: PluginCapabilitySyncContract;
  writeStdin: PluginCapabilitySyncContract;
  closeStdin: PluginCapabilitySyncContract;
  readStdout: PluginCapabilitySyncContract;
  readStderr: PluginCapabilitySyncContract;
  wait: PluginCapabilitySyncContract;
  terminate: PluginCapabilitySyncContract;
  kill: PluginCapabilitySyncContract;
  close: PluginCapabilitySyncContract;
}>;

export function createPluginProcessClient(bridge: PluginBridgeClient, contracts: PluginProcessMethodContracts) {
  return {
    start(request: PluginProcessStartRequest, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<PluginProcessStartRequest, PluginProcessStatus>(bridge, contracts.start, request, options);
    },
    attach(request: Readonly<{ client_key: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, PluginProcessStatus>(bridge, contracts.attach, request, options);
    },
    status(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, PluginProcessStatus>(bridge, contracts.status, request, options);
    },
    writeStdin(request: Readonly<{ handle: string; data_base64: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, Readonly<{ written: number }>>(bridge, contracts.writeStdin, request, options);
    },
    closeStdin(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, Readonly<{ ok: boolean }>>(bridge, contracts.closeStdin, request, options);
    },
    readStdout(request: Readonly<{ handle: string; cursor?: number; max_bytes: number }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, PluginProcessReadResult>(bridge, contracts.readStdout, request, options);
    },
    readStderr(request: Readonly<{ handle: string; cursor?: number; max_bytes: number }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, PluginProcessReadResult>(bridge, contracts.readStderr, request, options);
    },
    wait(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, PluginProcessExitResult>(bridge, contracts.wait, request, options);
    },
    terminate(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, Readonly<{ ok: boolean }>>(bridge, contracts.terminate, request, options);
    },
    kill(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, Readonly<{ ok: boolean }>>(bridge, contracts.kill, request, options);
    },
    close(request: Readonly<{ handle: string }>, options?: PluginBridgeRequestOptions) {
      return callCapabilitySync<typeof request, Readonly<{ ok: boolean }>>(bridge, contracts.close, request, options);
    },
  };
}
