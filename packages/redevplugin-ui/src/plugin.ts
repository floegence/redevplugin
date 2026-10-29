export { PluginBridgeClient } from "./surface.js";
export { PluginFilesClient, PluginFileHandle, PluginFileWriteError } from "./files.js";
export type { PluginFileResource, PluginFileSelectionOptions, PluginFileOpenOptions, PluginFileStat, PluginDirectoryEntry } from "./files.js";
export { PluginBridgeError } from "./errors.js";
export { pluginAPIMajor } from "./contracts.gen.js";
export { createPluginProcessClient } from "./process.js";
export type {
  PluginProcessExitResult,
  PluginProcessMethodContracts,
  PluginProcessReadResult,
  PluginProcessResourceLimits,
  PluginProcessStartRequest,
  PluginProcessStatus,
} from "./process.js";
export {
  callCapabilityOperation,
  callCapabilityStream,
  callCapabilitySync,
  isCapabilityBusinessError,
} from "./capability-client.js";

export type {
  BridgeLifecycleEvent,
  MessagePortLike,
  PluginBridgeClientOptions,
  PluginBridgeClock,
  PluginBridgeRequestOptions,
  PluginFileExportRequest,
  PluginJSONObject,
  PluginJSONValue,
  PluginMethodResult,
  PluginExecutionFailureCode,
  PluginExecutionSnapshot,
  PluginExecutionProgress,
  PluginExecutionEvent,
  PluginExecutionEventList,
  PluginSurfaceContext,
  PluginSurfaceFileExportMediaType,
} from "./surface.js";

export type {
  PluginCapabilitySchema,
  PluginCapabilityEffect,
  PluginCapabilityOperationContract,
  PluginCapabilityStreamContract,
  PluginCapabilitySyncContract,
  PluginCapabilityStreamEvent,
  PluginCapabilityStreamReadResult,
  PluginExecution,
  PluginExecutionTerminalStatus,
  PluginExecutionWaitOptions,
  PluginStream,
} from "./capability-client.js";
