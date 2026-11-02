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
  observePluginExecution,
} from "./capability-client.js";

export type {
  BridgeLifecycleEvent,
  MessagePortLike,
  PluginBridgeClientOptions,
  PluginBridgeClock,
  PluginBridgeRequestOptions,
  PluginMethodHandler,
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
  PluginExecutionObservation,
  PluginExecutionTerminalStatus,
  PluginExecutionWaitOptions,
  PluginStream,
} from "./capability-client.js";
export { openPluginConnection } from "./connections.js";
export { pluginKV, pluginFiles, pluginDatabase, pluginSettings, PluginResourceError } from "./resources.js";
export type { PluginResourceOptions, PluginResourceOutcome, PluginStorageUsage, PluginResourcePage, PluginKVEntry, PluginPrivateFileEntry, PluginSettingsSnapshot, PluginSQLiteValue } from "./resources.js";
export type { PluginWebConnection, PluginConnectionOptions } from "./connections.js";
export { callPluginActionSync, callPluginActionOperation, callPluginActionStream, observePluginActionEvents } from "./actions.js";
export type { PluginActionContract, PluginActionStream } from "./actions.js";
export { describePluginResources } from "./resources.js";
export type { PluginResourceDescription } from "./resources.js";
export { openPluginWebSocket } from "./websocket.js";
export type { PluginSocket, PluginSocketMessage } from "./websocket.js";
