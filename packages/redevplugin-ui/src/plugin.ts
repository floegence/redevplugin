export { PluginBridgeClient } from "./surface.js";
export { PluginBridgeError } from "./errors.js";
export { surfaceAPIMajor } from "./contracts.gen.js";
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
  PluginBridgeRequestOptions,
  PluginCanvasAccessibilityState,
  PluginCanvasInputEvent,
  PluginCanvasKeyEvent,
  PluginCanvasPointerEvent,
  PluginCanvasResizeEvent,
  PluginCanvasSurface,
  PluginJSONObject,
  PluginJSONValue,
  PluginMethodResult,
  PluginExecutionFailureCode,
  PluginExecutionSnapshot,
  PluginExecutionProgress,
  PluginExecutionEvent,
  PluginExecutionEventList,
  PluginSurfaceContext,
  PluginUIActionEvent,
  PluginUIAttributeValue,
  PluginUIElementVNode,
  PluginUIPatchOperation,
  PluginUIVNode,
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
