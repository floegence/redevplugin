export { PluginBridgeClient } from "./surface.js";
export { PluginBridgeError } from "./errors.js";
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
  PluginJSONObject,
  PluginJSONValue,
  PluginMethodResult,
  PluginStreamTerminalStatus,
  PluginUIActionEvent,
  PluginUIAttributeValue,
  PluginUIVNode,
} from "./surface.js";

export type {
  PluginCapabilitySchema,
  PluginCapabilityStreamEvent,
  PluginCapabilityStreamReadResult,
  PluginOperation,
  PluginStream,
} from "./capability-client.js";
