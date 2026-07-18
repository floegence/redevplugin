import type {
  PluginBridgeClient,
  PluginBridgeRequestOptions,
  PluginJSONObject,
} from "./surface.js";

export type PluginBridgeCapabilityEffect = "read" | "write" | "execute" | "delete" | "admin";

export const pluginBridgeCapabilityEffect = Symbol("redevplugin.capability.effect");

export type PluginBridgeCapabilityRequestOptions = PluginBridgeRequestOptions & {
  [pluginBridgeCapabilityEffect]: PluginBridgeCapabilityEffect;
};

export function callPluginBridgeCapability<T>(
  bridge: PluginBridgeClient,
  method: string,
  params: PluginJSONObject | undefined,
  effect: PluginBridgeCapabilityEffect,
  options: PluginBridgeRequestOptions = {},
): Promise<T> {
  const capabilityOptions: PluginBridgeCapabilityRequestOptions = {
    signal: options.signal,
    [pluginBridgeCapabilityEffect]: effect,
  };
  return bridge.call<T>(method, params, capabilityOptions);
}
