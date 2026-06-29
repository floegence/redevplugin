export type BridgeLifecycleEvent =
  | { type: "ready" }
  | { type: "visible" }
  | { type: "hidden" }
  | { type: "dispose" };

export type PluginBridgeHandshake = {
  type: "redeven.plugin.handshake";
  plugin_id: string;
  surface_id: string;
  surface_instance_id: string;
  active_fingerprint: string;
  bridge_nonce: string;
  ui_protocol_version: "plugin-ui-v1";
};

export type PluginBridgeRequest = {
  id: string;
  method: string;
  params?: unknown;
};

export type PluginBridgeResponse =
  | { id: string; ok: true; data?: unknown }
  | { id: string; ok: false; error_code: string; error: string };

export type PluginSurfaceBootstrap = {
  pluginId: string;
  surfaceId: string;
  surfaceInstanceId: string;
  activeFingerprint: string;
  bridgeNonce: string;
};

export class PluginBridgeClient {
  readonly bootstrap: PluginSurfaceBootstrap;
  #nextID = 1;
  #target: Window;

  constructor(bootstrap: PluginSurfaceBootstrap, target: Window = window.parent) {
    this.bootstrap = bootstrap;
    this.#target = target;
  }

  handshake(): void {
    const message: PluginBridgeHandshake = {
      type: "redeven.plugin.handshake",
      plugin_id: this.bootstrap.pluginId,
      surface_id: this.bootstrap.surfaceId,
      surface_instance_id: this.bootstrap.surfaceInstanceId,
      active_fingerprint: this.bootstrap.activeFingerprint,
      bridge_nonce: this.bootstrap.bridgeNonce,
      ui_protocol_version: "plugin-ui-v1",
    };
    this.#target.postMessage(message, "*");
  }

  call(method: string, params?: unknown): PluginBridgeRequest {
    const request: PluginBridgeRequest = {
      id: String(this.#nextID++),
      method,
      params,
    };
    this.#target.postMessage({ type: "redeven.plugin.call", request }, "*");
    return request;
  }
}

