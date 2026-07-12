import { defaultFetch, readHostEnvelope, trimTrailingSlash, type FetchLike } from "./http.js";
import type { PluginPlatformClientOptions, PluginRecord } from "./platform.js";
import {
  defaultPluginSurfaceScope,
  disposePluginSurfaceScope,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export type PluginImportLocalPackageRequest = {
  package_base64: string;
  plugin_instance_id?: string;
  plugin_state_version: 0;
};

export type PluginUpdateLocalPackageRequest = {
  plugin_instance_id: string;
  package_base64: string;
  plugin_state_version: number;
};

export class PluginLocalImportClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #surfaceScope: PluginSurfaceScope;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#surfaceScope = options.surfaceScope ?? defaultPluginSurfaceScope;
  }

  importLocalPackage(request: PluginImportLocalPackageRequest): Promise<PluginRecord> {
    return this.#postJSON("/_redevplugin/api/plugins/local-import/install", request);
  }

  async updateLocalPackage(request: PluginUpdateLocalPackageRequest): Promise<PluginRecord> {
    const plugin = await this.#postJSON<PluginRecord>("/_redevplugin/api/plugins/local-import/update", request);
    disposePluginSurfaceScope(this.#surfaceScope, request.plugin_instance_id);
    return plugin;
  }

  async #postJSON<T>(path: string, body: unknown): Promise<T> {
    const response = await this.#fetch(this.#apiBaseURL + path, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      credentials: "same-origin",
    });
    return readHostEnvelope<T>(response, "PLUGIN_PLATFORM_REQUEST_FAILED");
  }
}
