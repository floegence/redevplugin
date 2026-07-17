import { defaultFetch, readMutationPlatformResponse, trimTrailingSlash, type FetchLike } from "./http.js";
import { PluginPlatformRequestError, PluginTransportError } from "./errors.js";
import type { components } from "./openapi.gen.js";
import type { PluginPlatformClientOptions, PluginRecord } from "./platform.js";
import {
  defaultPluginSurfaceScope,
  disposePluginSurfaceScope,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export type PluginImportLocalPackageRequest = components["schemas"]["ImportLocalPackageRequest"];
export type PluginUpdateLocalPackageRequest = components["schemas"]["UpdateLocalPackageRequest"];

export class PluginLocalImportClient {
  #fetch: FetchLike;
  #apiBaseURL: string;
  #surfaceScope: PluginSurfaceScope;
  #onMutationOutcomeUnknown?: (pluginInstanceId?: string) => void;

  constructor(options: PluginPlatformClientOptions = {}) {
    this.#fetch = options.fetch ?? defaultFetch();
    this.#apiBaseURL = trimTrailingSlash(options.apiBaseURL ?? "");
    this.#surfaceScope = options.surfaceScope ?? defaultPluginSurfaceScope;
    this.#onMutationOutcomeUnknown = options.onMutationOutcomeUnknown;
  }

  importLocalPackage(request: PluginImportLocalPackageRequest): Promise<PluginRecord> {
    return this.#requestMutation("/_redevplugin/api/plugins/local-import/install", request);
  }

  async updateLocalPackage(request: PluginUpdateLocalPackageRequest): Promise<PluginRecord> {
    try {
      const plugin = await this.#requestMutation<PluginRecord>("/_redevplugin/api/plugins/local-import/update", request);
      disposePluginSurfaceScope(this.#surfaceScope, request.plugin_instance_id);
      return plugin;
    } catch (error) {
      if (!(error instanceof PluginPlatformRequestError && error.mutationOutcome === "not_committed")) {
        disposePluginSurfaceScope(this.#surfaceScope, request.plugin_instance_id);
        this.#onMutationOutcomeUnknown?.(request.plugin_instance_id);
      }
      throw error;
    }
  }

  async #requestMutation<T>(path: string, body: unknown): Promise<T> {
    let response;
    try {
      response = await this.#fetch(this.#apiBaseURL + path, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request failed for POST ${path}`, cause, "unknown");
    }
    return readMutationPlatformResponse<T>(response);
  }
}
