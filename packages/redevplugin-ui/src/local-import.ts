import { defaultFetch, readMutationPlatformResponse, trimTrailingSlash, type FetchLike } from "./http.js";
import { PluginPlatformRequestError, PluginTransportError } from "./errors.js";
import type { PluginPlatformClientOptions, PluginRecord } from "./platform.js";
import {
  defaultPluginSurfaceScope,
  disposePluginSurfaceScope,
  type PluginSurfaceScope,
} from "./surface-scope.js";

export type PluginUploadProgress = (uploadedBytes: number, totalBytes: number) => void;

export type PluginLocalImportOptions = {
  signal?: AbortSignal;
  onProgress?: PluginUploadProgress;
};

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

  importLocalPackage(pluginInstanceId: string, packageBlob: Blob, options: PluginLocalImportOptions = {}): Promise<PluginRecord> {
    const canonicalPluginInstanceId = pluginInstanceId.trim();
    if (!canonicalPluginInstanceId) {
      throw new TypeError("pluginInstanceId is required");
    }
    return this.#requestMutation(
      `/_redevplugin/api/plugins/local-imports?plugin_instance_id=${encodeURIComponent(canonicalPluginInstanceId)}`,
      packageBlob,
      options,
    );
  }

  async updateLocalPackage(pluginInstanceId: string, expectedManagementRevision: number, packageBlob: Blob, options: PluginLocalImportOptions = {}): Promise<PluginRecord> {
    try {
      const plugin = await this.#requestMutation<PluginRecord>(
        `/_redevplugin/api/plugins/${encodeURIComponent(pluginInstanceId)}/local-import?expected_management_revision=${encodeURIComponent(String(expectedManagementRevision))}`,
        packageBlob,
        options,
      );
      disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
      return plugin;
    } catch (error) {
      if (!(error instanceof PluginPlatformRequestError && error.mutationOutcome === "not_committed")) {
        disposePluginSurfaceScope(this.#surfaceScope, pluginInstanceId);
        this.#onMutationOutcomeUnknown?.(pluginInstanceId);
      }
      throw error;
    }
  }

  async #requestMutation<T>(path: string, body: Blob, options: PluginLocalImportOptions): Promise<T> {
    if (!(body instanceof Blob)) {
      throw new TypeError("package upload must be a Blob");
    }
    options.onProgress?.(0, body.size);
    let response;
    try {
      response = await this.#fetch(this.#apiBaseURL + path, {
        method: path.includes("/local-import?") ? "PUT" : "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/vnd.redevplugin.package+zip",
        },
        body,
        credentials: "same-origin",
        signal: options.signal,
      });
    } catch (cause) {
      throw new PluginTransportError(`Plugin platform request failed for POST ${path}`, cause, "unknown");
    }
    const result = await readMutationPlatformResponse<T>(response);
    options.onProgress?.(body.size, body.size);
    return result;
  }
}
