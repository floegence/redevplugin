import {
  assertMutationDispatchable,
  defaultFetch,
  dispatchMutationRequest,
  readMutationPlatformResponse,
  trimTrailingSlash,
  type FetchLike,
} from "./http.js";
import {
  PluginMutationLifecycleError,
  pluginMutationOutcome,
} from "./errors.js";
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
      "POST",
      `/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import`,
      packageBlob,
      options,
    );
  }

  async updateLocalPackage(pluginInstanceId: string, expectedManagementRevision: number, packageBlob: Blob, options: PluginLocalImportOptions = {}): Promise<PluginRecord> {
    const canonicalPluginInstanceId = pluginInstanceId.trim();
    if (!canonicalPluginInstanceId) {
      throw new TypeError("pluginInstanceId is required");
    }
    if (!Number.isSafeInteger(expectedManagementRevision) || expectedManagementRevision <= 0) {
      throw new TypeError("expectedManagementRevision must be a positive safe integer");
    }
    let plugin: PluginRecord;
    try {
      plugin = await this.#requestMutation<PluginRecord>(
        "PUT",
        `/_redevplugin/api/plugins/${encodeURIComponent(canonicalPluginInstanceId)}/local-import`,
        packageBlob,
        options,
        { "X-ReDevPlugin-Expected-Management-Revision": String(expectedManagementRevision) },
      );
    } catch (error) {
      if (pluginMutationOutcome(error) !== "not_committed") {
        const lifecycleErrors: unknown[] = [];
        try {
          await disposePluginSurfaceScope(this.#surfaceScope, canonicalPluginInstanceId);
        } catch (caught) {
          lifecycleErrors.push(caught);
        }
        try {
          this.#onMutationOutcomeUnknown?.(canonicalPluginInstanceId);
        } catch (caught) {
          lifecycleErrors.push(caught);
        }
        if (lifecycleErrors.length > 0) {
          throw new PluginMutationLifecycleError("Local plugin update and surface teardown failed", error, lifecycleErrors);
        }
      }
      throw error;
    }
    await disposePluginSurfaceScope(this.#surfaceScope, canonicalPluginInstanceId);
    return plugin;
  }

  async #requestMutation<T>(
    method: "POST" | "PUT",
    path: string,
    body: Blob,
    options: PluginLocalImportOptions,
    metadataHeaders: Record<string, string> = {},
  ): Promise<T> {
    if (!(body instanceof Blob)) {
      throw new TypeError("package upload must be a Blob");
    }
    const operation = `${method} ${path}`;
    assertMutationDispatchable(options.signal, operation);
    options.onProgress?.(0, body.size);
    const response = await dispatchMutationRequest(this.#fetch, this.#apiBaseURL + path, {
      method,
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/vnd.redevplugin.package+zip",
        ...metadataHeaders,
      },
      body,
      credentials: "same-origin",
      signal: options.signal,
    }, operation);
    const result = await readMutationPlatformResponse<T>(response);
    options.onProgress?.(body.size, body.size);
    return result;
  }
}
