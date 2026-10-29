/** A connector-scoped base URL for the application's own HTTP client. */
export interface PluginWebConnection {
  readonly connectorId: string;
  readonly connectionId: string;
  readonly baseURL: string;
  readonly httpMethods: readonly string[];
}
export interface PluginConnectionOptions {
  /** Index in the signed fixed destination list; configurable connectors use 0. */
  readonly destinationIndex?: number;
  readonly signal?: AbortSignal;
}
/**
 * Discover a connection using the current child-origin session. Use native fetch,
 * Request and Response with baseURL. This helper never replaces window.fetch,
 * grants permission, retries a failed mutation, or exposes host credentials.
 */
export async function openPluginConnection(connectorId: string, options: PluginConnectionOptions = {}): Promise<PluginWebConnection> {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(connectorId)) throw new TypeError("Invalid connector ID");
  const index = options.destinationIndex ?? 0;
  if (!Number.isSafeInteger(index) || index < 0) throw new TypeError("Invalid destination index");
  const endpoint = new URL("/_redevplugin_web/connection", globalThis.location.origin);
  endpoint.searchParams.set("connector_id", connectorId);
  endpoint.searchParams.set("destination_index", String(index));
  const response = await fetch(endpoint, { signal: options.signal, credentials: "same-origin", redirect: "error", cache: "no-store" });
  if (!response.ok) throw new Error("Connection unavailable; review its configuration and permissions");
  const value: unknown = await response.json();
  if (!value || typeof value !== "object") throw new Error("Invalid connection response");
  const item = value as Record<string, unknown>;
  if (item.connector_id !== connectorId || typeof item.connection_id !== "string" || !/^(?:fixed-[0-9]+|[a-f0-9]{64})$/.test(item.connection_id) || !Array.isArray(item.http_methods) || item.http_methods.length === 0 || !item.http_methods.every(method => typeof method === "string" && /^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)$/.test(method))) throw new Error("Invalid connection response");
  const expected = "/_redevplugin_web/connections/" + encodeURIComponent(connectorId) + "/" + item.connection_id + "/";
  if (item.base_path !== expected) throw new Error("Invalid connection base URL");
  return Object.freeze({ connectorId, connectionId: item.connection_id, baseURL: new URL(expected, endpoint).href, httpMethods: Object.freeze([...item.http_methods] as string[]) });
}
