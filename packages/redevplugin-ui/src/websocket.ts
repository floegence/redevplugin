import type { PluginConnectionOptions } from "./connections.js";

export type PluginSocketMessage = string | Uint8Array;
export interface PluginSocket extends AsyncIterable<PluginSocketMessage> {
  readonly protocol: string;
  send(data: PluginSocketMessage): Promise<void>;
  close(): void;
}

/** Uses the current Surface's authenticated connection. A closed connection is
 * never reopened automatically: application protocols decide how to resync. */
export async function openPluginWebSocket(connectorId: string, path = "/", options: PluginConnectionOptions & { protocols?: string[] } = {}): Promise<PluginSocket> {
  options.signal?.throwIfAborted();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(connectorId) || !path.startsWith("/") || path.startsWith("//") || path.includes("#") || path.length > 8192) throw new TypeError("Invalid WebSocket target");
  const index = options.destinationIndex ?? 0;
  if (!Number.isSafeInteger(index) || index < 0) throw new TypeError("Invalid destination index");
  const endpoint = new URL("/_redevplugin_web/websocket", globalThis.location.origin);
  endpoint.searchParams.set("connector_id", connectorId); endpoint.searchParams.set("destination_index", String(index));
  const response = await fetch(endpoint, { signal: options.signal, credentials: "same-origin", redirect: "error", cache: "no-store" });
  if (!response.ok) throw new Error("WebSocket unavailable; review its connection and permissions");
  const value: unknown = await response.json();
  const id = value && typeof value === "object" && "connection_id" in value ? value.connection_id : undefined;
  if (typeof id !== "string" || !/^(?:fixed-[0-9]+|[a-f0-9]{64})$/.test(id)) throw new Error("Invalid WebSocket connection response");
  endpoint.pathname += "/connect"; endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
  endpoint.searchParams.set("connection_id", id); endpoint.searchParams.set("path", path);
  options.signal?.throwIfAborted();
  const socket = new WebSocket(endpoint, options.protocols);
  socket.binaryType = "arraybuffer";
  const queue: PluginSocketMessage[] = [];
  let bytes = 0, ended = false, failure: Error | undefined, wake: (() => void) | undefined, reading = false;
  const notify = () => { wake?.(); wake = undefined; };
  const close = () => { ended = true; socket.close(1000); notify(); };
  const abort = () => { failure = new Error("WebSocket canceled"); close(); };
  options.signal?.addEventListener("abort", abort, { once: true });
  socket.addEventListener("close", event => {
    if (!ended && event.code !== 1000 && !failure) failure = new Error("WebSocket closed; reconnect explicitly and resynchronize application state");
    ended = true;
    options.signal?.removeEventListener("abort", abort); notify();
  });
  socket.addEventListener("message", event => {
    if (ended) return;
    const data = typeof event.data === "string" ? event.data : new Uint8Array(event.data as ArrayBuffer);
    const size = typeof data === "string" ? new TextEncoder().encode(data).byteLength : data.byteLength;
    if (queue.length >= 32 || bytes + size > 1024 * 1024) {
      queue.length = 0; bytes = 0; failure = new Error("WebSocket buffer overflow; resynchronize application state"); close(); return;
    }
    queue.push(data); bytes += size; notify();
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const cleanup = () => { socket.removeEventListener("open", opened); socket.removeEventListener("error", failed); socket.removeEventListener("close", failed); };
      const opened = () => { cleanup(); resolve(); };
      const failed = () => { cleanup(); reject(failure ?? new Error("WebSocket connection failed")); };
      socket.addEventListener("open", opened, { once: true }); socket.addEventListener("error", failed, { once: true }); socket.addEventListener("close", failed, { once: true });
      if (options.signal?.aborted) abort();
    });
  } catch (error) { options.signal?.removeEventListener("abort", abort); close(); throw error; }
  let sending = false;
  return Object.freeze({ protocol: socket.protocol, close,
    async send(data: PluginSocketMessage): Promise<void> {
      if (sending) throw new TypeError("Await send before sending another message");
      const size = typeof data === "string" ? new TextEncoder().encode(data).byteLength : data.byteLength;
      if (size > 1024 * 1024) throw new RangeError("WebSocket messages are limited to 1 MiB");
      sending = true;
      try {
        while (socket.bufferedAmount > 256 * 1024) { if (ended) throw failure ?? new Error("WebSocket closed"); await new Promise(resolve => setTimeout(resolve, 10)); }
        if (ended) throw failure ?? new Error("WebSocket closed");
        if (typeof data === "string") socket.send(data); else socket.send(new Uint8Array(data).buffer);
      } finally { sending = false; }
    },
    async *[Symbol.asyncIterator](): AsyncIterableIterator<PluginSocketMessage> {
      if (reading) throw new TypeError("WebSocket supports one message consumer");
      reading = true;
      try {
        while (true) {
          if (failure) throw failure;
          const item = queue.shift();
          if (item !== undefined) { bytes -= typeof item === "string" ? new TextEncoder().encode(item).byteLength : item.byteLength; yield item; continue; }
          if (ended) return;
          await new Promise<void>(resolve => { wake = resolve; });
        }
      } finally { reading = false; close(); }
    },
  });
}
