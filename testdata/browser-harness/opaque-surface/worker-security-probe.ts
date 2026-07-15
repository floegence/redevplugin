export type WorkerSecurityProbe = Record<string, boolean | string>;

export async function runWorkerSecurityProbe(): Promise<WorkerSecurityProbe> {
  const hardenedGlobalAPIs = [
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "WebTransport",
    "Worker",
    "SharedWorker",
    "indexedDB",
    "caches",
    "RTCPeerConnection",
    "webkitRTCPeerConnection",
    "BroadcastChannel",
    "importScripts",
    "postMessage",
    "eval",
    "Function",
    "Blob",
    "File",
    "FileReader",
    "FileReaderSync",
  ];
  const probe: WorkerSecurityProbe = {
    dedicated_worker: typeof window === "undefined" && typeof document === "undefined",
    fetch_blocked: await rejects(() => fetch("https://redevplugin.invalid/worker-network-probe")),
    websocket_blocked: rejectsSync(() => new WebSocket("wss://redevplugin.invalid/worker-websocket")),
    nested_worker_blocked: rejectsSync(() => new Worker("data:text/javascript,close()")),
    indexeddb_blocked: typeof indexedDB === "undefined",
    cache_storage_blocked: typeof caches === "undefined",
    broadcast_channel_blocked: typeof BroadcastChannel === "undefined",
    global_postmessage_blocked: typeof postMessage === "undefined",
    navigator_storage_blocked: typeof navigator.storage === "undefined",
    eval_blocked: typeof eval === "undefined",
    function_constructor_blocked: typeof Function === "undefined",
    prototype_descriptors_sealed: hardenedGlobalAPIs.every((name) => descriptorsAreSealed(globalThis, name)) &&
      ["storage", "sendBeacon", "serviceWorker"].every((name) => descriptorsAreSealed(navigator, name)),
    message_port_prototype_sealed: messagePortPrototypeSealed(),
    prototype_fetch_blocked: await everyCallableDescriptorRejects(globalThis, "fetch", ["https://redevplugin.invalid/worker-prototype-fetch"]),
    prototype_indexeddb_blocked: descriptorValues(globalThis, "indexedDB").every((value) => value === undefined),
    prototype_nested_blob_worker_blocked: recoveredBlobWorkerIsBlocked(),
  };
  probe.all_blocked = Object.values(probe).every((value) => value === true);
  return probe;
}

function messagePortPrototypeSealed(): boolean {
  const channel = new MessageChannel();
  try {
    return ["postMessage", "start", "close", "addEventListener", "removeEventListener"]
      .every((name) => descriptorsAreSealed(channel.port1, name));
  } finally {
    channel.port1.close();
    channel.port2.close();
  }
}

function descriptorsAreSealed(target: object, name: string): boolean {
  const descriptors = descriptorChain(target, name);
  return descriptors.length > 0 && descriptors.every((descriptor) =>
    "value" in descriptor && descriptor.configurable === false && descriptor.writable === false
  );
}

function descriptorChain(target: object, name: string): PropertyDescriptor[] {
  const descriptors: PropertyDescriptor[] = [];
  let current: object | null = target;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor) descriptors.push(descriptor);
    current = Object.getPrototypeOf(current) as object | null;
  }
  return descriptors;
}

function descriptorValues(target: object, name: string): unknown[] {
  return descriptorChain(target, name).map((descriptor) => {
    try {
      return "value" in descriptor ? descriptor.value : descriptor.get?.call(target);
    } catch {
      return undefined;
    }
  });
}

async function everyCallableDescriptorRejects(target: object, name: string, args: unknown[]): Promise<boolean> {
  const callables = descriptorValues(target, name).filter((value): value is (...values: unknown[]) => unknown => typeof value === "function");
  for (const callable of callables) {
    if (!await rejects(() => Promise.resolve(Reflect.apply(callable, target, args)))) return false;
  }
  return true;
}

function recoveredBlobWorkerIsBlocked(): boolean {
  const BlobConstructor = descriptorValues(globalThis, "Blob").find((value) => typeof value === "function") as typeof Blob | undefined;
  const WorkerConstructor = descriptorValues(globalThis, "Worker").find((value) => typeof value === "function") as typeof Worker | undefined;
  if (!BlobConstructor || !WorkerConstructor) return true;
  let url = "";
  try {
    url = URL.createObjectURL(new BlobConstructor(["close()"], { type: "text/javascript" }));
    const nested = new WorkerConstructor(url);
    nested.terminate();
    return false;
  } catch {
    return true;
  } finally {
    if (url) URL.revokeObjectURL(url);
  }
}

async function rejects(action: () => Promise<unknown>): Promise<boolean> {
  try {
    await action();
    return false;
  } catch {
    return true;
  }
}

function rejectsSync(action: () => unknown): boolean {
  try {
    action();
    return false;
  } catch {
    return true;
  }
}
