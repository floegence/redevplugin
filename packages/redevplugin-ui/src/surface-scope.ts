type SurfaceRegistration = {
  pluginInstanceId: string;
  dispose: () => Promise<void> | void;
};

const registrations = new WeakMap<PluginSurfaceScope, Map<symbol, SurfaceRegistration>>();

function canonicalPluginInstanceId(pluginInstanceId: string): string {
  const canonical = typeof pluginInstanceId === "string" ? pluginInstanceId.trim() : "";
  if (!canonical) throw new TypeError("Plugin instance identifier must be a non-empty string");
  return canonical;
}

export class PluginSurfaceScope {
  private constructor() {
    registrations.set(this, new Map());
  }

  static create(): PluginSurfaceScope {
    return new PluginSurfaceScope();
  }
}

export function createPluginSurfaceScope(): PluginSurfaceScope {
  return PluginSurfaceScope.create();
}

export const defaultPluginSurfaceScope = createPluginSurfaceScope();

export function registerPluginSurface(
  scope: PluginSurfaceScope,
  pluginInstanceId: string,
  dispose: () => Promise<void> | void,
): () => void {
  const state = registrations.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const canonicalPluginId = canonicalPluginInstanceId(pluginInstanceId);
  const registration = Symbol(canonicalPluginId);
  state.set(registration, { pluginInstanceId: canonicalPluginId, dispose });
  return () => state.delete(registration);
}

export async function disposePluginSurfaceScope(scope: PluginSurfaceScope, pluginInstanceId?: string): Promise<void> {
  const state = registrations.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const canonicalPluginId = pluginInstanceId === undefined
    ? undefined
    : canonicalPluginInstanceId(pluginInstanceId);
  const selected = [...state.entries()].filter(([, registration]) =>
    canonicalPluginId === undefined || registration.pluginInstanceId === canonicalPluginId
  );
  for (const [key] of selected) state.delete(key);
  const results = await Promise.allSettled(selected.map(([, registration]) =>
    Promise.resolve().then(() => registration.dispose())
  ));
  const failures = results
    .filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => result.reason);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "Plugin surface scope teardown failed");
}
