type SurfaceRegistration = {
  pluginInstanceId: string;
  dispose: () => Promise<void> | void;
  invalidate: () => Promise<void> | void;
};

type SurfaceScopeState = {
  invalidated: boolean;
  registrations: Map<symbol, SurfaceRegistration>;
};

const scopes = new WeakMap<PluginSurfaceScope, SurfaceScopeState>();

function canonicalPluginInstanceId(pluginInstanceId: string): string {
  const canonical = typeof pluginInstanceId === "string" ? pluginInstanceId.trim() : "";
  if (!canonical) throw new TypeError("Plugin instance identifier must be a non-empty string");
  return canonical;
}

export class PluginSurfaceScope {
  private constructor() {
    scopes.set(this, { invalidated: false, registrations: new Map() });
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
  invalidate: () => Promise<void> | void,
): () => void {
  const state = scopes.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const canonicalPluginId = canonicalPluginInstanceId(pluginInstanceId);
  const registration = Symbol(canonicalPluginId);
  if (state.invalidated) {
    try {
      void Promise.resolve(invalidate()).catch(() => undefined);
    } catch {
      // A fenced session remains invalid even when a local observer fails.
    }
    return () => undefined;
  }
  state.registrations.set(registration, { pluginInstanceId: canonicalPluginId, dispose, invalidate });
  return () => state.registrations.delete(registration);
}

export async function disposePluginSurfaceScope(scope: PluginSurfaceScope, pluginInstanceId?: string): Promise<void> {
  const state = scopes.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const canonicalPluginId = pluginInstanceId === undefined
    ? undefined
    : canonicalPluginInstanceId(pluginInstanceId);
  const selected = [...state.registrations.entries()].filter(([, registration]) =>
    canonicalPluginId === undefined || registration.pluginInstanceId === canonicalPluginId
  );
  for (const [key] of selected) state.registrations.delete(key);
  const results = await Promise.allSettled(selected.map(([, registration]) =>
    Promise.resolve().then(() => registration.dispose())
  ));
  const failures = results
    .filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => result.reason);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "Plugin surface scope teardown failed");
}

export async function invalidatePluginSurfaceScope(scope: PluginSurfaceScope): Promise<void> {
  const state = scopes.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  state.invalidated = true;
  const selected = [...state.registrations.values()];
  state.registrations.clear();
  const results = await Promise.allSettled(selected.map((registration) =>
    Promise.resolve().then(() => registration.invalidate())
  ));
  const failures = results
    .filter((result): result is PromiseRejectedResult => result.status === "rejected")
    .map((result) => result.reason);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "Plugin surface scope invalidation failed");
}
