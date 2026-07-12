type SurfaceRegistration = {
  pluginInstanceId: string;
  dispose: () => void;
};

const registrations = new WeakMap<PluginSurfaceScope, Map<symbol, SurfaceRegistration>>();

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
  dispose: () => void,
): () => void {
  const state = registrations.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const registration = Symbol(pluginInstanceId);
  state.set(registration, { pluginInstanceId, dispose });
  return () => state.delete(registration);
}

export function disposePluginSurfaceScope(scope: PluginSurfaceScope, pluginInstanceId?: string): void {
  const state = registrations.get(scope);
  if (!state) throw new TypeError("Plugin surface scope is invalid");
  const selected = [...state.entries()].filter(([, registration]) =>
    pluginInstanceId === undefined || registration.pluginInstanceId === pluginInstanceId
  );
  for (const [key] of selected) state.delete(key);
  for (const [, registration] of selected) registration.dispose();
}
