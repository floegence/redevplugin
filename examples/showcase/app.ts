import {
  PluginSurfaceHost,
  createReDevPluginSurfaceTransport,
  toPluginSurfaceHostBootstrap,
  type PluginConfirmationIntent,
  type PluginSurfaceBootstrapResult,
} from "../../packages/redevplugin-ui/src/trusted-parent.js";

type CatalogPlugin = {
  slug: string;
  plugin_id: string;
  plugin_instance_id: string;
  plugin_state_version: number;
  surface_id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  icon: string;
  capabilities: string[];
};

const elements = {
  list: required<HTMLElement>("#plugin-list"),
  mobileList: required<HTMLElement>("#mobile-plugin-list"),
  stage: required<HTMLElement>("#surface-stage"),
  placeholder: required<HTMLElement>("#surface-placeholder"),
  loadingIcon: required<HTMLImageElement>("#loading-icon"),
  loadingTitle: required<HTMLElement>("#loading-title"),
  loadingMessage: required<HTMLElement>("#loading-message"),
  retry: required<HTMLButtonElement>("#retry-plugin"),
  detailIcon: required<HTMLImageElement>("#detail-icon"),
  detailTitle: required<HTMLElement>("#detail-title"),
  detailDescription: required<HTMLElement>("#detail-description"),
  detailVersion: required<HTMLElement>("#detail-version"),
  capabilities: required<HTMLElement>("#capability-list"),
  runtimeStatus: required<HTMLElement>(".runtime-status"),
  runtimeLabel: required<HTMLElement>("#runtime-label"),
  detailErrorRow: required<HTMLElement>("#detail-error-row"),
  detailError: required<HTMLElement>("#detail-error"),
  reload: required<HTMLButtonElement>("#reload-plugin"),
  inspector: required<HTMLElement>("#plugin-inspector"),
  inspectorToggle: required<HTMLButtonElement>("#inspector-toggle"),
  mobileInspectorToggle: required<HTMLButtonElement>("#mobile-inspector-toggle"),
  inspectorClose: required<HTMLButtonElement>("#inspector-close"),
  inspectorScrim: required<HTMLButtonElement>("#inspector-scrim"),
  confirmation: required<HTMLDialogElement>("#confirmation-dialog"),
  confirmationTitle: required<HTMLElement>("#confirmation-title"),
  confirmationSummary: required<HTMLElement>("#confirmation-summary"),
};

let catalog: CatalogPlugin[] = [];
let activePlugin: CatalogPlugin | undefined;
let surfaceHost: PluginSurfaceHost | undefined;
let openSequence = 0;
let inspectorReturnFocus: HTMLButtonElement | undefined;

elements.reload.addEventListener("click", () => {
  if (activePlugin) void openPlugin(activePlugin, "preserve");
});
elements.retry.addEventListener("click", () => {
  if (activePlugin) void openPlugin(activePlugin, "preserve");
});
for (const toggle of [elements.inspectorToggle, elements.mobileInspectorToggle]) {
  toggle.addEventListener("click", () => setInspectorOpen(elements.inspector.dataset.open !== "true", toggle));
}
elements.inspectorClose.addEventListener("click", () => setInspectorOpen(false));
elements.inspectorScrim.addEventListener("click", () => setInspectorOpen(false));
addEventListener("keydown", (event) => {
  if (event.key === "Escape") setInspectorOpen(false);
  if (event.key === "Tab" && elements.inspector.dataset.open === "true") containInspectorFocus(event);
});
addEventListener("popstate", () => {
  const plugin = selectedPluginFromURL() ?? catalog[0];
  if (plugin && plugin.slug !== activePlugin?.slug) void openPlugin(plugin, "preserve");
});
document.addEventListener("visibilitychange", () => sendSurfaceVisibility());
addEventListener("beforeunload", () => surfaceHost?.dispose());
void initialize();

async function initialize(): Promise<void> {
  try {
    const [plugins] = await Promise.all([request<CatalogPlugin[]>("/api/catalog"), checkHealth()]);
    catalog = plugins;
    renderNavigation();
    const first = catalog[0];
    if (!first) throw new Error("No example plugins are available");
    const selected = selectedPluginFromURL();
    await openPlugin(selected ?? first, selected ? "preserve" : "replace");
  } catch (error) {
    showError(error);
  }
}

async function checkHealth(): Promise<void> {
  const health = await request<{ ready: boolean; plugins: number }>("/api/health");
  elements.runtimeStatus.dataset.ready = String(health.ready);
  elements.runtimeLabel.textContent = health.ready ? "Connected" : "Unavailable";
}

function renderNavigation(): void {
  renderNavigationList(elements.list, false);
  renderNavigationList(elements.mobileList, true);
}

function renderNavigationList(container: HTMLElement, mobile: boolean): void {
  container.replaceChildren(...catalog.map((plugin) => {
    const button = document.createElement("button");
    button.className = mobile ? "plugin-nav mobile-plugin-nav" : "plugin-nav";
    button.type = "button";
    button.dataset.slug = plugin.slug;
    button.setAttribute("aria-label", `Open ${plugin.name}`);
    button.setAttribute("aria-pressed", String(plugin.slug === activePlugin?.slug));
    const image = document.createElement("img");
    image.src = plugin.icon;
    image.alt = "";
    const name = document.createElement("strong");
    name.textContent = plugin.name;
    button.append(image, name);
    button.addEventListener("click", () => {
      if (plugin.slug !== activePlugin?.slug) void openPlugin(plugin, "push", button);
    });
    return button;
  }));
}

function updateNavigationState(): void {
  for (const button of Array.from(document.querySelectorAll<HTMLButtonElement>(".plugin-nav[data-slug]"))) {
    button.setAttribute("aria-pressed", String(button.dataset.slug === activePlugin?.slug));
  }
}

async function openPlugin(
  plugin: CatalogPlugin,
  historyMode: "preserve" | "push" | "replace",
  navigationTrigger?: HTMLButtonElement,
): Promise<void> {
  setInspectorOpen(false);
  navigationTrigger?.focus({ preventScroll: true });
  const sequence = ++openSequence;
  updatePluginURL(plugin.slug, historyMode);
  activePlugin = plugin;
  updateNavigationState();
  renderMetadata(plugin);
  showLoading(plugin);
  setReloadDisabled(true);
  const previous = surfaceHost;
  surfaceHost = undefined;
  if (previous) await previous.close().catch(() => previous.dispose());
  if (sequence !== openSequence) return;
  restoreNavigationFocus(navigationTrigger);
  elements.stage.querySelector("iframe")?.remove();
  try {
    const bootstrap = await request<PluginSurfaceBootstrapResult>("/api/open", { slug: plugin.slug });
    if (sequence !== openSequence) return;
    const next = PluginSurfaceHost.create({
      bootstrap: toPluginSurfaceHostBootstrap(bootstrap),
      hostTransport: createReDevPluginSurfaceTransport(),
      confirm: confirmAction,
      onError: (error) => { if (sequence === openSequence) showError(error); },
    });
    next.element.title = `${plugin.name} plugin`;
    elements.stage.append(next.element);
    surfaceHost = next;
    await next.open();
    if (sequence !== openSequence || surfaceHost !== next) {
      await next.close().catch(() => next.dispose());
      return;
    }
    sendSurfaceVisibility();
    elements.placeholder.hidden = true;
    elements.stage.setAttribute("aria-busy", "false");
  } catch (error) {
    if (sequence === openSequence) showError(error);
  } finally {
    if (sequence === openSequence) setReloadDisabled(false);
  }
}

function restoreNavigationFocus(navigationTrigger?: HTMLButtonElement): void {
  if (!navigationTrigger || !document.contains(navigationTrigger) || document.activeElement === navigationTrigger) return;
  const activeElement = document.activeElement;
  if (
    activeElement === document.body ||
    activeElement === document.documentElement ||
    activeElement instanceof HTMLIFrameElement && elements.stage.contains(activeElement)
  ) {
    navigationTrigger.focus({ preventScroll: true });
  }
}

function showLoading(plugin: CatalogPlugin): void {
  elements.stage.setAttribute("aria-busy", "true");
  elements.placeholder.hidden = false;
  elements.placeholder.dataset.state = "loading";
  elements.loadingIcon.src = plugin.icon;
  elements.loadingTitle.textContent = plugin.name;
  elements.loadingMessage.textContent = "Opening your app...";
  elements.retry.hidden = true;
  elements.detailErrorRow.hidden = true;
  elements.detailError.textContent = "None";
}

function showError(error: unknown): void {
  elements.stage.setAttribute("aria-busy", "false");
  elements.placeholder.hidden = false;
  elements.placeholder.dataset.state = "error";
  elements.loadingTitle.textContent = activePlugin ? `${activePlugin.name} could not open` : "The app could not open";
  elements.loadingMessage.textContent = "The app session ended before it was ready. Try opening it again.";
  elements.retry.hidden = false;
  elements.detailErrorRow.hidden = false;
  elements.detailError.textContent = error instanceof Error ? error.message.slice(0, 240) : "Unknown app session error";
}

function setInspectorOpen(open: boolean, trigger?: HTMLButtonElement): void {
  if (open) inspectorReturnFocus = trigger ?? inspectorReturnFocus;
  elements.inspector.dataset.open = String(open);
  elements.inspector.setAttribute("aria-hidden", String(!open));
  elements.inspector.inert = !open;
  for (const toggle of [elements.inspectorToggle, elements.mobileInspectorToggle]) toggle.setAttribute("aria-expanded", String(open));
  elements.inspectorScrim.hidden = !open;
  document.body.dataset.inspectorOpen = String(open);
  if (open) elements.inspectorClose.focus({ preventScroll: true });
  else if (inspectorReturnFocus && document.contains(inspectorReturnFocus)) {
    inspectorReturnFocus.focus({ preventScroll: true });
    inspectorReturnFocus = undefined;
  }
}

function containInspectorFocus(event: KeyboardEvent): void {
  const controls = Array.from(elements.inspector.querySelectorAll<HTMLElement>("button, summary, [tabindex]")).filter((element) => !element.hasAttribute("disabled"));
  if (controls.length === 0) {
    event.preventDefault();
    elements.inspectorClose.focus({ preventScroll: true });
    return;
  }
  const first = controls[0];
  const last = controls[controls.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus({ preventScroll: true });
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus({ preventScroll: true });
  }
}

function selectedPluginFromURL(): CatalogPlugin | undefined {
  const slug = new URL(location.href).searchParams.get("plugin");
  return slug ? catalog.find((plugin) => plugin.slug === slug) : undefined;
}

function updatePluginURL(slug: string, mode: "preserve" | "push" | "replace"): void {
  if (mode === "preserve") return;
  const url = new URL(location.href);
  url.searchParams.set("plugin", slug);
  history[mode === "push" ? "pushState" : "replaceState"]({ plugin: slug }, "", url);
}

function renderMetadata(plugin: CatalogPlugin): void {
  document.documentElement.dataset.plugin = plugin.slug;
  elements.loadingIcon.src = plugin.icon;
  elements.detailIcon.src = plugin.icon;
  elements.detailTitle.textContent = plugin.name;
  elements.detailDescription.textContent = plugin.description;
  elements.detailVersion.textContent = plugin.version;
  elements.capabilities.replaceChildren(...plugin.capabilities.map((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    return item;
  }));
}

function confirmAction(intent: PluginConfirmationIntent): Promise<{ confirmed: boolean }> {
  elements.confirmationTitle.textContent = intent.method;
  elements.confirmationSummary.textContent = riskSummary(intent);
  elements.confirmation.showModal();
  return new Promise((resolve) => {
    const finish = (confirmed: boolean) => {
      elements.confirmation.removeEventListener("close", onClose);
      resolve({ confirmed });
    };
    const onClose = () => finish(elements.confirmation.returnValue === "approve");
    elements.confirmation.addEventListener("close", onClose, { once: true });
    intent.signal.addEventListener("abort", () => {
      if (elements.confirmation.open) elements.confirmation.close("deny");
    }, { once: true });
  });
}

function riskSummary(intent: PluginConfirmationIntent): string {
  const plan = intent.plan as { summary?: unknown } | undefined;
  return typeof plan?.summary === "string" ? plan.summary : "This app is requesting a protected action.";
}

function setReloadDisabled(disabled: boolean): void {
  elements.reload.disabled = disabled;
  elements.retry.disabled = disabled;
}

function sendSurfaceVisibility(): void {
  if (!surfaceHost) return;
  try {
    surfaceHost.sendLifecycle({ type: document.hidden ? "hidden" : "visible" });
  } catch {
    // The surface can close concurrently with a browser visibility transition.
  }
}

async function request<T>(url: string, body?: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, body === undefined ? { headers: { Accept: "application/json" } } : {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const envelope = await response.json() as { success?: boolean; data?: T; error?: { message?: string } };
  if (!response.ok || envelope.success !== true) throw new Error(envelope.error?.message || `Request failed with HTTP ${response.status}`);
  return envelope.data as T;
}

function required<T extends Element>(selector: string): T {
  const value = document.querySelector(selector);
  if (!(value instanceof Element)) throw new Error(`Missing required element ${selector}`);
  return value as T;
}
