import type { PluginBridgeClient } from "../../packages/redevplugin-ui/src/plugin.js";

/** The examples consume the published Floe standalone material without owning host chrome. */
export function connectTheme(bridge: PluginBridgeClient): () => void {
  const root = document.documentElement;
  root.dataset.floeSurfaceStyle = "soft-neumorphic";
  return bridge.onContext((context) => {
    root.classList.toggle("dark", context.appearance.color_scheme === "dark");
    root.classList.toggle("light", context.appearance.color_scheme === "light");
    root.style.colorScheme = context.appearance.color_scheme;
    root.style.setProperty("--destructive", context.appearance.colors.danger);
    root.lang = context.locale.language_tag;
    root.dir = context.locale.direction;
    const mapping = { canvas: "background", surface: "card", surface_elevated: "popover", text: "foreground", text_muted: "muted-foreground", border: "border", accent: "primary", accent_text: "primary-foreground", success: "success", warning: "warning", danger: "error", focus: "ring" } as const;
    for (const [source, token] of Object.entries(mapping)) {
      root.style.setProperty(`--${token}`, context.appearance.colors[source as keyof typeof mapping]);
    }
  });
}
