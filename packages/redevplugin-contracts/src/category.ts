/** Author-owned discovery categories. Omission means other; unknown values are invalid. */
export const pluginCategories = [
  "development", "infrastructure", "utilities", "data",
  "collaboration", "productivity", "games", "lifestyle",
  "health", "education", "finance", "media", "other",
] as const;

import type { PluginCategory } from "./security-summary.gen.js";
export type { PluginCategory } from "./security-summary.gen.js";

export function resolvePluginCategory(value: unknown): PluginCategory {
  if (value === undefined) return "other";
  if (typeof value === "string" && pluginCategories.some(category => category === value)) return value as PluginCategory;
  throw new TypeError("presentation.category must be a predefined plugin category");
}
