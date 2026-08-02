export type SettingOptionPresentation = Readonly<{
  value: string;
  label: string;
}>;

export type ResolvedSurfacePresentation = Readonly<{
  surface_id: string;
  label: string;
}>;

export type ResolvedSettingPresentation = Readonly<{
  key: string;
  label: string;
  options: readonly SettingOptionPresentation[];
}>;

export type PresentationLocale = Readonly<{
  locale: string;
  plugin_name: string;
  publisher_name?: string;
  summary: string;
  description: readonly string[];
  highlights: readonly string[];
  keywords: readonly string[];
  surfaces: readonly ResolvedSurfacePresentation[];
  settings: readonly ResolvedSettingPresentation[];
}>;

export type PresentationCatalog = Readonly<{
  default_locale: string;
  locales: readonly PresentationLocale[];
}>;

export type ResolvedPresentation = Readonly<{
  requested_locale?: string;
  resolved_locale: string;
  default_locale: string;
  plugin_name: string;
  publisher_name?: string;
  summary: string;
  description: readonly string[];
  highlights: readonly string[];
  keywords: readonly string[];
  surfaces: readonly ResolvedSurfacePresentation[];
  settings: readonly ResolvedSettingPresentation[];
}>;

export function resolvePresentation(
  catalog: PresentationCatalog,
  requestedLocale: string,
): ResolvedPresentation {
  const byLocale = new Map(catalog.locales.map((locale) => [locale.locale, locale]));
  const requested = canonicalLocale(requestedLocale);
  let resolved = byLocale.get(catalog.default_locale);
  if (resolved === undefined) throw new TypeError("presentation default locale is missing");
  if (requested !== undefined) {
    for (const candidate of localeLookupCandidates(requested)) {
      const match = byLocale.get(candidate);
      if (match !== undefined) {
        resolved = match;
        break;
      }
    }
  }
  return deepClonePresentation(resolved, catalog.default_locale, requested);
}

function canonicalLocale(value: string): string | undefined {
  if (value === "" || value.trim() !== value || value.includes("_")) return undefined;
  try {
    const canonical = Intl.getCanonicalLocales(value)[0];
    return canonical === "und" ? undefined : canonical;
  } catch {
    return undefined;
  }
}

function localeLookupCandidates(locale: string): string[] {
  const parts = locale.split("-");
  const result: string[] = [];
  while (parts.length > 0) {
    result.push(parts.join("-"));
    parts.pop();
    if (parts.at(-1)?.length === 1) parts.pop();
  }
  return result;
}

function deepClonePresentation(
  locale: PresentationLocale,
  defaultLocale: string,
  requestedLocale: string | undefined,
): ResolvedPresentation {
  return {
    ...(requestedLocale === undefined ? {} : { requested_locale: requestedLocale }),
    resolved_locale: locale.locale,
    default_locale: defaultLocale,
    plugin_name: locale.plugin_name,
    ...(locale.publisher_name === undefined ? {} : { publisher_name: locale.publisher_name }),
    summary: locale.summary,
    description: [...locale.description],
    highlights: [...locale.highlights],
    keywords: [...locale.keywords],
    surfaces: locale.surfaces.map((surface) => ({ ...surface })),
    settings: locale.settings.map((setting) => ({
      ...setting,
      options: setting.options.map((option) => ({ ...option })),
    })),
  };
}
