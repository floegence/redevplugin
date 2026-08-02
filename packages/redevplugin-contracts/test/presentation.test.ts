import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { resolvePresentation, type PresentationCatalog } from "../src/presentation.js";

type LocaleFixture = Readonly<{
  default_locale: string;
  available_locales: readonly string[];
  cases: readonly Readonly<{ requested_locale: string; resolved_locale: string }>[];
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../../spec/plugin/presentation-locale-fixtures-v1.json", import.meta.url),
  "utf8",
)) as LocaleFixture;

test("resolvePresentation matches the shared RFC 4647 fixtures without an English fallback", () => {
    const catalog: PresentationCatalog = {
      default_locale: fixture.default_locale,
      locales: fixture.available_locales.map((locale) => ({
        locale,
        plugin_name: locale,
        summary: locale,
        description: [locale],
        highlights: [],
        keywords: [locale],
        surfaces: [],
        settings: [],
      })),
    };
    for (const testCase of fixture.cases) {
      assert.equal(
        resolvePresentation(catalog, testCase.requested_locale).resolved_locale,
        testCase.resolved_locale,
        testCase.requested_locale,
      );
    }
});

test("resolvePresentation returns a detached resolved projection", () => {
    const catalog: PresentationCatalog = {
      default_locale: "en-US",
      locales: [{
        locale: "en-US",
        plugin_name: "Example",
        summary: "Example",
        description: ["Original"],
        highlights: [],
        keywords: ["example"],
        surfaces: [{ surface_id: "view", label: "View" }],
        settings: [{ key: "mode", label: "Mode", options: [{ value: "one", label: "One" }] }],
      }],
    };
    const resolved = resolvePresentation(catalog, "en-US");
    (resolved.description as string[])[0] = "Changed";
    assert.equal(catalog.locales[0]?.description[0], "Original");
});
