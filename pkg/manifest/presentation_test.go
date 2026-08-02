package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestResolvePresentationMatchesSharedLocaleFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/presentation-locale-fixtures-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		DefaultLocale    string   `json:"default_locale"`
		AvailableLocales []string `json:"available_locales"`
		Cases            []struct {
			RequestedLocale string `json:"requested_locale"`
			ResolvedLocale  string `json:"resolved_locale"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	catalog := PresentationCatalog{DefaultLocale: fixture.DefaultLocale}
	for _, locale := range fixture.AvailableLocales {
		catalog.Locales = append(catalog.Locales, PresentationLocale{
			Locale: locale, PluginName: locale, Summary: locale, Description: []string{locale}, Keywords: []string{locale},
			Surfaces: []ResolvedSurfacePresentation{}, Settings: []ResolvedSettingPresentation{},
		})
	}
	for _, testCase := range fixture.Cases {
		if resolved := ResolvePresentation(catalog, testCase.RequestedLocale); resolved.ResolvedLocale != testCase.ResolvedLocale {
			t.Fatalf("ResolvePresentation(%q) locale = %q, want %q", testCase.RequestedLocale, resolved.ResolvedLocale, testCase.ResolvedLocale)
		}
	}
}

func TestResolvePresentationUsesRFC4647ThenAuthorDefault(t *testing.T) {
	catalog := validManifest().PresentationCatalog()
	tests := []struct {
		name      string
		requested string
		locale    string
		plugin    string
	}{
		{name: "exact", requested: "fr-FR", locale: "fr-FR", plugin: "Ressources"},
		{name: "parent", requested: "fr-FR-u-ca-gregory", locale: "fr-FR", plugin: "Ressources"},
		{name: "author default without english preference", requested: "ja-JP", locale: "en-US", plugin: "Resources"},
		{name: "invalid request", requested: "not_a_locale", locale: "en-US", plugin: "Resources"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := ResolvePresentation(catalog, test.requested)
			if resolved.ResolvedLocale != test.locale || resolved.PluginName != test.plugin {
				t.Fatalf("ResolvePresentation() = locale %q plugin %q", resolved.ResolvedLocale, resolved.PluginName)
			}
		})
	}
}

func TestResolvePresentationDoesNotMutateCatalog(t *testing.T) {
	catalog := validManifest().PresentationCatalog()
	resolved := ResolvePresentation(catalog, "fr-FR")
	resolved.Description[0] = "changed"
	resolved.Surfaces[0].Label = "changed"
	resolved.Settings[0].Options[0].Label = "changed"
	if catalog.Locales[1].Description[0] == "changed" || catalog.Locales[1].Surfaces[0].Label == "changed" || catalog.Locales[1].Settings[0].Options[0].Label == "changed" {
		t.Fatal("ResolvePresentation() returned aliases into the catalog")
	}
}

func TestPresentationCatalogDigestCoversLocalizedAuthorContent(t *testing.T) {
	manifest := validManifest()
	catalog := manifest.PresentationCatalog()
	first, err := PresentationCatalogSHA256(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len("sha256:")+64 {
		t.Fatalf("presentation digest = %q", first)
	}
	catalog.Locales[1].Description[0] += " Updated."
	second, err := PresentationCatalogSHA256(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("presentation digest did not cover localized description")
	}
}

func TestValidatePresentationRejectsIncompleteAndInvalidLocales(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*Manifest)
	}{
		{name: "non canonical default", field: "presentation.default_locale", mutate: func(m *Manifest) { m.Presentation.DefaultLocale = "en-us" }},
		{name: "too many locales", field: "presentation.localizations", mutate: func(m *Manifest) {
			m.Presentation.Localizations = make([]PresentationLocalizationSpec, maxPresentationLocales)
		}},
		{name: "duplicate locale", field: "presentation.localizations[0].locale", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Locale = "en-US" }},
		{name: "summary too long", field: "presentation.summary", mutate: func(m *Manifest) { m.Presentation.Summary = strings.Repeat("s", 241) }},
		{name: "description total too long", field: "presentation.description", mutate: func(m *Manifest) {
			m.Presentation.Description = make([]string, 9)
			for index := range m.Presentation.Description {
				m.Presentation.Description[index] = strings.Repeat("d", 1000)
			}
		}},
		{name: "too many highlights", field: "presentation.highlights", mutate: func(m *Manifest) { m.Presentation.Highlights = make([]string, 9) }},
		{name: "too many keywords", field: "presentation.keywords", mutate: func(m *Manifest) { m.Presentation.Keywords = make([]string, 13) }},
		{name: "leading whitespace", field: "presentation.summary", mutate: func(m *Manifest) { m.Presentation.Summary = " Invalid" }},
		{name: "control character", field: "presentation.summary", mutate: func(m *Manifest) { m.Presentation.Summary = "Invalid\x00summary" }},
		{name: "missing localized publisher", field: "presentation.localizations[0].publisher_name", mutate: func(m *Manifest) { m.Presentation.Localizations[0].PublisherName = "" }},
		{name: "unexpected localized publisher", field: "presentation.localizations[0].publisher_name", mutate: func(m *Manifest) { m.Publisher.DisplayName = "" }},
		{name: "missing surface", field: "presentation.localizations[0].surfaces", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Surfaces = nil }},
		{name: "unknown surface", field: "presentation.localizations[0].surfaces[0].surface_id", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Surfaces[0].SurfaceID = "unknown.view" }},
		{name: "duplicate surface", field: "presentation.localizations[0].surfaces[1].surface_id", mutate: func(m *Manifest) {
			surface := m.Surfaces[0]
			surface.SurfaceID = "other.view"
			m.Surfaces = append(m.Surfaces, surface)
			m.Presentation.Localizations[0].Surfaces = append(m.Presentation.Localizations[0].Surfaces, m.Presentation.Localizations[0].Surfaces[0])
		}},
		{name: "missing setting", field: "presentation.localizations[0].settings", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Settings = nil }},
		{name: "unknown setting", field: "presentation.localizations[0].settings[0].key", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Settings[0].Key = "unknown" }},
		{name: "duplicate setting", field: "presentation.localizations[0].settings[1].key", mutate: func(m *Manifest) {
			setting := m.Settings.Fields[0]
			setting.Key = "other"
			m.Settings.Fields = append(m.Settings.Fields, setting)
			m.Presentation.Localizations[0].Settings = append(m.Presentation.Localizations[0].Settings, m.Presentation.Localizations[0].Settings[0])
		}},
		{name: "wrong setting option", field: "presentation.localizations[0].settings[0].options[0].value", mutate: func(m *Manifest) { m.Presentation.Localizations[0].Settings[0].Options[0].Value = "other" }},
		{name: "duplicate setting option", field: "presentation.localizations[0].settings[0].options[1].value", mutate: func(m *Manifest) {
			m.Presentation.Localizations[0].Settings[0].Options[1].Value = m.Presentation.Localizations[0].Settings[0].Options[0].Value
		}},
		{name: "duplicate keyword", field: "presentation.keywords[1]", mutate: func(m *Manifest) { m.Presentation.Keywords = []string{"Resources", "resources"} }},
		{name: "non nfc", field: "presentation.summary", mutate: func(m *Manifest) { m.Presentation.Summary = "Cafe\u0301" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validManifest()
			test.mutate(&candidate)
			var validationErr ValidationError
			if err := Validate(candidate); !errors.As(err, &validationErr) || validationErr.Field != test.field {
				t.Fatalf("Validate() error = %v, want field %q", err, test.field)
			}
		})
	}
}

func TestPresentationCatalogKeepsSimplifiedAndTraditionalChineseIndependent(t *testing.T) {
	manifest := validManifest()
	manifest.Presentation.Localizations = []PresentationLocalizationSpec{
		localizedPresentation("zh-CN", "容器", "管理容器资源。"),
		localizedPresentation("zh-TW", "容器", "管理容器資源。"),
	}
	if err := Validate(manifest); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	catalog := manifest.PresentationCatalog()
	simplified := ResolvePresentation(catalog, "zh-CN")
	traditional := ResolvePresentation(catalog, "zh-TW")
	if simplified.Summary == traditional.Summary {
		t.Fatal("Simplified and Traditional Chinese resolved to the same author content")
	}
}

func localizedPresentation(locale, name, summary string) PresentationLocalizationSpec {
	return PresentationLocalizationSpec{
		Locale: locale, PluginName: name, PublisherName: "示例", Summary: summary,
		Description: []string{summary}, Highlights: []string{summary}, Keywords: []string{name},
		Surfaces: []LocalizedSurfacePresentation{{SurfaceID: "resources.view", Label: name}},
		Settings: []LocalizedSettingPresentation{{
			Key: "default_source", Label: name,
			Options: []SettingOptionSpec{{Value: "primary", Label: name}, {Value: "secondary", Label: name + "二"}},
		}},
	}
}
