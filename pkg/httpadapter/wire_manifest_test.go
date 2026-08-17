package httpadapter

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestPublicPresentationWireUsesEmptyArrays(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected string
	}{
		{
			name: "manifest presentation",
			value: publicManifestPresentation(manifest.PresentationSpec{
				DefaultLocale: "en-US",
				Summary:       "Summary",
				Localizations: []manifest.PresentationLocalizationSpec{{
					Locale: "fr-FR", PluginName: "Plugin", Summary: "Resume",
					Settings: []manifest.LocalizedSettingPresentation{{Key: "mode", Label: "Mode"}},
				}},
			}),
			expected: `{
				"default_locale":"en-US","summary":"Summary",
				"description":[],"highlights":[],"keywords":[],
				"localizations":[{
					"locale":"fr-FR","plugin_name":"Plugin","summary":"Resume",
					"description":[],"highlights":[],"keywords":[],"surfaces":[],
					"settings":[{"key":"mode","label":"Mode","options":[]}]
				}]
			}`,
		},
		{
			name: "resolved presentation catalog",
			value: publicPresentationCatalog(manifest.PresentationCatalog{
				DefaultLocale: "en-US",
				Locales: []manifest.PresentationLocale{{
					Locale: "en-US", PluginName: "Plugin", Summary: "Summary",
					Settings: []manifest.ResolvedSettingPresentation{{Key: "mode", Label: "Mode"}},
				}},
			}),
			expected: `{
				"default_locale":"en-US",
				"locales":[{
					"locale":"en-US","plugin_name":"Plugin","summary":"Summary",
					"description":[],"highlights":[],"keywords":[],"surfaces":[],
					"settings":[{"key":"mode","label":"Mode","options":[]}]
				}]
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualJSON, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var actual any
			if err := json.Unmarshal(actualJSON, &actual); err != nil {
				t.Fatalf("json.Unmarshal(actual) error = %v", err)
			}
			var expected any
			if err := json.Unmarshal([]byte(test.expected), &expected); err != nil {
				t.Fatalf("json.Unmarshal(expected) error = %v", err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("public JSON = %s, want %s", actualJSON, test.expected)
			}
		})
	}
}
