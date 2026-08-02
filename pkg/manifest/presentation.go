package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

const (
	maxPresentationLocales     = 16
	maxPresentationDescription = 8000
)

type PresentationSpec struct {
	DefaultLocale string                         `json:"default_locale"`
	Summary       string                         `json:"summary"`
	Description   []string                       `json:"description"`
	Highlights    []string                       `json:"highlights"`
	Keywords      []string                       `json:"keywords"`
	Localizations []PresentationLocalizationSpec `json:"localizations"`
}

type PresentationLocalizationSpec struct {
	Locale        string                         `json:"locale"`
	PluginName    string                         `json:"plugin_name"`
	PublisherName string                         `json:"publisher_name,omitempty"`
	Summary       string                         `json:"summary"`
	Description   []string                       `json:"description"`
	Highlights    []string                       `json:"highlights"`
	Keywords      []string                       `json:"keywords"`
	Surfaces      []LocalizedSurfacePresentation `json:"surfaces"`
	Settings      []LocalizedSettingPresentation `json:"settings"`
}

type LocalizedSurfacePresentation struct {
	SurfaceID string `json:"surface_id"`
	Label     string `json:"label"`
}

type LocalizedSettingPresentation struct {
	Key     string              `json:"key"`
	Label   string              `json:"label"`
	Options []SettingOptionSpec `json:"options"`
}

type PresentationCatalog struct {
	DefaultLocale string               `json:"default_locale"`
	Locales       []PresentationLocale `json:"locales"`
}

type PresentationLocale struct {
	Locale        string                        `json:"locale"`
	PluginName    string                        `json:"plugin_name"`
	PublisherName string                        `json:"publisher_name,omitempty"`
	Summary       string                        `json:"summary"`
	Description   []string                      `json:"description"`
	Highlights    []string                      `json:"highlights"`
	Keywords      []string                      `json:"keywords"`
	Surfaces      []ResolvedSurfacePresentation `json:"surfaces"`
	Settings      []ResolvedSettingPresentation `json:"settings"`
}

type ResolvedSurfacePresentation struct {
	SurfaceID string `json:"surface_id"`
	Label     string `json:"label"`
}

type ResolvedSettingPresentation struct {
	Key     string              `json:"key"`
	Label   string              `json:"label"`
	Options []SettingOptionSpec `json:"options"`
}

type ResolvedPresentation struct {
	RequestedLocale string                        `json:"requested_locale,omitempty"`
	ResolvedLocale  string                        `json:"resolved_locale"`
	DefaultLocale   string                        `json:"default_locale"`
	PluginName      string                        `json:"plugin_name"`
	PublisherName   string                        `json:"publisher_name,omitempty"`
	Summary         string                        `json:"summary"`
	Description     []string                      `json:"description"`
	Highlights      []string                      `json:"highlights"`
	Keywords        []string                      `json:"keywords"`
	Surfaces        []ResolvedSurfacePresentation `json:"surfaces"`
	Settings        []ResolvedSettingPresentation `json:"settings"`
}

func (m Manifest) PresentationCatalog() PresentationCatalog {
	locales := make([]PresentationLocale, 0, len(m.Presentation.Localizations)+1)
	defaultLocale := PresentationLocale{
		Locale:        m.Presentation.DefaultLocale,
		PluginName:    m.Plugin.DisplayName,
		PublisherName: m.Publisher.DisplayName,
		Summary:       m.Presentation.Summary,
		Description:   cloneStrings(m.Presentation.Description),
		Highlights:    cloneStrings(m.Presentation.Highlights),
		Keywords:      cloneStrings(m.Presentation.Keywords),
		Surfaces:      make([]ResolvedSurfacePresentation, len(m.Surfaces)),
	}
	for index, surface := range m.Surfaces {
		defaultLocale.Surfaces[index] = ResolvedSurfacePresentation{SurfaceID: surface.SurfaceID, Label: surface.Label}
	}
	if m.Settings != nil {
		defaultLocale.Settings = make([]ResolvedSettingPresentation, len(m.Settings.Fields))
		for index, field := range m.Settings.Fields {
			defaultLocale.Settings[index] = ResolvedSettingPresentation{Key: field.Key, Label: field.Label, Options: cloneSettingOptions(field.Options)}
		}
	} else {
		defaultLocale.Settings = []ResolvedSettingPresentation{}
	}
	locales = append(locales, defaultLocale)
	localizations := append([]PresentationLocalizationSpec(nil), m.Presentation.Localizations...)
	sort.Slice(localizations, func(i, j int) bool { return localizations[i].Locale < localizations[j].Locale })
	for _, localization := range localizations {
		localizedSurfaces := make(map[string]string, len(localization.Surfaces))
		for _, surface := range localization.Surfaces {
			localizedSurfaces[surface.SurfaceID] = surface.Label
		}
		localizedSettings := make(map[string]LocalizedSettingPresentation, len(localization.Settings))
		for _, setting := range localization.Settings {
			localizedSettings[setting.Key] = setting
		}
		locale := PresentationLocale{
			Locale:        localization.Locale,
			PluginName:    localization.PluginName,
			PublisherName: localization.PublisherName,
			Summary:       localization.Summary,
			Description:   cloneStrings(localization.Description),
			Highlights:    cloneStrings(localization.Highlights),
			Keywords:      cloneStrings(localization.Keywords),
			Surfaces:      make([]ResolvedSurfacePresentation, len(m.Surfaces)),
		}
		for index, surface := range m.Surfaces {
			locale.Surfaces[index] = ResolvedSurfacePresentation{SurfaceID: surface.SurfaceID, Label: localizedSurfaces[surface.SurfaceID]}
		}
		if m.Settings != nil {
			locale.Settings = make([]ResolvedSettingPresentation, len(m.Settings.Fields))
			for index, field := range m.Settings.Fields {
				setting := localizedSettings[field.Key]
				optionsByValue := make(map[string]string, len(setting.Options))
				for _, option := range setting.Options {
					optionsByValue[option.Value] = option.Label
				}
				options := make([]SettingOptionSpec, len(field.Options))
				for optionIndex, option := range field.Options {
					options[optionIndex] = SettingOptionSpec{Value: option.Value, Label: optionsByValue[option.Value]}
				}
				locale.Settings[index] = ResolvedSettingPresentation{Key: field.Key, Label: setting.Label, Options: options}
			}
		} else {
			locale.Settings = []ResolvedSettingPresentation{}
		}
		locales = append(locales, locale)
	}
	return PresentationCatalog{DefaultLocale: m.Presentation.DefaultLocale, Locales: locales}
}

func PresentationCatalogSHA256(catalog PresentationCatalog) (string, error) {
	raw, err := json.Marshal(catalog)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ResolvePresentation(catalog PresentationCatalog, requestedLocale string) ResolvedPresentation {
	byLocale := make(map[string]PresentationLocale, len(catalog.Locales))
	for _, locale := range catalog.Locales {
		byLocale[locale.Locale] = locale
	}
	requestedCanonical, ok := canonicalLocale(requestedLocale)
	resolved := byLocale[catalog.DefaultLocale]
	if ok {
		for _, candidate := range localeLookupCandidates(requestedCanonical) {
			if locale, exists := byLocale[candidate]; exists {
				resolved = locale
				break
			}
		}
	}
	return ResolvedPresentation{
		RequestedLocale: requestedCanonical,
		ResolvedLocale:  resolved.Locale,
		DefaultLocale:   catalog.DefaultLocale,
		PluginName:      resolved.PluginName,
		PublisherName:   resolved.PublisherName,
		Summary:         resolved.Summary,
		Description:     cloneStrings(resolved.Description),
		Highlights:      cloneStrings(resolved.Highlights),
		Keywords:        cloneStrings(resolved.Keywords),
		Surfaces:        cloneSurfaces(resolved.Surfaces),
		Settings:        cloneSettings(resolved.Settings),
	}
}

func validatePresentation(m Manifest) error {
	if len(m.Presentation.Localizations)+1 > maxPresentationLocales {
		return ValidationError{Field: "presentation.localizations", Message: fmt.Sprintf("must contain at most %d entries", maxPresentationLocales-1)}
	}
	defaultLocale, ok := canonicalLocale(m.Presentation.DefaultLocale)
	if !ok || defaultLocale != m.Presentation.DefaultLocale {
		return ValidationError{Field: "presentation.default_locale", Message: "must be a canonical BCP 47 language tag"}
	}
	if err := validatePresentationText("plugin.display_name", m.Plugin.DisplayName, 128); err != nil {
		return err
	}
	if m.Publisher.DisplayName != "" {
		if err := validatePresentationText("publisher.display_name", m.Publisher.DisplayName, 128); err != nil {
			return err
		}
	}
	if err := validatePresentationBody("presentation", m.Presentation.Summary, m.Presentation.Description, m.Presentation.Highlights, m.Presentation.Keywords); err != nil {
		return err
	}
	for index, surface := range m.Surfaces {
		if err := validatePresentationText(fmt.Sprintf("surfaces[%d].label", index), surface.Label, 128); err != nil {
			return err
		}
	}
	if m.Settings != nil {
		for index, setting := range m.Settings.Fields {
			if err := validatePresentationText(fmt.Sprintf("settings.fields[%d].label", index), setting.Label, 128); err != nil {
				return err
			}
		}
	}

	seenLocales := map[string]struct{}{defaultLocale: {}}
	for index, localization := range m.Presentation.Localizations {
		field := fmt.Sprintf("presentation.localizations[%d]", index)
		locale, valid := canonicalLocale(localization.Locale)
		if !valid || locale != localization.Locale {
			return ValidationError{Field: field + ".locale", Message: "must be a canonical BCP 47 language tag"}
		}
		if _, exists := seenLocales[locale]; exists {
			return ValidationError{Field: field + ".locale", Message: "must be unique and different from default_locale"}
		}
		seenLocales[locale] = struct{}{}
		if err := validatePresentationText(field+".plugin_name", localization.PluginName, 128); err != nil {
			return err
		}
		if m.Publisher.DisplayName == "" {
			if localization.PublisherName != "" {
				return ValidationError{Field: field + ".publisher_name", Message: "is not allowed when publisher.display_name is absent"}
			}
		} else if err := validatePresentationText(field+".publisher_name", localization.PublisherName, 128); err != nil {
			return err
		}
		if err := validatePresentationBody(field, localization.Summary, localization.Description, localization.Highlights, localization.Keywords); err != nil {
			return err
		}
		if err := validateLocalizedSurfaces(field+".surfaces", m.Surfaces, localization.Surfaces); err != nil {
			return err
		}
		if err := validateLocalizedSettings(field+".settings", m.Settings, localization.Settings); err != nil {
			return err
		}
	}
	return nil
}

func validatePresentationBody(field, summary string, description, highlights, keywords []string) error {
	if err := validatePresentationText(field+".summary", summary, 240); err != nil {
		return err
	}
	if len(description) < 1 || len(description) > 12 {
		return ValidationError{Field: field + ".description", Message: "must contain between 1 and 12 paragraphs"}
	}
	total := 0
	for index, paragraph := range description {
		if err := validatePresentationText(fmt.Sprintf("%s.description[%d]", field, index), paragraph, 1000); err != nil {
			return err
		}
		total += utf8.RuneCountInString(paragraph)
	}
	if total > maxPresentationDescription {
		return ValidationError{Field: field + ".description", Message: fmt.Sprintf("must contain at most %d characters", maxPresentationDescription)}
	}
	if len(highlights) > 8 {
		return ValidationError{Field: field + ".highlights", Message: "must contain at most 8 entries"}
	}
	for index, highlight := range highlights {
		if err := validatePresentationText(fmt.Sprintf("%s.highlights[%d]", field, index), highlight, 240); err != nil {
			return err
		}
	}
	if len(keywords) < 1 || len(keywords) > 12 {
		return ValidationError{Field: field + ".keywords", Message: "must contain between 1 and 12 entries"}
	}
	fold := cases.Fold()
	seen := map[string]struct{}{}
	for index, keyword := range keywords {
		keywordField := fmt.Sprintf("%s.keywords[%d]", field, index)
		if err := validatePresentationText(keywordField, keyword, 64); err != nil {
			return err
		}
		key := fold.String(keyword)
		if _, exists := seen[key]; exists {
			return ValidationError{Field: keywordField, Message: "must be unique ignoring case"}
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateLocalizedSurfaces(field string, defaults []SurfaceSpec, localized []LocalizedSurfacePresentation) error {
	if len(localized) != len(defaults) {
		return ValidationError{Field: field, Message: "must contain exactly one label for every surface"}
	}
	wanted := make(map[string]struct{}, len(defaults))
	for _, surface := range defaults {
		wanted[surface.SurfaceID] = struct{}{}
	}
	seen := map[string]struct{}{}
	for index, surface := range localized {
		itemField := fmt.Sprintf("%s[%d]", field, index)
		if _, exists := wanted[surface.SurfaceID]; !exists {
			return ValidationError{Field: itemField + ".surface_id", Message: "must reference a declared surface"}
		}
		if _, exists := seen[surface.SurfaceID]; exists {
			return ValidationError{Field: itemField + ".surface_id", Message: "must be unique"}
		}
		seen[surface.SurfaceID] = struct{}{}
		if err := validatePresentationText(itemField+".label", surface.Label, 128); err != nil {
			return err
		}
	}
	return nil
}

func validateLocalizedSettings(field string, defaults *SettingsSpec, localized []LocalizedSettingPresentation) error {
	if defaults == nil {
		if len(localized) != 0 {
			return ValidationError{Field: field, Message: "must be empty when settings are absent"}
		}
		return nil
	}
	if len(localized) != len(defaults.Fields) {
		return ValidationError{Field: field, Message: "must contain exactly one label for every setting"}
	}
	wanted := make(map[string]SettingFieldSpec, len(defaults.Fields))
	for _, setting := range defaults.Fields {
		wanted[setting.Key] = setting
	}
	seen := map[string]struct{}{}
	for index, setting := range localized {
		itemField := fmt.Sprintf("%s[%d]", field, index)
		defaultSetting, exists := wanted[setting.Key]
		if !exists {
			return ValidationError{Field: itemField + ".key", Message: "must reference a declared setting"}
		}
		if _, duplicate := seen[setting.Key]; duplicate {
			return ValidationError{Field: itemField + ".key", Message: "must be unique"}
		}
		seen[setting.Key] = struct{}{}
		if err := validatePresentationText(itemField+".label", setting.Label, 128); err != nil {
			return err
		}
		if len(setting.Options) != len(defaultSetting.Options) {
			return ValidationError{Field: itemField + ".options", Message: "must contain exactly one label for every setting option"}
		}
		wantedOptions := make(map[string]struct{}, len(defaultSetting.Options))
		for _, option := range defaultSetting.Options {
			wantedOptions[option.Value] = struct{}{}
		}
		seenOptions := map[string]struct{}{}
		for optionIndex, option := range setting.Options {
			optionField := fmt.Sprintf("%s.options[%d]", itemField, optionIndex)
			if _, exists := wantedOptions[option.Value]; !exists {
				return ValidationError{Field: optionField + ".value", Message: "must reference a declared setting option"}
			}
			if _, exists := seenOptions[option.Value]; exists {
				return ValidationError{Field: optionField + ".value", Message: "must be unique"}
			}
			seenOptions[option.Value] = struct{}{}
			if err := validatePresentationText(optionField+".label", option.Label, 128); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePresentationText(field, value string, maxRunes int) error {
	if value == "" || strings.TrimSpace(value) != value {
		return ValidationError{Field: field, Message: "must be non-empty without leading or trailing whitespace"}
	}
	if !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return ValidationError{Field: field, Message: "must be valid NFC-normalized UTF-8"}
	}
	if utf8.RuneCountInString(value) > maxRunes {
		return ValidationError{Field: field, Message: fmt.Sprintf("must contain at most %d characters", maxRunes)}
	}
	for _, valueRune := range value {
		if unicode.IsControl(valueRune) {
			return ValidationError{Field: field, Message: "must not contain control characters"}
		}
	}
	return nil
}

func canonicalLocale(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "_") {
		return "", false
	}
	tag, err := language.Parse(value)
	if err != nil || tag == language.Und {
		return "", false
	}
	return tag.String(), true
}

func localeLookupCandidates(locale string) []string {
	parts := strings.Split(locale, "-")
	result := make([]string, 0, len(parts))
	for len(parts) > 0 {
		result = append(result, strings.Join(parts, "-"))
		parts = parts[:len(parts)-1]
		if len(parts) > 0 && len(parts[len(parts)-1]) == 1 {
			parts = parts[:len(parts)-1]
		}
	}
	return result
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneSettingOptions(values []SettingOptionSpec) []SettingOptionSpec {
	return append([]SettingOptionSpec(nil), values...)
}

func cloneSurfaces(values []ResolvedSurfacePresentation) []ResolvedSurfacePresentation {
	return append([]ResolvedSurfacePresentation(nil), values...)
}

func cloneSettings(values []ResolvedSettingPresentation) []ResolvedSettingPresentation {
	result := make([]ResolvedSettingPresentation, len(values))
	for index, value := range values {
		result[index] = ResolvedSettingPresentation{Key: value.Key, Label: value.Label, Options: cloneSettingOptions(value.Options)}
	}
	return result
}
