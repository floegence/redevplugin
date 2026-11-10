package manifest

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPresentationCategoryContract(t *testing.T) {
	for _, category := range []string{"development", "infrastructure", "utilities", "data", "collaboration", "productivity", "other", ""} {
		t.Run(category, func(t *testing.T) {
			raw := v9TestManifest("")
			if category != "" {
				raw = bytes.Replace(raw, []byte(`"presentation":{`), []byte(`"presentation":{"category":"`+category+`",`), 1)
			}
			m, canonical, err := DecodeCanonical(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			expected := category
			if expected == "" {
				expected = "other"
			}
			for _, projection := range []any{ResolvePresentation(m.PresentationCatalog(), "en-US")} {
				encoded, err := json.Marshal(projection)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err := json.Unmarshal(encoded, &fields); err != nil {
					t.Fatal(err)
				}
				if fields["category"] != expected {
					t.Fatalf("category = %v, want %s", fields["category"], expected)
				}
			}
			if category == "" && bytes.Contains(canonical, []byte(`"category"`)) {
				t.Fatal("default rewrote canonical package bytes")
			}
			if category != "" {
				if m.Presentation.Category != PluginCategory(category) || m.PresentationCatalog().Category != PluginCategory(category) {
					t.Fatal("category missing from projection")
				}
				source, err := AuthorSource(canonical, "category-test")
				if err != nil {
					t.Fatal(err)
				}
				compiled, _, err := DecodeAuthorCanonical(bytes.NewReader(source))
				if err != nil || compiled.Presentation.Category != PluginCategory(category) {
					t.Fatalf("author category lost: %v", err)
				}
				first, err := PresentationCatalogSHA256(m.PresentationCatalog())
				if err != nil {
					t.Fatal(err)
				}
				m.Presentation.Category = ""
				second, err := PresentationCatalogSHA256(m.PresentationCatalog())
				if err != nil || first == second {
					t.Fatal("category is not digest-bound")
				}
			}
		})
	}
}

func TestPresentationCategoryRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{`""`, `"weather"`, `"Data"`, `" data"`, `null`, `[]`, `7`} {
		raw := bytes.Replace(v9TestManifest(""), []byte(`"presentation":{`), []byte(`"presentation":{"category":`+value+`,`), 1)
		if _, err := Decode(bytes.NewReader(raw)); err == nil {
			t.Fatalf("accepted category %s", value)
		}
	}
}
