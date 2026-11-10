package manifest

import "encoding/json"

// PluginCategory is author-owned discovery metadata, never execution authority.
type PluginCategory string

func (category PluginCategory) Valid() bool {
	switch category {
	case "development", "infrastructure", "utilities", "data", "collaboration", "productivity", "other":
		return true
	default:
		return false
	}
}

// Effective assigns uncategorized packages to other without rewriting package bytes
// or their presentation digest. Explicit values must pass manifest validation.
func (category PluginCategory) Effective() PluginCategory {
	if category == "" {
		return "other"
	}
	return category
}

func (category *PluginCategory) UnmarshalJSON(raw []byte) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || !PluginCategory(value).Valid() {
		return ValidationError{Field: "presentation.category", Message: "must be a predefined plugin category"}
	}
	*category = PluginCategory(value)
	return nil
}
