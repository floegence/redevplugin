package authorapi

import (
	"strings"
	"testing"
)

func TestRustRootPreservesComposedAndPatternedFields(t *testing.T) {
	for _, schema := range []map[string]any{
		{"type": "object"},
		{"type": "object", "additionalProperties": true},
		{"type": "object", "patternProperties": map[string]any{"^x": map[string]any{"type": "string"}}},
		{"type": "object", "oneOf": []any{map[string]any{"type": "object"}}},
		{"$ref": "#/$defs/Input"},
	} {
		var out strings.Builder
		rustRoot(&out, "Input", schema)
		if out.String() != "pub type Input = serde_json::Value;\n\n" {
			t.Fatal(out.String())
		}
	}
}

func TestTypeScriptPreservesOpenObjectsAndUnsupportedReferences(t *testing.T) {
	if got := tsType(map[string]any{"type": "object"}, "Input"); !strings.Contains(got, "[key: string]") {
		t.Fatal(got)
	}
	for _, ref := range []string{"#", "#/properties/item", "#/$defs/item/properties/value"} {
		if got := tsType(map[string]any{"$ref": ref}, "Input"); got != "PluginJSONValue" {
			t.Fatal(got)
		}
	}
}
