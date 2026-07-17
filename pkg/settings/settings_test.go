package settings

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
)

func TestCanonicalSchemaExcludesUIAndSecrets(t *testing.T) {
	spec := testSpec()
	schema, err := CanonicalSchema(&spec)
	if err != nil {
		t.Fatal(err)
	}
	if schema.SchemaVersion != 3 || len(schema.Fields) != 4 {
		t.Fatalf("schema = %#v", schema)
	}
	if got := fieldKeys(schema.Fields); !reflect.DeepEqual(got, []string{"enabled", "mode", "name", "retries"}) {
		t.Fatalf("field keys = %v", got)
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"label", "description", "secret", "secret_ref", "API token"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("canonical schema contains %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), `"schema_version":3`) || !strings.Contains(string(raw), `"min_length":2`) {
		t.Fatalf("canonical schema omitted data semantics: %s", raw)
	}
}

func TestCanonicalSchemaIsDeterministicAndDistinguishesSemantics(t *testing.T) {
	base := manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{
		{Key: "mode", Type: FieldSelect, Scope: "user", Label: "Mode", Options: []string{"slow", "fast"}, Default: "fast"},
	}}
	canonical := mustCanonicalJSON(t, base)
	reordered := base
	reordered.Fields = append([]manifest.SettingFieldSpec(nil), base.Fields...)
	reordered.Fields[0].Label = "Different UI copy"
	reordered.Fields[0].Options = []string{"fast", "slow"}
	if got := mustCanonicalJSON(t, reordered); got != canonical {
		t.Fatalf("non-data changes altered schema:\n%s\n%s", canonical, got)
	}

	tests := []struct {
		name   string
		mutate func(*manifest.SettingsSpec)
	}{
		{name: "schema version", mutate: func(spec *manifest.SettingsSpec) { spec.SchemaVersion++ }},
		{name: "type", mutate: func(spec *manifest.SettingsSpec) { spec.Fields[0].Type = FieldString; spec.Fields[0].Options = nil }},
		{name: "scope", mutate: func(spec *manifest.SettingsSpec) { spec.Fields[0].Scope = "environment" }},
		{name: "options", mutate: func(spec *manifest.SettingsSpec) { spec.Fields[0].Options = []string{"fast", "safe"} }},
		{name: "default", mutate: func(spec *manifest.SettingsSpec) { spec.Fields[0].Default = "slow" }},
		{name: "constraint", mutate: func(spec *manifest.SettingsSpec) {
			spec.Fields[0].Type = FieldString
			spec.Fields[0].Options = nil
			spec.Fields[0].Validation = map[string]any{"max_length": 8}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Fields = append([]manifest.SettingFieldSpec(nil), base.Fields...)
			test.mutate(&candidate)
			if got := mustCanonicalJSON(t, candidate); got == canonical {
				t.Fatalf("%s did not alter canonical schema: %s", test.name, got)
			}
		})
	}
}

func TestCanonicalizeSchemaCanonicalizesConstructedFields(t *testing.T) {
	minimum := float64(0)
	schema, err := CanonicalizeSchema(Schema{SchemaVersion: 2, Fields: []Field{
		{Key: " z ", Type: FieldNumber, Scope: "user", Validation: &Validation{Minimum: &minimum}},
		{Key: "a", Type: FieldSelect, Scope: "environment", Options: []string{"two", "one"}, Validation: &Validation{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fieldKeys(schema.Fields); !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatalf("keys = %v", got)
	}
	if !reflect.DeepEqual(schema.Fields[0].Options, []string{"one", "two"}) || schema.Fields[0].Validation != nil {
		t.Fatalf("field was not canonicalized: %#v", schema.Fields[0])
	}
	if _, err := CanonicalizeSchema(Schema{Fields: []Field{{Key: "value", Type: FieldString, Scope: "user"}}}); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("zero-version schema error = %v, want ErrInvalidSetting", err)
	}
	if schema, err := CanonicalizeSchema(Schema{SchemaVersion: 4}); err != nil || schema.SchemaVersion != 4 || len(schema.Fields) != 0 {
		t.Fatalf("secret-only schema normalization = %#v, %v", schema, err)
	}
}

func TestDefaultAndValueNormalization(t *testing.T) {
	fields, err := NonSecretFields(ptr(testSpec()))
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := DefaultValues(fields)
	if err != nil {
		t.Fatal(err)
	}
	if got := rawStrings(defaults); !reflect.DeepEqual(got, map[string]string{
		"enabled": "true",
		"mode":    `"fast"`,
		"name":    `"插件"`,
		"retries": "2",
	}) {
		t.Fatalf("defaults = %#v", got)
	}
	normalized, err := NormalizeRawValues(fields, map[string]json.RawMessage{
		"enabled": json.RawMessage("false"),
		"mode":    json.RawMessage(`"slow"`),
		"name":    json.RawMessage(`"用户"`),
		"retries": json.RawMessage("4.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rawStrings(normalized); !reflect.DeepEqual(got, map[string]string{
		"enabled": "false",
		"mode":    `"slow"`,
		"name":    `"用户"`,
		"retries": "4",
	}) {
		t.Fatalf("normalized = %#v", got)
	}
	decoded, err := DecodeValues(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["retries"] != json.Number("4") || decoded["name"] != "用户" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestNonSecretFieldsRejectsInvalidSchema(t *testing.T) {
	valid := manifest.SettingFieldSpec{Key: "value", Type: FieldString, Scope: "user"}
	tests := []struct {
		name   string
		fields []manifest.SettingFieldSpec
	}{
		{name: "missing key", fields: []manifest.SettingFieldSpec{{Type: FieldString, Scope: "user"}}},
		{name: "duplicate key", fields: []manifest.SettingFieldSpec{valid, valid}},
		{name: "invalid scope", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "global"}}},
		{name: "unknown type", fields: []manifest.SettingFieldSpec{{Key: "value", Type: "object", Scope: "user"}}},
		{name: "options on string", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", Options: []string{"x"}}}},
		{name: "missing options", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldEnum, Scope: "user"}}},
		{name: "empty option", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldEnum, Scope: "user", Options: []string{""}}}},
		{name: "duplicate option", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldEnum, Scope: "user", Options: []string{"x", " x "}}}},
		{name: "secret default", fields: []manifest.SettingFieldSpec{{Key: "token", Type: FieldSecret, Scope: "user", SecretRef: "token", Default: "unsafe"}}},
		{name: "secret ref on data", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", SecretRef: "token"}}},
		{name: "unknown validation", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", Validation: map[string]any{"pattern": ".*"}}}},
		{name: "fractional length", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", Validation: map[string]any{"min_length": 1.5}}}},
		{name: "negative length", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", Validation: map[string]any{"min_length": -1}}}},
		{name: "reversed length", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldString, Scope: "user", Validation: map[string]any{"min_length": 2, "max_length": 1}}}},
		{name: "nonfinite minimum", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldNumber, Scope: "user", Validation: map[string]any{"minimum": math.Inf(1)}}}},
		{name: "reversed range", fields: []manifest.SettingFieldSpec{{Key: "value", Type: FieldNumber, Scope: "user", Validation: map[string]any{"minimum": 2, "maximum": 1}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NonSecretFields(&manifest.SettingsSpec{SchemaVersion: 1, Fields: test.fields})
			if !errors.Is(err, ErrInvalidSetting) {
				t.Fatalf("error = %v, want ErrInvalidSetting", err)
			}
		})
	}
}

func TestNormalizeRawValuesRejectsInvalidValues(t *testing.T) {
	fields, err := NonSecretFields(ptr(testSpec()))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		key   string
		value json.RawMessage
	}{
		{name: "unknown", key: "missing", value: json.RawMessage("true")},
		{name: "secret", key: "api_token", value: json.RawMessage(`"unsafe"`)},
		{name: "wrong type", key: "enabled", value: json.RawMessage(`"true"`)},
		{name: "invalid enum", key: "mode", value: json.RawMessage(`"other"`)},
		{name: "below minimum", key: "retries", value: json.RawMessage("-1")},
		{name: "above maximum", key: "retries", value: json.RawMessage("6")},
		{name: "fractional integer", key: "retries", value: json.RawMessage("1.5")},
		{name: "unsafe integer", key: "retries", value: json.RawMessage("9007199254740992")},
		{name: "short unicode string", key: "name", value: json.RawMessage(`"a"`)},
		{name: "trailing json", key: "enabled", value: json.RawMessage("true false")},
		{name: "nonfinite json number", key: "retries", value: json.RawMessage("1e999")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeRawValues(fields, map[string]json.RawMessage{test.key: test.value})
			if !errors.Is(err, ErrInvalidSetting) {
				t.Fatalf("error = %v, want ErrInvalidSetting", err)
			}
		})
	}
}

func TestSettingsAPIsDoNotShareInputs(t *testing.T) {
	spec := testSpec()
	fields, err := NonSecretFields(&spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields[1].Options[0] = "mutated"
	spec.Fields[2].Validation["min_length"] = 99
	if fields[1].Options[0] != "fast" || *fields[2].Validation.MinLength != 2 {
		t.Fatalf("canonical fields share manifest inputs: %#v", fields)
	}

	defaults, err := DefaultValues(fields)
	if err != nil {
		t.Fatal(err)
	}
	defaults["name"][1] = 'X'
	if string(fields[2].Default) != `"插件"` {
		t.Fatalf("default output shares field storage: %s", fields[2].Default)
	}

	input := map[string]json.RawMessage{"name": json.RawMessage(`"用户"`)}
	normalized, err := NormalizeRawValues(fields, input)
	if err != nil {
		t.Fatal(err)
	}
	input["name"][1] = 'X'
	if string(normalized["name"]) != `"用户"` {
		t.Fatalf("normalized values share raw input: %s", normalized["name"])
	}

	raw := map[string]json.RawMessage{"nested": json.RawMessage(`{"list":[1,2]}`)}
	decoded, err := DecodeValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw["nested"][2] = 'X'
	object := decoded["nested"].(map[string]any)
	object["list"].([]any)[0] = json.Number("9")
	decodedAgain, err := DecodeValues(map[string]json.RawMessage{"nested": json.RawMessage(`{"list":[1,2]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := decodedAgain["nested"].(map[string]any)["list"].([]any)[0]; got != json.Number("1") {
		t.Fatalf("DecodeValues retained shared state: %#v", decodedAgain)
	}
}

func testSpec() manifest.SettingsSpec {
	return manifest.SettingsSpec{
		SchemaVersion: 3,
		Fields: []manifest.SettingFieldSpec{
			{Key: "enabled", Type: FieldBoolean, Label: "Enabled", Scope: "user", Default: true},
			{Key: "mode", Type: FieldSelect, Label: "Mode", Scope: "user", Options: []string{"slow", "fast"}, Default: "fast"},
			{Key: "name", Type: FieldString, Label: "Display name", Scope: "environment", Default: "插件", Validation: map[string]any{"min_length": 2, "max_length": 8}},
			{Key: "retries", Type: FieldInteger, Label: "Retries", Scope: "user", Default: 2, Validation: map[string]any{"minimum": 0, "maximum": 5}},
			{Key: "api_token", Type: FieldSecret, Label: "API token", Scope: "user", SecretRef: "api_token"},
		},
	}
}

func ptr(value manifest.SettingsSpec) *manifest.SettingsSpec {
	return &value
}

func mustCanonicalJSON(t *testing.T, spec manifest.SettingsSpec) string {
	t.Helper()
	raw, err := CanonicalSchemaJSON(&spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func fieldKeys(fields []Field) []string {
	keys := make([]string, len(fields))
	for i, field := range fields {
		keys[i] = field.Key
	}
	return keys
}

func rawStrings(values map[string]json.RawMessage) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = string(value)
	}
	return result
}
