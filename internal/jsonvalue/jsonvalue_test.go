package jsonvalue

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCloneCanonicalOwnsEveryNestedContainer(t *testing.T) {
	shared := map[string]any{"values": []any{map[string]any{"value": "original"}}}
	input := map[string]any{"first": shared, "second": shared}
	clonedValue, err := CloneCanonical(input)
	if err != nil {
		t.Fatal(err)
	}
	cloned := clonedValue.(map[string]any)
	shared["values"].([]any)[0].(map[string]any)["value"] = "adapter mutation"
	first := cloned["first"].(map[string]any)
	second := cloned["second"].(map[string]any)
	if got := first["values"].([]any)[0].(map[string]any)["value"]; got != "original" {
		t.Fatalf("clone retained adapter-owned state: %#v", got)
	}
	first["values"].([]any)[0].(map[string]any)["value"] = "first mutation"
	if got := second["values"].([]any)[0].(map[string]any)["value"]; got != "original" {
		t.Fatalf("clone retained repeated-container alias: %#v", got)
	}
}

func TestCloneCanonicalPreservesNumberAndNullRepresentations(t *testing.T) {
	input := map[string]any{
		"number": json.Number("42.5"),
		"object": map[string]any(nil),
		"array":  []any(nil),
	}
	clonedValue, err := CloneCanonical(input)
	if err != nil {
		t.Fatal(err)
	}
	cloned := clonedValue.(map[string]any)
	if cloned["number"] != json.Number("42.5") {
		t.Fatalf("number representation changed: %#v", cloned["number"])
	}
	raw, err := json.Marshal(cloned)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"array":null,"number":42.5,"object":null}` {
		t.Fatalf("canonical null projection = %s", got)
	}
}

func TestDecodeClosedPreservesNumbersAndRejectsOpenDocuments(t *testing.T) {
	type document struct {
		Value any `json:"value"`
	}
	var decoded document
	if err := DecodeClosed([]byte(`{"value":42.5}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Value != json.Number("42.5") {
		t.Fatalf("decoded number = %#v, want json.Number", decoded.Value)
	}
	for _, raw := range []string{
		`{"value":42.5,"unexpected":true}`,
		`{"value":42.5} {}`,
		``,
		string([]byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 0xff, '"', '}'}),
	} {
		if err := DecodeClosed([]byte(raw), &document{}); err == nil {
			t.Fatalf("DecodeClosed() accepted %q", raw)
		}
	}
}

func TestCloneCanonicalRejectsValuesOutsideClosedJSONSet(t *testing.T) {
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle
	sliceCycle := make([]any, 1)
	sliceCycle[0] = sliceCycle
	tests := []struct {
		name  string
		value any
	}{
		{name: "native integer", value: 1},
		{name: "typed slice", value: []string{"value"}},
		{name: "struct", value: struct{ Value string }{Value: "value"}},
		{name: "nan", value: math.NaN()},
		{name: "infinity", value: math.Inf(1)},
		{name: "unsafe float", value: float64(1 << 53)},
		{name: "unsafe number", value: json.Number("9007199254740992")},
		{name: "invalid number", value: json.Number("01")},
		{name: "map cycle", value: mapCycle},
		{name: "slice cycle", value: sliceCycle},
		{name: "prototype key", value: map[string]any{"__proto__": nil}},
		{name: "invalid utf8 value", value: string([]byte{0xff})},
		{name: "invalid utf8 key", value: map[string]any{string([]byte{0xff}): nil}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CloneCanonical(test.value); err == nil {
				t.Fatalf("CloneCanonical() accepted %#v", test.value)
			}
		})
	}
}

func TestCloneCanonicalEnforcesStructuralBudgets(t *testing.T) {
	deep := any("leaf")
	for range maxDepth + 1 {
		deep = []any{deep}
	}
	for _, value := range []any{
		deep,
		make([]any, maxNodes),
		strings.Repeat("x", maxEncodedBytes),
	} {
		if _, err := CloneCanonical(value); err == nil {
			t.Fatal("CloneCanonical() accepted a value beyond its structural budget")
		}
	}
}

func BenchmarkCloneCanonical(b *testing.B) {
	items := make([]any, 256)
	for index := range items {
		items[index] = map[string]any{
			"id":    json.Number("42"),
			"name":  "canonical-owned-value",
			"flags": []any{true, false, nil},
		}
	}
	value := map[string]any{"items": items}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := CloneCanonical(value); err != nil {
			b.Fatal(err)
		}
	}
}

func TestValidateCanonicalExactLimits(t *testing.T) {
	exactBytes := strings.Repeat("x", maxEncodedBytes-2)
	if raw, err := json.Marshal(exactBytes); err != nil || len(raw) != maxEncodedBytes {
		t.Fatalf("exact byte fixture length = %d, err=%v", len(raw), err)
	}
	if err := ValidateCanonical(exactBytes); err != nil {
		t.Fatalf("ValidateCanonical() rejected exact byte limit: %v", err)
	}
	if err := ValidateCanonical(exactBytes + "x"); err == nil {
		t.Fatal("ValidateCanonical() accepted byte limit + 1")
	}

	exactNodes := make([]any, maxNodes-1)
	if err := ValidateCanonical(exactNodes); err != nil {
		t.Fatalf("ValidateCanonical() rejected exact node limit: %v", err)
	}
	if err := ValidateCanonical(append(exactNodes, nil)); err == nil {
		t.Fatal("ValidateCanonical() accepted node limit + 1")
	}

	exactDepth := any("leaf")
	for range maxDepth {
		exactDepth = []any{exactDepth}
	}
	if err := ValidateCanonical(exactDepth); err != nil {
		t.Fatalf("ValidateCanonical() rejected exact depth limit: %v", err)
	}
	if err := ValidateCanonical([]any{exactDepth}); err == nil {
		t.Fatal("ValidateCanonical() accepted depth limit + 1")
	}
}

func TestNumberExceedsSafeMagnitudeExactDecimalForms(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "0", want: false},
		{value: "-0.000e999999999999999999999", want: false},
		{value: "9007199254740991", want: false},
		{value: "-9007199254740991.000000", want: false},
		{value: "9.007199254740991e15", want: false},
		{value: "900719925474099100e-2", want: false},
		{value: "9007199254740991." + strings.Repeat("0", 300) + "1", want: true},
		{value: "-9007199254740992", want: true},
		{value: "9.007199254740992e15", want: true},
		{value: "1e999999999999999999999", want: true},
		{value: "1e-999999999999999999999", want: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := numberExceedsSafeMagnitude(json.Number(test.value)); got != test.want {
				t.Fatalf("numberExceedsSafeMagnitude(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}
