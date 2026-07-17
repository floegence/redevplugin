package jsonvalue

import (
	"encoding/json"
	"strings"
	"testing"
)

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
