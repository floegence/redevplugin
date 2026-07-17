package version

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseSemVerAcceptsOnlyStrictPublicForm(t *testing.T) {
	for _, value := range []string{
		"0.0.0",
		"1.2.3",
		"1.2.3-alpha",
		"1.2.3-alpha.1",
		"1.2.3-0A-1+build.001",
		"999999999999999999999999.2.3",
	} {
		t.Run("valid_"+value, func(t *testing.T) {
			parsed, err := ParseSemVer(value)
			if err != nil {
				t.Fatalf("ParseSemVer(%q) error = %v", value, err)
			}
			if parsed.String() != value {
				t.Fatalf("ParseSemVer(%q).String() = %q", value, parsed.String())
			}
		})
	}

	for _, value := range []string{
		"", " ", " 1.2.3", "1.2.3 ", "v1.2.3", "V1.2.3",
		"1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
		"1.2.3-", "1.2.3+", "1.2.3-alpha..1", "1.2.3-alpha_1",
		"1.2.3-01", "1.2.3-alpha.01", "(devel)",
	} {
		t.Run("invalid_"+value, func(t *testing.T) {
			if _, err := ParseSemVer(value); !errors.Is(err, ErrInvalidSemVer) {
				t.Fatalf("ParseSemVer(%q) error = %v, want ErrInvalidSemVer", value, err)
			}
		})
	}
}

func TestSemVerCompareUsesPrecedenceAndIgnoresBuildMetadata(t *testing.T) {
	ordered := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	}
	for index := 0; index < len(ordered)-1; index++ {
		left, _ := ParseSemVer(ordered[index])
		right, _ := ParseSemVer(ordered[index+1])
		if left.Compare(right) >= 0 || right.Compare(left) <= 0 {
			t.Fatalf("SemVer order mismatch: %s, %s", left, right)
		}
	}
	left, _ := ParseSemVer("1.2.3+build.1")
	right, _ := ParseSemVer("1.2.3+build.2")
	if left.Compare(right) != 0 {
		t.Fatalf("build metadata affected precedence: %d", left.Compare(right))
	}
}

func TestSemVerJSONIsStrictAndRoundTrips(t *testing.T) {
	value, _ := ParseSemVer("1.2.3-rc.1+build.7")
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `"1.2.3-rc.1+build.7"` {
		t.Fatalf("SemVer JSON = %s", raw)
	}
	var decoded SemVer
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded != value {
		t.Fatalf("SemVer round trip = %v, err=%v", decoded, err)
	}
	for _, raw := range []string{`"v1.2.3"`, `"1.2"`, `"1.2.3-01"`, `null`, `1`} {
		if err := json.Unmarshal([]byte(raw), &decoded); !errors.Is(err, ErrInvalidSemVer) {
			t.Fatalf("UnmarshalJSON(%s) error = %v, want ErrInvalidSemVer", raw, err)
		}
	}
	if _, err := json.Marshal(SemVer{}); !errors.Is(err, ErrInvalidSemVer) {
		t.Fatalf("zero SemVer marshal error = %v, want ErrInvalidSemVer", err)
	}
	if err := decoded.UnmarshalJSON([]byte(`"1.2.3" {}`)); !errors.Is(err, ErrInvalidSemVer) {
		t.Fatalf("UnmarshalJSON() trailing document error = %v, want ErrInvalidSemVer", err)
	}
}
