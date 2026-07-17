package version

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	ErrInvalidSemVer    = errors.New("invalid semantic version")
	strictSemVerPattern = regexp.MustCompile(StrictSemVerPattern)
)

const StrictSemVerPattern = `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`

// SemVer is an immutable semantic version in the public, prefix-free form.
// Its zero value is invalid and cannot be encoded.
type SemVer struct {
	value string
}

func ParseSemVer(value string) (SemVer, error) {
	if !strictSemVerPattern.MatchString(value) || strings.TrimSpace(value) != value || !semver.IsValid("v"+value) {
		return SemVer{}, fmt.Errorf("%w: %q", ErrInvalidSemVer, value)
	}
	return SemVer{value: value}, nil
}

func (v SemVer) String() string {
	return v.value
}

func (v SemVer) Compare(other SemVer) int {
	if v.value == "" || other.value == "" {
		panic("version.SemVer.Compare called with an invalid zero value")
	}
	return semver.Compare("v"+v.value, "v"+other.value)
}

func (v SemVer) MarshalJSON() ([]byte, error) {
	if v.value == "" {
		return nil, ErrInvalidSemVer
	}
	return json.Marshal(v.value)
}

func (v *SemVer) UnmarshalJSON(raw []byte) error {
	if v == nil {
		return ErrInvalidSemVer
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value string
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("%w: semantic version must be a JSON string", ErrInvalidSemVer)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: semantic version must contain exactly one JSON value", ErrInvalidSemVer)
	}
	parsed, err := ParseSemVer(value)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

func (v SemVer) MarshalText() ([]byte, error) {
	if v.value == "" {
		return nil, ErrInvalidSemVer
	}
	return []byte(v.value), nil
}

func (v *SemVer) UnmarshalText(text []byte) error {
	if v == nil {
		return ErrInvalidSemVer
	}
	parsed, err := ParseSemVer(string(text))
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}
