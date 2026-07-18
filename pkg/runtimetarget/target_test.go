package runtimetarget

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestSupportedTargetsAreClosedAndCanonical(t *testing.T) {
	want := []Target{DarwinAMD64, DarwinARM64, LinuxAMD64, LinuxARM64}
	if got := Supported(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Supported() = %#v, want %#v", got, want)
	}
	wantStrings := []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}
	for index, target := range want {
		parsed, err := Parse(wantStrings[index])
		if err != nil || parsed != target || target.String() != wantStrings[index] {
			t.Fatalf("target %q round trip = %v, err=%v", wantStrings[index], parsed, err)
		}
		fromParts, err := FromParts(target.OS(), target.Arch())
		if err != nil || fromParts != target {
			t.Fatalf("target parts round trip = %v, err=%v", fromParts, err)
		}
	}

	mutated := Supported()
	mutated[0] = 0
	if Supported()[0] != DarwinAMD64 {
		t.Fatal("Supported() returned shared mutable storage")
	}
}

func TestTargetRejectsAliasesAndUnknownRepresentations(t *testing.T) {
	for _, value := range []string{"", "macos/arm64", "darwin/aarch64", "linux/x86_64", "linux/amd64 ", "LINUX/AMD64"} {
		if _, err := Parse(value); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Parse(%q) error = %v, want ErrUnsupported", value, err)
		}
	}
	for _, target := range []Target{0, 5, 255} {
		if err := Validate(target); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Validate(%d) error = %v, want ErrUnsupported", target, err)
		}
		if _, err := json.Marshal(target); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Marshal(%d) error = %v, want ErrUnsupported", target, err)
		}
	}
}

func TestTargetJSONIsCanonicalStringOnly(t *testing.T) {
	raw, err := json.Marshal(LinuxARM64)
	if err != nil || string(raw) != `"linux/arm64"` {
		t.Fatalf("Marshal() = %s, err=%v", raw, err)
	}
	var target Target
	if err := json.Unmarshal(raw, &target); err != nil || target != LinuxARM64 {
		t.Fatalf("Unmarshal() = %v, err=%v", target, err)
	}
	for _, raw := range []string{
		`"linux/x86_64"`,
		`{"os":"linux","arch":"amd64"}`,
		`null`,
		`1`,
		`"linux/amd64" true`,
	} {
		if err := json.Unmarshal([]byte(raw), &target); err == nil {
			t.Fatalf("Unmarshal(%s) unexpectedly succeeded", raw)
		}
	}
}
