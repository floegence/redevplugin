// Package runtimetarget defines the closed platform target contract shared by
// runtime supervision, host compatibility checks, and persisted registry data.
package runtimetarget

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
)

var ErrUnsupported = errors.New("runtime target is unsupported")

// Target identifies one supported runtime operating-system and architecture
// pair. The zero value and values outside the declared constants are invalid.
type Target uint8

const (
	DarwinAMD64 Target = iota + 1
	DarwinARM64
	LinuxAMD64
	LinuxARM64
)

var supportedTargets = [...]Target{
	DarwinAMD64,
	DarwinARM64,
	LinuxAMD64,
	LinuxARM64,
}

// Supported returns the complete canonical target set in lexical order.
func Supported() []Target {
	return append([]Target(nil), supportedTargets[:]...)
}

// Parse parses the canonical os/arch target identifier.
func Parse(value string) (Target, error) {
	switch value {
	case "darwin/amd64":
		return DarwinAMD64, nil
	case "darwin/arm64":
		return DarwinARM64, nil
	case "linux/amd64":
		return LinuxAMD64, nil
	case "linux/arm64":
		return LinuxARM64, nil
	default:
		return 0, fmt.Errorf("%w: target=%q", ErrUnsupported, value)
	}
}

// FromParts constructs a target from canonical wire components.
func FromParts(os, arch string) (Target, error) {
	return Parse(os + "/" + arch)
}

// Current resolves the current process platform to a supported target.
func Current() (Target, error) {
	return FromParts(runtime.GOOS, runtime.GOARCH)
}

func Validate(target Target) error {
	if target < DarwinAMD64 || target > LinuxARM64 {
		return fmt.Errorf("%w: target=%d", ErrUnsupported, target)
	}
	return nil
}

func (target Target) String() string {
	switch target {
	case DarwinAMD64:
		return "darwin/amd64"
	case DarwinARM64:
		return "darwin/arm64"
	case LinuxAMD64:
		return "linux/amd64"
	case LinuxARM64:
		return "linux/arm64"
	default:
		return ""
	}
}

func (target Target) OS() string {
	switch target {
	case DarwinAMD64, DarwinARM64:
		return "darwin"
	case LinuxAMD64, LinuxARM64:
		return "linux"
	default:
		return ""
	}
}

func (target Target) Arch() string {
	switch target {
	case DarwinAMD64, LinuxAMD64:
		return "amd64"
	case DarwinARM64, LinuxARM64:
		return "arm64"
	default:
		return ""
	}
}

func (target Target) MarshalJSON() ([]byte, error) {
	if err := Validate(target); err != nil {
		return nil, err
	}
	return json.Marshal(target.String())
}

func (target *Target) UnmarshalJSON(raw []byte) error {
	if target == nil {
		return ErrUnsupported
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%w: target must be a canonical string", ErrUnsupported)
	}
	parsed, err := Parse(value)
	if err != nil {
		return err
	}
	*target = parsed
	return nil
}
