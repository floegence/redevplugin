package runtimeclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/floegence/redevplugin/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/pkg/version"
)

const runtimeDescriptorSchemaVersion = "runtime-descriptor-v2"

var (
	ErrRuntimeDescriptorInvalid  = errors.New("runtime descriptor is invalid")
	ErrRuntimeDescriptorMismatch = errors.New("runtime descriptor does not match")
	lowerSHA256Pattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RuntimeDescriptorOptions struct {
	PlatformVersion   platformversion.SemVer
	Target            runtimetarget.Target
	RustIPCVersion    string
	WASMABIVersion    string
	ContractSetSHA256 string
	BinarySHA256      string
}

// RuntimeDescriptor is the immutable identity of one host-built runtime.
// Construct it with the options-only NewRuntimeDescriptor API.
type RuntimeDescriptor struct {
	platformVersion   platformversion.SemVer
	target            runtimetarget.Target
	rustIPCVersion    string
	wasmABIVersion    string
	contractSetSHA256 string
	binarySHA256      string
}

type runtimeDescriptorJSON struct {
	SchemaVersion     string `json:"schema_version"`
	PlatformVersion   string `json:"platform_version"`
	Target            string `json:"target"`
	RustIPCVersion    string `json:"rust_ipc_version"`
	WASMABIVersion    string `json:"wasm_abi_version"`
	ContractSetSHA256 string `json:"contract_set_sha256"`
	BinarySHA256      string `json:"binary_sha256"`
}

func NewRuntimeDescriptor(options RuntimeDescriptorOptions) (RuntimeDescriptor, error) {
	if options.PlatformVersion.String() == "" ||
		(options.Target != runtimetarget.LinuxAMD64 && options.Target != runtimetarget.LinuxARM64) ||
		options.RustIPCVersion != platformversion.RustIPCVersion ||
		options.WASMABIVersion != platformversion.WASMABIVersion ||
		!lowerSHA256Pattern.MatchString(options.ContractSetSHA256) ||
		!lowerSHA256Pattern.MatchString(options.BinarySHA256) {
		return RuntimeDescriptor{}, ErrRuntimeDescriptorInvalid
	}
	return RuntimeDescriptor{
		platformVersion:   options.PlatformVersion,
		target:            options.Target,
		rustIPCVersion:    options.RustIPCVersion,
		wasmABIVersion:    options.WASMABIVersion,
		contractSetSHA256: options.ContractSetSHA256,
		binarySHA256:      options.BinarySHA256,
	}, nil
}

func (d RuntimeDescriptor) PlatformVersion() platformversion.SemVer { return d.platformVersion }
func (d RuntimeDescriptor) Target() runtimetarget.Target            { return d.target }
func (d RuntimeDescriptor) RustIPCVersion() string                  { return d.rustIPCVersion }
func (d RuntimeDescriptor) WASMABIVersion() string                  { return d.wasmABIVersion }
func (d RuntimeDescriptor) ContractSetSHA256() string               { return d.contractSetSHA256 }
func (d RuntimeDescriptor) BinarySHA256() string                    { return d.binarySHA256 }

func (d RuntimeDescriptor) CompatibleWithPlatform() error {
	if d.platformVersion.String() != platformversion.CurrentCompatibilityVersion() ||
		d.rustIPCVersion != platformversion.RustIPCVersion ||
		d.wasmABIVersion != platformversion.WASMABIVersion ||
		d.contractSetSHA256 != platformversion.ContractSetSHA256 ||
		(d.target != runtimetarget.LinuxAMD64 && d.target != runtimetarget.LinuxARM64) ||
		!lowerSHA256Pattern.MatchString(d.binarySHA256) {
		return fmt.Errorf("%w: platform=%q target=%q ipc=%q wasm=%q contracts=%q", ErrRuntimeDescriptorMismatch, d.platformVersion.String(), d.target, d.rustIPCVersion, d.wasmABIVersion, d.contractSetSHA256)
	}
	return nil
}

func (d RuntimeDescriptor) MarshalJSON() ([]byte, error) {
	if err := d.CompatibleWithPlatform(); err != nil {
		return nil, errors.Join(ErrRuntimeDescriptorInvalid, err)
	}
	target, err := runtimeAdmissionTargetString(d.target)
	if err != nil {
		return nil, err
	}
	return json.Marshal(runtimeDescriptorJSON{
		SchemaVersion:     runtimeDescriptorSchemaVersion,
		PlatformVersion:   d.platformVersion.String(),
		Target:            target,
		RustIPCVersion:    d.rustIPCVersion,
		WASMABIVersion:    d.wasmABIVersion,
		ContractSetSHA256: d.contractSetSHA256,
		BinarySHA256:      d.binarySHA256,
	})
}

func (d *RuntimeDescriptor) UnmarshalJSON(raw []byte) error {
	if d == nil {
		return ErrRuntimeDescriptorInvalid
	}
	if err := rejectDuplicateDescriptorFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire runtimeDescriptorJSON
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrRuntimeDescriptorInvalid)
		}
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	if wire.SchemaVersion != runtimeDescriptorSchemaVersion {
		return fmt.Errorf("%w: schema_version", ErrRuntimeDescriptorInvalid)
	}
	parsedVersion, err := platformversion.ParseSemVer(wire.PlatformVersion)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	target, err := parseRuntimeAdmissionTarget(wire.Target)
	if err != nil {
		return err
	}
	parsed, err := NewRuntimeDescriptor(RuntimeDescriptorOptions{
		PlatformVersion:   parsedVersion,
		Target:            target,
		RustIPCVersion:    wire.RustIPCVersion,
		WASMABIVersion:    wire.WASMABIVersion,
		ContractSetSHA256: wire.ContractSetSHA256,
		BinarySHA256:      wire.BinarySHA256,
	})
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func runtimeAdmissionTargetString(target runtimetarget.Target) (string, error) {
	switch target {
	case runtimetarget.LinuxAMD64:
		return "linux/amd64", nil
	case runtimetarget.LinuxARM64:
		return "linux/arm64", nil
	default:
		return "", fmt.Errorf("%w: target", ErrRuntimeDescriptorInvalid)
	}
}

func parseRuntimeAdmissionTarget(value string) (runtimetarget.Target, error) {
	switch value {
	case "linux/amd64":
		return runtimetarget.LinuxAMD64, nil
	case "linux/arm64":
		return runtimetarget.LinuxARM64, nil
	default:
		return 0, fmt.Errorf("%w: target %q", ErrRuntimeDescriptorInvalid, value)
	}
}

func rejectDuplicateDescriptorFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return ErrRuntimeDescriptorInvalid
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return ErrRuntimeDescriptorInvalid
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate field %q", ErrRuntimeDescriptorInvalid, key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	return nil
}
