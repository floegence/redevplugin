package host

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
	ErrRuntimeDescriptorInvalid      = errors.New("runtime descriptor is invalid")
	ErrRuntimeDescriptorMismatch     = errors.New("runtime descriptor does not match the platform")
	ErrRuntimeAdmissionTargetInvalid = errors.New("runtime admission target is invalid")
	ErrRuntimeProtocolVersionInvalid = errors.New("runtime protocol version is invalid")
	ErrSHA256DigestInvalid           = errors.New("sha256 digest is invalid")
	ErrRuntimeBinaryNameInvalid      = errors.New("runtime binary name is invalid")

	lowerSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SHA256Digest is a validated lowercase SHA-256 digest without an algorithm
// prefix. Its zero value is invalid.
type SHA256Digest struct {
	value string
}

func ParseSHA256Digest(value string) (SHA256Digest, error) {
	if !lowerSHA256Pattern.MatchString(value) {
		return SHA256Digest{}, ErrSHA256DigestInvalid
	}
	return SHA256Digest{value: value}, nil
}

func (digest SHA256Digest) String() string { return digest.value }

func (digest SHA256Digest) valid() bool { return lowerSHA256Pattern.MatchString(digest.value) }

// RuntimeAdmissionTarget is the closed runtime target set supported by the
// fd-backed v0.6 runtime admission path.
type RuntimeAdmissionTarget struct {
	value string
}

var (
	RuntimeAdmissionLinuxAMD64 = RuntimeAdmissionTarget{value: "linux/amd64"}
	RuntimeAdmissionLinuxARM64 = RuntimeAdmissionTarget{value: "linux/arm64"}
)

func ParseRuntimeAdmissionTarget(value string) (RuntimeAdmissionTarget, error) {
	switch value {
	case RuntimeAdmissionLinuxAMD64.value:
		return RuntimeAdmissionLinuxAMD64, nil
	case RuntimeAdmissionLinuxARM64.value:
		return RuntimeAdmissionLinuxARM64, nil
	default:
		return RuntimeAdmissionTarget{}, fmt.Errorf("%w: %q", ErrRuntimeAdmissionTargetInvalid, value)
	}
}

func (target RuntimeAdmissionTarget) String() string { return target.value }

func (target RuntimeAdmissionTarget) valid() bool {
	return target == RuntimeAdmissionLinuxAMD64 || target == RuntimeAdmissionLinuxARM64
}

func (target RuntimeAdmissionTarget) classifierTarget() runtimetarget.Target {
	switch target {
	case RuntimeAdmissionLinuxAMD64:
		return runtimetarget.LinuxAMD64
	case RuntimeAdmissionLinuxARM64:
		return runtimetarget.LinuxARM64
	default:
		return 0
	}
}

// RustIPCVersion and WASMABIVersion are generated-version-bound newtypes. A
// host cannot construct an unconstrained protocol string.
type RustIPCVersion struct {
	value string
}

func ParseRustIPCVersion(value string) (RustIPCVersion, error) {
	if value != platformversion.RustIPCVersion {
		return RustIPCVersion{}, fmt.Errorf("%w: rust IPC %q", ErrRuntimeProtocolVersionInvalid, value)
	}
	return RustIPCVersion{value: value}, nil
}

func (version RustIPCVersion) String() string { return version.value }

func (version RustIPCVersion) valid() bool { return version.value == platformversion.RustIPCVersion }

type WASMABIVersion struct {
	value string
}

func ParseWASMABIVersion(value string) (WASMABIVersion, error) {
	if value != platformversion.WASMABIVersion {
		return WASMABIVersion{}, fmt.Errorf("%w: WASM ABI %q", ErrRuntimeProtocolVersionInvalid, value)
	}
	return WASMABIVersion{value: value}, nil
}

func (version WASMABIVersion) String() string { return version.value }

func (version WASMABIVersion) valid() bool { return version.value == platformversion.WASMABIVersion }

// RuntimeDescriptorOptions is the only constructor input for the public v2
// runtime identity.
type RuntimeDescriptorOptions struct {
	PlatformVersion   platformversion.SemVer
	Target            RuntimeAdmissionTarget
	RustIPCVersion    RustIPCVersion
	WASMABIVersion    WASMABIVersion
	ContractSetSHA256 SHA256Digest
	BinarySHA256      SHA256Digest
}

// RuntimeDescriptor is immutable and intentionally does not implement
// json.Marshaler or json.Unmarshaler. Wire boundaries use the explicit mapper
// below so domain values cannot silently accept alternate JSON shapes.
type RuntimeDescriptor struct {
	platformVersion   platformversion.SemVer
	target            RuntimeAdmissionTarget
	rustIPCVersion    RustIPCVersion
	wasmABIVersion    WASMABIVersion
	contractSetSHA256 SHA256Digest
	binarySHA256      SHA256Digest
}

func NewRuntimeDescriptor(options RuntimeDescriptorOptions) (RuntimeDescriptor, error) {
	if options.PlatformVersion.String() == "" || !options.Target.valid() ||
		!options.RustIPCVersion.valid() || !options.WASMABIVersion.valid() ||
		!options.ContractSetSHA256.valid() || !options.BinarySHA256.valid() {
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

func (descriptor RuntimeDescriptor) PlatformVersion() platformversion.SemVer {
	return descriptor.platformVersion
}

func (descriptor RuntimeDescriptor) Target() RuntimeAdmissionTarget { return descriptor.target }

func (descriptor RuntimeDescriptor) RustIPCVersion() RustIPCVersion {
	return descriptor.rustIPCVersion
}

func (descriptor RuntimeDescriptor) WASMABIVersion() WASMABIVersion {
	return descriptor.wasmABIVersion
}

func (descriptor RuntimeDescriptor) ContractSetSHA256() SHA256Digest {
	return descriptor.contractSetSHA256
}

func (descriptor RuntimeDescriptor) BinarySHA256() SHA256Digest { return descriptor.binarySHA256 }

func (descriptor RuntimeDescriptor) valid() bool {
	return descriptor.platformVersion.String() != "" && descriptor.target.valid() &&
		descriptor.rustIPCVersion.valid() && descriptor.wasmABIVersion.valid() &&
		descriptor.contractSetSHA256.valid() && descriptor.binarySHA256.valid()
}

func (descriptor RuntimeDescriptor) CompatibleWithPlatform() error {
	if !descriptor.valid() || descriptor.platformVersion.String() != platformversion.CurrentCompatibilityVersion() ||
		descriptor.contractSetSHA256.String() != platformversion.ContractSetSHA256 {
		return fmt.Errorf(
			"%w: platform=%q target=%q ipc=%q wasm=%q contracts=%q",
			ErrRuntimeDescriptorMismatch,
			descriptor.platformVersion.String(),
			descriptor.target.String(),
			descriptor.rustIPCVersion.String(),
			descriptor.wasmABIVersion.String(),
			descriptor.contractSetSHA256.String(),
		)
	}
	return nil
}

type runtimeDescriptorWire struct {
	SchemaVersion     string `json:"schema_version"`
	PlatformVersion   string `json:"platform_version"`
	Target            string `json:"target"`
	RustIPCVersion    string `json:"rust_ipc_version"`
	WASMABIVersion    string `json:"wasm_abi_version"`
	ContractSetSHA256 string `json:"contract_set_sha256"`
	BinarySHA256      string `json:"binary_sha256"`
}

func MarshalRuntimeDescriptorJSON(descriptor RuntimeDescriptor) ([]byte, error) {
	if !descriptor.valid() {
		return nil, ErrRuntimeDescriptorInvalid
	}
	return json.Marshal(runtimeDescriptorWire{
		SchemaVersion:     runtimeDescriptorSchemaVersion,
		PlatformVersion:   descriptor.platformVersion.String(),
		Target:            descriptor.target.String(),
		RustIPCVersion:    descriptor.rustIPCVersion.String(),
		WASMABIVersion:    descriptor.wasmABIVersion.String(),
		ContractSetSHA256: descriptor.contractSetSHA256.String(),
		BinarySHA256:      descriptor.binarySHA256.String(),
	})
}

func UnmarshalRuntimeDescriptorJSON(raw []byte) (RuntimeDescriptor, error) {
	if err := rejectDuplicateRuntimeDescriptorFields(raw); err != nil {
		return RuntimeDescriptor{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire runtimeDescriptorWire
	if err := decoder.Decode(&wire); err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RuntimeDescriptor{}, fmt.Errorf("%w: trailing JSON value", ErrRuntimeDescriptorInvalid)
	}
	if wire.SchemaVersion != runtimeDescriptorSchemaVersion {
		return RuntimeDescriptor{}, fmt.Errorf("%w: schema_version %q", ErrRuntimeDescriptorInvalid, wire.SchemaVersion)
	}
	platform, err := platformversion.ParseSemVer(wire.PlatformVersion)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	target, err := ParseRuntimeAdmissionTarget(wire.Target)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	ipc, err := ParseRustIPCVersion(wire.RustIPCVersion)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	abi, err := ParseWASMABIVersion(wire.WASMABIVersion)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	contractDigest, err := ParseSHA256Digest(wire.ContractSetSHA256)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	binaryDigest, err := ParseSHA256Digest(wire.BinarySHA256)
	if err != nil {
		return RuntimeDescriptor{}, fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	descriptor, err := NewRuntimeDescriptor(RuntimeDescriptorOptions{
		PlatformVersion:   platform,
		Target:            target,
		RustIPCVersion:    ipc,
		WASMABIVersion:    abi,
		ContractSetSHA256: contractDigest,
		BinarySHA256:      binaryDigest,
	})
	if err != nil {
		return RuntimeDescriptor{}, err
	}
	return descriptor, nil
}

func rejectDuplicateRuntimeDescriptorFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
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

// RuntimeBinaryName is the closed executable basename accepted by v0.6.
type RuntimeBinaryName struct {
	value string
}

func NewRuntimeBinaryName(value string) (RuntimeBinaryName, error) {
	if value != "redevplugin-runtime" {
		return RuntimeBinaryName{}, fmt.Errorf("%w: %q", ErrRuntimeBinaryNameInvalid, value)
	}
	return RuntimeBinaryName{value: value}, nil
}

func (name RuntimeBinaryName) String() string { return name.value }
