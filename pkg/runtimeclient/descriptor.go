package runtimeclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	platformversion "github.com/floegence/redevplugin/pkg/version"
)

var (
	ErrRuntimeDescriptorInvalid  = errors.New("runtime descriptor is invalid")
	ErrRuntimeDescriptorMismatch = errors.New("runtime descriptor does not match")
	ErrRuntimeTargetUnsupported  = errors.New("runtime target is unsupported")

	runtimeProtocolVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*-v(0|[1-9][0-9]*)$`)
	runtimeArtifactSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// RuntimeDescriptor is the immutable identity of one released runtime artifact.
// Construct it with NewRuntimeDescriptor; the zero value is invalid.
type RuntimeDescriptor struct {
	version        platformversion.SemVer
	target         Target
	ipcVersion     string
	wasmABIVersion string
	artifactSHA256 string
}

type runtimeDescriptorJSON struct {
	Version        string `json:"version"`
	Target         Target `json:"target"`
	IPCVersion     string `json:"ipc_version"`
	WASMABIVersion string `json:"wasm_abi_version"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

func NewRuntimeDescriptor(
	runtimeVersion platformversion.SemVer,
	target Target,
	ipcVersion string,
	wasmABIVersion string,
	artifactSHA256 string,
) (RuntimeDescriptor, error) {
	if runtimeVersion.String() == "" {
		return RuntimeDescriptor{}, fmt.Errorf("%w: version is required", ErrRuntimeDescriptorInvalid)
	}
	if err := ValidateTarget(target); err != nil {
		return RuntimeDescriptor{}, err
	}
	if !runtimeProtocolVersionPattern.MatchString(ipcVersion) || strings.TrimSpace(ipcVersion) != ipcVersion {
		return RuntimeDescriptor{}, fmt.Errorf("%w: ipc_version %q", ErrRuntimeDescriptorInvalid, ipcVersion)
	}
	if !runtimeProtocolVersionPattern.MatchString(wasmABIVersion) || strings.TrimSpace(wasmABIVersion) != wasmABIVersion {
		return RuntimeDescriptor{}, fmt.Errorf("%w: wasm_abi_version %q", ErrRuntimeDescriptorInvalid, wasmABIVersion)
	}
	if !runtimeArtifactSHA256Pattern.MatchString(artifactSHA256) {
		return RuntimeDescriptor{}, fmt.Errorf("%w: artifact_sha256 must be 64 lowercase hexadecimal characters", ErrRuntimeDescriptorInvalid)
	}
	return RuntimeDescriptor{
		version:        runtimeVersion,
		target:         target,
		ipcVersion:     ipcVersion,
		wasmABIVersion: wasmABIVersion,
		artifactSHA256: artifactSHA256,
	}, nil
}

func ValidateTarget(target Target) error {
	if (target.OS != "linux" && target.OS != "darwin") || (target.Arch != "amd64" && target.Arch != "arm64") {
		return fmt.Errorf("%w: os=%q arch=%q", ErrRuntimeTargetUnsupported, target.OS, target.Arch)
	}
	return nil
}

func (d RuntimeDescriptor) Version() platformversion.SemVer {
	return d.version
}

func (d RuntimeDescriptor) Target() Target {
	return d.target
}

func (d RuntimeDescriptor) IPCVersion() string {
	return d.ipcVersion
}

func (d RuntimeDescriptor) WASMABIVersion() string {
	return d.wasmABIVersion
}

func (d RuntimeDescriptor) ArtifactSHA256() string {
	return d.artifactSHA256
}

func (d RuntimeDescriptor) CompatibleWithPlatform() error {
	if d.version.String() == "" || d.ipcVersion != platformversion.RustIPCVersion || d.wasmABIVersion != platformversion.WASMABIVersion {
		return fmt.Errorf(
			"%w: version=%q ipc=%q wasm=%q",
			ErrRuntimeDescriptorMismatch,
			d.version.String(),
			d.ipcVersion,
			d.wasmABIVersion,
		)
	}
	return nil
}

func (d RuntimeDescriptor) MarshalJSON() ([]byte, error) {
	if d.version.String() == "" {
		return nil, ErrRuntimeDescriptorInvalid
	}
	return json.Marshal(runtimeDescriptorJSON{
		Version:        d.version.String(),
		Target:         d.target,
		IPCVersion:     d.ipcVersion,
		WASMABIVersion: d.wasmABIVersion,
		ArtifactSHA256: d.artifactSHA256,
	})
}

func (d *RuntimeDescriptor) UnmarshalJSON(raw []byte) error {
	if d == nil {
		return ErrRuntimeDescriptorInvalid
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
	parsedVersion, err := platformversion.ParseSemVer(wire.Version)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeDescriptorInvalid, err)
	}
	parsed, err := NewRuntimeDescriptor(parsedVersion, wire.Target, wire.IPCVersion, wire.WASMABIVersion, wire.ArtifactSHA256)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
