package runtimeclient

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/pkg/version"
)

func validRuntimeDescriptorOptions(t *testing.T) RuntimeDescriptorOptions {
	t.Helper()
	version, err := platformversion.ParseSemVer(platformversion.CurrentCompatibilityVersion())
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDescriptorOptions{
		PlatformVersion:   version,
		Target:            runtimetarget.LinuxAMD64,
		RustIPCVersion:    platformversion.RustIPCVersion,
		WASMABIVersion:    platformversion.WASMABIVersion,
		ContractSetSHA256: platformversion.ContractSetSHA256,
		BinarySHA256:      strings.Repeat("a", 64),
	}
}

func TestNewRuntimeDescriptorRequiresClosedIdentity(t *testing.T) {
	options := validRuntimeDescriptorOptions(t)
	descriptor, err := NewRuntimeDescriptor(options)
	if err != nil {
		t.Fatalf("NewRuntimeDescriptor() error = %v", err)
	}
	if descriptor.PlatformVersion() != options.PlatformVersion || descriptor.Target() != options.Target ||
		descriptor.RustIPCVersion() != options.RustIPCVersion || descriptor.WASMABIVersion() != options.WASMABIVersion ||
		descriptor.ContractSetSHA256() != options.ContractSetSHA256 || descriptor.BinarySHA256() != options.BinarySHA256 {
		t.Fatalf("descriptor projection = %#v", descriptor)
	}
	if err := descriptor.CompatibleWithPlatform(); err != nil {
		t.Fatalf("CompatibleWithPlatform() error = %v", err)
	}

	for _, mutate := range []func(*RuntimeDescriptorOptions){
		func(value *RuntimeDescriptorOptions) { value.Target = 0 },
		func(value *RuntimeDescriptorOptions) { value.Target = runtimetarget.DarwinARM64 },
		func(value *RuntimeDescriptorOptions) { value.RustIPCVersion = "rust-ipc-v9" },
		func(value *RuntimeDescriptorOptions) { value.WASMABIVersion = "" },
		func(value *RuntimeDescriptorOptions) { value.ContractSetSHA256 = "sha256:" + strings.Repeat("a", 64) },
		func(value *RuntimeDescriptorOptions) { value.BinarySHA256 = strings.Repeat("A", 64) },
	} {
		invalid := options
		mutate(&invalid)
		if _, err := NewRuntimeDescriptor(invalid); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
			t.Fatalf("NewRuntimeDescriptor() error = %v, want ErrRuntimeDescriptorInvalid", err)
		}
	}
}

func TestRuntimeDescriptorJSONIsClosedAndStrict(t *testing.T) {
	options := validRuntimeDescriptorOptions(t)
	descriptor, _ := NewRuntimeDescriptor(options)
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 7 || projection["schema_version"] != "runtime-descriptor-v2" ||
		projection["platform_version"] != platformversion.CurrentCompatibilityVersion() ||
		projection["target"] != "linux/amd64" || projection["binary_sha256"] != options.BinarySHA256 {
		t.Fatalf("descriptor JSON = %s", raw)
	}
	var decoded RuntimeDescriptor
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded != descriptor {
		t.Fatalf("descriptor round trip = %#v, err=%v", decoded, err)
	}
	unknown := append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
	if err := json.Unmarshal(unknown, &decoded); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("unknown descriptor field error = %v", err)
	}
	duplicate := append(raw[:len(raw)-1], []byte(`,"target":"linux/arm64"}`)...)
	if err := json.Unmarshal(duplicate, &decoded); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("duplicate descriptor field error = %v", err)
	}
	if _, err := json.Marshal(RuntimeDescriptor{}); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("zero descriptor marshal error = %v", err)
	}
}

func TestRuntimeDescriptorRejectsContractMismatch(t *testing.T) {
	options := validRuntimeDescriptorOptions(t)
	descriptor, _ := NewRuntimeDescriptor(options)
	descriptor.contractSetSHA256 = strings.Repeat("f", 64)
	if err := descriptor.CompatibleWithPlatform(); !errors.Is(err, ErrRuntimeDescriptorMismatch) {
		t.Fatalf("contract mismatch error = %v", err)
	}
}
