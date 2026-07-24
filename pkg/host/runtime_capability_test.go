package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	platformversion "github.com/floegence/redevplugin/pkg/version"
)

func TestRuntimeDescriptorV2UsesClosedValidatedIdentity(t *testing.T) {
	platform, err := platformversion.ParseSemVer("0.6.13")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseRuntimeAdmissionTarget("linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	ipc, err := ParseRustIPCVersion(platformversion.RustIPCVersion)
	if err != nil {
		t.Fatal(err)
	}
	abi, err := ParseWASMABIVersion(platformversion.WASMABIVersion)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := ParseSHA256Digest(platformversion.ContractSetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	binaryDigest, err := ParseSHA256Digest(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	if descriptor.PlatformVersion() != platform || descriptor.Target() != target ||
		descriptor.RustIPCVersion() != ipc || descriptor.WASMABIVersion() != abi ||
		descriptor.ContractSetSHA256() != contractDigest || descriptor.BinarySHA256() != binaryDigest {
		t.Fatalf("descriptor projection = %#v", descriptor)
	}
	if err := descriptor.CompatibleWithPlatform(); err != nil {
		t.Fatalf("CompatibleWithPlatform() error = %v", err)
	}

	raw, err := MarshalRuntimeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 7 || projection["schema_version"] != "runtime-descriptor-v2" ||
		projection["target"] != "linux/amd64" || projection["binary_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("descriptor wire = %s", raw)
	}
	decoded, err := UnmarshalRuntimeDescriptorJSON(raw)
	if err != nil || decoded != descriptor {
		t.Fatalf("descriptor round trip = %#v, err=%v", decoded, err)
	}
	projection["unexpected"] = true
	unknown, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRuntimeDescriptorJSON(unknown); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestRuntimeAdmissionIdentityRejectsAliasesAndUnsupportedTargets(t *testing.T) {
	for _, value := range []string{"", "linux/x86_64", "linux/AMD64", "darwin/arm64", "linux\\amd64", " linux/amd64"} {
		if _, err := ParseRuntimeAdmissionTarget(value); !errors.Is(err, ErrRuntimeAdmissionTargetInvalid) {
			t.Fatalf("ParseRuntimeAdmissionTarget(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "redevplugin-runtime.exe", "./redevplugin-runtime", "../redevplugin-runtime", "/bin/redevplugin-runtime", "REDEVPLUGIN-RUNTIME"} {
		if _, err := NewRuntimeBinaryName(value); !errors.Is(err, ErrRuntimeBinaryNameInvalid) {
			t.Fatalf("NewRuntimeBinaryName(%q) error = %v", value, err)
		}
	}
	name, err := NewRuntimeBinaryName("redevplugin-runtime")
	if err != nil || name.String() != "redevplugin-runtime" {
		t.Fatalf("runtime binary name = %q, err=%v", name, err)
	}
	for _, value := range []string{"", "sha256:" + strings.Repeat("a", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if _, err := ParseSHA256Digest(value); !errors.Is(err, ErrSHA256DigestInvalid) {
			t.Fatalf("ParseSHA256Digest(%q) error = %v", value, err)
		}
	}
}

func TestOpenVerifiedExecutableIsSideEffectFreeWhenUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux constructor contract")
	}
	rootPath := t.TempDir()
	executionPath := t.TempDir()
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	executionRoot, err := os.Open(executionPath)
	if err != nil {
		t.Fatal(err)
	}
	defer executionRoot.Close()
	name, err := NewRuntimeBinaryName("redevplugin-runtime")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testPublicRuntimeDescriptor(t, "linux/amd64", strings.Repeat("b", 64))

	result, err := OpenVerifiedExecutable(context.Background(), VerifiedExecutableOptions{
		RootDir:            root,
		ExecutionRoot:      executionRoot,
		RelativeName:       name,
		ExpectedDescriptor: descriptor,
	})
	if result != nil || !errors.Is(err, ErrRuntimeAdmissionUnsupported) {
		t.Fatalf("OpenVerifiedExecutable() = %#v, %v", result, err)
	}
	entries, err := os.ReadDir(executionPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unsupported admission mutated execution root: %#v", entries)
	}
}

func testPublicRuntimeDescriptor(t *testing.T, targetValue, binaryDigest string) RuntimeDescriptor {
	t.Helper()
	platform, err := platformversion.ParseSemVer("0.6.13")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseRuntimeAdmissionTarget(targetValue)
	if err != nil {
		t.Fatal(err)
	}
	ipc, err := ParseRustIPCVersion(platformversion.RustIPCVersion)
	if err != nil {
		t.Fatal(err)
	}
	abi, err := ParseWASMABIVersion(platformversion.WASMABIVersion)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := ParseSHA256Digest(platformversion.ContractSetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	binarySHA256, err := ParseSHA256Digest(binaryDigest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := NewRuntimeDescriptor(RuntimeDescriptorOptions{
		PlatformVersion:   platform,
		Target:            target,
		RustIPCVersion:    ipc,
		WASMABIVersion:    abi,
		ContractSetSHA256: contractDigest,
		BinarySHA256:      binarySHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
