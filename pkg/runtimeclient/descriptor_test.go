package runtimeclient

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/pkg/version"
)

func TestNewRuntimeDescriptorRequiresClosedIdentity(t *testing.T) {
	runtimeVersion, err := platformversion.ParseSemVer("0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	validDigest := strings.Repeat("a", 64)
	descriptor, err := NewRuntimeDescriptor(
		runtimeVersion,
		runtimetarget.LinuxAMD64,
		"rust-ipc-v5",
		"redevplugin-wasm-worker-v2",
		validDigest,
	)
	if err != nil {
		t.Fatalf("NewRuntimeDescriptor() error = %v", err)
	}
	if descriptor.Version() != runtimeVersion || descriptor.Target() != runtimetarget.LinuxAMD64 ||
		descriptor.IPCVersion() != "rust-ipc-v5" || descriptor.WASMABIVersion() != "redevplugin-wasm-worker-v2" ||
		descriptor.ArtifactSHA256() != validDigest {
		t.Fatalf("descriptor projection = %#v", descriptor)
	}
	if err := descriptor.CompatibleWithPlatform(); err != nil {
		t.Fatalf("CompatibleWithPlatform() error = %v", err)
	}

	wrongIPC, err := NewRuntimeDescriptor(runtimeVersion, runtimetarget.LinuxAMD64, "rust-ipc-v9", "redevplugin-wasm-worker-v2", validDigest)
	if err != nil {
		t.Fatalf("future descriptor construction error = %v", err)
	}
	if err := wrongIPC.CompatibleWithPlatform(); !errors.Is(err, ErrRuntimeDescriptorMismatch) {
		t.Fatalf("wrong IPC compatibility error = %v, want ErrRuntimeDescriptorMismatch", err)
	}

	for _, test := range []struct {
		name       string
		target     runtimetarget.Target
		ipc        string
		wasm       string
		digest     string
		wantTarget bool
	}{
		{name: "zero target", target: 0, ipc: "rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: validDigest, wantTarget: true},
		{name: "unknown target", target: runtimetarget.Target(255), ipc: "rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: validDigest, wantTarget: true},
		{name: "blank ipc", target: runtimetarget.LinuxAMD64, wasm: "redevplugin-wasm-worker-v2", digest: validDigest},
		{name: "whitespace ipc", target: runtimetarget.LinuxAMD64, ipc: " rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: validDigest},
		{name: "blank wasm", target: runtimetarget.LinuxAMD64, ipc: "rust-ipc-v5", digest: validDigest},
		{name: "prefixed digest", target: runtimetarget.LinuxAMD64, ipc: "rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: "sha256:" + validDigest},
		{name: "uppercase digest", target: runtimetarget.LinuxAMD64, ipc: "rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: strings.Repeat("A", 64)},
		{name: "short digest", target: runtimetarget.LinuxAMD64, ipc: "rust-ipc-v5", wasm: "redevplugin-wasm-worker-v2", digest: "abc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRuntimeDescriptor(runtimeVersion, test.target, test.ipc, test.wasm, test.digest)
			want := ErrRuntimeDescriptorInvalid
			if test.wantTarget {
				want = runtimetarget.ErrUnsupported
			}
			if !errors.Is(err, want) {
				t.Fatalf("NewRuntimeDescriptor() error = %v, want %v", err, want)
			}
		})
	}
}

func TestRuntimeDescriptorJSONIsClosedAndStrict(t *testing.T) {
	version, _ := platformversion.ParseSemVer("0.5.0+build.1")
	descriptor, _ := NewRuntimeDescriptor(
		version, runtimetarget.DarwinARM64, "rust-ipc-v5", "redevplugin-wasm-worker-v2", strings.Repeat("b", 64),
	)
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 5 || projection["version"] != "0.5.0+build.1" || projection["artifact_sha256"] != strings.Repeat("b", 64) {
		t.Fatalf("descriptor JSON = %s", raw)
	}
	var decoded RuntimeDescriptor
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded != descriptor {
		t.Fatalf("descriptor round trip = %#v, err=%v", decoded, err)
	}
	projection["unexpected"] = true
	unknown, _ := json.Marshal(projection)
	if err := json.Unmarshal(unknown, &decoded); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("unknown descriptor field error = %v", err)
	}
	if _, err := json.Marshal(RuntimeDescriptor{}); !errors.Is(err, ErrRuntimeDescriptorInvalid) {
		t.Fatalf("zero descriptor marshal error = %v", err)
	}
}

func TestRuntimeDescriptorIdentityIncludesBuildMetadata(t *testing.T) {
	leftVersion, _ := platformversion.ParseSemVer("0.5.0+build.1")
	rightVersion, _ := platformversion.ParseSemVer("0.5.0+build.2")
	left, _ := NewRuntimeDescriptor(leftVersion, runtimetarget.LinuxARM64, "rust-ipc-v5", "redevplugin-wasm-worker-v2", strings.Repeat("c", 64))
	right, _ := NewRuntimeDescriptor(rightVersion, runtimetarget.LinuxARM64, "rust-ipc-v5", "redevplugin-wasm-worker-v2", strings.Repeat("c", 64))
	if left == right {
		t.Fatal("descriptor identity ignored build metadata")
	}
	if left.Version().Compare(right.Version()) != 0 {
		t.Fatal("SemVer precedence included build metadata")
	}
}
