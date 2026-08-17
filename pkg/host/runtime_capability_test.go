package host

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/v3/pkg/version"
)

func TestRuntimeArtifactIdentityContainsOnlyArtifactFacts(t *testing.T) {
	platform, err := platformversion.ParseSemVer(platformversion.CurrentPlatformVersion())
	if err != nil {
		t.Fatal(err)
	}
	target := runtimetarget.LinuxAMD64
	binaryDigest, err := ParseSHA256Digest(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}

	identity, err := NewRuntimeArtifactIdentity(RuntimeArtifactIdentityOptions{
		PlatformVersion: platform,
		Target:          target,
		BinarySHA256:    binaryDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.PlatformVersion() != platform || identity.Target() != target || identity.BinarySHA256() != binaryDigest {
		t.Fatalf("runtime artifact identity = %#v", identity)
	}
	if err := identity.CompatibleWithPlatform(); err != nil {
		t.Fatalf("CompatibleWithPlatform() error = %v", err)
	}
}

func TestRuntimeAdmissionIdentityRejectsInvalidBinaryNamesAndDigests(t *testing.T) {
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
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip("unsupported-platform constructor contract")
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
	identity := testPublicRuntimeArtifactIdentity(t, "linux/amd64", strings.Repeat("b", 64))

	result, err := OpenVerifiedExecutable(context.Background(), VerifiedExecutableOptions{
		RootDir:                  root,
		ExecutionRoot:            executionRoot,
		RelativeName:             name,
		ExpectedArtifactIdentity: identity,
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

func testPublicRuntimeArtifactIdentity(t *testing.T, targetValue, binaryDigest string) RuntimeArtifactIdentity {
	t.Helper()
	platform, err := platformversion.ParseSemVer(platformversion.CurrentPlatformVersion())
	if err != nil {
		t.Fatal(err)
	}
	target, err := runtimetarget.Parse(targetValue)
	if err != nil {
		t.Fatal(err)
	}
	binarySHA256, err := ParseSHA256Digest(binaryDigest)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewRuntimeArtifactIdentity(RuntimeArtifactIdentityOptions{
		PlatformVersion: platform,
		Target:          target,
		BinarySHA256:    binarySHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
