package runtimeclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/v3/pkg/version"
)

func validRuntimeArtifactIdentityOptions(t *testing.T) RuntimeArtifactIdentityOptions {
	t.Helper()
	version, err := platformversion.ParseSemVer(platformversion.CurrentPlatformVersion())
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeArtifactIdentityOptions{
		PlatformVersion: version,
		Target:          runtimetarget.LinuxAMD64,
		BinarySHA256:    strings.Repeat("a", 64),
	}
}

func TestRuntimeArtifactIdentityContainsOnlyArtifactFacts(t *testing.T) {
	options := validRuntimeArtifactIdentityOptions(t)
	identity, err := NewRuntimeArtifactIdentity(options)
	if err != nil {
		t.Fatalf("NewRuntimeArtifactIdentity() error = %v", err)
	}
	if identity.PlatformVersion() != options.PlatformVersion || identity.Target() != options.Target || identity.BinarySHA256() != options.BinarySHA256 {
		t.Fatalf("runtime artifact identity = %#v", identity)
	}
	if err := identity.CompatibleWithPlatform(); err != nil {
		t.Fatalf("CompatibleWithPlatform() error = %v", err)
	}

	for _, mutate := range []func(*RuntimeArtifactIdentityOptions){
		func(value *RuntimeArtifactIdentityOptions) { value.Target = 0 },
		func(value *RuntimeArtifactIdentityOptions) { value.BinarySHA256 = strings.Repeat("A", 64) },
	} {
		invalid := options
		mutate(&invalid)
		if _, err := NewRuntimeArtifactIdentity(invalid); !errors.Is(err, ErrRuntimeArtifactIdentityInvalid) {
			t.Fatalf("NewRuntimeArtifactIdentity() error = %v, want ErrRuntimeArtifactIdentityInvalid", err)
		}
	}
}

func TestRuntimeArtifactIdentityAcceptsEveryCanonicalTarget(t *testing.T) {
	for _, target := range runtimetarget.Supported() {
		options := validRuntimeArtifactIdentityOptions(t)
		options.Target = target
		identity, err := NewRuntimeArtifactIdentity(options)
		if err != nil {
			t.Fatalf("NewRuntimeArtifactIdentity(%q) error = %v", target, err)
		}
		if identity.Target() != target {
			t.Fatalf("NewRuntimeArtifactIdentity(%q).Target() = %q", target, identity.Target())
		}
	}
}

func TestRuntimeArtifactIdentityRejectsPlatformMismatch(t *testing.T) {
	options := validRuntimeArtifactIdentityOptions(t)
	stale, err := platformversion.ParseSemVer("2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	options.PlatformVersion = stale
	identity, err := NewRuntimeArtifactIdentity(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.CompatibleWithPlatform(); !errors.Is(err, ErrRuntimeArtifactIdentityMismatch) {
		t.Fatalf("platform mismatch error = %v", err)
	}
}
