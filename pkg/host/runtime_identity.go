package host

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/v3/pkg/version"
)

var (
	ErrRuntimeArtifactIdentityInvalid  = errors.New("runtime artifact identity is invalid")
	ErrRuntimeArtifactIdentityMismatch = errors.New("runtime artifact identity does not match the platform")
	ErrSHA256DigestInvalid             = errors.New("sha256 digest is invalid")
	ErrRuntimeBinaryNameInvalid        = errors.New("runtime binary name is invalid")

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

type RuntimeArtifactIdentityOptions struct {
	PlatformVersion platformversion.SemVer
	Target          runtimetarget.Target
	BinarySHA256    SHA256Digest
}

// RuntimeArtifactIdentity is the immutable preflight identity of one
// host-built runtime. Hello/HelloAck owns internal wire compatibility.
type RuntimeArtifactIdentity struct {
	platformVersion platformversion.SemVer
	target          runtimetarget.Target
	binarySHA256    SHA256Digest
}

func NewRuntimeArtifactIdentity(options RuntimeArtifactIdentityOptions) (RuntimeArtifactIdentity, error) {
	if options.PlatformVersion.String() == "" || runtimetarget.Validate(options.Target) != nil || !options.BinarySHA256.valid() {
		return RuntimeArtifactIdentity{}, ErrRuntimeArtifactIdentityInvalid
	}
	return RuntimeArtifactIdentity{
		platformVersion: options.PlatformVersion,
		target:          options.Target,
		binarySHA256:    options.BinarySHA256,
	}, nil
}

func (descriptor RuntimeArtifactIdentity) PlatformVersion() platformversion.SemVer {
	return descriptor.platformVersion
}

func (descriptor RuntimeArtifactIdentity) Target() runtimetarget.Target { return descriptor.target }

func (descriptor RuntimeArtifactIdentity) BinarySHA256() SHA256Digest { return descriptor.binarySHA256 }

func (descriptor RuntimeArtifactIdentity) valid() bool {
	return descriptor.platformVersion.String() != "" && runtimetarget.Validate(descriptor.target) == nil && descriptor.binarySHA256.valid()
}

func (descriptor RuntimeArtifactIdentity) CompatibleWithPlatform() error {
	if !descriptor.valid() || descriptor.platformVersion.String() != platformversion.CurrentPlatformVersion() {
		return fmt.Errorf(
			"%w: platform=%q target=%q",
			ErrRuntimeArtifactIdentityMismatch,
			descriptor.platformVersion.String(),
			descriptor.target.String(),
		)
	}
	return nil
}

// RuntimeBinaryName is the closed executable basename accepted by the Host.
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
