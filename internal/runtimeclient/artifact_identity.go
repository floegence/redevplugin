package runtimeclient

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	platformversion "github.com/floegence/redevplugin/v3/pkg/version"
)

var (
	ErrRuntimeArtifactIdentityInvalid  = errors.New("runtime artifact identity is invalid")
	ErrRuntimeArtifactIdentityMismatch = errors.New("runtime artifact identity does not match")
	lowerSHA256Pattern                 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RuntimeArtifactIdentityOptions struct {
	PlatformVersion platformversion.SemVer
	Target          runtimetarget.Target
	BinarySHA256    string
}

// RuntimeArtifactIdentity is the immutable preflight identity of one
// host-built runtime. Internal wire compatibility is verified by Hello/HelloAck.
type RuntimeArtifactIdentity struct {
	platformVersion platformversion.SemVer
	target          runtimetarget.Target
	binarySHA256    string
}

func NewRuntimeArtifactIdentity(options RuntimeArtifactIdentityOptions) (RuntimeArtifactIdentity, error) {
	if options.PlatformVersion.String() == "" ||
		runtimetarget.Validate(options.Target) != nil ||
		!lowerSHA256Pattern.MatchString(options.BinarySHA256) {
		return RuntimeArtifactIdentity{}, ErrRuntimeArtifactIdentityInvalid
	}
	return RuntimeArtifactIdentity{
		platformVersion: options.PlatformVersion,
		target:          options.Target,
		binarySHA256:    options.BinarySHA256,
	}, nil
}

func (i RuntimeArtifactIdentity) PlatformVersion() platformversion.SemVer { return i.platformVersion }
func (i RuntimeArtifactIdentity) Target() runtimetarget.Target            { return i.target }
func (i RuntimeArtifactIdentity) BinarySHA256() string                    { return i.binarySHA256 }

func (i RuntimeArtifactIdentity) CompatibleWithPlatform() error {
	if i.platformVersion.String() != platformversion.CurrentPlatformVersion() ||
		runtimetarget.Validate(i.target) != nil ||
		!lowerSHA256Pattern.MatchString(i.binarySHA256) {
		return fmt.Errorf("%w: platform=%q target=%q", ErrRuntimeArtifactIdentityMismatch, i.platformVersion.String(), i.target)
	}
	return nil
}

func runtimeAdmissionTargetString(target runtimetarget.Target) (string, error) {
	if err := runtimetarget.Validate(target); err != nil {
		return "", fmt.Errorf("%w: target", ErrRuntimeArtifactIdentityInvalid)
	}
	return target.String(), nil
}

func parseRuntimeAdmissionTarget(value string) (runtimetarget.Target, error) {
	target, err := runtimetarget.Parse(value)
	if err != nil {
		return 0, fmt.Errorf("%w: target %q", ErrRuntimeArtifactIdentityInvalid, value)
	}
	return target, nil
}
