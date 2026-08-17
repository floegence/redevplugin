package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func inspectCommandRuntimeArtifact(path string, target runtimetarget.Target) (host.RuntimeArtifactIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return host.RuntimeArtifactIdentity{}, fmt.Errorf("open runtime artifact: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return host.RuntimeArtifactIdentity{}, fmt.Errorf("hash runtime artifact: %w", err)
	}
	platform, err := version.ParseSemVer(version.CurrentPlatformVersion())
	if err != nil {
		return host.RuntimeArtifactIdentity{}, err
	}
	digest, err := host.ParseSHA256Digest(hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		return host.RuntimeArtifactIdentity{}, err
	}
	return host.NewRuntimeArtifactIdentity(host.RuntimeArtifactIdentityOptions{
		PlatformVersion: platform,
		Target:          target,
		BinarySHA256:    digest,
	})
}

func newCommandRuntimeModule(
	ctx context.Context,
	runtimePath string,
	executionRootPath string,
	identity host.RuntimeArtifactIdentity,
	startupTimeout time.Duration,
) (*host.RuntimeModule, error) {
	root, err := os.Open(filepath.Dir(runtimePath))
	if err != nil {
		return nil, fmt.Errorf("open runtime root: %w", err)
	}
	defer root.Close()
	executionRoot, err := os.Open(executionRootPath)
	if err != nil {
		return nil, fmt.Errorf("open runtime execution root: %w", err)
	}
	defer executionRoot.Close()
	name, err := host.NewRuntimeBinaryName(filepath.Base(runtimePath))
	if err != nil {
		return nil, err
	}
	executable, err := host.OpenVerifiedExecutable(ctx, host.VerifiedExecutableOptions{
		RootDir:                  root,
		ExecutionRoot:            executionRoot,
		RelativeName:             name,
		ExpectedArtifactIdentity: identity,
	})
	if err != nil {
		return nil, err
	}
	module, err := host.NewRuntimeModule(executable, host.RuntimeModuleOptions{
		StartupTimeout: startupTimeout,
	})
	if err != nil {
		_, _ = executable.Close()
		return nil, err
	}
	return module, nil
}
