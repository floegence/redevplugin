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

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/version"
)

func describeCommandRuntime(path string, target runtimetarget.Target) (host.RuntimeDescriptor, error) {
	runtimeVersion, err := version.ParseSemVer(version.CurrentCompatibilityVersion())
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	admissionTarget, err := host.ParseRuntimeAdmissionTarget(target.String())
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return host.RuntimeDescriptor{}, fmt.Errorf("open runtime artifact: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return host.RuntimeDescriptor{}, fmt.Errorf("hash runtime artifact: %w", err)
	}
	ipcVersion, err := host.ParseRustIPCVersion(version.RustIPCVersion)
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	wasmVersion, err := host.ParseWASMABIVersion(version.WASMABIVersion)
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	contractDigest, err := host.ParseSHA256Digest(version.ContractSetSHA256)
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	binaryDigest, err := host.ParseSHA256Digest(hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		return host.RuntimeDescriptor{}, err
	}
	return host.NewRuntimeDescriptor(host.RuntimeDescriptorOptions{
		PlatformVersion:   runtimeVersion,
		Target:            admissionTarget,
		RustIPCVersion:    ipcVersion,
		WASMABIVersion:    wasmVersion,
		ContractSetSHA256: contractDigest,
		BinarySHA256:      binaryDigest,
	})
}

func newCommandRuntimeModule(
	ctx context.Context,
	runtimePath string,
	executionRootPath string,
	descriptor host.RuntimeDescriptor,
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
		RootDir:            root,
		ExecutionRoot:      executionRoot,
		RelativeName:       name,
		ExpectedDescriptor: descriptor,
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
