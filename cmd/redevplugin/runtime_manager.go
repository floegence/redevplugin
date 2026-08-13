package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
)

func loadCommandRuntimeDescriptor(path string, target runtimetarget.Target) (host.RuntimeDescriptor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return host.RuntimeDescriptor{}, fmt.Errorf("read runtime descriptor: %w", err)
	}
	descriptor, err := host.UnmarshalRuntimeDescriptorJSON(raw)
	if err != nil {
		return host.RuntimeDescriptor{}, fmt.Errorf("decode runtime descriptor: %w", err)
	}
	if err := descriptor.CompatibleWithPlatform(); err != nil {
		return host.RuntimeDescriptor{}, err
	}
	if descriptor.Target().String() != target.String() {
		return host.RuntimeDescriptor{}, host.ErrRuntimeDescriptorMismatch
	}
	return descriptor, nil
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
