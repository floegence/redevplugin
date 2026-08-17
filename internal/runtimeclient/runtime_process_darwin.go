//go:build darwin

package runtimeclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func launchRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	if options.executable != nil {
		verifiedPath, cleanup, err := stageDarwinRuntimeExecutable(options)
		if err != nil {
			return nil, err
		}
		options.path = verifiedPath
		options.executable = nil
		options.executionRoot = nil
		process, err := launchFixedDarwinRuntimeProcess(options)
		if err != nil {
			cleanup()
			return nil, err
		}
		process.cleanup = cleanup
		return process, nil
	}
	return launchFixedDarwinRuntimeProcess(options)
}

type darwinRuntimePipes struct {
	ipcHostWrite     *os.File
	ipcHostRead      *os.File
	diagnosticRead   *os.File
	diagnosticErr    *os.File
	controlHostWrite *os.File
	controlHostRead  *os.File
	child            [runtimeControlWriteFD + 1]*os.File
}

func launchFixedDarwinRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	pipes, err := openDarwinRuntimePipes()
	if err != nil {
		return nil, err
	}
	cleanupParent := true
	defer func() {
		pipes.closeChild()
		if cleanupParent {
			pipes.closeParent()
		}
	}()
	cmd := exec.CommandContext(options.context, options.path, options.args...)
	cmd.Env = append([]string{"LANG=C", "LC_ALL=C"}, options.env...)
	cmd.Stdin = pipes.child[0]
	cmd.Stdout = pipes.child[1]
	cmd.Stderr = pipes.child[2]
	cmd.ExtraFiles = []*os.File{pipes.child[3], pipes.child[4], pipes.child[5], pipes.child[6]}
	cmd.Dir = options.dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pipes.closeChild()
	cleanupParent = false
	return &runtimeProcess{
		pid:           cmd.Process.Pid,
		pidfd:         -1,
		ipcIn:         pipes.ipcHostWrite,
		ipcOut:        pipes.ipcHostRead,
		diagnosticOut: pipes.diagnosticRead,
		diagnosticErr: pipes.diagnosticErr,
		controlIn:     pipes.controlHostWrite,
		controlOut:    pipes.controlHostRead,
		wait:          cmd.Wait,
		kill:          cmd.Process.Kill,
		alive: func() bool {
			return cmd.Process.Signal(syscall.Signal(0)) == nil
		},
	}, nil
}

func openDarwinRuntimePipes() (_ *darwinRuntimePipes, err error) {
	pipes := &darwinRuntimePipes{}
	opened := make([]*os.File, 0, 14)
	defer func() {
		if err != nil {
			for _, file := range opened {
				_ = file.Close()
			}
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		read, write, pipeErr := os.Pipe()
		if pipeErr == nil {
			opened = append(opened, read, write)
		}
		return read, write, pipeErr
	}
	eofRead, eofWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	_ = eofWrite.Close()
	diagnosticRead, diagnosticWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	diagnosticErr, diagnosticErrWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	ipcChildRead, ipcHostWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	ipcHostRead, ipcChildWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	controlChildRead, controlHostWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	controlHostRead, controlChildWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	pipes.ipcHostWrite = ipcHostWrite
	pipes.ipcHostRead = ipcHostRead
	pipes.diagnosticRead = diagnosticRead
	pipes.diagnosticErr = diagnosticErr
	pipes.controlHostWrite = controlHostWrite
	pipes.controlHostRead = controlHostRead
	pipes.child = [runtimeControlWriteFD + 1]*os.File{
		eofRead,
		diagnosticWrite,
		diagnosticErrWrite,
		ipcChildRead,
		ipcChildWrite,
		controlChildRead,
		controlChildWrite,
	}
	return pipes, nil
}

func (pipes *darwinRuntimePipes) closeChild() {
	if pipes == nil {
		return
	}
	for index, file := range pipes.child {
		if file != nil {
			_ = file.Close()
			pipes.child[index] = nil
		}
	}
}

func (pipes *darwinRuntimePipes) closeParent() {
	if pipes == nil {
		return
	}
	for _, file := range []*os.File{
		pipes.ipcHostWrite,
		pipes.ipcHostRead,
		pipes.diagnosticRead,
		pipes.diagnosticErr,
		pipes.controlHostWrite,
		pipes.controlHostRead,
	} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func stageDarwinRuntimeExecutable(options runtimeProcessLaunchOptions) (string, func(), error) {
	if err := verifyRuntimeExecutableFile(options.context, options.executable, options.expectedDigest); err != nil {
		return "", nil, err
	}
	if _, err := options.executable.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	directory, err := os.MkdirTemp("", "redevplugin-runtime-verified-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	verifiedPath := filepath.Join(directory, "redevplugin-runtime")
	destination, err := os.OpenFile(verifiedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	hasher := sha256.New()
	if err := copyBoundedRuntimeExecutable(options.context, options.executable, io.MultiWriter(destination, hasher)); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, err
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, err
	}
	if err := destination.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != options.expectedDigest {
		cleanup()
		return "", nil, fmt.Errorf("%w: got %s want %s", ErrRuntimeArtifactDigest, actual, options.expectedDigest)
	}
	if err := os.Chmod(verifiedPath, 0o500); err != nil {
		cleanup()
		return "", nil, err
	}
	return verifiedPath, cleanup, nil
}

func closeRuntimePIDFD(int) error { return nil }
