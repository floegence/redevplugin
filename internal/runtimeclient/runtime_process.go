package runtimeclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

const (
	runtimeIPCReadFD            = 3
	runtimeIPCWriteFD           = 4
	runtimeControlReadFD        = 5
	runtimeControlWriteFD       = 6
	runtimeContainmentProfile   = "linux-runtime-v1"
	runtimeContainmentPolicySHA = "6305735925c1fbacaf4950df2e535d3a11cebec8ab7aa16ce37fca3c31745543"
)

type runtimeProcessLaunchOptions struct {
	context        context.Context
	path           string
	executable     *os.File
	executionRoot  *os.File
	expectedDigest string
	args           []string
	env            []string
	dir            string
}

type runtimeProcess struct {
	pid                 int
	pidfd               int
	containmentRequired bool
	containmentIdentity string
	ipcIn               io.WriteCloser
	ipcOut              io.ReadCloser
	diagnosticOut       io.ReadCloser
	diagnosticErr       io.ReadCloser
	controlIn           io.WriteCloser
	controlOut          io.ReadCloser
	wait                func() error
	kill                func() error
	alive               func() bool
	cleanup             func()
	closeOnce           sync.Once
}

func (process *runtimeProcess) Wait() error {
	if process == nil || process.wait == nil {
		return nil
	}
	err := process.wait()
	process.closeOnce.Do(func() {
		if process.pidfd >= 0 {
			_ = closeRuntimePIDFD(process.pidfd)
			process.pidfd = -1
		}
		if process.cleanup != nil {
			process.cleanup()
			process.cleanup = nil
		}
	})
	return err
}

func (process *runtimeProcess) Kill() error {
	if process == nil || process.kill == nil {
		return nil
	}
	return process.kill()
}

func (process *runtimeProcess) Alive() bool {
	if process == nil || process.alive == nil {
		return false
	}
	return process.alive()
}

func launchPortableRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	if options.context == nil {
		return nil, errors.New("runtime process context is required")
	}
	cmd := exec.CommandContext(options.context, options.path, options.args...)
	commandEnv := append([]string(nil), options.env...)
	if len(commandEnv) == 0 {
		commandEnv = os.Environ()
	}
	ipcRuntimeRead, ipcHostWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	ipcHostRead, ipcRuntimeWrite, err := os.Pipe()
	if err != nil {
		_ = ipcRuntimeRead.Close()
		_ = ipcHostWrite.Close()
		return nil, err
	}
	controlRuntimeRead, controlHostWrite, err := os.Pipe()
	if err != nil {
		_ = ipcRuntimeRead.Close()
		_ = ipcHostWrite.Close()
		_ = ipcHostRead.Close()
		_ = ipcRuntimeWrite.Close()
		return nil, err
	}
	controlHostRead, controlRuntimeWrite, err := os.Pipe()
	if err != nil {
		_ = ipcRuntimeRead.Close()
		_ = ipcHostWrite.Close()
		_ = ipcHostRead.Close()
		_ = ipcRuntimeWrite.Close()
		_ = controlRuntimeRead.Close()
		_ = controlHostWrite.Close()
		return nil, err
	}
	closeChild := func() {
		_ = ipcRuntimeRead.Close()
		_ = ipcRuntimeWrite.Close()
		_ = controlRuntimeRead.Close()
		_ = controlRuntimeWrite.Close()
	}
	closeParent := func() {
		_ = ipcHostWrite.Close()
		_ = ipcHostRead.Close()
		_ = controlHostWrite.Close()
		_ = controlHostRead.Close()
	}
	cmd.Env = commandEnv
	cmd.ExtraFiles = []*os.File{ipcRuntimeRead, ipcRuntimeWrite, controlRuntimeRead, controlRuntimeWrite}
	cmd.Dir = options.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		closeChild()
		closeParent()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		closeChild()
		closeParent()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		closeChild()
		closeParent()
		return nil, err
	}
	closeChild()
	return &runtimeProcess{
		pid:           cmd.Process.Pid,
		pidfd:         -1,
		ipcIn:         ipcHostWrite,
		ipcOut:        ipcHostRead,
		diagnosticOut: stdout,
		diagnosticErr: stderr,
		controlIn:     controlHostWrite,
		controlOut:    controlHostRead,
		wait:          cmd.Wait,
		kill:          cmd.Process.Kill,
		alive: func() bool {
			return cmd.Process.Signal(syscall.Signal(0)) == nil
		},
	}, nil
}

type runtimeProcessWaitError struct {
	exitCode int
	signal   int
}

func (err *runtimeProcessWaitError) Error() string {
	if err == nil {
		return "runtime process exited"
	}
	if err.signal != 0 {
		return fmt.Sprintf("runtime process terminated by signal %d", err.signal)
	}
	return fmt.Sprintf("runtime process exited with code %d", err.exitCode)
}

func (err *runtimeProcessWaitError) ExitCode() int {
	if err == nil || err.signal != 0 {
		return -1
	}
	return err.exitCode
}
