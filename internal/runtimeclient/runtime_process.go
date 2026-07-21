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

func launchLegacyRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	if options.context == nil {
		return nil, errors.New("runtime process context is required")
	}
	cmd := exec.CommandContext(options.context, options.path, options.args...)
	commandEnv := append([]string(nil), options.env...)
	if len(commandEnv) == 0 {
		commandEnv = os.Environ()
	}
	controlRuntimeRead, controlHostWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	controlHostRead, controlRuntimeWrite, err := os.Pipe()
	if err != nil {
		_ = controlRuntimeRead.Close()
		_ = controlHostWrite.Close()
		return nil, err
	}
	closeControl := func() {
		_ = controlRuntimeRead.Close()
		_ = controlHostWrite.Close()
		_ = controlHostRead.Close()
		_ = controlRuntimeWrite.Close()
	}
	controlReadFD := 3
	extraFiles := make([]*os.File, 0, 3)
	if options.executable != nil {
		inheritedExecutable, duplicateErr := duplicateRuntimeExecutableForChild(options.executable)
		if duplicateErr != nil {
			closeControl()
			return nil, duplicateErr
		}
		defer inheritedExecutable.Close()
		extraFiles = append(extraFiles, inheritedExecutable)
		controlReadFD++
	}
	cmd.Env = append(commandEnv,
		fmt.Sprintf("REDEVPLUGIN_CONTROL_READ_FD=%d", controlReadFD),
		fmt.Sprintf("REDEVPLUGIN_CONTROL_WRITE_FD=%d", controlReadFD+1),
	)
	cmd.ExtraFiles = append(extraFiles, controlRuntimeRead, controlRuntimeWrite)
	cmd.Dir = options.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		closeControl()
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		closeControl()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		closeControl()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		closeControl()
		return nil, err
	}
	_ = controlRuntimeRead.Close()
	_ = controlRuntimeWrite.Close()
	return &runtimeProcess{
		pid:           cmd.Process.Pid,
		pidfd:         -1,
		ipcIn:         stdin,
		ipcOut:        stdout,
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
