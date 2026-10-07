//go:build !windows

package process

import (
	"os/exec"
	"syscall"
)

type processTree struct{}

func configureCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func attachProcessTree(command *exec.Cmd) (processTree, error) {
	return processTree{}, nil
}

func terminateProcessTree(_ processTree, command *exec.Cmd, force bool) error {
	if command.Process == nil {
		return nil
	}
	signal := syscall.SIGTERM
	if force {
		signal = syscall.SIGKILL
	}
	return syscall.Kill(-command.Process.Pid, signal)
}

func closeProcessTree(_ processTree) {}
