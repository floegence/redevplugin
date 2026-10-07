//go:build windows

package process

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processTree struct {
	job windows.Handle
}

func configureCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

func attachProcessTree(command *exec.Cmd) (processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return processTree{}, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	processHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION, false, uint32(command.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	defer windows.CloseHandle(processHandle)
	if err := windows.AssignProcessToJobObject(job, processHandle); err != nil {
		_ = windows.CloseHandle(job)
		return processTree{}, err
	}
	return processTree{job: job}, nil
}

func terminateProcessTree(tree processTree, command *exec.Cmd, force bool) error {
	if tree.job != 0 {
		if force {
			return windows.TerminateJobObject(tree.job, 1)
		}
	}
	if command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}

func closeProcessTree(tree processTree) {
	if tree.job != 0 {
		_ = windows.CloseHandle(tree.job)
	}
}
