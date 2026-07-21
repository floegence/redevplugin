//go:build linux

package runtimeclient

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func duplicateRuntimeExecutableForChild(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrRuntimePathRequired
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate runtime executable: %w", err)
	}
	duplicated := os.NewFile(uintptr(fd), "redevplugin-runtime-inherited")
	if duplicated == nil {
		_ = unix.Close(fd)
		return nil, ErrRuntimePathRequired
	}
	return duplicated, nil
}
