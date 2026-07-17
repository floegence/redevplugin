//go:build !windows

package plugindata

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type rootLock interface {
	Close() error
}

type unixRootLock struct {
	file *os.File
}

func acquireRootLock(root string) (rootLock, error) {
	path := filepath.Join(root, ".redevplugin.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("%w: plugin data root lock is a symlink", ErrUnsafeFilesystem)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open plugin data root lock")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = file.Close()
		return nil, err
	}
	var named unix.Stat_t
	if err := unix.Lstat(path, &named); err != nil {
		_ = file.Close()
		return nil, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || opened.Dev != named.Dev || opened.Ino != named.Ino {
		_ = file.Close()
		return nil, fmt.Errorf("%w: plugin data root lock is not a unique regular file", ErrUnsafeFilesystem)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("plugin data root is already open: %w", err)
	}
	return &unixRootLock{file: file}, nil
}

func (l *unixRootLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
