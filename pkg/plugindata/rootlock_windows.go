//go:build windows

package plugindata

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type rootLock interface {
	Close() error
}

type windowsRootLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireRootLock(root string) (rootLock, error) {
	path := filepath.Join(root, ".redevplugin.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("%w: plugin data root lock is not a regular file", ErrUnsafeFilesystem)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(opened, named) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: plugin data root lock changed while opening", ErrUnsafeFilesystem)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil || handleInfo.NumberOfLinks != 1 || handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: plugin data root lock is linked or reparse-backed", ErrUnsafeFilesystem)
	}
	lock := &windowsRootLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("plugin data root is already open: %w", err)
	}
	return lock, nil
}

func (l *windowsRootLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
