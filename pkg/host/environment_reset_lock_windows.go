//go:build windows

package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type environmentRootLock interface {
	Close() error
}

type windowsEnvironmentRootLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireEnvironmentRootLock(rawRoot string, create bool) (environmentRootLock, error) {
	root, err := validatedEnvironmentResetRoot(rawRoot, create)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(root, ".redevplugin-environment.lock")
	if info, err := os.Lstat(lockPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, fmt.Errorf("%w: environment lock is not a regular file", ErrEnvironmentResetBlocked)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &windowsEnvironmentRootLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: ReDevPlugin environment is still open", ErrEnvironmentResetBlocked)
	}
	return lock, nil
}

func (lock *windowsEnvironmentRootLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func validatedEnvironmentResetRoot(rawRoot string, create bool) (string, error) {
	root := strings.TrimSpace(rawRoot)
	if root == "" || root != rawRoot {
		return "", fmt.Errorf("%w: canonical state root is required", ErrEnvironmentResetRequest)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil || absRoot != filepath.Clean(root) {
		return "", fmt.Errorf("%w: absolute canonical state root is required", ErrEnvironmentResetRequest)
	}
	if absRoot == filepath.VolumeName(absRoot)+string(filepath.Separator) {
		return "", fmt.Errorf("%w: filesystem root cannot be reset", ErrEnvironmentResetBlocked)
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && filepath.Clean(home) == absRoot {
		return "", fmt.Errorf("%w: user home cannot be reset", ErrEnvironmentResetBlocked)
	}
	if create {
		if err := os.MkdirAll(absRoot, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: state root must be a real directory", ErrEnvironmentResetBlocked)
	}
	resolved, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", fmt.Errorf("%w: resolve state root: %v", ErrEnvironmentResetBlocked, err)
	}
	resolved = filepath.Clean(resolved)
	if resolved == filepath.VolumeName(resolved)+string(filepath.Separator) {
		return "", fmt.Errorf("%w: filesystem root cannot be reset", ErrEnvironmentResetBlocked)
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		resolvedHome, resolveHomeErr := filepath.EvalSymlinks(filepath.Clean(home))
		if resolveHomeErr == nil && filepath.Clean(resolvedHome) == resolved {
			return "", fmt.Errorf("%w: user home cannot be reset", ErrEnvironmentResetBlocked)
		}
	}
	return resolved, nil
}
