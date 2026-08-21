//go:build !windows

package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type environmentRootLock interface {
	Close() error
}

type unixEnvironmentRootLock struct {
	file *os.File
}

func acquireEnvironmentRootLock(rawRoot string, create bool) (environmentRootLock, error) {
	root, err := validatedEnvironmentResetRoot(rawRoot, create)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(root, ".redevplugin-environment.lock")
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("%w: environment lock is a symlink", ErrEnvironmentResetBlocked)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open ReDevPlugin environment lock")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = file.Close()
		return nil, err
	}
	var named unix.Stat_t
	if err := unix.Lstat(lockPath, &named); err != nil {
		_ = file.Close()
		return nil, err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 || opened.Dev != named.Dev || opened.Ino != named.Ino {
		_ = file.Close()
		return nil, fmt.Errorf("%w: environment lock is not a unique regular file", ErrEnvironmentResetBlocked)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: ReDevPlugin environment is still open", ErrEnvironmentResetBlocked)
	}
	return &unixEnvironmentRootLock{file: file}, nil
}

func (lock *unixEnvironmentRootLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
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
