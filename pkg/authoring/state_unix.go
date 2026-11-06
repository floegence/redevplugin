//go:build darwin || linux

package authoring

import (
	"errors"
	"os"
	"syscall"
)

func lockAuthorState(path string) (*os.File, error) {
	// Hosts can launch long-lived terminals and services. Their exec must not
	// inherit this lock and keep author state unavailable after the host exits.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("development state is already open in another process")
	}
	return file, nil
}
