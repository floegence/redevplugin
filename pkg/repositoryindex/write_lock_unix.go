//go:build !windows

package repositoryindex

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock the directory itself: kernel release on exit avoids stale lock files.
func lockIndex(directory string) (*os.File, error) {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), directory)
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("repository index is being updated: %w", err)
	}
	// Assert the locked directory is still the directory naming the index.
	named, err := os.Lstat(filepath.Clean(directory))
	if err != nil {
		f.Close()
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(named, opened) {
		f.Close()
		return nil, fmt.Errorf("index directory changed")
	}
	return f, nil
}

func syncIndexDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
