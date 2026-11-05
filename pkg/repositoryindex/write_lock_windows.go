//go:build windows

package repositoryindex

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockIndex(directory string) (*os.File, error) {
	path := filepath.Join(directory, ".index.lock")
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("index lock must be a regular file")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !named.Mode().IsRegular() || !os.SameFile(named, opened) {
		file.Close()
		return nil, fmt.Errorf("index lock changed")
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// Windows rename durability is provided by the filesystem; directory fsync is unsupported.
func syncIndexDirectory(string) error { return nil }
