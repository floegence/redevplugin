//go:build aix || darwin || dragonfly || freebsd || linux

package externalsource

import (
	"os"

	"golang.org/x/sys/unix"
)

func stageFreeBytes(root *os.Root) (int64, error) {
	dir, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &stat); err != nil {
		return 0, err
	}
	return stageBlockBytes(uint64(max(stat.Bavail, 0)), uint64(max(stat.Bsize, 0))), nil
}
