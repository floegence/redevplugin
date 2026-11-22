//go:build netbsd || solaris

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
	var stat unix.Statvfs_t
	if err := unix.Fstatvfs(int(dir.Fd()), &stat); err != nil {
		return 0, err
	}
	return stageBlockBytes(uint64(stat.Bavail), uint64(stat.Frsize)), nil
}
