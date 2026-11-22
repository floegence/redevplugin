package externalsource

import (
	"os"

	"golang.org/x/sys/windows"
)

func stageFreeBytes(root *os.Root) (int64, error) {
	path, err := windows.UTF16PtrFromString(root.Name())
	if err != nil {
		return 0, err
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, nil, nil); err != nil {
		return 0, err
	}
	return int64(min(free, uint64(maxStreamBytes))), nil
}
