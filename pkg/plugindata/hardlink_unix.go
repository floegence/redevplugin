//go:build !windows

package plugindata

import (
	"io/fs"
	"os"
	"syscall"
)

func isMultiplyLinked(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}

func validPathRegular(_ string, info fs.FileInfo) bool {
	return info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && !isMultiplyLinked(info)
}

func validRootRegular(_ *os.Root, _ string, info fs.FileInfo) bool {
	return validPathRegular("", info)
}
