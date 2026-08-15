//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package resourceio

import (
	"io/fs"
	"os"
	"syscall"
)

func safeRegularFile(_ *os.File, info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Nlink == 1
}
