//go:build aix

package externalsource

import (
	"os"
	"syscall"
)

func stageLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}
