//go:build darwin || linux

package resourceio

import (
	"golang.org/x/sys/unix"
	"os"
)

// Open only the final component of a pinned parent. O_NONBLOCK prevents an
// object replaced by a FIFO from blocking before its regular-file check.
func openSelected(root *os.Root, leaf string, flags int, mode os.FileMode) (*os.File, error) {
	return root.OpenFile(leaf, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, mode)
}
