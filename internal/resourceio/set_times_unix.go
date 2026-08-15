//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package resourceio

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func setFileTimes(file *os.File, accessed, modified time.Time) error {
	times := []unix.Timeval{
		unix.NsecToTimeval(accessed.UnixNano()),
		unix.NsecToTimeval(modified.UnixNano()),
	}
	return unix.Futimes(int(file.Fd()), times)
}
