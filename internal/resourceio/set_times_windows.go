//go:build windows

package resourceio

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func setFileTimes(file *os.File, accessed, modified time.Time) error {
	accessedTime := windows.NsecToFiletime(accessed.UnixNano())
	modifiedTime := windows.NsecToFiletime(modified.UnixNano())
	return windows.SetFileTime(windows.Handle(file.Fd()), nil, &accessedTime, &modifiedTime)
}
