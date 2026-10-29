//go:build windows

package resourceio

import (
	"golang.org/x/sys/windows"
	"os"
)

func selectedObjectIdentity(file *os.File) (ObjectIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return ObjectIdentity{}, err
	}
	nanos := info.CreationTime.Nanoseconds()
	id := ObjectIdentity{Device: uint64(info.VolumeSerialNumber), Object: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), CreatedSeconds: nanos / 1_000_000_000, CreatedNanos: nanos % 1_000_000_000, Directory: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0}
	if !selectedIdentityValid(id) || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	return id, nil
}
