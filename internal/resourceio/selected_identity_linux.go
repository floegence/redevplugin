//go:build linux

package resourceio

import (
	"golang.org/x/sys/unix"
	"os"
)

func selectedObjectIdentity(file *os.File) (ObjectIdentity, error) {
	var stat unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_TYPE|unix.STATX_BTIME, &stat); err != nil {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	required := uint32(unix.STATX_INO | unix.STATX_TYPE | unix.STATX_BTIME)
	if stat.Mask&required != required {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	id := ObjectIdentity{Device: uint64(stat.Dev_major)<<32 | uint64(stat.Dev_minor), Object: stat.Ino, CreatedSeconds: stat.Btime.Sec, CreatedNanos: int64(stat.Btime.Nsec), Directory: stat.Mode&unix.S_IFMT == unix.S_IFDIR}
	if !selectedIdentityValid(id) {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	return id, nil
}
