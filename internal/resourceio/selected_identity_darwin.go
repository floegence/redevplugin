//go:build darwin

package resourceio

import (
	"os"
	"syscall"
)

func selectedObjectIdentity(file *os.File) (ObjectIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return ObjectIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	id := ObjectIdentity{Device: uint64(stat.Dev), Object: stat.Ino, CreatedSeconds: stat.Birthtimespec.Sec, CreatedNanos: stat.Birthtimespec.Nsec, Directory: info.IsDir()}
	if !selectedIdentityValid(id) {
		return ObjectIdentity{}, ErrUnsafeFile
	}
	return id, nil
}
