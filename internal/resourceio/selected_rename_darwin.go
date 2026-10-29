//go:build darwin

package resourceio

import (
	"golang.org/x/sys/unix"
	"os"
)

func renameSelected(from *os.Root, oldName string, to *os.Root, newName string, overwrite bool) error {
	src, err := from.Open(".")
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := to.Open(".")
	if err != nil {
		return err
	}
	defer dst.Close()
	var flags uint32
	if !overwrite {
		flags = unix.RENAME_EXCL
	}
	return unix.RenameatxNp(int(src.Fd()), oldName, int(dst.Fd()), newName, flags)
}
