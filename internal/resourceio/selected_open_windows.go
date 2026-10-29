//go:build windows

package resourceio

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func selectedWindowsError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		return status.Errno()
	}
	return err
}

func openSelectedHandle(parent *os.File, leaf string, access, disposition uint32) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent.Fd()), ObjectName: name, Attributes: windows.OBJ_DONT_REPARSE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		return 0, selectedWindowsError(err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return 0, ErrUnsafeFile
	}
	return handle, nil
}

func openSelected(root *os.Root, leaf string, flags int, _ os.FileMode) (*os.File, error) {
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	access := uint32(windows.FILE_GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.FILE_GENERIC_WRITE
	} else if flags&os.O_WRONLY != 0 {
		access = windows.FILE_GENERIC_WRITE
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
		if flags&os.O_EXCL != 0 {
			disposition = windows.FILE_CREATE
		}
	}
	handle, err := openSelectedHandle(parent, leaf, access, disposition)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), leaf), nil
}

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
	handle, err := openSelectedHandle(src, oldName, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	name, err := windows.UTF16FromString(newName)
	if err != nil {
		return err
	}
	type renameInfo struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	var layout renameInfo
	bytes := (len(name) - 1) * 2
	buffer := make([]byte, int(unsafe.Offsetof(layout.Name))+bytes)
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	if overwrite {
		info.Replace = windows.FILE_RENAME_REPLACE_IF_EXISTS
	}
	info.Root = windows.Handle(dst.Fd())
	info.Length = uint32(bytes)
	copy(unsafe.Slice(&info.Name[0], len(name)-1), name[:len(name)-1])
	return selectedWindowsError(windows.NtSetInformationFile(handle, &windows.IO_STATUS_BLOCK{}, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation))
}
