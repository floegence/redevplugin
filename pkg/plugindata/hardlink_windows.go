//go:build windows

package plugindata

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func validPathRegular(path string, info fs.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	return validWindowsRegularHandle(file, info)
}

func validRootRegular(root *os.Root, path string, info fs.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false
	}
	file, err := root.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	return validWindowsRegularHandle(file, info)
}

func validWindowsRegularHandle(file *os.File, named fs.FileInfo) bool {
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, named) {
		return false
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		return false
	}
	return handleInfo.NumberOfLinks == 1 && handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
