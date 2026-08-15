//go:build windows

package resourceio

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func safeRegularFile(file *os.File, info fs.FileInfo) bool {
	if file == nil || !info.Mode().IsRegular() {
		return false
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &details); err != nil {
		return false
	}
	return details.NumberOfLinks == 1 && details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}
