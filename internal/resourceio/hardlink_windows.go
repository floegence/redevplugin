//go:build windows

package resourceio

import "io/fs"

func safeRegularFile(info fs.FileInfo) bool {
	return info.Mode().IsRegular()
}
