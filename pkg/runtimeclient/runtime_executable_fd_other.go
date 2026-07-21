//go:build !linux

package runtimeclient

import "os"

func duplicateRuntimeExecutableForChild(*os.File) (*os.File, error) {
	return nil, ErrRuntimePathRequired
}
