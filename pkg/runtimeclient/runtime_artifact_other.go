//go:build !darwin && !linux

package runtimeclient

import "os"

func openRuntimeExecutable(path string) (*os.File, error) {
	return os.Open(path)
}
