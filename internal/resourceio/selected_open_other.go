//go:build !darwin && !linux && !windows

package resourceio

import "os"

func openSelected(*os.Root, string, int, os.FileMode) (*os.File, error) { return nil, ErrUnsafeFile }
func renameSelected(*os.Root, string, *os.Root, string, bool) error     { return ErrUnsafeFile }
