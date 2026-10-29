//go:build !darwin && !linux && !windows

package resourceio

import "os"

func selectedObjectIdentity(*os.File) (ObjectIdentity, error) { return ObjectIdentity{}, ErrUnsafeFile }
