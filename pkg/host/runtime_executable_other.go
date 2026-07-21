//go:build !linux

package host

import "context"

func openVerifiedExecutable(context.Context, VerifiedExecutableOptions) (*VerifiedExecutable, error) {
	return nil, ErrRuntimeAdmissionUnsupported
}
