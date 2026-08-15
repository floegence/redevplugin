//go:build !linux

package resourceio

import "os"

func openWatchImplementation(_ *os.File, _ URI) (watchImplementation, error) {
	return nil, ErrWatchUnsupported
}
