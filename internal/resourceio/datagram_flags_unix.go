//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package resourceio

import "syscall"

func datagramTruncated(flags int) bool {
	return flags&syscall.MSG_TRUNC != 0
}
