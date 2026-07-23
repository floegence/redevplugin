//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package externalsource

import "os"

// Unknown platforms fail closed until they provide a trustworthy link count.
func stageLinkCount(os.FileInfo) uint64 { return 0 }
