//go:build windows

package externalsource

import "os"

func stageLinkCount(os.FileInfo) uint64 { return 1 }
