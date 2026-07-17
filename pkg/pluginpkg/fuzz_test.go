package pluginpkg

import (
	"bytes"
	"context"
	"testing"
)

// FuzzReadPackageZip is the fixed-seed and fuzz entry point for the package
// archive parser. Read must reject malformed archives without panicking or
// allocating outside the configured limits.
func FuzzReadPackageZip(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, archive []byte) {
		limits := DefaultReadLimits()
		_, _ = Read(context.Background(), bytes.NewReader(archive), int64(len(archive)), limits)
	})
}
