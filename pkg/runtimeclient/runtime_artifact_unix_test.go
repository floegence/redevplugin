//go:build darwin || linux

package runtimeclient

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifyRuntimeExecutableRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyRuntimeExecutable(ctx, path, ""); !errors.Is(err, ErrRuntimeArtifactDigest) {
		t.Fatalf("verifyRuntimeExecutable() error = %v, want ErrRuntimeArtifactDigest", err)
	}
}
