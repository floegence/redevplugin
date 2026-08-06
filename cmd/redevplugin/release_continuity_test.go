package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReleasePrepareAcceptsVerifiedPreviousOutput(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-config.json")
	err := runRelease(context.Background(), []string{
		"prepare", missing, "missing-package.redevplugin", "workspace", "--previous", "previous-output",
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release prepare previous-output syntax error = %v, want config read error", err)
	}
}
