//go:build !windows

package externalsource

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

func TestStageStoreRejectsSymlinkReplacement(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	archive := buildMinimalPackage(t)
	artifact, err := store.Stage(context.Background(), bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, stageFilename(artifact.ID))
	target := filepath.Join(directory, "replacement")
	if err := os.WriteFile(target, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
	_, err = store.VerifyPackage(context.Background(), artifact, pluginpkg.DefaultReadLimits())
	if CodeOf(err) != ErrorStageIntegrity {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
}

func TestStageStoreRejectsHardLinkedArtifact(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	artifact, err := store.Stage(context.Background(), bytes.NewReader(buildMinimalPackage(t)))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, stageFilename(artifact.ID))
	if err := os.Link(name, filepath.Join(directory, "second-link")); err != nil {
		t.Fatal(err)
	}
	_, err = store.VerifyPackage(context.Background(), artifact, pluginpkg.DefaultReadLimits())
	if CodeOf(err) != ErrorStageIntegrity {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
}

func TestNewStageStoreDoesNotRemoveStageNamedSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, stageFilename("0123456789abcdef0123456789abcdef"))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("stage-named symlink changed: info=%v err=%v", info, err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
		t.Fatalf("symlink target changed: %q err=%v", raw, err)
	}
}
