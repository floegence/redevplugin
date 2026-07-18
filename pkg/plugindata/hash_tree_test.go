package plugindata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestHashTreePreservesCanonicalOrderingAndRootFileExclusion(t *testing.T) {
	root := t.TempDir()
	writeHashTreeFixture(t, root, map[string]string{
		"a/inside.txt":  "inside",
		"a.txt":         "sibling",
		"manifest.json": "excluded-v1",
		"z/nested.txt":  "nested",
	})
	want, err := referenceHashTree(root, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := hashTree(root, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("hashTree() = %q, want canonical reference %q", got, want)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte("excluded-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	excludedChanged, err := hashTree(root, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if excludedChanged != got {
		t.Fatalf("excluded root file changed hash: %q != %q", excludedChanged, got)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	includedChanged, err := hashTree(root, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if includedChanged == got {
		t.Fatal("included file content did not change hash")
	}
}

func TestHashTreeRejectsSymlinkDuringRootWalk(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := hashTree(root, ""); !errors.Is(err, ErrUnsafeFilesystem) {
		t.Fatalf("hashTree(symlink) error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestHashTreeRejectsHardlinkDuringRootWalk(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	if err := os.WriteFile(first, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(root, "second.txt")); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	if _, err := hashTree(root, ""); !errors.Is(err, ErrUnsafeFilesystem) {
		t.Fatalf("hashTree(hardlink) error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestRootedTreeSnapshotReusesCanonicalHashAndSize(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"a/inside.txt": "inside",
		"a.txt":        "sibling",
		"z/nested.txt": "nested",
	}
	writeHashTreeFixture(t, root, files)
	wantHash, err := referenceHashTree(root, "")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		t.Fatal(err)
	}
	var wantSize int64
	for _, content := range files {
		wantSize += int64(len(content))
	}
	if snapshot.contentHash != wantHash || snapshot.sizeBytes != wantSize {
		t.Fatalf("snapshot = {hash:%q size:%d}, want {hash:%q size:%d}", snapshot.contentHash, snapshot.sizeBytes, wantHash, wantSize)
	}
}

func TestRootedTreeSnapshotRejectsFileMutationAfterHash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "settings.json")
	before := []byte(`{"revision":1}`)
	after := []byte(`{"revision":2}`)
	if len(before) != len(after) {
		t.Fatal("test mutation must preserve file size")
	}
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, after, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.revalidate(root); !errors.Is(err, ErrUnsafeFilesystem) {
		t.Fatalf("revalidate() error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestRootedTreeSnapshotRejectsDirectorySymlinkReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "value.txt"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		t.Fatal(err)
	}
	relocated := filepath.Join(t.TempDir(), "relocated")
	if err := os.Rename(directory, relocated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relocated, directory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := snapshot.revalidate(root); !errors.Is(err, ErrUnsafeFilesystem) {
		t.Fatalf("revalidate() error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestValidateExportStageRejectsSameSizeManifestReplacement(t *testing.T) {
	stage := t.TempDir()
	payloadRoot := filepath.Join(stage, exportPayloadName)
	if err := os.Mkdir(payloadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloadRoot, "value.txt"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := snapshotRootedTree(payloadRoot, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte("{\"value\":\"a\"}\n")
	replacement := []byte("{\"value\":\"b\"}\n")
	if len(expected) != len(replacement) || bytes.Equal(expected, replacement) {
		t.Fatal("test replacement must differ while preserving manifest size")
	}
	if err := os.WriteFile(filepath.Join(stage, exportManifestName), replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateExportStage(stage, payload, expected); !errors.Is(err, ErrDatasetCorrupt) {
		t.Fatalf("validateExportStage() error = %v, want ErrDatasetCorrupt", err)
	}
}

func BenchmarkHashTree(b *testing.B) {
	root := benchmarkHashTreeFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := hashTree(root, ""); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(2_000, "files")
}

func BenchmarkRootedTreeSnapshotPipeline(b *testing.B) {
	root := benchmarkHashTreeFixture(b)
	b.Run("rooted_snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			snapshot, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{hashContents: true, syncContents: true})
			if err != nil {
				b.Fatal(err)
			}
			if err := snapshot.revalidate(root); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("separate_validation_hash_sync_size", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			if err := validateTree(root); err != nil {
				b.Fatal(err)
			}
			if _, err := hashTree(root, ""); err != nil {
				b.Fatal(err)
			}
			if err := syncTree(root); err != nil {
				b.Fatal(err)
			}
			if _, err := regularFileTreeSize(root); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.ReportMetric(2_000, "files")
}

func benchmarkHashTreeFixture(b *testing.B) string {
	b.Helper()
	root := b.TempDir()
	for directory := 0; directory < 100; directory++ {
		for file := 0; file < 20; file++ {
			path := filepath.Join(root, fmt.Sprintf("dir-%03d", directory), fmt.Sprintf("file-%03d.txt", file))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	return root
}

func writeHashTreeFixture(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for relative, content := range files {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func referenceHashTree(root, excludedRootFile string) (string, error) {
	if err := validateTree(root); err != nil {
		return "", err
	}
	var paths []string
	if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == excludedRootFile {
			return nil
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(paths)
	hasher := sha256.New()
	for _, relative := range paths {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			writeHashRecord(hasher, 'd', relative, 0)
			continue
		}
		if !validPathRegular(path, info) {
			return "", fmt.Errorf("%w: hardlink %s", ErrUnsafeFilesystem, path)
		}
		writeHashRecord(hasher, 'f', relative, info.Size())
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hasher, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
