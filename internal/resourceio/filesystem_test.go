package resourceio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestMountStreamsSixtyFourMiBFileWithoutWholeFileBuffering(t *testing.T) {
	mount, _ := testMount(t, false)
	uri, err := ParseURI("redevfs://workspace/large.bin")
	if err != nil {
		t.Fatal(err)
	}
	file, err := mount.OpenFile(uri, OpenOptions{Read: true, Write: true, CreateNew: true})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	chunk := bytes.Repeat([]byte{0xa5}, MaxIOChunkBytes)
	for range (64 << 20) / len(chunk) {
		if n, writeErr := file.Write(chunk); writeErr != nil || n != len(chunk) {
			t.Fatalf("write chunk = %d, %v", n, writeErr)
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, MaxIOChunkBytes)
	for range (64 << 20) / len(buffer) {
		if _, err := io.ReadFull(file, buffer); err != nil || !bytes.Equal(buffer, chunk) {
			t.Fatalf("read chunk: %v", err)
		}
	}
}

func testMount(t *testing.T, readOnly bool) (Mount, string) {
	t.Helper()
	directory := t.TempDir()
	mount, err := OpenMount("workspace", directory, readOnly, sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env", OwnerUserHash: "user"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mount.Close() })
	return mount, directory
}

func TestMountStreamsFilesAndDirectoriesWithoutLeakingRootPath(t *testing.T) {
	mount, root := testMount(t, false)
	fileURI, _ := ParseURI("redevfs://workspace/nested/data.bin")
	directoryURI, _ := ParseURI("redevfs://workspace/nested")
	if err := mount.Mkdir(directoryURI, false, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := mount.OpenFile(fileURI, OpenOptions{Read: true, Write: true, CreateNew: true, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0, 1, 2, 0xff}, 32*1024)
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > MaxIOChunkBytes {
			chunk = chunk[:MaxIOChunkBytes]
		}
		if _, err := file.Write(chunk); err != nil {
			t.Fatal(err)
		}
		payload = payload[len(chunk):]
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 128*1024 {
		t.Fatalf("streamed length = %d", len(got))
	}
	stat, err := mount.Stat(fileURI, true)
	if err != nil {
		t.Fatal(err)
	}
	if stat.URI != fileURI.String() || stat.Kind != FileKindFile || bytes.Contains([]byte(stat.URI), []byte(root)) {
		t.Fatalf("stat projection leaked or changed identity: %#v", stat)
	}
	stream, err := mount.OpenDirectory(directoryURI)
	if err != nil {
		t.Fatal(err)
	}
	page, err := stream.Next(1)
	if err != nil || len(page.Entries) != 1 || page.Entries[0].URI != fileURI.String() {
		t.Fatalf("directory page = %#v, %v", page, err)
	}
	page, err = stream.Next(1)
	if err != nil || !page.EOF {
		t.Fatalf("directory EOF page = %#v, %v", page, err)
	}
}

func TestMountRejectsSymlinkEscapeHardlinksAndSpecialFiles(t *testing.T) {
	mount, root := testMount(t, false)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	escapeURI, _ := ParseURI("redevfs://workspace/escape")
	if _, err := mount.OpenFile(escapeURI, OpenOptions{Read: true}); err == nil {
		t.Fatal("symlink outside root unexpectedly opened")
	}
	inside := filepath.Join(root, "inside.txt")
	if err := os.WriteFile(inside, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(inside, filepath.Join(root, "linked.txt")); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	insideURI, _ := ParseURI("redevfs://workspace/inside.txt")
	if _, err := mount.OpenFile(insideURI, OpenOptions{Read: true}); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("hardlink error = %v, want ErrUnsafeFile", err)
	}
}

func TestMountCopyRenameRemoveAndReadOnlyPolicy(t *testing.T) {
	mount, _ := testMount(t, false)
	source, _ := ParseURI("redevfs://workspace/source.txt")
	copyURI, _ := ParseURI("redevfs://workspace/copy.txt")
	renamed, _ := ParseURI("redevfs://workspace/renamed.txt")
	file, err := mount.OpenFile(source, OpenOptions{Write: true, CreateNew: true})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("content"))
	_ = file.Close()
	if err := mount.Copy(source, copyURI, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := mount.Rename(copyURI, renamed, false); err != nil {
		t.Fatal(err)
	}
	if err := mount.SetTimes(renamed, time.Unix(10, 0), time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}
	if err := mount.Remove(renamed, false); err != nil {
		t.Fatal(err)
	}
	other, _ := ParseURI("redevfs://home/file")
	if err := mount.Copy(source, other, false, 0); !errors.Is(err, ErrCrossDevice) {
		t.Fatalf("cross mount copy error = %v", err)
	}

	readOnly, _ := testMount(t, true)
	readOnlyURI, _ := ParseURI("redevfs://workspace/file")
	if _, err := readOnly.OpenFile(readOnlyURI, OpenOptions{Write: true, CreateNew: true}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read-only open error = %v", err)
	}
	rootURI, _ := ParseURI("redevfs://workspace/")
	if err := mount.Remove(rootURI, true); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("root removal error = %v", err)
	}
}
