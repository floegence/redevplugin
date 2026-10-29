package resourceio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
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

func TestMountRejectedTruncatePreservesHardlinkContents(t *testing.T) {
	for _, options := range []OpenOptions{
		{Write: true, Truncate: true},
		{Read: true, Write: true, Truncate: true},
		{Write: true, Create: true, Truncate: true},
	} {
		t.Run(fmt.Sprintf("read=%t/create=%t", options.Read, options.Create), func(t *testing.T) {
			mount, root := testMount(t, false)
			outside := filepath.Join(t.TempDir(), "original.txt")
			selected := filepath.Join(root, "selected.txt")
			want := []byte("preserve original bytes")
			if err := os.WriteFile(outside, want, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(outside, selected); err != nil {
				t.Skipf("hardlink unavailable: %v", err)
			}
			uri, _ := ParseURI("redevfs://workspace/selected.txt")
			file, err := mount.OpenFile(uri, options)
			if file != nil {
				_ = file.Close()
			}
			if !errors.Is(err, ErrUnsafeFile) {
				t.Fatalf("open error = %v, want ErrUnsafeFile", err)
			}
			for _, path := range []string{outside, selected} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("rejected open changed %s: %q, %v", path, got, err)
				}
			}
		})
	}
}

func TestMountRejectedCopyPreservesHardlinkContents(t *testing.T) {
	mount, root := testMount(t, false)
	outside := filepath.Join(t.TempDir(), "original.txt")
	selected := filepath.Join(root, "selected.txt")
	want := []byte("preserve destination bytes")
	if err := os.WriteFile(outside, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, selected); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	from, _ := ParseURI("redevfs://workspace/source.txt")
	to, _ := ParseURI("redevfs://workspace/selected.txt")
	if err := mount.Copy(from, to, true, 0); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("copy error = %v, want ErrUnsafeFile", err)
	}
	for _, path := range []string{outside, selected} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("rejected copy changed %s: %q, %v", path, got, err)
		}
	}
}

func TestMountValidatedTruncateAppendAndExclusiveCreate(t *testing.T) {
	for _, test := range []struct {
		name    string
		options OpenOptions
		write   string
		want    string
	}{
		{"truncate", OpenOptions{Write: true, Truncate: true}, "new", "new"},
		{"truncate-empty", OpenOptions{Write: true, Truncate: true}, "", ""},
		{"read-write-truncate", OpenOptions{Read: true, Write: true, Truncate: true}, "new", "new"},
		{"append", OpenOptions{Write: true, Append: true}, "new", "originalnew"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mount, root := testMount(t, false)
			path := filepath.Join(root, "file.txt")
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			uri, _ := ParseURI("redevfs://workspace/file.txt")
			file, err := mount.OpenFile(uri, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte(test.write)); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != test.want {
				t.Fatalf("contents = %q, %v; want %q", got, err, test.want)
			}
			if file, err := mount.OpenFile(uri, OpenOptions{Write: true, CreateNew: true, Truncate: true}); !errors.Is(err, os.ErrExist) {
				if file != nil {
					_ = file.Close()
				}
				t.Fatalf("exclusive creation error = %v", err)
			}
			got, err = os.ReadFile(path)
			if err != nil || string(got) != test.want {
				t.Fatalf("exclusive creation changed contents: %q, %v", got, err)
			}
		})
	}
}

func TestMountCopyRejectsSymlinkToSameFileWithoutTruncating(t *testing.T) {
	mount, root := testMount(t, false)
	want := []byte("preserve source bytes")
	path := filepath.Join(root, "source.txt")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("source.txt", filepath.Join(root, "alias.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	from, _ := ParseURI("redevfs://workspace/source.txt")
	to, _ := ParseURI("redevfs://workspace/alias.txt")
	if err := mount.Copy(from, to, true, 0); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("copy error = %v, want ErrInvalidOptions", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("alias copy changed source: %q, %v", got, err)
	}
}

func TestMountCopyOverwriteTruncatesOnlyValidatedDestination(t *testing.T) {
	mount, root := testMount(t, false)
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination.txt"), []byte("previous longer contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	from, _ := ParseURI("redevfs://workspace/source.txt")
	to, _ := ParseURI("redevfs://workspace/destination.txt")
	if err := mount.Copy(from, to, true, 0); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"source.txt", "destination.txt"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != "new" {
			t.Fatalf("copy contents %s = %q, %v", name, got, err)
		}
	}
}

func TestMountCopyRejectsSameFileWithoutTruncating(t *testing.T) {
	mount, root := testMount(t, false)
	want := []byte("preserve source bytes")
	path := filepath.Join(root, "source.txt")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	uri, _ := ParseURI("redevfs://workspace/source.txt")
	if err := mount.Copy(uri, uri, true, 0); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("copy error = %v, want ErrInvalidOptions", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("self copy changed source: %q, %v", got, err)
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
