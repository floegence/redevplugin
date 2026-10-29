package resourceio

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func TestSelectedRecursiveMkdirReportsPartialMutation(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSelection(dir, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	uri := URI{MountID: "selected-test", Path: "created/" + strings.Repeat("x", 300)}
	err = s.Mkdir(uri, true, 0700)
	if err == nil || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("partial mkdir outcome: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "created")); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedIdentityReopenRequiresSameObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chosen")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = ValidateSelectionIdentity(path, false, true, id)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := ValidateSelectionIdentity(path, false, true, id); err == nil {
		s.Close()
		t.Fatal("identity transferred to replacement")
	}
}

func TestSelectedDirectoryListingCannotDescendWithoutRecursiveGrant(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "visible"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSelection(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if stream, err := s.OpenDirectory(URI{MountID: "selected-test", Path: "nested"}); err == nil {
		stream.Close()
		t.Fatal("nonrecursive grant listed child contents")
	}
	stream, err := s.OpenDirectory(URI{MountID: "selected-test", Path: "."})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	page, err := stream.Next(10)
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	s.Close()
	if _, err := stream.Next(1); err == nil {
		t.Fatal("closed selection listed directory")
	}
}

func TestSelectedSeekRejectsOverflowWithoutChangingPosition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chosen")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f, err := s.OpenFile(URI{MountID: "selected-test", Path: "."}, OpenOptions{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(math.MaxInt64, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(math.MaxInt64, io.SeekCurrent); err == nil {
		t.Fatal("overflow accepted")
	}
	if got, err := f.Seek(0, io.SeekCurrent); err != nil || got != math.MaxInt64 {
		t.Fatalf("position=%d err=%v", got, err)
	}
}

func TestSelectedFileDoesNotAuthorizeParentOrSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chosen.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "neighbor.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	uri := URI{MountID: "selected-test", Path: "."}
	f, err := selection.OpenFile(uri, OpenOptions{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, path := range []string{"chosen.txt", "neighbor.txt", "../neighbor.txt"} {
		if _, err := selection.OpenFile(URI{MountID: uri.MountID, Path: path}, OpenOptions{Read: true}); err == nil {
			t.Fatalf("file selection authorized %q", path)
		}
	}
	if _, err := f.Write([]byte("changed!")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "changed!" {
		t.Fatalf("saved bytes=%q err=%v", got, err)
	}
}

func TestSelectedFileRejectsReplacementAndHardlinkBeforeTruncation(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "hardlink", true: "replacement"}[replace], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "chosen.txt")
			if err := os.WriteFile(path, []byte("keep-bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			selection, err := OpenSelection(path, false, true)
			if err != nil {
				t.Fatal(err)
			}
			defer selection.Close()
			if replace {
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("new-object"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			if _, err := selection.OpenFile(URI{MountID: "selected-test", Path: "."}, OpenOptions{Write: true, Truncate: true}); err == nil {
				t.Fatal("unsafe selection accepted")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatalf("rejection changed bytes: %q -> %q", before, after)
			}
		})
	}
}

func TestSelectedDirectoryIsBoundedAndSurvivesIndependentStreams(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "private.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "direct.txt"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested/private.txt", filepath.Join(dir, "shortcut")); err != nil {
		t.Fatal(err)
	}
	selection, err := OpenSelection(dir, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	for _, path := range []string{"nested/private.txt", "shortcut", "../escape"} {
		if _, err := selection.OpenFile(URI{MountID: "selected-test", Path: path}, OpenOptions{Read: true}); err == nil {
			t.Fatalf("nonrecursive selection accepted %q", path)
		}
	}
	for range 2 {
		f, err := selection.OpenFile(URI{MountID: "selected-test", Path: "direct.txt"}, OpenOptions{Read: true})
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 3)
		if _, err := f.Read(b); err != nil {
			t.Fatal(err)
		}
		if string(b) != "con" {
			t.Fatalf("independent stream started at %q", b)
		}
		f.Close()
	}
}

func TestSelectedOpenStreamRejectsReplacementAndSelectionClose(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "chosen.txt")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			selectedPath, relative := path, "."
			if directory {
				selectedPath, relative = dir, "chosen.txt"
			}
			selection, err := OpenSelection(selectedPath, false, true)
			if err != nil {
				t.Fatal(err)
			}
			defer selection.Close()
			f, err := selection.OpenFile(URI{MountID: "selected-test", Path: relative}, OpenOptions{Read: true, Write: true})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("bad")); err == nil {
				t.Fatal("open stream accepted replaced object")
			}
			if err := selection.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, 0); err == nil {
				t.Fatal("closed selection stream remained valid")
			}
			if b, _ := os.ReadFile(path + ".old"); string(b) != "original" {
				t.Fatalf("old object changed: %q", b)
			}
			if b, _ := os.ReadFile(path); string(b) != "replacement" {
				t.Fatalf("new object changed: %q", b)
			}
		})
	}
}

func TestSelectedRecursiveMkdirCreatesParentsAndRejectsLinks(t *testing.T) {
	root := t.TempDir()
	selection, err := OpenSelection(root, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	uri := URI{MountID: "selected-test", Path: "one/two/three"}
	for range 2 {
		if err := selection.Mkdir(uri, true, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(filepath.Join(root, "one/two/three")); err != nil || !info.IsDir() {
		t.Fatalf("nested directory: %v %v", info, err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := selection.Mkdir(URI{MountID: uri.MountID, Path: "link/escape"}, true, 0700); err == nil {
		t.Fatal("followed symbolic link")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside changed: %v", err)
	}
}

func TestSelectedRenameDoesNotOverwriteWithoutExplicitConsent(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"source": "source bytes", "target": "target bytes"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := OpenSelection(root, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	from := URI{MountID: "selected-fixture", Path: "source"}
	to := URI{MountID: "selected-fixture", Path: "target"}
	if err := selection.Rename(from, to, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive rename: %v", err)
	}
	for name, want := range map[string]string{"source": "source bytes", "target": "target bytes"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q %v", name, got, err)
		}
	}
	if err := selection.Rename(from, to, true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "target")); err != nil || string(got) != "source bytes" {
		t.Fatalf("overwrite: %q %v", got, err)
	}
}
