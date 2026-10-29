package resourceio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func (s *Selection) mutationPathLocked(uri URI) (*os.Root, string, error) {
	if err := s.validateLocked(); err != nil {
		return nil, "", err
	}
	path, err := s.relativeLocked(uri)
	if err != nil {
		return nil, "", err
	}
	if !s.writable || !s.Directory() || path == "." {
		return nil, "", os.ErrPermission
	}
	return s.openParentLocked(path)
}
func (s *Selection) Mkdir(uri URI, recursive bool, mode fs.FileMode) (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	defer func() {
		if changed && retErr != nil {
			retErr = mutation.Unknown(retErr)
		}
	}()
	if recursive && !s.recursive || mode&^fs.FileMode(0777) != 0 {
		return ErrInvalidOptions
	}
	if mode == 0 {
		mode = 0700
	}
	if recursive {
		if err := s.validateLocked(); err != nil {
			return err
		}
		path, err := s.relativeLocked(uri)
		if err != nil {
			return err
		}
		if !s.writable || !s.Directory() || path == "." {
			return os.ErrPermission
		}
		root, err := s.root.OpenRoot(".")
		if err != nil {
			return err
		}
		defer func() { root.Close() }()
		for _, component := range strings.Split(path, "/") {
			if err := root.Mkdir(component, mode); err != nil {
				if !errors.Is(err, os.ErrExist) {
					return err
				}
			} else {
				changed = true
			}
			info, err := root.Lstat(component)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrUnsafeFile
			}
			next, err := root.OpenRoot(component)
			if err != nil {
				return err
			}
			opened, err := next.Stat(".")
			if err != nil || !os.SameFile(info, opened) {
				next.Close()
				return ErrUnsafeFile
			}
			root.Close()
			root = next
		}
		return nil
	}
	root, leaf, err := s.mutationPathLocked(uri)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Mkdir(leaf, mode)
}
func (s *Selection) Remove(uri URI, recursive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if recursive && !s.recursive {
		return os.ErrPermission
	}
	root, leaf, err := s.mutationPathLocked(uri)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(leaf)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeFile
	}
	if recursive {
		// RemoveAll may have removed siblings before returning its first error.
		return mutation.Unknown(root.RemoveAll(leaf))
	}
	return root.Remove(leaf)
}
func (s *Selection) Rename(from, to URI, overwrite bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from.MountID != to.MountID {
		return ErrCrossDevice
	}
	src, oldLeaf, err := s.mutationPathLocked(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, newLeaf, err := s.mutationPathLocked(to)
	if err != nil {
		return err
	}
	defer dst.Close()
	info, err := src.Lstat(oldLeaf)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeFile
	}
	if current, err := dst.Lstat(newLeaf); err == nil {
		if !overwrite {
			return os.ErrExist
		}
		if current.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeFile
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if filepath.Clean(from.Path) == filepath.Clean(to.Path) {
		return ErrInvalidOptions
	}
	return renameSelected(src, oldLeaf, dst, newLeaf, overwrite)
}
func (s *Selection) SetTimes(uri URI, accessed, modified time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateLocked(); err != nil {
		return err
	}
	if !s.writable {
		return os.ErrPermission
	}
	path, err := s.relativeLocked(uri)
	if err != nil {
		return err
	}
	if path == "." {
		return setFileTimes(s.file, accessed, modified)
	}
	root, leaf, err := s.openParentLocked(path)
	if err != nil {
		return err
	}
	defer root.Close()
	named, err := root.Lstat(leaf)
	if err != nil {
		return err
	}
	if named.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeFile
	}
	f, err := openSelected(root, leaf, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(info, named) || !info.IsDir() && !safeRegularFile(f, info) {
		return ErrUnsafeFile
	}
	return setFileTimes(f, accessed, modified)
}
