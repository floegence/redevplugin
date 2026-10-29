package resourceio

import (
	"context"
	"io/fs"
	"os"
)

type DirectoryReader interface {
	Next(int) (DirectoryPage, error)
	Close() error
}
type selectedDirectory struct {
	selection *Selection
	stream    *DirectoryStream
	info      fs.FileInfo
	relative  string
	closed    bool
}

func (s *Selection) OpenDirectory(uri URI) (DirectoryReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateLocked(); err != nil {
		return nil, err
	}
	path, err := s.relativeLocked(uri)
	if err != nil {
		return nil, err
	}
	if !s.Directory() || !s.recursive && path != "." {
		return nil, os.ErrPermission
	}
	var file *os.File
	if path == "." {
		file, err = s.root.Open(".")
	} else {
		var root *os.Root
		var leaf string
		root, leaf, err = s.openParentLocked(path)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		named, statErr := root.Lstat(leaf)
		if statErr != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafeFile
		}
		file, err = root.Open(leaf)
		if err == nil {
			info, statErr := file.Stat()
			if statErr != nil || !os.SameFile(info, named) {
				file.Close()
				return nil, ErrUnsafeFile
			}
		}
	}
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		file.Close()
		return nil, ErrUnsafeFile
	}
	d := &selectedDirectory{selection: s, stream: &DirectoryStream{file: file, mountID: uri.MountID, path: path}, info: info, relative: path}
	s.directories[d] = struct{}{}
	return d, nil
}

func (d *selectedDirectory) Next(limit int) (DirectoryPage, error) {
	s := d.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.closed {
		return DirectoryPage{}, ErrResourceClosed
	}
	if err := s.validateLocked(); err != nil {
		return DirectoryPage{}, err
	}
	info, err := s.root.Lstat(d.relative)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, d.info) {
		return DirectoryPage{}, ErrUnsafeFile
	}
	if d.relative != "." {
		root, _, err := s.openParentLocked(d.relative)
		if err != nil {
			return DirectoryPage{}, err
		}
		root.Close()
	}
	return d.stream.Next(limit)
}
func (d *selectedDirectory) Close() error {
	s := d.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	return d.closeLocked()
}
func (d *selectedDirectory) closeLocked() error {
	if d.closed {
		return nil
	}
	d.closed = true
	delete(d.selection.directories, d)
	return d.stream.Close()
}

type selectedAuthorizedDirectory struct {
	mount     *selectedMount
	uri       URI
	directory DirectoryReader
}

func (d *selectedAuthorizedDirectory) Next(limit int) (DirectoryPage, error) {
	return d.NextContext(d.mount.ctx, limit)
}
func (d *selectedAuthorizedDirectory) NextContext(ctx context.Context, limit int) (page DirectoryPage, err error) {
	err = d.mount.useContext(ctx, d.uri, false, func(*Selection) error { var e error; page, e = d.directory.Next(limit); return e })
	return
}
func (d *selectedAuthorizedDirectory) Close() error { return d.directory.Close() }
