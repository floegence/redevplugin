package resourceio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type Mount struct {
	ID       string
	Root     *os.Root
	ReadOnly bool
	Scope    sessionctx.ResourceScope
}

func OpenMount(id, path string, readOnly bool, scope sessionctx.ResourceScope) (Mount, error) {
	if id == "" || path == "" || !scope.Valid() {
		return Mount{}, ErrInvalidURI
	}
	root, err := os.OpenRoot(filepath.Clean(path))
	if err != nil {
		return Mount{}, err
	}
	return Mount{ID: id, Root: root, ReadOnly: readOnly, Scope: scope}, nil
}

func (mount Mount) Close() error {
	if mount.Root == nil {
		return nil
	}
	return mount.Root.Close()
}

func (mount Mount) relative(uri URI) (string, error) {
	if uri.MountID != mount.ID || uri.Path == "" {
		return "", ErrInvalidURI
	}
	return uri.Path, nil
}

func (mount Mount) OpenFile(uri URI, flag int, mode fs.FileMode) (*os.File, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return nil, err
	}
	if mount.ReadOnly && flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, os.ErrPermission
	}
	return mount.Root.OpenFile(path, flag, mode)
}

func (mount Mount) Stat(uri URI, followSymlinks bool) (fs.FileInfo, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return nil, err
	}
	if followSymlinks {
		return mount.Root.Stat(path)
	}
	return mount.Root.Lstat(path)
}

func (mount Mount) Mkdir(uri URI, mode fs.FileMode) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	path, err := mount.relative(uri)
	if err != nil {
		return err
	}
	return mount.Root.MkdirAll(path, mode)
}

func (mount Mount) Remove(uri URI, recursive bool) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	path, err := mount.relative(uri)
	if err != nil {
		return err
	}
	if path == "." || path == "" {
		return errors.New("root mount cannot be removed")
	}
	if recursive {
		return mount.Root.RemoveAll(path)
	}
	return mount.Root.Remove(path)
}

func (mount Mount) Rename(from, to URI, overwrite bool) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	oldPath, err := mount.relative(from)
	if err != nil {
		return err
	}
	newPath, err := mount.relative(to)
	if err != nil {
		return err
	}
	if !overwrite {
		if _, statErr := mount.Root.Lstat(newPath); statErr == nil {
			return os.ErrExist
		}
	}
	return mount.Root.Rename(oldPath, newPath)
}
