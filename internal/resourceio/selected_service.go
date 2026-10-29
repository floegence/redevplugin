package resourceio

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
)

const PermissionFSSelectedRead = "fs.selected.read"
const PermissionFSSelectedWrite = "fs.selected.write"

// SelectedResources keeps object authorization and each bounded operation in
// one authority interval. Implementations must not return an unlocked object.
type SelectedResources interface {
	WithSelection(context.Context, Invocation, URI, bool, func(*Selection) error) error
}

func (s *Service) SetSelectedResources(authority SelectedResources) { s.selected = authority }

type selectedMount struct {
	authority  SelectedResources
	invocation Invocation
	ctx        context.Context
}

func (m *selectedMount) use(uri URI, write bool, call func(*Selection) error) error {
	return m.useContext(m.ctx, uri, write, call)
}
func (m *selectedMount) useContext(ctx context.Context, uri URI, write bool, call func(*Selection) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.invocation.CanRead || (write && !m.invocation.CanWrite) {
		return os.ErrPermission
	}
	p := m.invocation.Permissions
	if write && !p[PermissionFSSelectedWrite] || !write && !p[PermissionFSSelectedRead] && !p[PermissionFSSelectedWrite] {
		return os.ErrPermission
	}
	return m.authority.WithSelection(ctx, m.invocation, uri, write, call)
}

func (m *selectedMount) persistent() *selectedMount {
	copy := *m
	copy.ctx = context.Background()
	return &copy
}

type FileStream interface {
	io.ReadWriteSeeker
	io.Closer
	Sync() error
	Stat() (fs.FileInfo, error)
	Truncate(int64) error
}

type selectedAuthorizedFile struct {
	mount *selectedMount
	uri   URI
	file  SelectedFile
}

func (f *selectedAuthorizedFile) Read(p []byte) (n int, err error) {
	err = f.mount.use(f.uri, false, func(*Selection) error { var e error; n, e = f.file.Read(p); return e })
	return
}
func (f *selectedAuthorizedFile) ReadChunk(ctx context.Context, p []byte) (n int, flags uint32, err error) {
	err = f.mount.useContext(ctx, f.uri, false, func(*Selection) error { var e error; n, e = f.file.Read(p); return e })
	if errors.Is(err, io.EOF) {
		flags = IOFlagEOF
		err = nil
	}
	return
}
func (f *selectedAuthorizedFile) WriteChunk(ctx context.Context, p []byte, flags uint32) (n int, err error) {
	if flags != 0 {
		return 0, ErrInvalidHandle
	}
	err = f.mount.useContext(ctx, f.uri, true, func(*Selection) error { var e error; n, e = f.file.Write(p); return e })
	return
}
func (f *selectedAuthorizedFile) Write(p []byte) (n int, err error) {
	err = f.mount.use(f.uri, true, func(*Selection) error { var e error; n, e = f.file.Write(p); return e })
	return
}
func (f *selectedAuthorizedFile) Seek(offset int64, whence int) (int64, error) {
	return f.SeekContext(f.mount.ctx, offset, whence)
}
func (f *selectedAuthorizedFile) SeekContext(ctx context.Context, offset int64, whence int) (n int64, err error) {
	err = f.mount.useContext(ctx, f.uri, false, func(*Selection) error { var e error; n, e = f.file.Seek(offset, whence); return e })
	return
}
func (f *selectedAuthorizedFile) Sync() error { return f.SyncContext(f.mount.ctx) }
func (f *selectedAuthorizedFile) SyncContext(ctx context.Context) error {
	return f.mount.useContext(ctx, f.uri, true, func(*Selection) error { return f.file.Sync() })
}
func (f *selectedAuthorizedFile) Stat() (info fs.FileInfo, err error) {
	err = f.mount.use(f.uri, false, func(*Selection) error { var e error; info, e = f.file.Stat(); return e })
	return
}
func (f *selectedAuthorizedFile) Truncate(size int64) error {
	return f.mount.use(f.uri, true, func(*Selection) error { return f.file.Truncate(size) })
}
func (f *selectedAuthorizedFile) Close() error { return f.file.Close() }

func selectedMountID(id string) bool { return strings.HasPrefix(id, "selected-") }
