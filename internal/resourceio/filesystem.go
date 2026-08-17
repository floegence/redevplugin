package resourceio

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var (
	ErrCrossDevice      = errors.New("cross-device operation is not allowed")
	ErrUnsafeFile       = errors.New("filesystem object is unsafe")
	ErrInvalidOptions   = errors.New("file open options are invalid")
	ErrMountUnavailable = errors.New("filesystem mount is unavailable")
	ErrWatchUnsupported = errors.New("filesystem watch is unavailable")
)

type Mount struct {
	ID       string
	Root     *os.Root
	ReadOnly bool
	Scope    sessionctx.ResourceScope
}

type OpenOptions struct {
	Read      bool        `json:"read"`
	Write     bool        `json:"write"`
	Create    bool        `json:"create"`
	CreateNew bool        `json:"create_new"`
	Truncate  bool        `json:"truncate"`
	Append    bool        `json:"append"`
	Mode      fs.FileMode `json:"mode,omitempty"`
}

type FileKind string

const (
	FileKindFile      FileKind = "file"
	FileKindDirectory FileKind = "directory"
	FileKindSymlink   FileKind = "symlink"
	FileKindOther     FileKind = "other"
)

type FileStat struct {
	URI            string   `json:"uri"`
	Kind           FileKind `json:"kind"`
	Size           int64    `json:"size"`
	Mode           uint32   `json:"mode"`
	ModifiedUnixMS int64    `json:"modified_unix_ms"`
	CreatedUnixMS  *int64   `json:"created_unix_ms,omitempty"`
}

type DirectoryEntry struct {
	Name string   `json:"name"`
	URI  string   `json:"uri"`
	Kind FileKind `json:"kind"`
}

type DirectoryPage struct {
	Entries []DirectoryEntry `json:"entries"`
	EOF     bool             `json:"eof"`
}

type WatchKind string

const (
	WatchKindCreate   WatchKind = "create"
	WatchKindChange   WatchKind = "change"
	WatchKindDelete   WatchKind = "delete"
	WatchKindRename   WatchKind = "rename"
	WatchKindOverflow WatchKind = "overflow"
)

type WatchEvent struct {
	Sequence    uint64    `json:"sequence"`
	Kind        WatchKind `json:"kind"`
	URI         string    `json:"uri"`
	PreviousURI string    `json:"previous_uri,omitempty"`
}

type watchImplementation interface {
	Next(context.Context, time.Duration) (WatchEvent, error)
	Close() error
}

type WatchStream struct {
	implementation watchImplementation
}

func (stream *WatchStream) Next(ctx context.Context, timeout time.Duration) (WatchEvent, error) {
	if stream == nil || stream.implementation == nil {
		return WatchEvent{}, ErrResourceClosed
	}
	return stream.implementation.Next(ctx, timeout)
}

func (stream *WatchStream) Close() error {
	if stream == nil || stream.implementation == nil {
		return nil
	}
	return stream.implementation.Close()
}

type DirectoryStream struct {
	file    *os.File
	mountID string
	path    string
	closed  bool
}

func OpenMount(id, path string, readOnly bool, scope sessionctx.ResourceScope) (Mount, error) {
	if !validMountID(id) || path == "" || !filepath.IsAbs(path) || !scope.Valid() {
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
	if mount.Root == nil || uri.MountID != mount.ID || uri.Path == "" {
		return "", ErrInvalidURI
	}
	return uri.Path, nil
}

func (mount Mount) Stat(uri URI, followSymlinks bool) (FileStat, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return FileStat{}, err
	}
	var info fs.FileInfo
	if followSymlinks {
		info, err = mount.Root.Stat(path)
	} else {
		info, err = mount.Root.Lstat(path)
	}
	if err != nil {
		return FileStat{}, err
	}
	return fileStat(uri, info), nil
}

func fileStat(uri URI, info fs.FileInfo) FileStat {
	return FileStat{
		URI:            uri.String(),
		Kind:           fileKind(info.Mode()),
		Size:           info.Size(),
		Mode:           uint32(info.Mode().Perm()),
		ModifiedUnixMS: info.ModTime().UnixMilli(),
	}
}

func fileKind(mode fs.FileMode) FileKind {
	switch {
	case mode&fs.ModeSymlink != 0:
		return FileKindSymlink
	case mode.IsRegular():
		return FileKindFile
	case mode.IsDir():
		return FileKindDirectory
	default:
		return FileKindOther
	}
}

func (mount Mount) OpenFile(uri URI, options OpenOptions) (*os.File, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return nil, err
	}
	flags, mode, err := normalizeOpenOptions(options)
	if err != nil {
		return nil, err
	}
	if mount.ReadOnly && flags&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return nil, os.ErrPermission
	}
	file, err := mount.Root.OpenFile(path, flags, mode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !safeRegularFile(file, info) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsafeFile
	}
	return file, nil
}

func normalizeOpenOptions(options OpenOptions) (int, fs.FileMode, error) {
	if !options.Read && !options.Write ||
		(options.CreateNew && !options.Write) || (options.Create && !options.Write) ||
		(options.Truncate && !options.Write) || (options.Append && !options.Write) ||
		(options.Append && options.Truncate) || options.Mode&^fs.FileMode(0o777) != 0 {
		return 0, 0, ErrInvalidOptions
	}
	flags := os.O_RDONLY
	if options.Read && options.Write {
		flags = os.O_RDWR
	} else if options.Write {
		flags = os.O_WRONLY
	}
	if options.Create {
		flags |= os.O_CREATE
	}
	if options.CreateNew {
		flags |= os.O_CREATE | os.O_EXCL
	}
	if options.Truncate {
		flags |= os.O_TRUNC
	}
	if options.Append {
		flags |= os.O_APPEND
	}
	mode := options.Mode
	if mode == 0 {
		mode = 0o600
	}
	return flags, mode, nil
}

func (mount Mount) Mkdir(uri URI, recursive bool, mode fs.FileMode) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	path, err := mount.relative(uri)
	if err != nil {
		return err
	}
	if path == "." || mode&^fs.FileMode(0o777) != 0 {
		return ErrInvalidOptions
	}
	if mode == 0 {
		mode = 0o700
	}
	if recursive {
		return mount.Root.MkdirAll(path, mode)
	}
	return mount.Root.Mkdir(path, mode)
}

func (mount Mount) Remove(uri URI, recursive bool) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	path, err := mount.relative(uri)
	if err != nil {
		return err
	}
	if path == "." {
		return os.ErrPermission
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
		if to.MountID != mount.ID {
			return ErrCrossDevice
		}
		return err
	}
	if oldPath == "." || newPath == "." {
		return os.ErrPermission
	}
	if !overwrite {
		if _, statErr := mount.Root.Lstat(newPath); statErr == nil {
			return os.ErrExist
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}
	}
	return mount.Root.Rename(oldPath, newPath)
}

func (mount Mount) Copy(from, to URI, overwrite bool, mode fs.FileMode) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	if from.MountID != mount.ID || to.MountID != mount.ID {
		return ErrCrossDevice
	}
	source, err := mount.OpenFile(from, OpenOptions{Read: true})
	if err != nil {
		return err
	}
	defer source.Close()
	if mode == 0 {
		if info, statErr := source.Stat(); statErr == nil {
			mode = info.Mode().Perm()
		}
	}
	destination, err := mount.OpenFile(to, OpenOptions{Write: true, Create: overwrite, CreateNew: !overwrite, Truncate: overwrite, Mode: mode})
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(destination, source, make([]byte, MaxIOChunkBytes))
	syncErr := destination.Sync()
	closeErr := destination.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func (mount Mount) OpenDirectory(uri URI) (*DirectoryStream, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return nil, err
	}
	file, err := mount.Root.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsafeFile
	}
	return &DirectoryStream{file: file, mountID: mount.ID, path: path}, nil
}

func (mount Mount) OpenWatch(uri URI) (*WatchStream, error) {
	path, err := mount.relative(uri)
	if err != nil {
		return nil, err
	}
	target, err := mount.Root.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := target.Stat()
	if err != nil || !(info.IsDir() || safeRegularFile(target, info)) {
		_ = target.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsafeFile
	}
	implementation, err := openWatchImplementation(target, uri)
	if err != nil {
		_ = target.Close()
		return nil, err
	}
	return &WatchStream{implementation: implementation}, nil
}

func (stream *DirectoryStream) Next(limit int) (DirectoryPage, error) {
	if stream == nil || stream.file == nil || stream.closed {
		return DirectoryPage{}, ErrResourceClosed
	}
	if limit < 1 || limit > 1000 {
		return DirectoryPage{}, ErrResourceLimit
	}
	entries, err := stream.file.ReadDir(limit)
	eof := errors.Is(err, io.EOF)
	if err != nil && !eof {
		return DirectoryPage{}, err
	}
	page := DirectoryPage{Entries: make([]DirectoryEntry, 0, len(entries)), EOF: eof}
	for _, entry := range entries {
		path := entry.Name()
		if stream.path != "." {
			path = stream.path + "/" + path
		}
		uri := URI{MountID: stream.mountID, Path: path}
		page.Entries = append(page.Entries, DirectoryEntry{Name: entry.Name(), URI: uri.String(), Kind: fileKind(entry.Type())})
	}
	if eof {
		_ = stream.Close()
	}
	return page, nil
}

func (stream *DirectoryStream) Close() error {
	if stream == nil || stream.file == nil || stream.closed {
		return nil
	}
	stream.closed = true
	return stream.file.Close()
}

func Sync(resource io.Closer) error {
	file, ok := resource.(*os.File)
	if !ok {
		return ErrInvalidHandle
	}
	return file.Sync()
}

func (mount Mount) SetTimes(uri URI, accessed, modified time.Time) error {
	if mount.ReadOnly {
		return os.ErrPermission
	}
	path, err := mount.relative(uri)
	if err != nil {
		return err
	}
	file, err := mount.Root.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || fileKind(info.Mode()) == FileKindOther {
		return ErrUnsafeFile
	}
	return setFileTimes(file, accessed, modified)
}
