package resourceio

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Selection retains the verified object across review and approval. Paths are
// Host-only evidence; callers expose only opaque resource references.
type Selection struct {
	mu          sync.Mutex
	path        string
	info        fs.FileInfo
	file        *os.File
	root        *os.Root
	recursive   bool
	writable    bool
	closed      bool
	streams     map[*selectedFile]struct{}
	directories map[*selectedDirectory]struct{}
}

func OpenSelection(path string, recursive, writable bool) (*Selection, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidURI
	}
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if named.Mode()&os.ModeSymlink != 0 || !named.IsDir() && !named.Mode().IsRegular() {
		return nil, ErrUnsafeFile
	}
	flags := os.O_RDONLY
	if writable && !named.IsDir() {
		flags = os.O_RDWR
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	f, err := openSelected(parent, filepath.Base(path), flags, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(named, info) || !info.IsDir() && !safeRegularFile(f, info) {
		f.Close()
		return nil, ErrUnsafeFile
	}
	s := &Selection{path: path, info: info, file: f, recursive: recursive, writable: writable, streams: make(map[*selectedFile]struct{}), directories: make(map[*selectedDirectory]struct{})}
	if info.IsDir() {
		s.root, err = os.OpenRoot(path)
		if err != nil {
			f.Close()
			return nil, err
		}
		rootInfo, statErr := s.root.Stat(".")
		if statErr != nil || !os.SameFile(info, rootInfo) {
			s.Close()
			return nil, ErrUnsafeFile
		}
	} else if recursive {
		s.Close()
		return nil, ErrInvalidOptions
	}
	return s, nil
}

func (s *Selection) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	for stream := range s.streams {
		err = errors.Join(err, stream.closeLocked())
	}
	for directory := range s.directories {
		err = errors.Join(err, directory.closeLocked())
	}
	if s.root != nil {
		err = errors.Join(err, s.root.Close())
	}
	return errors.Join(err, s.file.Close())
}

func (s *Selection) validateLocked() error {
	if s.closed {
		return ErrResourceClosed
	}
	info, err := s.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(s.path)
	if err != nil {
		return ErrUnsafeFile
	}
	if !os.SameFile(s.info, info) || !os.SameFile(info, named) || named.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !safeRegularFile(s.file, info) {
		return ErrUnsafeFile
	}
	return nil
}

func (s *Selection) Validate() error { s.mu.Lock(); defer s.mu.Unlock(); return s.validateLocked() }
func (s *Selection) Directory() bool { return s.info.IsDir() }
func (s *Selection) Name() string    { return filepath.Base(s.path) }

func (s *Selection) relativeLocked(uri URI) (string, error) {
	if uri.String() == "" {
		return "", ErrInvalidURI
	}
	if !s.info.IsDir() {
		if uri.Path != "." {
			return "", os.ErrPermission
		}
		return ".", nil
	}
	if !s.recursive && strings.Contains(uri.Path, "/") {
		return "", os.ErrPermission
	}
	// Walk through opened directories so symlink replacement cannot redirect an
	// operation to another subtree of the selected root.
	return uri.Path, nil
}

func (s *Selection) openParentLocked(path string) (*os.Root, string, error) {
	parent, leaf := filepath.Split(filepath.FromSlash(path))
	parent = filepath.Clean(parent)
	root, err := s.root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	if parent != "." {
		for _, component := range strings.Split(filepath.ToSlash(parent), "/") {
			info, err := root.Lstat(component)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				root.Close()
				return nil, "", ErrUnsafeFile
			}
			next, err := root.OpenRoot(component)
			if err != nil {
				root.Close()
				return nil, "", err
			}
			opened, err := next.Stat(".")
			root.Close()
			if err != nil || !os.SameFile(info, opened) {
				next.Close()
				return nil, "", ErrUnsafeFile
			}
			root = next
		}
	}
	return root, leaf, nil
}

func (s *Selection) OpenFile(uri URI, options OpenOptions) (SelectedFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateLocked(); err != nil {
		return nil, err
	}
	path, err := s.relativeLocked(uri)
	if err != nil {
		return nil, err
	}
	flags, mode, err := normalizeOpenOptions(options)
	if err != nil {
		return nil, err
	}
	if options.Write && !s.writable {
		return nil, os.ErrPermission
	}
	if !s.info.IsDir() {
		if options.Create || options.CreateNew {
			return nil, ErrInvalidOptions
		}
		if options.Truncate {
			if err := s.file.Truncate(0); err != nil {
				return nil, err
			}
		}
		stream := &selectedFile{selection: s, file: s.file, info: s.info, relative: ".", read: options.Read, write: options.Write, append: options.Append}
		s.streams[stream] = struct{}{}
		return stream, nil
	}
	if path == "." {
		return nil, ErrInvalidOptions
	}
	root, leaf, err := s.openParentLocked(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	named, err := root.Lstat(leaf)
	if err == nil && (named.Mode()&os.ModeSymlink != 0 || !named.Mode().IsRegular()) {
		return nil, ErrUnsafeFile
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if named == nil {
		flags |= os.O_EXCL
	}
	f, err := openSelected(root, leaf, flags&^(os.O_TRUNC|os.O_APPEND), mode)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !safeRegularFile(f, info) {
		f.Close()
		return nil, ErrUnsafeFile
	}
	current, err := root.Lstat(leaf)
	if err != nil || !os.SameFile(current, info) || current.Mode()&os.ModeSymlink != 0 || named != nil && !os.SameFile(named, info) {
		f.Close()
		return nil, ErrUnsafeFile
	}
	if options.Truncate {
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, err
		}
	}
	stream := &selectedFile{selection: s, file: f, info: info, relative: path, read: options.Read, write: options.Write, append: options.Append, owns: true}
	s.streams[stream] = struct{}{}
	return stream, nil
}

type SelectedFile interface {
	io.ReadWriteSeeker
	io.Closer
	Sync() error
	Stat() (fs.FileInfo, error)
	Truncate(int64) error
}

func (s *Selection) Stat(uri URI) (FileStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateLocked(); err != nil {
		return FileStat{}, err
	}
	path, err := s.relativeLocked(uri)
	if err != nil {
		return FileStat{}, err
	}
	if path == "." {
		info, err := s.file.Stat()
		if err != nil {
			return FileStat{}, err
		}
		return fileStat(uri, info), nil
	}
	root, leaf, err := s.openParentLocked(path)
	if err != nil {
		return FileStat{}, err
	}
	defer root.Close()
	info, err := root.Lstat(leaf)
	if err != nil {
		return FileStat{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
		return FileStat{}, ErrUnsafeFile
	}
	return fileStat(uri, info), nil
}
func (f *selectedFile) Stat() (fs.FileInfo, error) {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return nil, ErrResourceClosed
	}
	if err := f.validateLocked(); err != nil {
		return nil, err
	}
	return f.file.Stat()
}
func (f *selectedFile) Truncate(size int64) error {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return ErrResourceClosed
	}
	if !f.write {
		return os.ErrPermission
	}
	if size < 0 {
		return ErrInvalidOptions
	}
	if err := f.validateLocked(); err != nil {
		return err
	}
	return f.file.Truncate(size)
}

type selectedFile struct {
	selection                   *Selection
	file                        *os.File
	info                        fs.FileInfo
	relative                    string
	owns                        bool
	offset                      int64
	read, write, append, closed bool
}

func (f *selectedFile) Read(p []byte) (int, error) {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return 0, ErrResourceClosed
	}
	if !f.read {
		return 0, os.ErrPermission
	}
	if err := f.validateLocked(); err != nil {
		return 0, err
	}
	n, err := f.file.ReadAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}
func (f *selectedFile) Write(p []byte) (int, error) {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return 0, ErrResourceClosed
	}
	if !f.write {
		return 0, os.ErrPermission
	}
	if err := f.validateLocked(); err != nil {
		return 0, err
	}
	if f.append {
		info, err := f.file.Stat()
		if err != nil {
			return 0, err
		}
		f.offset = info.Size()
	}
	n, err := f.file.WriteAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}
func (f *selectedFile) Seek(offset int64, whence int) (int64, error) {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return 0, ErrResourceClosed
	}
	if err := f.validateLocked(); err != nil {
		return 0, err
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.offset
	case io.SeekEnd:
		info, err := f.file.Stat()
		if err != nil {
			return 0, err
		}
		offset += info.Size()
	default:
		return 0, ErrInvalidOptions
	}
	if offset < 0 {
		return 0, ErrInvalidOptions
	}
	f.offset = offset
	return offset, nil
}
func (f *selectedFile) Sync() error {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.closed {
		return ErrResourceClosed
	}
	if err := f.validateLocked(); err != nil {
		return err
	}
	return f.file.Sync()
}
func (f *selectedFile) Close() error {
	s := f.selection
	s.mu.Lock()
	defer s.mu.Unlock()
	return f.closeLocked()
}

func (f *selectedFile) closeLocked() error {
	if f.closed {
		return nil
	}
	f.closed = true
	delete(f.selection.streams, f)
	if f.owns {
		return f.file.Close()
	}
	return nil
}
func (f *selectedFile) validateLocked() error {
	s := f.selection
	if err := s.validateLocked(); err != nil {
		return err
	}
	info, err := f.file.Stat()
	if err != nil || !safeRegularFile(f.file, info) || !os.SameFile(f.info, info) {
		return ErrUnsafeFile
	}
	if !f.owns {
		return nil
	}
	root, leaf, err := s.openParentLocked(f.relative)
	if err != nil {
		return err
	}
	defer root.Close()
	named, err := root.Lstat(leaf)
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, named) {
		return ErrUnsafeFile
	}
	return nil
}
