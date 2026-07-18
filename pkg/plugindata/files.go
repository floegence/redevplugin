package plugindata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func ensurePrivateDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: %s is not a private directory", ErrUnsafeFilesystem, path)
		}
		return os.Chmod(path, 0o700)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrUnsafeFilesystem, path)
	}
	return os.Chmod(path, 0o700)
}

func writeJSON(path string, value any) error {
	data, err := marshalJSON(value)
	if err != nil {
		return err
	}
	return writeFile(path, data, 0o600)
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode plugin data JSON: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

func readJSON(path string, target any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !validPathRegular(path, info) {
		return fmt.Errorf("%w: metadata is not a regular file: %s", ErrUnsafeFilesystem, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrDatasetCorrupt, path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON in %s", ErrDatasetCorrupt, path)
		}
		return fmt.Errorf("%w: decode trailing JSON in %s: %v", ErrDatasetCorrupt, path, err)
	}
	return nil
}

func writeFile(path string, data []byte, mode fs.FileMode) error {
	return writeFileWithSync(path, data, mode, syncDirectory)
}

func writeFileWithSync(path string, data []byte, mode fs.FileMode, syncDir func(string) error) error {
	parent := filepath.Dir(path)
	if err := ensurePrivateDirectory(parent); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".write-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	if err := syncDir(parent); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}

func (s *FileStore) copyDirectory(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: copy source is not a directory", ErrUnsafeFilesystem)
	}
	if err := ensurePrivateDirectory(destination); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %s", ErrUnsafeFilesystem, path)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return fmt.Errorf("%w: copy path escapes source", ErrUnsafeFilesystem)
		}
		target := filepath.Join(destination, relative)
		switch {
		case info.IsDir():
			return ensurePrivateDirectory(target)
		case validPathRegular(path, info):
			return copyRegularFile(path, target, info.Mode().Perm())
		default:
			return fmt.Errorf("%w: unsupported filesystem entry %s", ErrUnsafeFilesystem, path)
		}
	})
}

func copyRegularFile(source, destination string, mode fs.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := ensurePrivateDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode&0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func validateTree(root string) error {
	_, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{})
	return err
}

func hashTree(root, excludedRootFile string) (string, error) {
	snapshot, err := snapshotRootedTree(root, rootedTreeSnapshotOptions{excludedRootFile: excludedRootFile, hashContents: true})
	if err != nil {
		return "", err
	}
	return snapshot.contentHash, nil
}

type rootedTreeSnapshotOptions struct {
	excludedRootFile string
	hashContents     bool
	syncContents     bool
}

type rootedTreeEntry struct {
	path string
	info fs.FileInfo
}

type rootedTreeSnapshot struct {
	contentHash string
	sizeBytes   int64
	rootInfo    fs.FileInfo
	entries     []rootedTreeEntry
}

func snapshotRootedTree(path string, options rootedTreeSnapshotOptions) (rootedTreeSnapshot, error) {
	namedRoot, err := os.Lstat(path)
	if err != nil {
		return rootedTreeSnapshot{}, err
	}
	if namedRoot.Mode()&os.ModeSymlink != 0 || !namedRoot.IsDir() {
		return rootedTreeSnapshot{}, fmt.Errorf("%w: dataset root is not a directory", ErrUnsafeFilesystem)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return rootedTreeSnapshot{}, err
	}
	defer root.Close()
	openedRoot, err := root.Lstat(".")
	if err != nil {
		return rootedTreeSnapshot{}, err
	}
	if !sameSnapshotInfo(namedRoot, openedRoot) {
		return rootedTreeSnapshot{}, fmt.Errorf("%w: dataset root changed while opening", ErrUnsafeFilesystem)
	}

	entries := make([]rootedTreeEntry, 0, 64)
	if err := fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if relative == "." {
				return fmt.Errorf("%w: dataset root is not a directory", ErrUnsafeFilesystem)
			}
			return fmt.Errorf("%w: symlink %s", ErrUnsafeFilesystem, relative)
		}
		if relative == "." {
			if !info.IsDir() || !sameSnapshotInfo(openedRoot, info) {
				return fmt.Errorf("%w: dataset root changed during traversal", ErrUnsafeFilesystem)
			}
			return nil
		}
		if !fs.ValidPath(relative) || relative == ".." || strings.HasPrefix(relative, "../") {
			return fmt.Errorf("%w: path escapes dataset root", ErrUnsafeFilesystem)
		}
		if !info.IsDir() && !validRootRegular(root, relative, info) {
			return fmt.Errorf("%w: unsupported filesystem entry %s", ErrUnsafeFilesystem, relative)
		}
		entries = append(entries, rootedTreeEntry{path: relative, info: info})
		return nil
	}); err != nil {
		return rootedTreeSnapshot{}, err
	}
	slices.SortFunc(entries, func(left, right rootedTreeEntry) int {
		return strings.Compare(left.path, right.path)
	})

	var hasher hash.Hash
	if options.hashContents {
		hasher = sha256.New()
	}
	var copyBuffer []byte
	directories := make([]rootedTreeEntry, 0, len(entries)/4+1)
	var sizeBytes int64
	for _, entry := range entries {
		if entry.info.IsDir() {
			directories = append(directories, entry)
			if hasher != nil && entry.path != options.excludedRootFile {
				writeHashRecord(hasher, 'd', entry.path, 0)
			}
			continue
		}
		if !options.hashContents && !options.syncContents {
			sizeBytes += entry.info.Size()
			continue
		}
		file, err := root.Open(entry.path)
		if err != nil {
			return rootedTreeSnapshot{}, err
		}
		opened, err := file.Stat()
		if err != nil || !sameSnapshotInfo(entry.info, opened) || !validRootRegular(root, entry.path, opened) {
			file.Close()
			return rootedTreeSnapshot{}, fmt.Errorf("%w: file %s changed during snapshot", ErrUnsafeFilesystem, entry.path)
		}
		sizeBytes += opened.Size()
		if hasher != nil && entry.path != options.excludedRootFile {
			writeHashRecord(hasher, 'f', entry.path, opened.Size())
			if copyBuffer == nil {
				copyBuffer = make([]byte, 32<<10)
			}
			reader := struct{ io.Reader }{Reader: file}
			if _, err := io.CopyBuffer(hasher, reader, copyBuffer); err != nil {
				file.Close()
				return rootedTreeSnapshot{}, err
			}
		}
		if options.syncContents {
			if err := file.Sync(); err != nil {
				file.Close()
				return rootedTreeSnapshot{}, err
			}
		}
		closedInfo, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || !sameSnapshotInfo(opened, closedInfo) {
			return rootedTreeSnapshot{}, fmt.Errorf("%w: file %s changed while reading", ErrUnsafeFilesystem, entry.path)
		}
		if closeErr != nil {
			return rootedTreeSnapshot{}, closeErr
		}
	}

	slices.SortFunc(directories, func(left, right rootedTreeEntry) int {
		leftDepth := strings.Count(left.path, "/")
		rightDepth := strings.Count(right.path, "/")
		if leftDepth != rightDepth {
			return rightDepth - leftDepth
		}
		return strings.Compare(left.path, right.path)
	})
	for _, directory := range directories {
		current, err := root.Lstat(directory.path)
		if err != nil || !current.IsDir() || !sameSnapshotInfo(directory.info, current) {
			return rootedTreeSnapshot{}, fmt.Errorf("%w: directory %s changed during snapshot", ErrUnsafeFilesystem, directory.path)
		}
		if options.syncContents {
			handle, err := root.Open(directory.path)
			if err != nil {
				return rootedTreeSnapshot{}, err
			}
			opened, statErr := handle.Stat()
			if statErr != nil || !sameSnapshotInfo(directory.info, opened) {
				handle.Close()
				return rootedTreeSnapshot{}, fmt.Errorf("%w: directory %s changed while opening", ErrUnsafeFilesystem, directory.path)
			}
			syncErr := handle.Sync()
			closeErr := handle.Close()
			if syncErr != nil {
				return rootedTreeSnapshot{}, syncErr
			}
			if closeErr != nil {
				return rootedTreeSnapshot{}, closeErr
			}
		}
	}
	currentRoot, err := os.Lstat(path)
	if err != nil || !sameSnapshotInfo(namedRoot, currentRoot) {
		return rootedTreeSnapshot{}, fmt.Errorf("%w: dataset root changed during snapshot", ErrUnsafeFilesystem)
	}
	if options.syncContents {
		handle, err := root.Open(".")
		if err != nil {
			return rootedTreeSnapshot{}, err
		}
		opened, statErr := handle.Stat()
		if statErr != nil || !sameSnapshotInfo(openedRoot, opened) {
			handle.Close()
			return rootedTreeSnapshot{}, fmt.Errorf("%w: dataset root changed while syncing", ErrUnsafeFilesystem)
		}
		syncErr := handle.Sync()
		closeErr := handle.Close()
		if syncErr != nil {
			return rootedTreeSnapshot{}, syncErr
		}
		if closeErr != nil {
			return rootedTreeSnapshot{}, closeErr
		}
		currentRoot, err = os.Lstat(path)
		if err != nil || !sameSnapshotInfo(namedRoot, currentRoot) {
			return rootedTreeSnapshot{}, fmt.Errorf("%w: dataset root changed after sync", ErrUnsafeFilesystem)
		}
	}

	snapshot := rootedTreeSnapshot{sizeBytes: sizeBytes, rootInfo: namedRoot, entries: entries}
	if hasher != nil {
		snapshot.contentHash = hex.EncodeToString(hasher.Sum(nil))
	}
	return snapshot, nil
}

func (snapshot rootedTreeSnapshot) validateRoot(path string) error {
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !sameSnapshotInfo(snapshot.rootInfo, current) {
		return fmt.Errorf("%w: dataset root changed after snapshot", ErrUnsafeFilesystem)
	}
	return nil
}

func (snapshot rootedTreeSnapshot) revalidate(path string) error {
	if err := snapshot.validateRoot(path); err != nil {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	openedRoot, err := root.Lstat(".")
	if err != nil || !sameSnapshotInfo(snapshot.rootInfo, openedRoot) {
		return fmt.Errorf("%w: dataset root changed while revalidating", ErrUnsafeFilesystem)
	}
	for _, entry := range snapshot.entries {
		current, err := root.Lstat(entry.path)
		if err != nil || !sameSnapshotInfo(entry.info, current) {
			return fmt.Errorf("%w: entry %s changed after snapshot", ErrUnsafeFilesystem, entry.path)
		}
		if current.IsDir() {
			continue
		}
		if !validRootRegular(root, entry.path, current) {
			return fmt.Errorf("%w: unsafe entry %s after snapshot", ErrUnsafeFilesystem, entry.path)
		}
	}
	currentRoot, err := os.Lstat(path)
	if err != nil || !sameSnapshotInfo(snapshot.rootInfo, currentRoot) {
		return fmt.Errorf("%w: dataset root changed after revalidation", ErrUnsafeFilesystem)
	}
	return nil
}

func sameSnapshotInfo(left, right fs.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func writeHashRecord(hasher hash.Hash, kind byte, path string, size int64) {
	hasher.Write([]byte{kind})
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], uint64(len(path)))
	hasher.Write(buffer[:])
	hasher.Write([]byte(path))
	binary.BigEndian.PutUint64(buffer[:], uint64(size))
	hasher.Write(buffer[:])
}

func syncTree(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}); err != nil {
		return err
	}
	slices.SortFunc(directories, func(a, b string) int {
		depthA := strings.Count(a, string(filepath.Separator))
		depthB := strings.Count(b, string(filepath.Separator))
		return depthB - depthA
	})
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeDirectoryContents(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in staging directory", ErrUnsafeFilesystem)
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return syncDirectory(root)
}
