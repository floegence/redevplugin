package plugindata

import (
	"bufio"
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
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode plugin data JSON: %w", err)
	}
	data = append(data, '\n')
	return writeFile(path, data, 0o600)
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
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("%w: dataset root is not a directory", ErrUnsafeFilesystem)
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %s", ErrUnsafeFilesystem, path)
		}
		if !info.IsDir() && !validPathRegular(path, info) {
			return fmt.Errorf("%w: unsupported filesystem entry %s", ErrUnsafeFilesystem, path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return fmt.Errorf("%w: path escapes dataset root", ErrUnsafeFilesystem)
		}
		return nil
	})
}

func hashTree(root, excludedRootFile string) (string, error) {
	if err := validateTree(root); err != nil {
		return "", err
	}
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == excludedRootFile {
			return nil
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		return "", err
	}
	slices.Sort(paths)
	hasher := sha256.New()
	for _, relative := range paths {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			writeHashRecord(hasher, 'd', relative, 0)
			continue
		}
		if !validPathRegular(path, info) {
			return "", fmt.Errorf("%w: hardlink %s", ErrUnsafeFilesystem, path)
		}
		writeHashRecord(hasher, 'f', relative, info.Size())
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hasher, bufio.NewReader(file))
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
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

func directorySize(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
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
