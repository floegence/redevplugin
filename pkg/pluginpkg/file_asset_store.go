package pluginpkg

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	fileAssetPackagesDir  = "packages"
	fileAssetFilesDir     = "files"
	fileAssetManifestFile = "assets.json"
)

type FileAssetStore struct {
	rootDir    string
	packages   *os.Root
	state      *fileAssetRootState
	lifecycle  sync.RWMutex
	closed     bool
	closeError error
}

type fileAssetManifest struct {
	PackageHash string  `json:"package_hash"`
	Entries     []Entry `json:"entries"`
}

type fileAssetManifestIndex struct {
	entriesByPath map[string]Entry
	entries       []Entry
}

type fileAssetRootState struct {
	mu        sync.RWMutex
	identity  os.FileInfo
	refs      int
	manifests map[string]*fileAssetManifestIndex
}

var fileAssetRootRegistry = struct {
	sync.Mutex
	states map[string]*fileAssetRootState
}{states: make(map[string]*fileAssetRootState)}

const maxFileAssetManifestBytes int64 = 8 << 20

func NewFileAssetStore(root string) (*FileAssetStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: asset store root is required", ErrInvalidAssetPath)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	if err := rootHandle.MkdirAll(fileAssetPackagesDir, 0o700); err != nil {
		_ = rootHandle.Close()
		return nil, err
	}
	packagesRoot, err := openRootedDirectory(rootHandle, fileAssetPackagesDir)
	if closeErr := rootHandle.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		if packagesRoot != nil {
			_ = packagesRoot.Close()
		}
		return nil, err
	}
	identity, err := packagesRoot.Stat(".")
	if err != nil {
		_ = packagesRoot.Close()
		return nil, err
	}
	state, err := acquireFileAssetRootState(abs, identity)
	if err != nil {
		_ = packagesRoot.Close()
		return nil, err
	}
	store := &FileAssetStore{rootDir: abs, packages: packagesRoot, state: state}
	return store, nil
}

func (s *FileAssetStore) PutOwnedPackage(ctx context.Context, pkg *Package) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	files, err := takePackageFiles(pkg)
	if err != nil {
		return err
	}
	release, err := s.acquire()
	if err != nil {
		return err
	}
	defer release()
	if strings.TrimSpace(pkg.PackageHash) == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	manifest := fileAssetManifest{
		PackageHash: strings.TrimSpace(pkg.PackageHash),
		Entries:     append([]Entry(nil), pkg.Entries...),
	}
	if len(manifest.Entries) == 0 {
		return fmt.Errorf("%w: package entries are required", ErrInvalidAssetPath)
	}
	if len(files) != len(manifest.Entries) {
		return fmt.Errorf("%w: package files do not match entries", ErrPackageAssetNotFound)
	}
	index, err := newFileAssetManifestIndex(manifest, manifest.PackageHash)
	if err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryPath, err := validateServableAssetPath(entry.Path)
		if err != nil {
			return err
		}
		content, ok := files[entryPath]
		if !ok {
			return fmt.Errorf("%w: package entry %q has no content", ErrPackageAssetNotFound, entryPath)
		}
		if err := validateStoredAssetContent(entry, content); err != nil {
			return err
		}
	}

	tmpName, tmpRoot, err := s.createTempPackageDir()
	if err != nil {
		return err
	}
	cleanupTmp := true
	defer func() {
		if tmpRoot != nil {
			_ = tmpRoot.Close()
		}
		if cleanupTmp {
			_ = s.packages.RemoveAll(tmpName)
		}
	}()
	filesRoot := fileAssetFilesDir
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		target, err := resolveAssetFilePath(filesRoot, entry.Path)
		if err != nil {
			return err
		}
		if err := tmpRoot.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := tmpRoot.WriteFile(target, files[entry.Path], 0o600); err != nil {
			return err
		}
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(manifestBytes)) > maxFileAssetManifestBytes {
		return fmt.Errorf("%w: asset manifest exceeds %d bytes", ErrInvalidAssetPath, maxFileAssetManifestBytes)
	}
	if err := tmpRoot.WriteFile(fileAssetManifestFile, manifestBytes, 0o600); err != nil {
		return err
	}
	if err := tmpRoot.Close(); err != nil {
		return err
	}
	tmpRoot = nil
	finalName, err := fileAssetPackageDirName(manifest.PackageHash)
	if err != nil {
		return err
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	delete(s.state.manifests, manifest.PackageHash)
	if err := s.packages.RemoveAll(finalName); err != nil {
		return err
	}
	if err := s.packages.Rename(tmpName, finalName); err != nil {
		return err
	}
	s.state.manifests[manifest.PackageHash] = index
	cleanupTmp = false
	return nil
}

func (s *FileAssetStore) ReadAsset(ctx context.Context, packageHash string, assetPath string) (Asset, error) {
	if s == nil {
		return Asset{}, errors.New("package asset store is nil")
	}
	release, err := s.acquire()
	if err != nil {
		return Asset{}, err
	}
	defer release()
	packageHash = strings.TrimSpace(packageHash)
	assetPath, err = validateServableAssetPath(assetPath)
	if err != nil {
		return Asset{}, err
	}
	if err := ctx.Err(); err != nil {
		return Asset{}, err
	}

	if err := s.ensureManifestIndex(ctx, packageHash); err != nil {
		return Asset{}, err
	}

	s.state.mu.RLock()
	index, ok := s.state.manifests[packageHash]
	if !ok {
		s.state.mu.RUnlock()
		return Asset{}, ErrPackageAssetNotFound
	}
	entry, ok := index.entriesByPath[assetPath]
	if !ok {
		s.state.mu.RUnlock()
		return Asset{}, ErrPackageAssetNotFound
	}
	base, err := fileAssetPackageDirName(packageHash)
	if err != nil {
		s.state.mu.RUnlock()
		return Asset{}, err
	}
	target, err := resolveAssetFilePath(filepath.Join(base, fileAssetFilesDir), assetPath)
	if err != nil {
		s.state.mu.RUnlock()
		return Asset{}, err
	}
	file, info, err := openRootedRegularFile(s.packages, target)
	if errors.Is(err, os.ErrNotExist) {
		s.state.mu.RUnlock()
		return Asset{}, ErrPackageAssetNotFound
	}
	if err != nil {
		s.state.mu.RUnlock()
		return Asset{}, err
	}
	if info.Size() != entry.Size {
		_ = file.Close()
		s.state.mu.RUnlock()
		return Asset{}, fmt.Errorf("%w: asset %q size mismatch", ErrPackageAssetNotFound, entry.Path)
	}
	s.state.mu.RUnlock()
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, entry.Size+1))
	if err != nil {
		return Asset{}, err
	}
	if err := validateStoredAssetContent(entry, content); err != nil {
		return Asset{}, err
	}
	return Asset{
		Entry:   entry,
		Content: append([]byte(nil), content...),
	}, nil
}

func (s *FileAssetStore) ReadPackageMetadata(ctx context.Context, packageHash string) ([]Entry, error) {
	if s == nil {
		return nil, errors.New("package asset store is nil")
	}
	release, err := s.acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packageHash = strings.TrimSpace(packageHash)
	if err := s.ensureManifestIndex(ctx, packageHash); err != nil {
		return nil, err
	}
	s.state.mu.RLock()
	index, ok := s.state.manifests[packageHash]
	if !ok {
		s.state.mu.RUnlock()
		return nil, ErrPackageAssetNotFound
	}
	entries := append([]Entry(nil), index.entries...)
	s.state.mu.RUnlock()
	return entries, nil
}

func (s *FileAssetStore) DeletePackage(_ context.Context, packageHash string) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	release, err := s.acquire()
	if err != nil {
		return err
	}
	defer release()
	packageHash = strings.TrimSpace(packageHash)
	if packageHash == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}

	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	delete(s.state.manifests, packageHash)

	target, err := fileAssetPackageDirName(packageHash)
	if err != nil {
		return err
	}
	if err := s.packages.RemoveAll(target); err != nil {
		return err
	}
	return nil
}

func (s *FileAssetStore) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return s.closeError
	}
	s.closed = true
	releaseFileAssetRootState(s.rootDir, s.state)
	s.closeError = s.packages.Close()
	return s.closeError
}

func (s *FileAssetStore) acquire() (func(), error) {
	s.lifecycle.RLock()
	if s.closed {
		s.lifecycle.RUnlock()
		return nil, ErrAssetStoreClosed
	}
	return s.lifecycle.RUnlock, nil
}

func acquireFileAssetRootState(root string, identity os.FileInfo) (*fileAssetRootState, error) {
	fileAssetRootRegistry.Lock()
	defer fileAssetRootRegistry.Unlock()
	if existing, ok := fileAssetRootRegistry.states[root]; ok {
		if !os.SameFile(existing.identity, identity) {
			return nil, fmt.Errorf("%w: asset store packages directory was replaced", ErrInvalidAssetPath)
		}
		existing.refs++
		return existing, nil
	}
	state := &fileAssetRootState{identity: identity, refs: 1, manifests: make(map[string]*fileAssetManifestIndex)}
	fileAssetRootRegistry.states[root] = state
	return state, nil
}

func releaseFileAssetRootState(root string, state *fileAssetRootState) {
	fileAssetRootRegistry.Lock()
	defer fileAssetRootRegistry.Unlock()
	current, ok := fileAssetRootRegistry.states[root]
	if !ok || current != state {
		return
	}
	if current.refs <= 1 {
		delete(fileAssetRootRegistry.states, root)
		return
	}
	current.refs--
}

func (s *FileAssetStore) packagesRoot() string {
	return filepath.Join(s.rootDir, fileAssetPackagesDir)
}

func (s *FileAssetStore) createTempPackageDir() (string, *os.Root, error) {
	if s == nil || s.packages == nil {
		return "", nil, errors.New("package asset store is nil")
	}
	for attempts := 0; attempts < 128; attempts++ {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, err
		}
		name := ".pkg-" + hex.EncodeToString(suffix[:])
		if err := s.packages.Mkdir(name, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", nil, err
		}
		root, err := openRootedDirectory(s.packages, name)
		if err != nil {
			_ = s.packages.RemoveAll(name)
			return "", nil, err
		}
		return name, root, nil
	}
	return "", nil, errors.New("could not allocate a temporary package directory")
}

func (s *FileAssetStore) ensureManifestIndex(ctx context.Context, packageHash string) error {
	packageHash = strings.TrimSpace(packageHash)
	if packageHash == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	s.state.mu.RLock()
	_, loaded := s.state.manifests[packageHash]
	s.state.mu.RUnlock()
	if loaded {
		return nil
	}

	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, loaded := s.state.manifests[packageHash]; loaded {
		return nil
	}
	base, err := fileAssetPackageDirName(packageHash)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(base, fileAssetManifestFile)
	file, info, err := openRootedRegularFile(s.packages, manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return ErrPackageAssetNotFound
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if info.Size() > maxFileAssetManifestBytes {
		return fmt.Errorf("%w: asset manifest exceeds %d bytes", ErrInvalidAssetPath, maxFileAssetManifestBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxFileAssetManifestBytes+1))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(raw)) > maxFileAssetManifestBytes {
		return fmt.Errorf("%w: asset manifest exceeds %d bytes", ErrInvalidAssetPath, maxFileAssetManifestBytes)
	}
	var manifest fileAssetManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("%w: invalid asset manifest: %v", ErrInvalidAssetPath, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: asset manifest contains multiple JSON values", ErrInvalidAssetPath)
		}
		return fmt.Errorf("%w: invalid asset manifest trailer: %v", ErrInvalidAssetPath, err)
	}
	index, err := newFileAssetManifestIndex(manifest, packageHash)
	if err != nil {
		return err
	}
	s.state.manifests[packageHash] = index
	return nil
}

func newFileAssetManifestIndex(manifest fileAssetManifest, expectedPackageHash string) (*fileAssetManifestIndex, error) {
	if manifest.PackageHash != expectedPackageHash {
		return nil, fmt.Errorf("%w: package hash mismatch", ErrPackageAssetNotFound)
	}
	limits := DefaultReadLimits()
	if len(manifest.Entries) == 0 || len(manifest.Entries) > limits.maxFiles {
		return nil, fmt.Errorf("%w: asset manifest entry count is invalid", ErrInvalidAssetPath)
	}
	entries := make([]Entry, 0, len(manifest.Entries))
	entriesByPath := make(map[string]Entry, len(manifest.Entries))
	var total int64
	for _, entry := range manifest.Entries {
		path, err := validateServableAssetPath(entry.Path)
		if err != nil || path != entry.Path {
			return nil, fmt.Errorf("%w: invalid asset manifest entry path %q", ErrInvalidAssetPath, entry.Path)
		}
		if err := validateEntryPathLength(entry.Path, limits.maxPathBytes); err != nil {
			return nil, err
		}
		if entry.Size < 0 || entry.Size > limits.maxEntryBytes || total > limits.maxUncompressedBytes-entry.Size {
			return nil, fmt.Errorf("%w: asset manifest entry size is invalid", ErrInvalidAssetPath)
		}
		if _, exists := entriesByPath[entry.Path]; exists {
			return nil, fmt.Errorf("%w: asset manifest contains duplicate path %q", ErrInvalidAssetPath, entry.Path)
		}
		if entry.SHA256 != "" && !validAssetSHA256(entry.SHA256) {
			return nil, fmt.Errorf("%w: asset manifest entry %q has invalid sha256", ErrInvalidAssetPath, entry.Path)
		}
		total += entry.Size
		entries = append(entries, entry)
		entriesByPath[entry.Path] = entry
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return &fileAssetManifestIndex{entriesByPath: entriesByPath, entries: entries}, nil
}

func validAssetSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == "sha256:"+hex.EncodeToString(decoded)
}

func openRootedDirectory(root *os.Root, name string) (*os.Root, error) {
	if root == nil {
		return nil, errors.New("package asset store is nil")
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, fmt.Errorf("%w: rooted path component %q is not a directory", ErrInvalidAssetPath, name)
	}
	opened, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("%w: rooted directory changed while opening", ErrInvalidAssetPath)
	}
	after, err := opened.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = opened.Close()
		return nil, fmt.Errorf("%w: rooted directory changed while opening", ErrInvalidAssetPath)
	}
	return opened, nil
}

func openRootedRegularFile(root *os.Root, relativePath string) (*os.File, os.FileInfo, error) {
	if root == nil {
		return nil, nil, errors.New("package asset store is nil")
	}
	clean := filepath.Clean(filepath.FromSlash(relativePath))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, nil, fmt.Errorf("%w: rooted path escapes asset store root", ErrInvalidAssetPath)
	}
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, nil, fmt.Errorf("%w: rooted path is not canonical", ErrInvalidAssetPath)
		}
	}
	current := root
	openedRoots := make([]*os.Root, 0, len(parts)-1)
	defer func() {
		for _, opened := range openedRoots {
			_ = opened.Close()
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		before, err := current.Lstat(part)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, os.ErrNotExist
		}
		if err != nil {
			return nil, nil, err
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, nil, fmt.Errorf("%w: rooted path component %q is not a directory", ErrInvalidAssetPath, part)
		}
		opened, err := openRootedDirectory(current, part)
		if err != nil {
			return nil, nil, err
		}
		openedRoots = append(openedRoots, opened)
		current = opened
	}
	name := parts[len(parts)-1]
	before, err := current.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, os.ErrNotExist
	}
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: rooted path is not a regular file", ErrInvalidAssetPath)
	}
	file, err := current.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: rooted file changed while opening", ErrInvalidAssetPath)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: rooted file changed while opening", ErrInvalidAssetPath)
	}
	return file, after, nil
}

func (s *FileAssetStore) packagePath(packageHash string) (string, error) {
	dirName, err := fileAssetPackageDirName(packageHash)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.packagesRoot(), dirName), nil
}

func fileAssetPackageDirName(packageHash string) (string, error) {
	packageHash = strings.TrimSpace(packageHash)
	if packageHash == "" {
		return "", fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	sum := sha256.Sum256([]byte(packageHash))
	return hex.EncodeToString(sum[:]), nil
}

func validateServableAssetPath(assetPath string) (string, error) {
	assetPath, err := validateEntryPath(strings.TrimSpace(assetPath))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidAssetPath, err)
	}
	if strings.HasPrefix(assetPath, "signatures/") {
		return "", fmt.Errorf("%w: signatures are not served", ErrInvalidAssetPath)
	}
	return assetPath, nil
}

func resolveAssetFilePath(root string, assetPath string) (string, error) {
	assetPath, err := validateServableAssetPath(assetPath)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, filepath.FromSlash(assetPath))
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: asset path escapes package root", ErrInvalidAssetPath)
	}
	return target, nil
}

func validateStoredAssetContent(entry Entry, content []byte) error {
	if int64(len(content)) != entry.Size {
		return fmt.Errorf("%w: asset %q size mismatch", ErrPackageAssetNotFound, entry.Path)
	}
	if entry.SHA256 != "" && sha256String(content) != entry.SHA256 {
		return fmt.Errorf("%w: asset %q hash mismatch", ErrPackageAssetNotFound, entry.Path)
	}
	return nil
}

var _ AssetStore = (*FileAssetStore)(nil)
