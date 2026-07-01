package pluginpkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	fileAssetPackagesDir  = "packages"
	fileAssetFilesDir     = "files"
	fileAssetManifestFile = "assets.json"
)

type FileAssetStore struct {
	mu   sync.Mutex
	root string
}

type fileAssetManifest struct {
	PackageHash string  `json:"package_hash"`
	Entries     []Entry `json:"entries"`
}

func NewFileAssetStore(root string) (*FileAssetStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: asset store root is required", ErrInvalidAssetPath)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	store := &FileAssetStore{root: abs}
	if err := os.MkdirAll(store.packagesRoot(), 0o700); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileAssetStore) PutPackage(ctx context.Context, pkg Package) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
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
	assets := make(map[string][]byte, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryPath, err := validateServableAssetPath(entry.Path)
		if err != nil {
			return err
		}
		content, ok := pkg.Files[entryPath]
		if !ok {
			return fmt.Errorf("%w: package entry %q has no content", ErrPackageAssetNotFound, entryPath)
		}
		if err := validateStoredAssetContent(entry, content); err != nil {
			return err
		}
		assets[entryPath] = append([]byte(nil), content...)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmpPath, err := os.MkdirTemp(s.packagesRoot(), ".pkg-*")
	if err != nil {
		return err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.RemoveAll(tmpPath)
		}
	}()
	filesRoot := filepath.Join(tmpPath, fileAssetFilesDir)
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		target, err := resolveAssetFilePath(filesRoot, entry.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, assets[entry.Path], 0o600); err != nil {
			return err
		}
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpPath, fileAssetManifestFile), manifestBytes, 0o600); err != nil {
		return err
	}
	finalPath, err := s.packagePath(manifest.PackageHash)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(finalPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	cleanupTmp = false
	return nil
}

func (s *FileAssetStore) ReadAsset(ctx context.Context, packageHash string, assetPath string) (Asset, error) {
	if s == nil {
		return Asset{}, errors.New("package asset store is nil")
	}
	packageHash = strings.TrimSpace(packageHash)
	assetPath, err := validateServableAssetPath(assetPath)
	if err != nil {
		return Asset{}, err
	}
	if err := ctx.Err(); err != nil {
		return Asset{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	base, err := s.packagePath(packageHash)
	if err != nil {
		return Asset{}, err
	}
	manifest, err := readFileAssetManifest(base)
	if err != nil {
		return Asset{}, err
	}
	if manifest.PackageHash != packageHash {
		return Asset{}, fmt.Errorf("%w: package hash mismatch", ErrPackageAssetNotFound)
	}
	var entry Entry
	found := false
	for _, candidate := range manifest.Entries {
		if candidate.Path == assetPath {
			entry = candidate
			found = true
			break
		}
	}
	if !found {
		return Asset{}, ErrPackageAssetNotFound
	}
	target, err := resolveAssetFilePath(filepath.Join(base, fileAssetFilesDir), assetPath)
	if err != nil {
		return Asset{}, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return Asset{}, ErrPackageAssetNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Asset{}, fmt.Errorf("%w: asset path is not a regular file", ErrInvalidAssetPath)
	}
	content, err := os.ReadFile(target)
	if errors.Is(err, os.ErrNotExist) {
		return Asset{}, ErrPackageAssetNotFound
	}
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

func (s *FileAssetStore) DeletePackage(_ context.Context, packageHash string) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	packageHash = strings.TrimSpace(packageHash)
	if packageHash == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.packagePath(packageHash)
	if err != nil {
		return err
	}
	return os.RemoveAll(target)
}

func (s *FileAssetStore) packagesRoot() string {
	return filepath.Join(s.root, fileAssetPackagesDir)
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

func readFileAssetManifest(base string) (fileAssetManifest, error) {
	raw, err := os.ReadFile(filepath.Join(base, fileAssetManifestFile))
	if errors.Is(err, os.ErrNotExist) {
		return fileAssetManifest{}, ErrPackageAssetNotFound
	}
	if err != nil {
		return fileAssetManifest{}, err
	}
	var manifest fileAssetManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fileAssetManifest{}, err
	}
	return manifest, nil
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
