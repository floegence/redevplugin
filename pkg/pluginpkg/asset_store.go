package pluginpkg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	ErrPackageAssetNotFound = errors.New("package asset not found")
	ErrInvalidAssetPath     = errors.New("package asset path is invalid")
	ErrAssetStoreClosed     = errors.New("package asset store is closed")
)

type AssetStore interface {
	// PutOwnedPackage takes ownership of pkg.Files and pkg.SignatureFiles when
	// the call begins, including when the operation returns an error. Callers
	// must not retain aliases to transferred byte slices.
	PutOwnedPackage(ctx context.Context, pkg *Package) error
	ReadPackageMetadata(ctx context.Context, packageHash string) ([]Entry, error)
	ReadAsset(ctx context.Context, packageHash string, assetPath string) (Asset, error)
	DeletePackage(ctx context.Context, packageHash string) error
	Close() error
}

type MemoryAssetStore struct {
	mu       sync.RWMutex
	packages map[string]memoryAssetPackage
	closed   bool
}

type memoryAssetPackage struct {
	entries map[string]Entry
	files   map[string][]byte
}

func NewMemoryAssetStore() *MemoryAssetStore {
	return &MemoryAssetStore{packages: map[string]memoryAssetPackage{}}
}

func (s *MemoryAssetStore) PutOwnedPackage(_ context.Context, pkg *Package) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	files, err := takePackageFiles(pkg)
	if err != nil {
		return err
	}
	if strings.TrimSpace(pkg.PackageHash) == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	if len(files) != len(pkg.Entries) {
		return fmt.Errorf("%w: package files do not match entries", ErrPackageAssetNotFound)
	}
	entries := make(map[string]Entry, len(pkg.Entries))
	for _, entry := range pkg.Entries {
		entryPath, err := validateServableAssetPath(entry.Path)
		if err != nil {
			return err
		}
		content, ok := files[entryPath]
		if !ok {
			return fmt.Errorf("%w: package entry %q has no content", ErrPackageAssetNotFound, entry.Path)
		}
		if _, duplicate := entries[entryPath]; duplicate {
			return fmt.Errorf("%w: duplicate package entry %q", ErrInvalidAssetPath, entryPath)
		}
		if err := validateStoredAssetContent(entry, content); err != nil {
			return err
		}
		entries[entryPath] = entry
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrAssetStoreClosed
	}
	s.packages[pkg.PackageHash] = memoryAssetPackage{entries: entries, files: files}
	return nil
}

func takePackageFiles(pkg *Package) (map[string][]byte, error) {
	if pkg == nil {
		return nil, errors.New("package is required")
	}
	files := pkg.Files
	pkg.Files = nil
	pkg.SignatureFiles = nil
	if len(files) == 0 {
		return nil, errors.New("package files are required")
	}
	return files, nil
}

func (s *MemoryAssetStore) ReadAsset(_ context.Context, packageHash string, assetPath string) (Asset, error) {
	if s == nil {
		return Asset{}, errors.New("package asset store is nil")
	}
	packageHash = strings.TrimSpace(packageHash)
	assetPath, err := validateEntryPath(strings.TrimSpace(assetPath))
	if err != nil {
		return Asset{}, fmt.Errorf("%w: %v", ErrInvalidAssetPath, err)
	}
	if strings.HasPrefix(assetPath, "signatures/") {
		return Asset{}, fmt.Errorf("%w: signatures are not served", ErrInvalidAssetPath)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Asset{}, ErrAssetStoreClosed
	}
	pkg, ok := s.packages[packageHash]
	if !ok {
		return Asset{}, ErrPackageAssetNotFound
	}
	entry, ok := pkg.entries[assetPath]
	if !ok {
		return Asset{}, ErrPackageAssetNotFound
	}
	return Asset{Entry: entry, Content: append([]byte(nil), pkg.files[assetPath]...)}, nil
}

func (s *MemoryAssetStore) ReadPackageMetadata(_ context.Context, packageHash string) ([]Entry, error) {
	if s == nil {
		return nil, errors.New("package asset store is nil")
	}
	packageHash = strings.TrimSpace(packageHash)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrAssetStoreClosed
	}
	pkg, ok := s.packages[packageHash]
	if !ok {
		return nil, ErrPackageAssetNotFound
	}
	entries := make([]Entry, 0, len(pkg.entries))
	for _, entry := range pkg.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func (s *MemoryAssetStore) DeletePackage(_ context.Context, packageHash string) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	packageHash = strings.TrimSpace(packageHash)
	if packageHash == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrAssetStoreClosed
	}
	delete(s.packages, packageHash)
	return nil
}

func (s *MemoryAssetStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.packages = nil
	return nil
}
