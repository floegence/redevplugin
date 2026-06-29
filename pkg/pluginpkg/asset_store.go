package pluginpkg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrPackageAssetNotFound = errors.New("package asset not found")
	ErrInvalidAssetPath     = errors.New("package asset path is invalid")
)

type AssetStore interface {
	PutPackage(ctx context.Context, pkg Package) error
	ReadAsset(ctx context.Context, packageHash string, assetPath string) (Asset, error)
	DeletePackage(ctx context.Context, packageHash string) error
}

type MemoryAssetStore struct {
	mu       sync.RWMutex
	packages map[string]map[string]Asset
}

func NewMemoryAssetStore() *MemoryAssetStore {
	return &MemoryAssetStore{packages: map[string]map[string]Asset{}}
}

func (s *MemoryAssetStore) PutPackage(_ context.Context, pkg Package) error {
	if s == nil {
		return errors.New("package asset store is nil")
	}
	if strings.TrimSpace(pkg.PackageHash) == "" {
		return fmt.Errorf("%w: package_hash is required", ErrInvalidAssetPath)
	}
	assets := make(map[string]Asset, len(pkg.Entries))
	for _, entry := range pkg.Entries {
		content, ok := pkg.Files[entry.Path]
		if !ok {
			return fmt.Errorf("%w: package entry %q has no content", ErrPackageAssetNotFound, entry.Path)
		}
		assets[entry.Path] = Asset{
			Entry:   entry,
			Content: append([]byte(nil), content...),
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.packages[pkg.PackageHash] = assets
	return nil
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
	assets, ok := s.packages[packageHash]
	if !ok {
		return Asset{}, ErrPackageAssetNotFound
	}
	asset, ok := assets[assetPath]
	if !ok {
		return Asset{}, ErrPackageAssetNotFound
	}
	asset.Content = append([]byte(nil), asset.Content...)
	return asset, nil
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
	delete(s.packages, packageHash)
	return nil
}
