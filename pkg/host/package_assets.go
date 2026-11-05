package host

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

// preparePackageAssets serializes package publication with its catalog commit.
// Existing bytes are shared by digest and never removed by a failed sibling
// installation. A new uncommitted package is removed before releasing the lock.
func (h *Host) preparePackageAssets(ctx context.Context, pkg *pluginpkg.Package) (func(bool) error, error) {
	hash := pkg.PackageHash
	unlock, err := h.packageAssetLocks.acquireWrite(ctx, hash)
	if err != nil {
		return nil, err
	}
	entries, err := h.adapters.Assets.ReadPackageMetadata(ctx, hash)
	existing := err == nil
	if err != nil && !errors.Is(err, pluginpkg.ErrPackageAssetNotFound) {
		unlock()
		return nil, err
	}
	if existing {
		if !reflect.DeepEqual(entries, pkg.Entries) {
			unlock()
			return nil, pluginpkg.ErrPackageAssetNotFound
		}
		// Validate retained bytes before reusing them; never overwrite corrupt state.
		for _, entry := range entries {
			if _, err = h.adapters.Assets.ReadAsset(ctx, hash, entry.Path); err != nil {
				unlock()
				return nil, err
			}
		}
		pkg.Files = nil
	} else if err = h.adapters.Assets.PutOwnedPackage(ctx, pkg); err != nil {
		unlock()
		return nil, err
	}
	var once sync.Once
	var result error
	return func(committed bool) error {
		once.Do(func() {
			defer unlock()
			if !existing && !committed {
				result = h.adapters.Assets.DeletePackage(context.WithoutCancel(ctx), hash)
			}
		})
		return result
	}, nil
}
