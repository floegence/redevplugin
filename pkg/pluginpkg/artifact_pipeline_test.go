package pluginpkg

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadLimitsRejectsZeroValueAndInvalidWithMethods(t *testing.T) {
	if _, err := Read(context.Background(), bytes.NewReader(nil), 0, ReadLimits{}); err == nil {
		t.Fatal("Read() accepted zero-value limits")
	}
	limits := DefaultReadLimits()
	for name, update := range map[string]func(ReadLimits) (ReadLimits, error){
		"uncompressed": func(value ReadLimits) (ReadLimits, error) { return value.WithMaxUncompressedBytes(0) },
		"files":        func(value ReadLimits) (ReadLimits, error) { return value.WithMaxFiles(0) },
		"entry":        func(value ReadLimits) (ReadLimits, error) { return value.WithMaxEntryBytes(-1) },
		"path":         func(value ReadLimits) (ReadLimits, error) { return value.WithMaxPathBytes(0) },
		"ratio":        func(value ReadLimits) (ReadLimits, error) { return value.WithMaxCompressionRatio(0) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := update(limits); err == nil {
				t.Fatal("invalid limit accepted")
			}
		})
	}
}

func TestAssetStoreExposesImmutablePackageMetadata(t *testing.T) {
	pkg := testAssetPackage(t)
	store := NewMemoryAssetStore()
	if err := store.PutPackage(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	entries, err := store.ReadPackageMetadata(context.Background(), pkg.PackageHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(pkg.Entries) {
		t.Fatalf("metadata entries = %d, want %d", len(entries), len(pkg.Entries))
	}
	entries[0].Path = "mutated"
	again, err := store.ReadPackageMetadata(context.Background(), pkg.PackageHash)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Path == "mutated" {
		t.Fatal("metadata escaped asset store")
	}
}

func TestFileAssetStoreRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg := testAssetPackage(t)
	if err := store.PutPackage(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	packagePath, err := store.packagePath(pkg.PackageHash)
	if err != nil {
		t.Fatal(err)
	}
	uiPath := filepath.Join(packagePath, fileAssetFilesDir, "ui")
	if err := os.RemoveAll(uiPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(uiPath), uiPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html"); err == nil {
		t.Fatal("ReadAsset() followed an intermediate symlink")
	} else if !errors.Is(err, ErrInvalidAssetPath) {
		t.Fatalf("ReadAsset() error = %v, want ErrInvalidAssetPath", err)
	}
}

func testAssetPackage(t *testing.T) Package {
	t.Helper()
	files := map[string][]byte{
		"manifest.json":    []byte(validManifestJSON()),
		"ui/index.html":    []byte("<!doctype html><title>Plugin</title><script type=\"text/redevplugin-worker\" src=\"assets/app.js\"></script>"),
		"ui/assets/app.js": []byte("void 0;"),
	}
	pkg, err := packageFromFiles(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}
