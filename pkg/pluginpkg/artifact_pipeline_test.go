package pluginpkg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestNewFileAssetStoreRejectsPackagesSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "redirected"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("redirected", filepath.Join(root, fileAssetPackagesDir)); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileAssetStore(root); err == nil {
		t.Fatal("NewFileAssetStore() accepted a symlinked packages directory")
	} else if !errors.Is(err, ErrInvalidAssetPath) {
		t.Fatalf("NewFileAssetStore() error = %v, want ErrInvalidAssetPath", err)
	}
}

func TestFileAssetStoreRejectsFinalSymlink(t *testing.T) {
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
	filesPath := filepath.Join(packagePath, fileAssetFilesDir, "ui")
	indexPath := filepath.Join(filesPath, "index.html")
	realPath := filepath.Join(filesPath, "real.html")
	content := pkg.Files["ui/index.html"]
	if err := os.WriteFile(realPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(indexPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.html", indexPath); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html"); err == nil {
		t.Fatal("ReadAsset() followed a final symlink")
	} else if !errors.Is(err, ErrInvalidAssetPath) {
		t.Fatalf("ReadAsset() error = %v, want ErrInvalidAssetPath", err)
	}
}

func TestFileAssetStoreRejectsAssetSizeMismatch(t *testing.T) {
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
	indexPath := filepath.Join(packagePath, fileAssetFilesDir, "ui", "index.html")
	if err := os.WriteFile(indexPath, append(pkg.Files["ui/index.html"], 'x'), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html"); err == nil {
		t.Fatal("ReadAsset() accepted content whose size differs from immutable metadata")
	} else if !errors.Is(err, ErrPackageAssetNotFound) {
		t.Fatalf("ReadAsset() error = %v, want ErrPackageAssetNotFound", err)
	}
}

func TestFileAssetStoreSharesRootStateAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileAssetStore(filepath.Join(root, "."))
	if err != nil {
		t.Fatal(err)
	}
	if first.state != second.state {
		t.Fatal("stores for the same canonical root do not share synchronization and manifest state")
	}
}

func TestFileAssetStoreRejectsReplacedPackagesDirectoryWhileRootIsLive(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	packagesPath := filepath.Join(root, fileAssetPackagesDir)
	if err := os.Rename(packagesPath, filepath.Join(root, "packages-old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(packagesPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileAssetStore(root); err == nil {
		t.Fatal("NewFileAssetStore() accepted a replaced packages directory while the original root was live")
	} else if !errors.Is(err, ErrInvalidAssetPath) {
		t.Fatalf("NewFileAssetStore() error = %v, want ErrInvalidAssetPath", err)
	}
}

func TestFileAssetStoreCloseReleasesSharedRootState(t *testing.T) {
	root := t.TempDir()
	first, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.PutPackage(context.Background(), testAssetPackage(t)); err != nil {
		t.Fatalf("remaining store failed after peer close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.ReadPackageMetadata(context.Background(), "sha256:closed"); !errors.Is(err, ErrAssetStoreClosed) {
		t.Fatalf("closed store error = %v, want ErrAssetStoreClosed", err)
	}

	packagesPath := filepath.Join(root, fileAssetPackagesDir)
	if err := os.Rename(packagesPath, filepath.Join(root, "packages-before-reopen")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(packagesPath, 0o700); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatalf("NewFileAssetStore() after final close error = %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileAssetStoreUsesImmutableCachedManifestIndex(t *testing.T) {
	root := t.TempDir()
	first, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg := testAssetPackage(t)
	if err := first.PutPackage(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}

	packagePath, err := first.packagePath(pkg.PackageHash)
	if err != nil {
		t.Fatal(err)
	}
	tampered := fileAssetManifest{PackageHash: pkg.PackageHash, Entries: append([]Entry(nil), pkg.Entries...)}
	tampered.Entries[0].ContentType = "application/x-tampered"
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packagePath, fileAssetManifestFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := second.ReadPackageMetadata(context.Background(), pkg.PackageHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.ContentType == "application/x-tampered" {
			t.Fatal("ReadPackageMetadata() reloaded mutable manifest content from disk")
		}
	}
}

func TestFileAssetStoreRejectsOversizedManifest(t *testing.T) {
	root := t.TempDir()
	packageHash := "sha256:" + strings.Repeat("a", 64)
	dirName, err := fileAssetPackageDirName(packageHash)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(root, fileAssetPackagesDir, dirName)
	if err := os.MkdirAll(packagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(packagePath, fileAssetManifestFile),
		bytes.Repeat([]byte{' '}, (8<<20)+1),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadPackageMetadata(context.Background(), packageHash); err == nil {
		t.Fatal("ReadPackageMetadata() accepted an oversized manifest")
	} else if !errors.Is(err, ErrInvalidAssetPath) {
		t.Fatalf("ReadPackageMetadata() error = %v, want ErrInvalidAssetPath", err)
	}
}

func testAssetPackage(t *testing.T) Package {
	t.Helper()
	files := map[string][]byte{
		"manifest.json":    []byte(validManifestJSON()),
		"ui/index.html":    []byte("<!doctype html><title>Plugin</title><script type=\"text/redevplugin-worker\" src=\"assets/app.js\"></script>"),
		"ui/assets/app.js": []byte("void 0;"),
	}
	pkg, err := packageFromFiles(context.Background(), files, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}
