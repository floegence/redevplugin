package pluginpkg

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"testing"
)

func TestStreamPackageToFileAssetStore(t *testing.T) {
	ctx := context.Background()
	archive, err := os.CreateTemp(t.TempDir(), "package-*")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	writer := zip.NewWriter(archive)
	for entry, data := range map[string]string{"manifest.json": validManifestJSON(), "ui/index.html": fixtureSurfaceHTML, "ui/assets/app.js": fixtureWorkerJS} {
		part, err := writer.Create(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, data); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateHeader(&zip.FileHeader{Name: "ui/assets/model.dat", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1<<20)
	for range 33 {
		if _, err := part.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(ctx, archive, info.Size(), DefaultReadLimits()); err == nil {
		t.Fatal("heap reader accepted an oversized entry")
	}
	pkg, err := ReadStreamed(ctx, archive, info.Size(), 1<<30, func(context.Context) (*os.File, error) { return os.Open(archive.Name()) })
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Files["ui/assets/model.dat"]) != 0 {
		t.Fatal("bulk asset materialized")
	}
	store, err := NewFileAssetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutOwnedPackage(ctx, &pkg); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAsset(ctx, pkg.PackageHash, "ui/assets/model.dat"); err != nil {
		t.Fatal(err)
	}
}
