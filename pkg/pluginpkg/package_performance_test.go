package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"math/rand"
	"testing"
)

func BenchmarkReadLargePackage(b *testing.B) {
	payload := make([]byte, 8<<20)
	if _, err := rand.New(rand.NewSource(1)).Read(payload); err != nil {
		b.Fatal(err)
	}
	copy(payload[:16], []byte("plugin asset data"))
	archive := buildBenchmarkPackage(b, map[string][]byte{
		"manifest.json":         []byte(validManifestJSON()),
		"ui/index.html":         []byte(fixtureSurfaceHTML),
		"ui/assets/app.js":      []byte("void 0;"),
		"ui/assets/payload.bin": payload,
	})
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkg, err := Read(context.Background(), bytes.NewReader(archive), int64(len(archive)), DefaultReadLimits())
		if err != nil {
			b.Fatal(err)
		}
		if len(pkg.Files["ui/assets/payload.bin"]) != len(payload) {
			b.Fatal("large package payload size mismatch")
		}
	}
}

func BenchmarkReadAndStoreOwnedLargePackage(b *testing.B) {
	payload := make([]byte, 8<<20)
	if _, err := rand.New(rand.NewSource(1)).Read(payload); err != nil {
		b.Fatal(err)
	}
	copy(payload[:16], []byte("plugin asset data"))
	archive := buildBenchmarkPackage(b, map[string][]byte{
		"manifest.json":         []byte(validManifestJSON()),
		"ui/index.html":         []byte(fixtureSurfaceHTML),
		"ui/assets/app.js":      []byte("void 0;"),
		"ui/assets/payload.bin": payload,
	})
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		pkg, err := Read(context.Background(), bytes.NewReader(archive), int64(len(archive)), DefaultReadLimits())
		if err != nil {
			b.Fatal(err)
		}
		store := NewMemoryAssetStore()
		if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
			b.Fatal(err)
		}
		if pkg.Files != nil || len(store.packages[pkg.PackageHash].files["ui/assets/payload.bin"]) != len(payload) {
			b.Fatal("owned package transfer failed")
		}
	}
}

func BenchmarkWriteBorrowedLargePackage(b *testing.B) {
	payload := make([]byte, 8<<20)
	if _, err := rand.New(rand.NewSource(1)).Read(payload); err != nil {
		b.Fatal(err)
	}
	copy(payload[:16], []byte("plugin asset data"))
	archive := buildBenchmarkPackage(b, map[string][]byte{
		"manifest.json":         []byte(validManifestJSON()),
		"ui/index.html":         []byte(fixtureSurfaceHTML),
		"ui/assets/app.js":      []byte("void 0;"),
		"ui/assets/payload.bin": payload,
	})
	pkg, err := Read(context.Background(), bytes.NewReader(archive), int64(len(archive)), DefaultReadLimits())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := WritePackage(context.Background(), io.Discard, pkg); err != nil {
			b.Fatal(err)
		}
	}
}

func buildBenchmarkPackage(b *testing.B, files map[string][]byte) []byte {
	b.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entryPath := range sortedFilePaths(files) {
		header := &zip.FileHeader{Name: entryPath, Method: zip.Store, Modified: deterministicModTime}
		header.SetMode(0o644)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := entry.Write(files[entryPath]); err != nil {
			b.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		b.Fatal(err)
	}
	return output.Bytes()
}
