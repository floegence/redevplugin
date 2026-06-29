package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndReadPackage(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var buf bytes.Buffer
	built, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err != nil {
		t.Fatalf("BuildFromDir() error = %v", err)
	}

	read, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions())
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if read.PackageHash != built.PackageHash {
		t.Fatalf("PackageHash mismatch: got %s want %s", read.PackageHash, built.PackageHash)
	}
	if read.Manifest.PluginID() != "com.example.pkg" {
		t.Fatalf("PluginID() = %q", read.Manifest.PluginID())
	}
}

func TestBuildPackageIsDeterministic(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var first bytes.Buffer
	var second bytes.Buffer
	firstPkg, err := BuildFromDir(context.Background(), dir, &first, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	secondPkg, err := BuildFromDir(context.Background(), dir, &second, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if firstPkg.PackageHash != secondPkg.PackageHash {
		t.Fatalf("package hash changed: %s != %s", firstPkg.PackageHash, secondPkg.PackageHash)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("zip bytes are not deterministic")
	}
}

func TestSignaturesAreExcludedFromCanonicalHash(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var before bytes.Buffer
	beforePkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "signatures"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signatures", "package.sig"), []byte("signature"), 0o644); err != nil {
		t.Fatal(err)
	}
	var after bytes.Buffer
	afterPkg, err := BuildFromDir(context.Background(), dir, &after, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if beforePkg.PackageHash != afterPkg.PackageHash {
		t.Fatalf("signature changed canonical package hash: %s != %s", beforePkg.PackageHash, afterPkg.PackageHash)
	}
}

func TestReadRejectsUnsafePath(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writer, err := zw.Create("../manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions()); err == nil {
		t.Fatal("Read() expected unsafe path error")
	}
}

func TestReadRejectsDuplicateEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 2; i++ {
		writer, err := zw.Create("manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(validManifestJSON())); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions()); err == nil {
		t.Fatal("Read() expected duplicate entry error")
	}
}

func TestBuildRejectsMissingWorkerArtifact(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected missing worker artifact error")
	}
}

func TestReadRejectsMissingWorkerArtifact(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entryPath, content := range map[string]string{
		"manifest.json": workerManifestJSON(),
		"ui/index.html": "<!doctype html><title>Plugin</title>",
	} {
		writer, err := zw.Create(entryPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions()); err == nil {
		t.Fatal("Read() expected missing worker artifact error")
	}
}

func TestMemoryAssetStoreReadsPackageAssets(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var buf bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryAssetStore()
	if err := store.PutPackage(context.Background(), pkg); err != nil {
		t.Fatalf("PutPackage() error = %v", err)
	}
	asset, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
	if err != nil {
		t.Fatalf("ReadAsset() error = %v", err)
	}
	if string(asset.Content) != "<!doctype html><title>Plugin</title>" || asset.Entry.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("asset mismatch: %#v content=%q", asset.Entry, string(asset.Content))
	}
	asset.Content[0] = 'x'
	again, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Content) != "<!doctype html><title>Plugin</title>" {
		t.Fatalf("asset content was not cloned: %q", string(again.Content))
	}
}

func TestMemoryAssetStoreRejectsUnsafeAssetPath(t *testing.T) {
	store := NewMemoryAssetStore()
	if _, err := store.ReadAsset(context.Background(), "sha256:test", "../manifest.json"); err == nil {
		t.Fatal("ReadAsset() expected unsafe path error")
	}
}

func writeFixturePackageDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "manifest.json"), validManifestJSON())
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Plugin</title>")
	mustWrite(t, filepath.Join(dir, "ui", "assets", "app.js"), "console.log('plugin');")
	return dir
}

func mustWrite(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func validManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.pkg",
			"display_name": "Package",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "pkg.activity", "kind": "activity", "label": "Package", "entry": "ui/index.html"}
		]
	}`
}

func workerManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redeven-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redeven_worker_invoke"}
			}
		]
	}`
}
