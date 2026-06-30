package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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

func TestWritePackageRoundTripsUnsignedPackage(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var builtBytes bytes.Buffer
	built, err := BuildFromDir(context.Background(), dir, &builtBytes, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}

	var first bytes.Buffer
	var second bytes.Buffer
	if err := WritePackage(context.Background(), &first, built); err != nil {
		t.Fatalf("WritePackage() error = %v", err)
	}
	if err := WritePackage(context.Background(), &second, built); err != nil {
		t.Fatalf("WritePackage() second error = %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("WritePackage() bytes are not deterministic")
	}
	read, err := Read(context.Background(), bytes.NewReader(first.Bytes()), int64(first.Len()), DefaultReadOptions())
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if read.PackageHash != built.PackageHash || read.PackageSignature != nil {
		t.Fatalf("unsigned package round trip mismatch: hash=%s signature=%#v", read.PackageHash, read.PackageSignature)
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
	if err := os.WriteFile(filepath.Join(dir, "signatures", "package.sig"), packageSignatureJSON(t, beforePkg, "test-signature"), 0o644); err != nil {
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
	if afterPkg.PackageSignature == nil || afterPkg.PackageSignature.KeyID != "test-key" {
		t.Fatalf("package signature was not parsed: %#v", afterPkg.PackageSignature)
	}

	read, err := Read(context.Background(), bytes.NewReader(after.Bytes()), int64(after.Len()), DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	if read.PackageSignature == nil || read.PackageSignature.PackageHash != beforePkg.PackageHash {
		t.Fatalf("read package signature mismatch: %#v", read.PackageSignature)
	}
	if _, ok := read.SignatureFiles[PackageSignaturePath]; !ok {
		t.Fatalf("signature file was not retained: %#v", read.SignatureFiles)
	}
	if _, ok := read.Files[PackageSignaturePath]; ok {
		t.Fatal("signature file leaked into canonical file set")
	}
}

func TestWritePackageMaterializesDetachedSignature(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var before bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	sig := PackageSignature{
		SchemaVersion: "redevplugin.package_signature.v1",
		Algorithm:     PackageSignatureAlgorithmEd25519,
		KeyID:         "test-key",
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "test-signature",
		SignedAt:      "2026-06-30T00:00:00Z",
	}
	pkg.PackageSignature = &sig

	var signedBytes bytes.Buffer
	if err := WritePackage(context.Background(), &signedBytes, pkg); err != nil {
		t.Fatalf("WritePackage() error = %v", err)
	}
	read, err := Read(context.Background(), bytes.NewReader(signedBytes.Bytes()), int64(signedBytes.Len()), DefaultReadOptions())
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if read.PackageHash != pkg.PackageHash {
		t.Fatalf("signature changed package hash: %s != %s", read.PackageHash, pkg.PackageHash)
	}
	if read.PackageSignature == nil || read.PackageSignature.KeyID != "test-key" {
		t.Fatalf("signature not materialized: %#v", read.PackageSignature)
	}
	if _, ok := read.SignatureFiles[PackageSignaturePath]; !ok {
		t.Fatal("signature file missing from detached signature set")
	}
	if _, ok := read.Files[PackageSignaturePath]; ok {
		t.Fatal("signature file leaked into canonical files")
	}
}

func TestReadRejectsSignatureHashMismatch(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entryPath, content := range map[string][]byte{
		"manifest.json": []byte(validManifestJSON()),
		"ui/index.html": []byte("<!doctype html><title>Plugin</title>"),
		PackageSignaturePath: []byte(`{
			"schema_version": "redevplugin.package_signature.v1",
			"algorithm": "ed25519",
			"key_id": "test-key",
			"package_hash": "sha256:wrong",
			"manifest_hash": "sha256:wrong",
			"entries_hash": "sha256:wrong",
			"signature": "test-signature"
		}`),
	} {
		writer, err := zw.Create(entryPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions()); err == nil {
		t.Fatal("Read() expected signature hash mismatch error")
	}
}

func TestBuildRejectsSignatureIdentityMismatch(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var before bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	sig := PackageSignature{
		SchemaVersion: "redevplugin.package_signature.v1",
		Algorithm:     "ed25519",
		KeyID:         "test-key",
		PublisherID:   "other-publisher",
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "test-signature",
	}
	raw, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "signatures"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PackageSignaturePath), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	var after bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &after, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected signature identity mismatch error")
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

func TestBuildRejectsMalformedWorkerWASM(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWrite(t, filepath.Join(dir, "workers", "echo.wasm"), "wasm-placeholder")
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redeven_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected malformed worker wasm error")
	}
}

func TestReadRejectsWorkerRouteMissingExport(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entries := map[string][]byte{
		"manifest.json":       []byte(workerManifestJSON()),
		"ui/index.html":       []byte("<!doctype html><title>Plugin</title>"),
		"workers/echo.wasm":   minimalWorkerWASMForTest("other_export"),
		"ui/assets/app.js":    []byte("console.log('plugin');"),
		"workers/abi.json":    []byte(workerABIJSON("redeven_worker_invoke")),
		"workers/echo.wat":    []byte("(module)"),
		"ui/assets/style.css": []byte("body{}"),
	}
	for entryPath, content := range entries {
		writer, err := zw.Create(entryPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadOptions()); err == nil {
		t.Fatal("Read() expected missing worker export error")
	}
}

func TestBuildRejectsWorkerRouteExportedAsMemory(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalMemoryExportWASMForTest("redeven_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redeven_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected non-function worker export error")
	}
}

func TestBuildAcceptsWorkerWASMExport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redeven_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redeven_worker_invoke"))

	var buf bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err != nil {
		t.Fatalf("BuildFromDir() worker error = %v", err)
	}
	if pkg.Manifest.Workers[0].Artifact != "workers/echo.wasm" {
		t.Fatalf("worker artifact mismatch: %#v", pkg.Manifest.Workers[0])
	}
}

func TestBuildRejectsWorkerWithoutABIDescriptor(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redeven_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected missing worker ABI descriptor error")
	}
}

func TestBuildRejectsWorkerRouteMissingABIDescriptorExport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redeven_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redeven_actor_start"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected missing worker ABI export error")
	}
}

func TestBuildRejectsUnknownWorkerABIImport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redeven_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), "{\n"+
		"  \"abi_version\": \"redeven-wasm-worker-v1\",\n"+
		"  \"exports\": [\"redeven_worker_invoke\"],\n"+
		"  \"imports\": [\"redeven.shell\"]\n"+
		"}\n")

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected unsupported worker ABI import error")
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
	mustWriteBytes(t, filename, []byte(content))
}

func mustWriteBytes(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func minimalWorkerWASMForTest(exportName string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07,
	}
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x00)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b)
	return module
}

func minimalMemoryExportWASMForTest(exportName string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07,
	}
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x02, 0x00)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	return module
}

func workerABIJSON(exports ...string) string {
	rawExports, err := json.Marshal(exports)
	if err != nil {
		panic(err)
	}
	return "{\n" +
		"  \"abi_version\": \"redeven-wasm-worker-v1\",\n" +
		"  \"exports\": " + string(rawExports) + ",\n" +
		"  \"imports\": [\"redeven.log\", \"redeven.storage\", \"redeven.network\", \"redeven.operation\", \"redeven.clock\"]\n" +
		"}\n"
}

func packageSignatureJSON(t *testing.T, pkg Package, signature string) []byte {
	t.Helper()
	raw, err := json.Marshal(PackageSignature{
		SchemaVersion: "redevplugin.package_signature.v1",
		Algorithm:     "ed25519",
		KeyID:         "test-key",
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     signature,
		SignedAt:      "2026-06-30T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
