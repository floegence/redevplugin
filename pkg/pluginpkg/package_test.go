package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestBuildAcceptsPackageLocalSurfaceAssets(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), `<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="assets/styles.css">
    <script src="assets/app.js" defer></script>
  </head>
  <body>
    <img src="assets/icon.png" srcset="assets/icon-small.png 1x, assets/icon-large.png 2x" alt="">
    <img src="data:image/png;base64,iVBORw0KGgo=" alt="">
    <a href="#details">Details</a>
  </body>
</html>`)
	mustWrite(t, filepath.Join(dir, "ui", "assets", "styles.css"), "body{}")
	mustWrite(t, filepath.Join(dir, "ui", "assets", "icon.png"), "png")
	mustWrite(t, filepath.Join(dir, "ui", "assets", "icon-small.png"), "small")
	mustWrite(t, filepath.Join(dir, "ui", "assets", "icon-large.png"), "large")

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err != nil {
		t.Fatalf("BuildFromDir() local surface assets error = %v", err)
	}
}

func TestBuildRejectsUnsafeSurfaceHTMLAssets(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		wantErr string
	}{
		{
			name:    "external script",
			html:    `<!doctype html><script src="https://cdn.example/plugin.js"></script>`,
			wantErr: "must reference a package-local relative asset",
		},
		{
			name:    "root absolute stylesheet",
			html:    `<!doctype html><link rel="stylesheet" href="/assets/styles.css">`,
			wantErr: "must reference a package-local relative asset",
		},
		{
			name:    "missing local script",
			html:    `<!doctype html><script src="assets/missing.js"></script>`,
			wantErr: `missing package asset "ui/assets/missing.js"`,
		},
		{
			name:    "inline script",
			html:    `<!doctype html><script>console.log("inline")</script>`,
			wantErr: "inline script is not allowed",
		},
		{
			name:    "inline event handler",
			html:    `<!doctype html><button onclick="run()">Run</button>`,
			wantErr: "inline event handler",
		},
		{
			name:    "inline style block",
			html:    `<!doctype html><style>body{color:red}</style>`,
			wantErr: "inline style block is not allowed",
		},
		{
			name:    "inline style attribute",
			html:    `<!doctype html><main style="display:block"></main>`,
			wantErr: "inline style attribute is not allowed",
		},
		{
			name:    "base element",
			html:    `<!doctype html><base href="assets/">`,
			wantErr: "base element is not allowed",
		},
		{
			name:    "iframe srcdoc",
			html:    `<!doctype html><iframe srcdoc="<script></script>"></iframe>`,
			wantErr: "iframe srcdoc is not allowed",
		},
		{
			name:    "meta refresh",
			html:    `<!doctype html><meta http-equiv="refresh" content="0; url=https://example.com">`,
			wantErr: "meta refresh is not allowed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWrite(t, filepath.Join(dir, "ui", "index.html"), tc.html)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildRejectsSurfaceEntryWithoutPackagedHTML(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		wantErr  string
	}{
		{
			name:     "missing entry",
			manifest: strings.ReplaceAll(validManifestJSON(), `"entry": "ui/index.html"`, `"entry": "ui/missing.html"`),
			wantErr:  `entry "ui/missing.html" is not present in package`,
		},
		{
			name:     "non html entry",
			manifest: strings.ReplaceAll(validManifestJSON(), `"entry": "ui/index.html"`, `"entry": "ui/assets/app.js"`),
			wantErr:  `entry "ui/assets/app.js" must be an HTML asset`,
		},
		{
			name:     "query entry",
			manifest: strings.ReplaceAll(validManifestJSON(), `"entry": "ui/index.html"`, `"entry": "ui/index.html?v=1"`),
			wantErr:  "must not include query or fragment",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWrite(t, filepath.Join(dir, "manifest.json"), tc.manifest)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildRejectsServiceWorkerRegistrationDependency(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), `<!doctype html><script src="assets/app.js" defer></script>`)
	mustWrite(t, filepath.Join(dir, "ui", "assets", "app.js"), `navigator.serviceWorker.register("sw.js");`)

	var buf bytes.Buffer
	_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err == nil || !strings.Contains(err.Error(), "Service Worker registration APIs are not allowed") {
		t.Fatalf("BuildFromDir() error = %v, want Service Worker rejection", err)
	}
}

func TestBuildRejectsForbiddenExecutablePackageArtifacts(t *testing.T) {
	tests := []struct {
		name      string
		entryPath string
		content   []byte
		wantErr   string
	}{
		{
			name:      "shell extension",
			entryPath: "scripts/install.sh",
			content:   []byte("echo install\n"),
			wantErr:   "shell script artifacts are not allowed",
		},
		{
			name:      "shebang script",
			entryPath: "ui/assets/tool.js",
			content:   []byte("#!/usr/bin/env node\nconsole.log('tool');\n"),
			wantErr:   "executable shebang scripts are not allowed",
		},
		{
			name:      "node native addon",
			entryPath: "ui/assets/addon.node",
			content:   []byte("addon"),
			wantErr:   "native executable or dynamic library artifacts are not allowed",
		},
		{
			name:      "versioned shared library",
			entryPath: "lib/libplugin.so.1",
			content:   []byte("shared-library"),
			wantErr:   "native executable or dynamic library artifacts are not allowed",
		},
		{
			name:      "elf magic",
			entryPath: "assets/plugin.dat",
			content:   []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01},
			wantErr:   "native executable or dynamic library artifacts are not allowed",
		},
		{
			name:      "mach-o magic",
			entryPath: "assets/plugin.payload",
			content:   []byte{0xcf, 0xfa, 0xed, 0xfe, 0x00},
			wantErr:   "native executable or dynamic library artifacts are not allowed",
		},
		{
			name:      "windows executable magic",
			entryPath: "assets/plugin.payload",
			content:   []byte{'M', 'Z', 0x90, 0x00},
			wantErr:   "native executable or dynamic library artifacts are not allowed",
		},
		{
			name:      "postinstall package json",
			entryPath: "package.json",
			content:   []byte(`{"scripts":{"postinstall":"node install.js"}}`),
			wantErr:   `package manager lifecycle script "postinstall" is not allowed`,
		},
		{
			name:      "prepare package json",
			entryPath: "package.json",
			content:   []byte(`{"scripts":{"prepare":"node build.js"}}`),
			wantErr:   `package manager lifecycle script "prepare" is not allowed`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWriteBytes(t, filepath.Join(dir, filepath.FromSlash(tc.entryPath)), tc.content)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildAllowsNonExecutableBinaryDataAsset(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWriteBytes(t, filepath.Join(dir, "ui", "assets", "model.bin"), []byte{0x00, 0x01, 0x02, 0x03})

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err != nil {
		t.Fatalf("BuildFromDir() binary data asset error = %v", err)
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
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_worker_invoke"))

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
		"workers/abi.json":    []byte(workerABIJSON("redevplugin_worker_invoke")),
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
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalMemoryExportWASMForTest("redevplugin_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected non-function worker export error")
	}
}

func TestBuildAcceptsWorkerWASMExport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_worker_invoke"))

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
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected missing worker ABI descriptor error")
	}
}

func TestBuildRejectsWorkerRouteMissingABIDescriptorExport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_actor_start"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected missing worker ABI export error")
	}
}

func TestBuildRejectsUnknownWorkerABIImport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), "{\n"+
		"  \"abi_version\": \"redevplugin-wasm-worker-v1\",\n"+
		"  \"exports\": [\"redevplugin_worker_invoke\"],\n"+
		"  \"imports\": [\"redeven.shell\"]\n"+
		"}\n")

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected unsupported worker ABI import error")
	}
}

func TestBuildRejectsActorWorkerMissingWASMExports(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), actorWorkerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_worker_invoke", "redevplugin_actor_start", "redevplugin_actor_stop"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions()); err == nil {
		t.Fatal("BuildFromDir() expected actor worker wasm export error")
	}
}

func TestBuildAcceptsActorWorkerLifecycleExports(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), actorWorkerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMWithExportsForTest("redevplugin_worker_invoke", "redevplugin_actor_start", "redevplugin_actor_stop"))
	mustWrite(t, filepath.Join(dir, "workers", "abi.json"), workerABIJSON("redevplugin_worker_invoke", "redevplugin_actor_start", "redevplugin_actor_stop"))

	var buf bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err != nil {
		t.Fatalf("BuildFromDir() actor worker error = %v", err)
	}
	if pkg.Manifest.Workers[0].Mode != "actor" {
		t.Fatalf("worker mode = %s, want actor", pkg.Manifest.Workers[0].Mode)
	}
}

func TestAssetStoreReadsPackageAssets(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			var buf bytes.Buffer
			pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
			if err != nil {
				t.Fatal(err)
			}
			store := tc.open(t)
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
		})
	}
}

func TestAssetStoreRejectsUnsafeAssetPath(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.ReadAsset(context.Background(), "sha256:test", "../manifest.json"); err == nil {
				t.Fatal("ReadAsset() expected unsafe path error")
			}
			if _, err := store.ReadAsset(context.Background(), "sha256:test", PackageSignaturePath); err == nil {
				t.Fatal("ReadAsset() expected signature path error")
			}
		})
	}
}

func TestAssetStoreDeletePackage(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			var buf bytes.Buffer
			pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
			if err != nil {
				t.Fatal(err)
			}
			store := tc.open(t)
			if err := store.PutPackage(context.Background(), pkg); err != nil {
				t.Fatalf("PutPackage() error = %v", err)
			}
			if err := store.DeletePackage(context.Background(), pkg.PackageHash); err != nil {
				t.Fatalf("DeletePackage() error = %v", err)
			}
			if _, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html"); err == nil {
				t.Fatal("ReadAsset() after DeletePackage expected error")
			}
		})
	}
}

func TestFileAssetStorePersistsAssetsAcrossOpen(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var buf bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutPackage(context.Background(), pkg); err != nil {
		t.Fatalf("PutPackage() error = %v", err)
	}

	reopened, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := reopened.ReadAsset(context.Background(), pkg.PackageHash, "ui/assets/app.js")
	if err != nil {
		t.Fatalf("ReadAsset() after reopen error = %v", err)
	}
	if string(asset.Content) != "console.log('plugin');" {
		t.Fatalf("persisted asset content = %q", string(asset.Content))
	}
}

type assetStoreCase struct {
	name string
	open func(t *testing.T) AssetStore
}

func assetStoreCases() []assetStoreCase {
	return []assetStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) AssetStore {
				t.Helper()
				return NewMemoryAssetStore()
			},
		},
		{
			name: "file",
			open: func(t *testing.T) AssetStore {
				t.Helper()
				store, err := NewFileAssetStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				return store
			},
		},
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
	return minimalWorkerWASMWithExportsForTest(exportName)
}

func minimalWorkerWASMWithExportsForTest(exportNames ...string) []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07,
	}
	exportPayload := []byte{byte(len(exportNames))}
	for _, exportName := range exportNames {
		exportNameBytes := []byte(exportName)
		exportPayload = append(exportPayload, byte(len(exportNameBytes)))
		exportPayload = append(exportPayload, exportNameBytes...)
		exportPayload = append(exportPayload, 0x00, 0x00)
	}
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
		"  \"abi_version\": \"redevplugin-wasm-worker-v1\",\n" +
		"  \"exports\": " + string(rawExports) + ",\n" +
		"  \"imports\": [\"redevplugin.log\", \"redevplugin.storage\", \"redevplugin.network\", \"redevplugin.operation\", \"redevplugin.clock\"]\n" +
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
		"schema_version": "redevplugin.manifest.v1",
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
		"schema_version": "redevplugin.manifest.v1",
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
				"abi": "redevplugin-wasm-worker-v1",
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
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		]
		}`
}

func actorWorkerManifestJSON() string {
	return `{
			"schema_version": "redevplugin.manifest.v1",
			"publisher": {"publisher_id": "example", "display_name": "Example"},
			"plugin": {
				"plugin_id": "com.example.actor",
				"display_name": "Actor",
				"version": "1.0.0",
				"api_version": "plugin-v1",
				"min_runtime_version": "0.1.0",
				"ui_protocol_version": "plugin-ui-v1"
			},
			"surfaces": [
				{"surface_id": "actor.activity", "kind": "activity", "label": "Actor", "entry": "ui/index.html", "method": "worker.echo"}
			],
			"workers": [
				{
					"worker_id": "echo_worker",
					"artifact": "workers/echo.wasm",
					"abi": "redevplugin-wasm-worker-v1",
					"mode": "actor",
					"scope": "user",
					"memory_limit_bytes": 16777216
				}
			],
			"methods": [
				{
					"method": "worker.echo",
					"effect": "read",
					"execution": "sync",
					"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
				}
			]
		}`
}
