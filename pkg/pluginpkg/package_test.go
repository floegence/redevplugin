package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestBuildAndReadPackage(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var buf bytes.Buffer
	built, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	if err != nil {
		t.Fatalf("BuildFromDir() error = %v", err)
	}

	read, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits())
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

func TestPackageFromOwnedFilesTakesOwnership(t *testing.T) {
	files, signatureFiles, err := collectFiles(writeFixturePackageDir(t), DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := files["manifest.json"]
	pkg, err := packageFromOwnedFiles(context.Background(), files, signatureFiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifestBytes) == 0 || len(pkg.Files["manifest.json"]) == 0 {
		t.Fatal("manifest bytes are empty")
	}
	if &pkg.Files["manifest.json"][0] != &manifestBytes[0] {
		t.Fatal("packageFromOwnedFiles cloned owned file bytes")
	}
}

func TestBuildGeneratedPluginFixtures(t *testing.T) {
	for _, name := range []string{"minimal", "networked", "storage", "method-contract"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "generated_plugins", name)
			var buf bytes.Buffer
			built, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err != nil {
				t.Fatalf("BuildFromDir(%s) error = %v", name, err)
			}
			read, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits())
			if err != nil {
				t.Fatalf("Read(%s) error = %v", name, err)
			}
			if read.PackageHash != built.PackageHash {
				t.Fatalf("PackageHash(%s) mismatch: got %s want %s", name, read.PackageHash, built.PackageHash)
			}
			if read.Manifest.PluginID() == "" {
				t.Fatalf("generated fixture %s has empty plugin_id", name)
			}
		})
	}
}

func TestBuildPackageIsDeterministic(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var first bytes.Buffer
	var second bytes.Buffer
	firstPkg, err := BuildFromDir(context.Background(), dir, &first, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	secondPkg, err := BuildFromDir(context.Background(), dir, &second, DefaultReadLimits())
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
	built, err := BuildFromDir(context.Background(), dir, &builtBytes, DefaultReadLimits())
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
	read, err := Read(context.Background(), bytes.NewReader(first.Bytes()), int64(first.Len()), DefaultReadLimits())
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if read.PackageHash != built.PackageHash || read.PackageSignature != nil {
		t.Fatalf("unsigned package round trip mismatch: hash=%s signature=%#v", read.PackageHash, read.PackageSignature)
	}
}

func TestWritePackageBorrowsPackageFilesWithoutMutation(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var builtBytes bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &builtBytes, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := pkg.Files["manifest.json"]
	manifestBefore := append([]byte(nil), manifestBytes...)
	filesBefore := pkg.Files
	signaturesBefore := pkg.SignatureFiles

	var output bytes.Buffer
	if err := WritePackage(context.Background(), &output, pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Files == nil || pkg.SignatureFiles == nil || len(pkg.Files) != len(filesBefore) || len(pkg.SignatureFiles) != len(signaturesBefore) {
		t.Fatal("WritePackage() changed caller-owned maps")
	}
	if len(manifestBytes) == 0 || &pkg.Files["manifest.json"][0] != &manifestBytes[0] || !bytes.Equal(pkg.Files["manifest.json"], manifestBefore) {
		t.Fatal("WritePackage() replaced or mutated caller-owned file bytes")
	}
}

func TestSignaturesAreExcludedFromCanonicalHash(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var before bytes.Buffer
	beforePkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadLimits())
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
	afterPkg, err := BuildFromDir(context.Background(), dir, &after, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	if beforePkg.PackageHash != afterPkg.PackageHash {
		t.Fatalf("signature changed canonical package hash: %s != %s", beforePkg.PackageHash, afterPkg.PackageHash)
	}
	if afterPkg.PackageSignature == nil || afterPkg.PackageSignature.KeyID != "test-key" {
		t.Fatalf("package signature was not parsed: %#v", afterPkg.PackageSignature)
	}

	read, err := Read(context.Background(), bytes.NewReader(after.Bytes()), int64(after.Len()), DefaultReadLimits())
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
	pkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadLimits())
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
	read, err := Read(context.Background(), bytes.NewReader(signedBytes.Bytes()), int64(signedBytes.Len()), DefaultReadLimits())
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

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits()); err == nil {
		t.Fatal("Read() expected signature hash mismatch error")
	}
}

func TestParsePackageSignatureRejectsTrailingJSONDocument(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var built bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &built, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(PackageSignature{
		SchemaVersion: PackageSignatureSchemaVersion,
		Algorithm:     PackageSignatureAlgorithmEd25519,
		KeyID:         "test-key",
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "test-signature",
		SignedAt:      "2026-07-20T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte(` true`)...)
	if _, err := parsePackageSignature(map[string][]byte{PackageSignaturePath: raw}, pkg.Manifest, pkg.ManifestHash, pkg.EntriesHash, pkg.PackageHash); err == nil {
		t.Fatal("parsePackageSignature() accepted a trailing JSON document")
	}
}

func TestBuildRejectsSignatureIdentityMismatch(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var before bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &before, DefaultReadLimits())
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
	if _, err := BuildFromDir(context.Background(), dir, &after, DefaultReadLimits()); err == nil {
		t.Fatal("BuildFromDir() expected signature identity mismatch error")
	}
}

func TestBuildRejectsUnsupportedSignatureEntry(t *testing.T) {
	dir := writeFixturePackageDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "signatures"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signatures", "extra.sig"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	requireValidationError(t, err, ValidationCodePackagePathForbidden, "unsupported_signature_entry", "signatures/extra.sig", "")
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

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits()); err == nil {
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

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits()); err == nil {
		t.Fatal("Read() expected duplicate entry error")
	}
}

func TestReadRejectsAmbiguousArchivePaths(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string][]byte
		reason  string
		path    string
	}{
		{
			name: "case folded collision",
			entries: map[string][]byte{
				"ui/App.js": []byte("first"),
				"ui/app.js": []byte("second"),
			},
			reason: "ambiguous_entry",
			path:   "ui/app.js",
		},
		{
			name: "non NFC path",
			entries: map[string][]byte{
				"ui/cafe\u0301.js": []byte("content"),
			},
			reason: "non_nfc_path",
			path:   "ui/cafe\u0301.js",
		},
		{
			name: "invalid UTF-8 path",
			entries: map[string][]byte{
				"ui/" + string([]byte{0xff}) + ".js": []byte("content"),
			},
			reason: "invalid_utf8_path",
			path:   "ui/" + string([]byte{0xff}) + ".js",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := packageZipBytes(t, tc.entries)
			_, err := Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), DefaultReadLimits())
			requireValidationError(t, err, ValidationCodePackagePathForbidden, tc.reason, tc.path, "")
		})
	}
}

func TestReadRejectsNonRegularArchiveEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	header := &zip.FileHeader{Name: "ui/runtime.pipe", Method: zip.Store}
	header.SetMode(fs.ModeNamedPipe | 0o600)
	if _, err := zw.CreateHeader(header); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits())
	requireValidationError(t, err, ValidationCodePackagePathForbidden, "non_regular_entry", "ui/runtime.pipe", "")
}

func TestReadClassifiesPackageValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string][]byte
		opts    ReadLimits
		want    ValidationErrorCode
		reason  string
		path    string
		pointer string
	}{
		{
			name: "path traversal",
			entries: map[string][]byte{
				"../manifest.json": []byte("{}"),
			},
			want:   ValidationCodePackagePathForbidden,
			reason: "path_traversal",
			path:   "../manifest.json",
		},
		{
			name: "package too large",
			entries: map[string][]byte{
				"manifest.json": []byte(validManifestJSON()),
				"ui/index.html": []byte("<!doctype html><title>Plugin</title>"),
			},
			opts:   testReadLimits(1, 16, 1<<20, 512, 100),
			want:   ValidationCodePackageTooLarge,
			reason: "total_uncompressed_bytes",
		},
		{
			name: "path length",
			entries: map[string][]byte{
				"manifest.json": []byte(validManifestJSON()),
			},
			opts:   testReadLimits(128<<20, 4096, 32<<20, 4, 100),
			want:   ValidationCodePackageTooLarge,
			reason: "path_length",
			path:   "manifest.json",
		},
		{
			name: "unsupported signature entry",
			entries: map[string][]byte{
				"manifest.json":        []byte(validManifestJSON()),
				"ui/index.html":        []byte("<!doctype html><title>Plugin</title>"),
				"signatures/extra.sig": []byte("extra"),
			},
			want:   ValidationCodePackagePathForbidden,
			reason: "unsupported_signature_entry",
			path:   "signatures/extra.sig",
		},
		{
			name: "manifest field",
			entries: map[string][]byte{
				"manifest.json": []byte(strings.ReplaceAll(validManifestJSON(), `"version": "1.0.0"`, `"version": ""`)),
				"ui/index.html": []byte("<!doctype html><title>Plugin</title>"),
			},
			want:    ValidationCodeManifestInvalid,
			reason:  "manifest_field",
			path:    "manifest.json",
			pointer: "/plugin/version",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := packageZipBytes(t, tc.entries)
			opts := tc.opts
			if opts == (ReadLimits{}) {
				opts = DefaultReadLimits()
			}
			_, err := Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), opts)
			requireValidationError(t, err, tc.want, tc.reason, tc.path, tc.pointer)
		})
	}
}

func TestBuildFromDirRejectsPathLengthLimit(t *testing.T) {
	dir := writeFixturePackageDir(t)
	var buf bytes.Buffer
	_, err := BuildFromDir(context.Background(), dir, &buf, testReadLimits(128<<20, 4096, 32<<20, 4, 100))
	requireValidationError(t, err, ValidationCodePackageTooLarge, "path_length", "manifest.json", "")
}

func TestBuildAcceptsPackageLocalSurfaceAssets(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), `<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="assets/styles.css">
  </head>
  <body>
    <main><img src="assets/icon.png" alt=""></main>
    <script type="text/redevplugin-worker" src="assets/app.js"></script>
  </body>
</html>`)
	mustWrite(t, filepath.Join(dir, "ui", "assets", "styles.css"), "body{}")
	mustWriteBytes(t, filepath.Join(dir, "ui", "assets", "icon.png"), minimalPNGForTest())

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err != nil {
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
			html:    `<!doctype html><script type="text/redevplugin-worker" src="https://cdn.example/plugin.js"></script>`,
			wantErr: "canonical package-local path",
		},
		{
			name:    "root absolute stylesheet",
			html:    `<!doctype html><link rel="stylesheet" href="/assets/styles.css">`,
			wantErr: "canonical package-local path",
		},
		{
			name:    "missing local script",
			html:    `<!doctype html><script type="text/redevplugin-worker" src="assets/missing.js"></script>`,
			wantErr: `missing package asset "ui/assets/missing.js"`,
		},
		{
			name:    "inline script",
			html:    `<!doctype html><script type="text/redevplugin-worker">console.log("inline")</script>`,
			wantErr: "external bundled worker",
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
			wantErr: "embedded browsing context or base URL",
		},
		{
			name:    "iframe srcdoc",
			html:    `<!doctype html><iframe srcdoc="<script></script>"></iframe>`,
			wantErr: "embedded browsing context or base URL",
		},
		{
			name:    "meta refresh",
			html:    `<!doctype html><meta http-equiv="refresh" content="0; url=https://example.com">`,
			wantErr: "meta refresh is not allowed",
		},
		{
			name:    "unsupported navigation element",
			html:    `<!doctype html><body><a href="#details">Details</a><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`,
			wantErr: "element <a> is not supported",
		},
		{
			name:    "unsupported srcset",
			html:    `<!doctype html><body><img srcset="assets/icon.png 1x" alt=""><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`,
			wantErr: "srcset is not supported",
		},
		{
			name:    "unsupported plugin metadata attribute",
			html:    `<!doctype html><body><main data-plugin-id="com.example.plugin"></main><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`,
			wantErr: `attribute "data-plugin-id" is not supported`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWrite(t, filepath.Join(dir, "ui", "index.html"), tc.html)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
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
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildValidatesSurfaceIconAsset(t *testing.T) {
	tests := []struct {
		name     string
		icon     string
		content  []byte
		wantErr  string
		noWrite  bool
		filename string
	}{
		{
			name:     "packaged png icon",
			icon:     "ui/assets/icon.png",
			content:  minimalPNGForTest(),
			filename: "ui/assets/icon.png",
		},
		{
			name:     "svg icon rejected",
			icon:     "ui/assets/icon.svg",
			content:  []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`),
			wantErr:  "SVG icons are not allowed",
			filename: "ui/assets/icon.svg",
		},
		{
			name:    "external icon rejected",
			icon:    "https://cdn.example/icon.png",
			wantErr: "must reference a package-local relative raster image asset",
			noWrite: true,
		},
		{
			name:     "missing icon rejected",
			icon:     "ui/assets/missing.png",
			wantErr:  `icon "ui/assets/missing.png" is not present in package`,
			noWrite:  true,
			filename: "ui/assets/missing.png",
		},
		{
			name:     "svg content masquerading as png rejected",
			icon:     "ui/assets/icon.png",
			content:  []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`),
			wantErr:  "content does not match a supported raster image format",
			filename: "ui/assets/icon.png",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			manifestJSON := strings.ReplaceAll(validManifestJSON(), `"entry": "ui/index.html"`, `"entry": "ui/index.html", "icon": "`+tc.icon+`"`)
			mustWrite(t, filepath.Join(dir, "manifest.json"), manifestJSON)
			if !tc.noWrite {
				filename := tc.filename
				if filename == "" {
					filename = tc.icon
				}
				mustWriteBytes(t, filepath.Join(dir, filepath.FromSlash(filename)), tc.content)
			}

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("BuildFromDir() icon error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildRejectsServiceWorkerRegistrationDependency(t *testing.T) {
	for _, source := range []string{
		`navigator.serviceWorker.register("sw.js");`,
		`navigator?.serviceWorker?.register("sw.js");`,
		`navigator["serviceWorker"].register("sw.js");`,
		`navigator?.["serviceWorker"]?.["register"]("sw.js");`,
		`serviceWorker["register"]("sw.js");`,
	} {
		t.Run(source, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWrite(t, filepath.Join(dir, "ui", "index.html"), `<!doctype html><script type="text/redevplugin-worker" src="assets/app.js"></script>`)
			mustWrite(t, filepath.Join(dir, "ui", "assets", "app.js"), source)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err == nil || !strings.Contains(err.Error(), "Service Worker registration APIs are not allowed") {
				t.Fatalf("BuildFromDir() error = %v, want Service Worker rejection", err)
			}
		})
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
		{
			name:      "package json dependencies",
			entryPath: "package.json",
			content:   []byte(`{"dependencies":{"left-pad":"latest"}}`),
			wantErr:   `package manager dependency field "dependencies" is not allowed`,
		},
		{
			name:      "Cargo build rs",
			entryPath: "build.rs",
			content:   []byte(`fn main() { println!("cargo:rerun-if-changed=build.rs"); }`),
			wantErr:   `Cargo build.rs scripts are not allowed`,
		},
		{
			name:      "Cargo build script",
			entryPath: "Cargo.toml",
			content:   []byte("[package]\nname = \"malicious\"\nversion = \"0.1.0\"\nbuild = \"build.rs\"\n"),
			wantErr:   `Cargo build scripts are not allowed`,
		},
		{
			name:      "Cargo proc macro",
			entryPath: "Cargo.toml",
			content:   []byte("[lib]\nproc-macro = true\n"),
			wantErr:   `Cargo proc macro crates are not allowed`,
		},
		{
			name:      "Cargo native links",
			entryPath: "Cargo.toml",
			content:   []byte("[package]\nname = \"malicious\"\nversion = \"0.1.0\"\nlinks = \"ssl\"\n"),
			wantErr:   `Cargo native linker configuration is not allowed`,
		},
		{
			name:      "Cargo rustflags link arg",
			entryPath: "Cargo.toml",
			content:   []byte("[build]\nrustflags = [\"-C\", \"link-arg=-Wl,-rpath,/tmp/malicious\"]\n"),
			wantErr:   `Cargo native linker configuration is not allowed`,
		},
		{
			name:      "Cargo dependencies",
			entryPath: "Cargo.toml",
			content:   []byte("[dependencies]\nanyhow = \"1\"\n"),
			wantErr:   `Cargo dependency section "dependencies" is not allowed`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			mustWriteBytes(t, filepath.Join(dir, filepath.FromSlash(tc.entryPath)), tc.content)

			var buf bytes.Buffer
			_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildFromDir() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildReportsArtifactBoundaryBeforeInvalidSurfaceShape(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Missing worker</title>")
	mustWrite(t, filepath.Join(dir, "package.json"), `{"scripts":{"postinstall":"node install.js"}}`)

	var buf bytes.Buffer
	_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	if err == nil || !strings.Contains(err.Error(), `package manager lifecycle script "postinstall" is not allowed`) {
		t.Fatalf("BuildFromDir() error = %v, want artifact boundary rejection", err)
	}
	if strings.Contains(err.Error(), "bundled worker") {
		t.Fatalf("artifact boundary error was masked by surface validation: %v", err)
	}
}

func TestBuildAllowsNonExecutableBinaryDataAsset(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWriteBytes(t, filepath.Join(dir, "ui", "assets", "model.bin"), []byte{0x00, 0x01, 0x02, 0x03})

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err != nil {
		t.Fatalf("BuildFromDir() binary data asset error = %v", err)
	}
}

func TestBuildRejectsMissingWorkerArtifact(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err == nil {
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

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits()); err == nil {
		t.Fatal("Read() expected missing worker artifact error")
	}
}

func TestBuildRejectsMalformedWorkerWASM(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWrite(t, filepath.Join(dir, "workers", "echo.wasm"), "wasm-placeholder")

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err == nil {
		t.Fatal("BuildFromDir() expected malformed worker wasm error")
	}
}

func TestWASMInspectionRejectsSharedInvalidOpcodeFixture(t *testing.T) {
	module := decodeSharedWASMFixture(t, "invalid-final-opcode.hex")
	if _, err := inspectWASMModule(module); err == nil {
		t.Fatal("inspectWASMModule() accepted a module with an invalid function opcode")
	}
}

func TestWASMValidationRejectsSharedTableMaximumFixture(t *testing.T) {
	module := decodeSharedWASMFixture(t, "table-maximum-exceeds-limit.hex")
	contract, err := inspectWASMModule(module)
	if err != nil {
		t.Fatal(err)
	}
	err = validateWASMWorkerContract(contract, wasmPageBytes)
	if err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("validateWASMWorkerContract() error = %v, want table maximum limit", err)
	}
}

func TestReadRejectsWorkerMissingRequiredInvokeExport(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entries := map[string][]byte{
		"manifest.json":       []byte(workerManifestJSON()),
		"ui/index.html":       []byte("<!doctype html><title>Plugin</title>"),
		"workers/echo.wasm":   minimalWorkerWASMForTest("other_export"),
		"ui/assets/app.js":    []byte("console.log('plugin');"),
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

	if _, err := Read(context.Background(), bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultReadLimits()); err == nil {
		t.Fatal("Read() expected missing worker export error")
	}
}

func TestBuildRejectsRequiredInvokeExportedAsMemory(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalMemoryExportWASMForTest("redevplugin_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err == nil {
		t.Fatal("BuildFromDir() expected non-function worker export error")
	}
}

func TestBuildAcceptsWorkerWASMExport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))

	var buf bytes.Buffer
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	if err != nil {
		t.Fatalf("BuildFromDir() worker error = %v", err)
	}
	if pkg.Manifest.Workers[0].Artifact != "workers/echo.wasm" {
		t.Fatalf("worker artifact mismatch: %#v", pkg.Manifest.Workers[0])
	}
}

func TestBuildRejectsWorkerTableAboveLimit(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), workerWASMWithTableForTest(maxWASMTableElements+1))

	var buf bytes.Buffer
	_, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	if err == nil || !strings.Contains(err.Error(), "table") {
		t.Fatalf("BuildFromDir() error = %v, want table element limit", err)
	}
}

func TestBuildRejectsUnsupportedWorkerImport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), workerWASMWithHostcallForTest("redeven.shell", "execute"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err == nil {
		t.Fatal("BuildFromDir() expected unsupported worker import error")
	}
}

func TestBuildAcceptsSupportedWorkerImport(t *testing.T) {
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), workerWASMWithHostcallForTest("redevplugin.network", "execute"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err != nil {
		t.Fatalf("BuildFromDir() worker import error = %v", err)
	}
}

func TestBuildRejectsUnsupportedActorWorkerMode(t *testing.T) {
	dir := writeFixturePackageDir(t)
	manifestJSON := strings.Replace(workerManifestJSON(), `"mode": "job"`, `"mode": "actor"`, 1)
	mustWrite(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))

	var buf bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits()); err == nil {
		t.Fatal("BuildFromDir() expected unsupported actor worker mode error")
	}
}

func TestAssetStoreReadsPackageAssets(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixturePackageDir(t)
			var buf bytes.Buffer
			pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err != nil {
				t.Fatal(err)
			}
			store := tc.open(t)
			if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
				t.Fatalf("PutOwnedPackage() error = %v", err)
			}
			asset, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
			if err != nil {
				t.Fatalf("ReadAsset() error = %v", err)
			}
			if string(asset.Content) != fixtureSurfaceHTML || asset.Entry.ContentType != "text/html; charset=utf-8" {
				t.Fatalf("asset mismatch: %#v content=%q", asset.Entry, string(asset.Content))
			}
			asset.Content[0] = 'x'
			again, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
			if err != nil {
				t.Fatal(err)
			}
			if string(again.Content) != fixtureSurfaceHTML {
				t.Fatalf("asset content was not cloned: %q", string(again.Content))
			}
		})
	}
}

func TestAssetStoreConsumesOwnedPackageFiles(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			pkg := testAssetPackage(t)
			pkg.SignatureFiles = map[string][]byte{PackageSignaturePath: []byte("signature")}
			store := tc.open(t)
			if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
				t.Fatal(err)
			}
			if pkg.Files != nil || pkg.SignatureFiles != nil {
				t.Fatal("PutOwnedPackage() retained caller access to transferred maps")
			}
		})
	}
}

func TestMemoryAssetStoreRetainsTransferredBytesWithoutClone(t *testing.T) {
	pkg := testAssetPackage(t)
	content := pkg.Files["ui/index.html"]
	store := NewMemoryAssetStore()
	if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
		t.Fatal(err)
	}
	stored := store.packages[pkg.PackageHash].files["ui/index.html"]
	if len(content) == 0 || len(stored) == 0 || &content[0] != &stored[0] {
		t.Fatal("MemoryAssetStore cloned transferred package bytes")
	}
}

func TestPutOwnedPackageConsumesFilesOnValidationFailure(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			pkg := Package{
				Entries:        []Entry{{Path: "ui/index.html", Size: 1, SHA256: sha256String([]byte("x")), Mode: "0644"}},
				Files:          map[string][]byte{"ui/index.html": []byte("x")},
				SignatureFiles: map[string][]byte{PackageSignaturePath: []byte("signature")},
			}
			if err := tc.open(t).PutOwnedPackage(context.Background(), &pkg); err == nil {
				t.Fatal("PutOwnedPackage() accepted a missing package hash")
			}
			if pkg.Files != nil || pkg.SignatureFiles != nil {
				t.Fatal("failed PutOwnedPackage() did not consume transferred maps")
			}
		})
	}
}

func TestPutOwnedPackageRejectsUnindexedFiles(t *testing.T) {
	for _, tc := range assetStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			pkg := testAssetPackage(t)
			pkg.Files["ui/unindexed.bin"] = []byte("unindexed")
			if err := tc.open(t).PutOwnedPackage(context.Background(), &pkg); err == nil {
				t.Fatal("PutOwnedPackage() accepted an unindexed file")
			}
			if pkg.Files != nil || pkg.SignatureFiles != nil {
				t.Fatal("failed PutOwnedPackage() did not consume transferred maps")
			}
		})
	}
}

func TestMemoryAssetStoreConcurrentReadsCloneTransferredContent(t *testing.T) {
	pkg := testAssetPackage(t)
	want := append([]byte(nil), pkg.Files["ui/index.html"]...)
	store := NewMemoryAssetStore()
	if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
		t.Fatal(err)
	}
	const readers = 32
	var wait sync.WaitGroup
	wait.Add(readers)
	for index := 0; index < readers; index++ {
		go func() {
			defer wait.Done()
			asset, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
			if err != nil {
				t.Error(err)
				return
			}
			asset.Content[0] ^= 0xff
		}()
	}
	wait.Wait()
	asset, err := store.ReadAsset(context.Background(), pkg.PackageHash, "ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(asset.Content, want) {
		t.Fatalf("stored content changed through read alias: %q", string(asset.Content))
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
			pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
			if err != nil {
				t.Fatal(err)
			}
			store := tc.open(t)
			if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
				t.Fatalf("PutOwnedPackage() error = %v", err)
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
	pkg, err := BuildFromDir(context.Background(), dir, &buf, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOwnedPackage(context.Background(), &pkg); err != nil {
		t.Fatalf("PutOwnedPackage() error = %v", err)
	}

	reopened, err := NewFileAssetStore(root)
	if err != nil {
		t.Fatal(err)
	}
	asset, err := reopened.ReadAsset(context.Background(), pkg.PackageHash, "ui/assets/app.js")
	if err != nil {
		t.Fatalf("ReadAsset() after reopen error = %v", err)
	}
	if string(asset.Content) != fixtureWorkerJS {
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

const (
	fixtureSurfaceHTML = `<!doctype html><title>Plugin</title><body><main>Plugin</main><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`
	fixtureWorkerJS    = "void 0;"
)

func writeFixturePackageDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "manifest.json"), validManifestJSON())
	mustWrite(t, filepath.Join(dir, "ui", "index.html"), fixtureSurfaceHTML)
	mustWrite(t, filepath.Join(dir, "ui", "assets", "app.js"), fixtureWorkerJS)
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

func packageZipBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entryPaths := make([]string, 0, len(entries))
	for entryPath := range entries {
		entryPaths = append(entryPaths, entryPath)
	}
	sort.Strings(entryPaths)
	for _, entryPath := range entryPaths {
		content := entries[entryPath]
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
	return buf.Bytes()
}

func requireValidationError(t *testing.T, err error, code ValidationErrorCode, reason string, entryPath string, pointer string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %v, want ValidationError", err)
	}
	if validationErr.Code != code || validationErr.Reason != reason || validationErr.Path != entryPath || validationErr.Pointer != pointer {
		t.Fatalf("validation error = %#v, want code=%s reason=%s path=%s pointer=%s", validationErr, code, reason, entryPath, pointer)
	}
}

func testReadLimits(uncompressed int64, files int, entry int64, path int, ratio int64) ReadLimits {
	limits, err := DefaultReadLimits().WithMaxUncompressedBytes(uncompressed)
	if err != nil {
		panic(err)
	}
	limits, err = limits.WithMaxFiles(files)
	if err != nil {
		panic(err)
	}
	limits, err = limits.WithMaxEntryBytes(entry)
	if err != nil {
		panic(err)
	}
	limits, err = limits.WithMaxPathBytes(path)
	if err != nil {
		panic(err)
	}
	limits, err = limits.WithMaxCompressionRatio(ratio)
	if err != nil {
		panic(err)
	}
	return limits
}

func decodeSharedWASMFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "wasm", name))
	if err != nil {
		t.Fatal(err)
	}
	module, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func minimalPNGForTest() []byte {
	raw, err := hex.DecodeString("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")
	if err != nil {
		panic(err)
	}
	return raw
}

func minimalWorkerWASMForTest(exportName string) []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x11, 0x03,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
		0x60, 0x02, 0x7f, 0x7f, 0x00,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
		0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
		0x05, 0x03, 0x01, 0x00, 0x01,
	}
	exportPayload := []byte{0x04}
	for _, export := range []struct {
		name  string
		kind  byte
		index byte
	}{
		{name: "memory", kind: 0x02, index: 0x00},
		{name: "redevplugin_worker_alloc", kind: 0x00, index: 0x00},
		{name: "redevplugin_worker_dealloc", kind: 0x00, index: 0x01},
		{name: exportName, kind: 0x00, index: 0x02},
	} {
		exportPayload = append(exportPayload, byte(len(export.name)))
		exportPayload = append(exportPayload, export.name...)
		exportPayload = append(exportPayload, export.kind, export.index)
	}
	module = append(module, 0x07, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module,
		0x0a, 0x0f, 0x03,
		0x05, 0x00, 0x41, 0x80, 0x08, 0x0b,
		0x02, 0x00, 0x0b,
		0x04, 0x00, 0x42, 0x00, 0x0b,
	)
	return module
}

func workerWASMWithHostcallForTest(moduleName string, functionName string) []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x19, 0x04,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
		0x60, 0x02, 0x7f, 0x7f, 0x00,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
		0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
	}
	importPayload := []byte{0x01, byte(len(moduleName))}
	importPayload = append(importPayload, moduleName...)
	importPayload = append(importPayload, byte(len(functionName)))
	importPayload = append(importPayload, functionName...)
	importPayload = append(importPayload, 0x00, 0x03)
	module = append(module, 0x02)
	module = append(module, encodeWASMVarUint32ForTest(uint32(len(importPayload)))...)
	module = append(module, importPayload...)
	module = append(module,
		0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
		0x05, 0x03, 0x01, 0x00, 0x01,
	)
	exportPayload := []byte{0x04}
	for _, export := range []struct {
		name  string
		kind  byte
		index byte
	}{
		{name: "memory", kind: 0x02, index: 0x00},
		{name: "redevplugin_worker_alloc", kind: 0x00, index: 0x01},
		{name: "redevplugin_worker_dealloc", kind: 0x00, index: 0x02},
		{name: "redevplugin_worker_invoke", kind: 0x00, index: 0x03},
	} {
		exportPayload = append(exportPayload, byte(len(export.name)))
		exportPayload = append(exportPayload, export.name...)
		exportPayload = append(exportPayload, export.kind, export.index)
	}
	module = append(module, 0x07, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module,
		0x0a, 0x0f, 0x03,
		0x05, 0x00, 0x41, 0x80, 0x08, 0x0b,
		0x02, 0x00, 0x0b,
		0x04, 0x00, 0x42, 0x00, 0x0b,
	)
	return module
}

func workerWASMWithTableForTest(initialElements uint32) []byte {
	module := minimalWorkerWASMForTest("redevplugin_worker_invoke")
	memorySection := []byte{0x05, 0x03, 0x01, 0x00, 0x01}
	index := bytes.Index(module, memorySection)
	if index < 0 {
		panic("minimal worker memory section not found")
	}
	payload := []byte{0x01, 0x70, 0x00}
	payload = append(payload, encodeWASMVarUint32ForTest(initialElements)...)
	section := []byte{0x04}
	section = append(section, encodeWASMVarUint32ForTest(uint32(len(payload)))...)
	section = append(section, payload...)
	withTable := make([]byte, 0, len(module)+len(section))
	withTable = append(withTable, module[:index]...)
	withTable = append(withTable, section...)
	withTable = append(withTable, module[index:]...)
	return withTable
}

func encodeWASMVarUint32ForTest(value uint32) []byte {
	encoded := make([]byte, 0, 5)
	for {
		current := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			current |= 0x80
		}
		encoded = append(encoded, current)
		if value == 0 {
			return encoded
		}
	}
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.pkg",
			"display_name": "Package",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "pkg.view", "kind": "view", "label": "Package", "entry": "ui/index.html"}
		]
	}`
}

func workerManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				"request_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"message": {"type": "string"}}
				},
				"response_schema": {"type": "object", "additionalProperties": false},
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		]
		}`
}
