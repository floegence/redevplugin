package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/tetratelabs/wazero"
	"golang.org/x/net/html"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type Entry struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Mode        string `json:"mode"`
	ContentType string `json:"content_type,omitempty"`
}

type Asset struct {
	Entry   Entry  `json:"entry"`
	Content []byte `json:"-"`
}

type Package struct {
	Manifest          manifest.Manifest `json:"manifest"`
	PackageHash       string            `json:"package_hash"`
	ManifestHash      string            `json:"manifest_hash"`
	CanonicalManifest string            `json:"canonical_manifest"`
	Entries           []Entry           `json:"entries"`
	EntriesHash       string            `json:"entries_hash"`
	PackageSignature  *PackageSignature `json:"package_signature,omitempty"`
	Files             map[string][]byte `json:"-"`
	SignatureFiles    map[string][]byte `json:"-"`
}

type ReadOptions struct {
	MaxUncompressedBytes int64 `json:"max_uncompressed_bytes"`
	MaxFiles             int   `json:"max_files"`
	MaxEntryBytes        int64 `json:"max_entry_bytes"`
	MaxPathBytes         int   `json:"max_path_bytes"`
	MaxCompressionRatio  int64 `json:"max_compression_ratio"`
}

const PackageSignaturePath = "signatures/package.sig"
const PackageSignatureSchemaVersion = "redevplugin.package_signature.v1"
const PackageSignatureAlgorithmEd25519 = "ed25519"
const workerABIPath = "workers/abi.json"
const maxWASMTableElements uint32 = 65_536

var serviceWorkerDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bnavigator\s*(?:\?\s*)?\.\s*serviceWorker\b`),
	regexp.MustCompile(`\bnavigator\s*(?:\?\s*\.)?\s*\[\s*["']serviceWorker["']\s*\]`),
	regexp.MustCompile(`\bserviceWorker\s*(?:\?\s*)?\.\s*register\b`),
	regexp.MustCompile(`\bserviceWorker\s*(?:\?\s*\.)?\s*\[\s*["']register["']\s*\]`),
	regexp.MustCompile(`\bServiceWorkerRegistration\b`),
	regexp.MustCompile(`\bServiceWorkerContainer\b`),
}

var forbiddenShellExtensions = map[string]struct{}{
	".bash": {},
	".bat":  {},
	".cmd":  {},
	".fish": {},
	".ps1":  {},
	".psm1": {},
	".sh":   {},
	".zsh":  {},
}

var forbiddenNativeExtensions = map[string]struct{}{
	".a":     {},
	".app":   {},
	".deb":   {},
	".dll":   {},
	".dylib": {},
	".exe":   {},
	".lib":   {},
	".msi":   {},
	".node":  {},
	".o":     {},
	".obj":   {},
	".rpm":   {},
}

var forbiddenPackageLifecycleScripts = map[string]struct{}{
	"install":     {},
	"postinstall": {},
	"postpack":    {},
	"preinstall":  {},
	"prepare":     {},
	"prepack":     {},
}

var allowedSurfaceIconExtensions = map[string]struct{}{
	".gif":  {},
	".ico":  {},
	".jpeg": {},
	".jpg":  {},
	".png":  {},
	".webp": {},
}

type PackageSignature struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id,omitempty"`
	PluginID      string `json:"plugin_id,omitempty"`
	PackageHash   string `json:"package_hash"`
	ManifestHash  string `json:"manifest_hash"`
	EntriesHash   string `json:"entries_hash"`
	Signature     string `json:"signature"`
	SignedAt      string `json:"signed_at,omitempty"`
}

type workerABIDescriptor struct {
	ABIVersion string   `json:"abi_version"`
	Exports    []string `json:"exports"`
	Imports    []string `json:"imports"`
}

type Reader interface {
	ReadPackage(ctx context.Context, r io.Reader, opts ReadOptions) (Package, error)
}

type Writer interface {
	WritePackage(ctx context.Context, w io.Writer, pkg Package) error
}

var deterministicModTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func DefaultReadOptions() ReadOptions {
	return ReadOptions{
		MaxUncompressedBytes: 128 << 20,
		MaxFiles:             4096,
		MaxEntryBytes:        32 << 20,
		MaxPathBytes:         512,
		MaxCompressionRatio:  100,
	}
}

func BuildFromDir(ctx context.Context, srcDir string, w io.Writer, opts ReadOptions) (Package, error) {
	if opts == (ReadOptions{}) {
		opts = DefaultReadOptions()
	}
	files, signatureFiles, err := collectFiles(srcDir, opts)
	if err != nil {
		return Package{}, err
	}
	pkg, err := packageFromFiles(files, signatureFiles)
	if err != nil {
		return Package{}, err
	}
	if err := WritePackage(ctx, w, pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

func WritePackage(ctx context.Context, w io.Writer, pkg Package) error {
	if w == nil {
		return errors.New("package writer is required")
	}
	if len(pkg.Files) == 0 {
		return errors.New("package files are required")
	}
	files := cloneFiles(pkg.Files)
	signatureFiles := map[string][]byte{}
	if pkg.PackageSignature != nil {
		signatureBytes, err := marshalPackageSignature(*pkg.PackageSignature)
		if err != nil {
			return err
		}
		signatureFiles[PackageSignaturePath] = signatureBytes
	}
	normalized, err := packageFromFiles(files, signatureFiles)
	if err != nil {
		return err
	}
	if pkg.PackageHash != "" && normalized.PackageHash != pkg.PackageHash {
		return fmt.Errorf("package_hash mismatch: %s != %s", normalized.PackageHash, pkg.PackageHash)
	}
	if pkg.ManifestHash != "" && normalized.ManifestHash != pkg.ManifestHash {
		return fmt.Errorf("manifest_hash mismatch: %s != %s", normalized.ManifestHash, pkg.ManifestHash)
	}
	if pkg.EntriesHash != "" && normalized.EntriesHash != pkg.EntriesHash {
		return fmt.Errorf("entries_hash mismatch: %s != %s", normalized.EntriesHash, pkg.EntriesHash)
	}
	return writePackageZip(ctx, w, normalized)
}

func writePackageZip(ctx context.Context, w io.Writer, pkg Package) error {
	zipWriter := zip.NewWriter(w)
	for _, entry := range pkg.Entries {
		select {
		case <-ctx.Done():
			_ = zipWriter.Close()
			return ctx.Err()
		default:
		}
		header := &zip.FileHeader{
			Name:     entry.Path,
			Method:   zip.Deflate,
			Modified: deterministicModTime,
		}
		header.SetMode(0o644)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			_ = zipWriter.Close()
			return err
		}
		if _, err := writer.Write(pkg.Files[entry.Path]); err != nil {
			_ = zipWriter.Close()
			return err
		}
	}
	signaturePaths := sortedFilePaths(pkg.SignatureFiles)
	for _, entryPath := range signaturePaths {
		select {
		case <-ctx.Done():
			_ = zipWriter.Close()
			return ctx.Err()
		default:
		}
		header := &zip.FileHeader{
			Name:     entryPath,
			Method:   zip.Deflate,
			Modified: deterministicModTime,
		}
		header.SetMode(0o644)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			_ = zipWriter.Close()
			return err
		}
		if _, err := writer.Write(pkg.SignatureFiles[entryPath]); err != nil {
			_ = zipWriter.Close()
			return err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return err
	}
	return nil
}

func Read(ctx context.Context, r io.ReaderAt, size int64, opts ReadOptions) (Package, error) {
	if opts == (ReadOptions{}) {
		opts = DefaultReadOptions()
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return Package{}, wrapValidationError(ValidationCodePackageInvalid, "zip_invalid", "", "", err)
	}
	if opts.MaxFiles > 0 && len(zr.File) > opts.MaxFiles {
		return Package{}, validationErrorf(ValidationCodePackageTooLarge, "file_count", "", "", "too many files: %d > %d", len(zr.File), opts.MaxFiles)
	}

	files := map[string][]byte{}
	signatureFiles := map[string][]byte{}
	seenPaths := map[string]struct{}{}
	securityPaths := map[string]string{}
	var total int64
	for _, file := range zr.File {
		select {
		case <-ctx.Done():
			return Package{}, ctx.Err()
		default:
		}
		entryPath, err := validateEntryPath(file.Name)
		if err != nil {
			return Package{}, err
		}
		if err := validateEntryPathLength(entryPath, opts.MaxPathBytes); err != nil {
			return Package{}, err
		}
		if _, ok := seenPaths[entryPath]; ok {
			return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "duplicate_entry", entryPath, "", "duplicate entry %q", entryPath)
		}
		seenPaths[entryPath] = struct{}{}
		securityKey := entryPathSecurityKey(entryPath)
		if previous, ok := securityPaths[securityKey]; ok {
			return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "ambiguous_entry", entryPath, "", "entry %q aliases %q after Unicode case folding", entryPath, previous)
		}
		securityPaths[securityKey] = entryPath
		if file.FileInfo().Mode()&fs.ModeSymlink != 0 {
			return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "symlink_entry", entryPath, "", "symlink entry %q is not allowed", entryPath)
		}
		if strings.HasSuffix(entryPath, "/") {
			return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "directory_entry", entryPath, "", "directory entry %q is not allowed", entryPath)
		}
		if !file.FileInfo().Mode().IsRegular() {
			return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "non_regular_entry", entryPath, "", "non-regular entry %q is not allowed", entryPath)
		}
		if opts.MaxEntryBytes > 0 && int64(file.UncompressedSize64) > opts.MaxEntryBytes {
			return Package{}, validationErrorf(ValidationCodePackageTooLarge, "entry_bytes", entryPath, "", "entry %q too large", entryPath)
		}
		if opts.MaxCompressionRatio > 0 && file.CompressedSize64 > 0 && int64(file.UncompressedSize64/file.CompressedSize64) > opts.MaxCompressionRatio {
			return Package{}, validationErrorf(ValidationCodePackageTooLarge, "compression_ratio", entryPath, "", "entry %q compression ratio exceeds limit", entryPath)
		}
		total += int64(file.UncompressedSize64)
		if opts.MaxUncompressedBytes > 0 && total > opts.MaxUncompressedBytes {
			return Package{}, validationErrorf(ValidationCodePackageTooLarge, "total_uncompressed_bytes", "", "", "package too large")
		}
		rc, err := file.Open()
		if err != nil {
			return Package{}, wrapValidationError(ValidationCodePackageInvalid, "entry_open_failed", entryPath, "", err)
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, int64(file.UncompressedSize64)+1))
		closeErr := rc.Close()
		if readErr != nil {
			return Package{}, wrapValidationError(ValidationCodePackageInvalid, "entry_read_failed", entryPath, "", readErr)
		}
		if closeErr != nil {
			return Package{}, wrapValidationError(ValidationCodePackageInvalid, "entry_close_failed", entryPath, "", closeErr)
		}
		if uint64(len(content)) != file.UncompressedSize64 {
			return Package{}, validationErrorf(ValidationCodePackageInvalid, "entry_size_mismatch", entryPath, "", "entry %q size mismatch", entryPath)
		}
		if strings.HasPrefix(entryPath, "signatures/") {
			if entryPath != PackageSignaturePath {
				return Package{}, validationErrorf(ValidationCodePackagePathForbidden, "unsupported_signature_entry", entryPath, "", "unsupported signature entry %q", entryPath)
			}
			signatureFiles[entryPath] = content
			continue
		}
		files[entryPath] = content
	}

	return packageFromFiles(files, signatureFiles)
}

func ReadFile(ctx context.Context, filename string, opts ReadOptions) (Package, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Package{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return Package{}, err
	}
	return Read(ctx, file, stat.Size(), opts)
}

func packageFromFiles(files map[string][]byte, signatureFiles map[string][]byte) (Package, error) {
	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return Package{}, validationErrorf(ValidationCodeManifestInvalid, "manifest_missing", "manifest.json", "", "manifest.json is required")
	}
	decodedManifest, err := manifest.Decode(bytes.NewReader(manifestBytes))
	if err != nil {
		return Package{}, manifestDecodeValidationError(err)
	}
	if err := validatePackageArtifactBoundary(files); err != nil {
		return Package{}, ensurePackageValidationError(err, ValidationCodePackageInvalid, "package_artifact_boundary")
	}
	if err := validateManifestArtifacts(decodedManifest, files); err != nil {
		return Package{}, ensurePackageValidationError(err, ValidationCodePackageInvalid, "manifest_artifact")
	}
	if err := validatePackageAssetSecurity(decodedManifest, files); err != nil {
		return Package{}, ensurePackageValidationError(err, ValidationCodePackageInvalid, "package_asset_security")
	}
	entries := make([]Entry, 0, len(files))
	for entryPath, content := range files {
		entry, err := makeEntry(entryPath, content)
		if err != nil {
			return Package{}, ensurePackageValidationError(err, ValidationCodePackagePathForbidden, "entry_path")
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)
	canonicalManifest, err := canonicalJSON(decodedManifest)
	if err != nil {
		return Package{}, wrapValidationError(ValidationCodeManifestInvalid, "manifest_canonical_json", "manifest.json", "", err)
	}
	manifestHash := sha256String(canonicalManifest)
	entriesHash, packageHash, err := canonicalHashes(entries, manifestHash)
	if err != nil {
		return Package{}, wrapValidationError(ValidationCodePackageInvalid, "canonical_hash", "", "", err)
	}
	packageSignature, err := parsePackageSignature(signatureFiles, decodedManifest, manifestHash, entriesHash, packageHash)
	if err != nil {
		return Package{}, ensurePackageValidationError(err, ValidationCodePackageInvalid, "package_signature")
	}
	return Package{
		Manifest:          decodedManifest,
		PackageHash:       packageHash,
		ManifestHash:      manifestHash,
		CanonicalManifest: string(canonicalManifest),
		Entries:           entries,
		EntriesHash:       entriesHash,
		PackageSignature:  packageSignature,
		Files:             cloneFiles(files),
		SignatureFiles:    cloneFiles(signatureFiles),
	}, nil
}

func collectFiles(srcDir string, opts ReadOptions) (map[string][]byte, map[string][]byte, error) {
	files := map[string][]byte{}
	signatureFiles := map[string][]byte{}
	securityPaths := map[string]string{}
	var total int64
	err := filepath.WalkDir(srcDir, func(filename string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filename == srcDir {
			return nil
		}
		rel, err := filepath.Rel(srcDir, filename)
		if err != nil {
			return err
		}
		entryPath, err := validateEntryPath(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if err := validateEntryPathLength(entryPath, opts.MaxPathBytes); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return validationErrorf(ValidationCodePackagePathForbidden, "symlink_entry", entryPath, "", "symlink entry %q is not allowed", entryPath)
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return validationErrorf(ValidationCodePackagePathForbidden, "non_regular_entry", entryPath, "", "non-regular entry %q is not allowed", entryPath)
		}
		securityKey := entryPathSecurityKey(entryPath)
		if previous, ok := securityPaths[securityKey]; ok {
			return validationErrorf(ValidationCodePackagePathForbidden, "ambiguous_entry", entryPath, "", "entry %q aliases %q after Unicode case folding", entryPath, previous)
		}
		securityPaths[securityKey] = entryPath
		if opts.MaxFiles > 0 && len(files)+1 > opts.MaxFiles {
			return validationErrorf(ValidationCodePackageTooLarge, "file_count", "", "", "too many files")
		}
		if opts.MaxEntryBytes > 0 && info.Size() > opts.MaxEntryBytes {
			return validationErrorf(ValidationCodePackageTooLarge, "entry_bytes", entryPath, "", "entry %q too large", entryPath)
		}
		total += info.Size()
		if opts.MaxUncompressedBytes > 0 && total > opts.MaxUncompressedBytes {
			return validationErrorf(ValidationCodePackageTooLarge, "total_uncompressed_bytes", "", "", "package too large")
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if strings.HasPrefix(entryPath, "signatures/") {
			if entryPath != PackageSignaturePath {
				return validationErrorf(ValidationCodePackagePathForbidden, "unsupported_signature_entry", entryPath, "", "unsupported signature entry %q", entryPath)
			}
			signatureFiles[entryPath] = content
			return nil
		}
		files[entryPath] = content
		return nil
	})
	return files, signatureFiles, err
}

func validateEntryPath(entryPath string) (string, error) {
	if entryPath == "" {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "empty_path", "", "", "empty entry path")
	}
	if !utf8.ValidString(entryPath) {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "invalid_utf8_path", entryPath, "", "entry path is not valid UTF-8")
	}
	if !norm.NFC.IsNormalString(entryPath) {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "non_nfc_path", entryPath, "", "entry %q must use Unicode NFC", entryPath)
	}
	if strings.Contains(entryPath, "\\") {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "slash_separator", entryPath, "", "entry %q must use slash separators", entryPath)
	}
	clean := path.Clean(entryPath)
	if clean == "." || clean != entryPath {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "non_canonical_path", entryPath, "", "entry %q is not canonical", entryPath)
	}
	if path.IsAbs(entryPath) || strings.HasPrefix(entryPath, "../") || strings.Contains(entryPath, "/../") || entryPath == ".." {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "path_traversal", entryPath, "", "entry %q escapes package root", entryPath)
	}
	if strings.HasPrefix(entryPath, ".") || strings.Contains(entryPath, "/.") {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "hidden_path", entryPath, "", "hidden entry %q is not allowed", entryPath)
	}
	return entryPath, nil
}

func entryPathSecurityKey(entryPath string) string {
	return norm.NFC.String(cases.Fold().String(entryPath))
}

func validateEntryPathLength(entryPath string, maxPathBytes int) error {
	if maxPathBytes > 0 && len(entryPath) > maxPathBytes {
		return validationErrorf(ValidationCodePackageTooLarge, "path_length", entryPath, "", "entry path %q exceeds maximum length %d", entryPath, maxPathBytes)
	}
	return nil
}

func manifestDecodeValidationError(err error) error {
	var validationErr manifest.ValidationError
	if errors.As(err, &validationErr) {
		return validationErrorf(
			ValidationCodeManifestInvalid,
			"manifest_field",
			"manifest.json",
			jsonPointerFromManifestField(validationErr.Field),
			"manifest.json: %s",
			validationErr.Error(),
		)
	}
	return wrapValidationError(ValidationCodeManifestInvalid, "manifest_decode", "manifest.json", "", fmt.Errorf("manifest.json: %w", err))
}

func ensurePackageValidationError(err error, code ValidationErrorCode, reason string) error {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return err
	}
	return wrapValidationError(code, reason, "", "", err)
}

func jsonPointerFromManifestField(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	var tokens []string
	for _, segment := range strings.Split(field, ".") {
		for segment != "" {
			bracket := strings.Index(segment, "[")
			if bracket < 0 {
				tokens = append(tokens, segment)
				break
			}
			if bracket > 0 {
				tokens = append(tokens, segment[:bracket])
			}
			closeBracket := strings.Index(segment[bracket:], "]")
			if closeBracket < 0 {
				tokens = append(tokens, segment[bracket:])
				break
			}
			index := segment[bracket+1 : bracket+closeBracket]
			if index != "" {
				tokens = append(tokens, index)
			}
			segment = segment[bracket+closeBracket+1:]
		}
	}
	if len(tokens) == 0 {
		return ""
	}
	for i, token := range tokens {
		token = strings.ReplaceAll(token, "~", "~0")
		token = strings.ReplaceAll(token, "/", "~1")
		tokens[i] = token
	}
	return "/" + strings.Join(tokens, "/")
}

func validateManifestArtifacts(m manifest.Manifest, files map[string][]byte) error {
	workerABI, err := validateWorkerABIDescriptor(m, files)
	if err != nil {
		return err
	}
	workerExports := map[string]map[string]struct{}{}
	actualImports := map[string]struct{}{}
	for i, worker := range m.Workers {
		artifact, err := validateEntryPath(worker.Artifact)
		if err != nil {
			return fmt.Errorf("workers[%d].artifact: %w", i, err)
		}
		content, ok := files[artifact]
		if !ok {
			return fmt.Errorf("workers[%d].artifact %q is not present in package", i, artifact)
		}
		contract, err := inspectWASMModule(content)
		if err != nil {
			return fmt.Errorf("workers[%d].artifact %q: %w", i, artifact, err)
		}
		if err := validateWASMWorkerContract(contract, worker.MemoryLimitBytes); err != nil {
			return fmt.Errorf("workers[%d].artifact %q: %w", i, artifact, err)
		}
		for module := range contract.ImportModules {
			if _, ok := workerABI.Imports[module]; !ok {
				return fmt.Errorf("workers[%d].artifact %q imports undeclared module %q", i, artifact, module)
			}
			actualImports[module] = struct{}{}
		}
		workerExports[worker.WorkerID] = contract.FunctionExports()
	}
	if !sameStringSet(actualImports, workerABI.Imports) {
		return fmt.Errorf("%s imports do not match packaged worker modules", workerABIPath)
	}
	for i, method := range m.Methods {
		if method.Route.Kind != manifest.MethodRouteWorker {
			continue
		}
		exports, ok := workerExports[method.Route.WorkerID]
		if !ok {
			return fmt.Errorf("methods[%d].route.worker_id %q does not reference a packaged worker", i, method.Route.WorkerID)
		}
		if _, ok := workerABI.Exports[method.Route.Export]; !ok {
			return fmt.Errorf("methods[%d].route.export %q is not declared by %s", i, method.Route.Export, workerABIPath)
		}
		if _, ok := exports[method.Route.Export]; !ok {
			return fmt.Errorf("methods[%d].route.export %q is not exported by worker %q", i, method.Route.Export, method.Route.WorkerID)
		}
	}
	return nil
}

func validatePackageArtifactBoundary(files map[string][]byte) error {
	for entryPath, content := range files {
		if err := validateNoForbiddenExecutableArtifact(entryPath, content); err != nil {
			return err
		}
		if strings.EqualFold(path.Base(entryPath), "build.rs") {
			return fmt.Errorf("%s: Cargo build.rs scripts are not allowed in plugin packages", entryPath)
		}
		if path.Base(entryPath) == "package.json" {
			if err := validatePackageJSONLifecycleScripts(entryPath, content); err != nil {
				return err
			}
		}
		if strings.EqualFold(path.Base(entryPath), "Cargo.toml") {
			if err := validateCargoBuildBoundary(entryPath, content); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateNoForbiddenExecutableArtifact(entryPath string, content []byte) error {
	lowerPath := strings.ToLower(entryPath)
	ext := path.Ext(lowerPath)
	if _, ok := forbiddenShellExtensions[ext]; ok {
		return fmt.Errorf("%s: shell script artifacts are not allowed in plugin packages", entryPath)
	}
	if hasShebang(content) {
		return fmt.Errorf("%s: executable shebang scripts are not allowed in plugin packages", entryPath)
	}
	if _, ok := forbiddenNativeExtensions[ext]; ok || strings.HasSuffix(lowerPath, ".so") || strings.Contains(lowerPath, ".so.") {
		return fmt.Errorf("%s: native executable or dynamic library artifacts are not allowed in plugin packages", entryPath)
	}
	if hasNativeExecutableMagic(content) {
		return fmt.Errorf("%s: native executable or dynamic library artifacts are not allowed in plugin packages", entryPath)
	}
	return nil
}

func validatePackageJSONLifecycleScripts(entryPath string, content []byte) error {
	var doc struct {
		Scripts              map[string]any `json:"scripts"`
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("%s: invalid package.json: %w", entryPath, err)
	}
	for name, value := range doc.Scripts {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if _, ok := forbiddenPackageLifecycleScripts[normalized]; !ok {
			continue
		}
		if strings.TrimSpace(fmt.Sprint(value)) != "" {
			return fmt.Errorf("%s: package manager lifecycle script %q is not allowed in plugin packages", entryPath, name)
		}
	}
	for name, dependencies := range map[string]map[string]any{
		"dependencies":         doc.Dependencies,
		"devDependencies":      doc.DevDependencies,
		"peerDependencies":     doc.PeerDependencies,
		"optionalDependencies": doc.OptionalDependencies,
	} {
		if len(dependencies) > 0 {
			return fmt.Errorf("%s: package manager dependency field %q is not allowed in plugin packages", entryPath, name)
		}
	}
	return nil
}

func validateCargoBuildBoundary(entryPath string, content []byte) error {
	section := ""
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(stripTOMLComment(rawLine))
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "[") && strings.Contains(lowerLine, "]") {
			section = strings.TrimSpace(strings.Trim(lowerLine, "[]"))
			continue
		}
		key, value, ok := strings.Cut(lowerLine, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if cargoDependencySection(section) {
			return fmt.Errorf("%s: Cargo dependency section %q is not allowed in plugin packages", entryPath, section)
		}
		switch key {
		case "build":
			return fmt.Errorf("%s: Cargo build scripts are not allowed in plugin packages", entryPath)
		case "proc-macro":
			if value == "true" {
				return fmt.Errorf("%s: Cargo proc macro crates are not allowed in plugin packages", entryPath)
			}
		case "links", "linker", "rustflags":
			return fmt.Errorf("%s: Cargo native linker configuration is not allowed in plugin packages", entryPath)
		}
		if strings.Contains(value, "link-arg") || strings.Contains(value, "linker") {
			return fmt.Errorf("%s: Cargo native linker configuration is not allowed in plugin packages", entryPath)
		}
	}
	return nil
}

func cargoDependencySection(section string) bool {
	return section == "dependencies" ||
		section == "dev-dependencies" ||
		section == "build-dependencies" ||
		section == "workspace.dependencies" ||
		strings.HasSuffix(section, ".dependencies") ||
		strings.HasSuffix(section, ".dev-dependencies") ||
		strings.HasSuffix(section, ".build-dependencies")
}

func stripTOMLComment(line string) string {
	inString := false
	escaped := false
	for i, r := range line {
		if r == '"' && !escaped {
			inString = !inString
		}
		if r == '#' && !inString {
			return line[:i]
		}
		escaped = r == '\\' && !escaped
		if r != '\\' {
			escaped = false
		}
	}
	return line
}

func hasShebang(content []byte) bool {
	return len(content) >= 2 && content[0] == '#' && content[1] == '!'
}

func hasNativeExecutableMagic(content []byte) bool {
	if len(content) >= 2 && content[0] == 'M' && content[1] == 'Z' {
		return true
	}
	if len(content) >= 4 {
		switch {
		case bytes.Equal(content[:4], []byte{0x7f, 'E', 'L', 'F'}):
			return true
		case bytes.Equal(content[:4], []byte{0xfe, 0xed, 0xfa, 0xce}):
			return true
		case bytes.Equal(content[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}):
			return true
		case bytes.Equal(content[:4], []byte{0xce, 0xfa, 0xed, 0xfe}):
			return true
		case bytes.Equal(content[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}):
			return true
		case bytes.Equal(content[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
			return true
		}
	}
	return false
}

func validatePackageAssetSecurity(m manifest.Manifest, files map[string][]byte) error {
	for i, surface := range m.Surfaces {
		entry, err := validatePackageAssetPath(surface.Entry)
		if err != nil {
			return fmt.Errorf("surfaces[%d].entry: %w", i, err)
		}
		content, ok := files[entry]
		if !ok {
			return fmt.Errorf("surfaces[%d].entry %q is not present in package", i, entry)
		}
		if !isHTMLAsset(entry) {
			return fmt.Errorf("surfaces[%d].entry %q must be an HTML asset", i, entry)
		}
		if err := validateSurfaceHTMLAsset(entry, content, files); err != nil {
			return err
		}
		if strings.TrimSpace(surface.Icon) != "" {
			if err := validateSurfaceIconAsset(i, surface.Icon, files); err != nil {
				return err
			}
		}
	}
	for entryPath, content := range files {
		if isScriptAsset(entryPath) {
			if err := validateNoServiceWorkerDependency(entryPath, content); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSurfaceIconAsset(surfaceIndex int, iconPath string, files map[string][]byte) error {
	iconValue := strings.TrimSpace(iconPath)
	if strings.Contains(iconValue, "://") || strings.HasPrefix(iconValue, "//") || strings.HasPrefix(iconValue, "/") {
		return validationErrorf(ValidationCodePackagePathForbidden, "external_icon_path", iconPath, fmt.Sprintf("/surfaces/%d/icon", surfaceIndex), "surfaces[%d].icon %q must reference a package-local relative raster image asset", surfaceIndex, iconPath)
	}
	icon, err := validatePackageAssetPath(iconPath)
	if err != nil {
		return fmt.Errorf("surfaces[%d].icon: %w", surfaceIndex, err)
	}
	ext := strings.ToLower(path.Ext(icon))
	if _, ok := allowedSurfaceIconExtensions[ext]; !ok {
		return validationErrorf(ValidationCodePackageInvalid, "unsupported_icon_format", icon, fmt.Sprintf("/surfaces/%d/icon", surfaceIndex), "surfaces[%d].icon %q must be a packaged raster image asset; SVG icons are not allowed", surfaceIndex, icon)
	}
	content, ok := files[icon]
	if !ok {
		return validationErrorf(ValidationCodePackageInvalid, "missing_icon_asset", icon, fmt.Sprintf("/surfaces/%d/icon", surfaceIndex), "surfaces[%d].icon %q is not present in package", surfaceIndex, icon)
	}
	if !hasRasterIconMagic(ext, content) {
		return validationErrorf(ValidationCodePackageInvalid, "icon_magic_mismatch", icon, fmt.Sprintf("/surfaces/%d/icon", surfaceIndex), "surfaces[%d].icon %q content does not match a supported raster image format", surfaceIndex, icon)
	}
	return nil
}

func validateSurfaceHTMLAsset(entryPath string, content []byte, files map[string][]byte) error {
	if err := validateNoServiceWorkerDependency(entryPath, content); err != nil {
		return err
	}
	_, err := BuildOpaqueSurfaceDocument(entryPath, func(assetPath string) (Asset, error) {
		assetContent, ok := files[assetPath]
		if !ok {
			return Asset{}, fmt.Errorf("missing package asset %q", assetPath)
		}
		entry, err := makeEntry(assetPath, assetContent)
		if err != nil {
			return Asset{}, err
		}
		return Asset{Entry: entry, Content: assetContent}, nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", entryPath, err)
	}
	return nil
}

func validateNoServiceWorkerDependency(entryPath string, content []byte) error {
	for _, pattern := range serviceWorkerDependencyPatterns {
		if pattern.Match(content) {
			return fmt.Errorf("%s: Service Worker registration APIs are not allowed in plugin package assets", entryPath)
		}
	}
	return nil
}

func resolvePackageRelativeAssetPath(baseDir string, rawPath string) (string, error) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || strings.HasPrefix(rawPath, "/") || strings.HasPrefix(rawPath, "//") || strings.ContainsAny(rawPath, "\\?#:\r\n\t\x00") {
		return "", fmt.Errorf("asset path %q must be a canonical package-local path", rawPath)
	}
	for _, part := range strings.Split(rawPath, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("asset path %q must be a canonical package-local path", rawPath)
		}
	}
	joined := path.Clean(path.Join(baseDir, rawPath))
	if joined == "." {
		return "", errors.New("asset path is empty")
	}
	return validatePackageAssetPath(joined)
}

func validatePackageAssetPath(entryPath string) (string, error) {
	if strings.ContainsAny(entryPath, "?#") {
		return "", validationErrorf(ValidationCodePackagePathForbidden, "query_or_fragment", entryPath, "", "entry %q must not include query or fragment", entryPath)
	}
	return validateEntryPath(entryPath)
}

func isHTMLURLAttribute(tag string, attr string) bool {
	switch attr {
	case "src", "href", "poster", "data", "action", "formaction", "cite", "background", "srcset":
		return true
	default:
		return false
	}
}

func nodeTextContent(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.TrimSpace(builder.String())
}

func isHTMLAsset(entryPath string) bool {
	ext := strings.ToLower(path.Ext(entryPath))
	return ext == ".html" || ext == ".htm"
}

func isScriptAsset(entryPath string) bool {
	ext := strings.ToLower(path.Ext(entryPath))
	return ext == ".js" || ext == ".mjs"
}

func hasRasterIconMagic(ext string, content []byte) bool {
	switch ext {
	case ".png":
		return bytes.HasPrefix(content, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	case ".jpg", ".jpeg":
		return len(content) >= 3 && content[0] == 0xff && content[1] == 0xd8 && content[2] == 0xff
	case ".gif":
		return bytes.HasPrefix(content, []byte("GIF87a")) || bytes.HasPrefix(content, []byte("GIF89a"))
	case ".webp":
		return len(content) >= 12 && bytes.Equal(content[0:4], []byte("RIFF")) && bytes.Equal(content[8:12], []byte("WEBP"))
	case ".ico":
		return len(content) >= 4 && content[0] == 0x00 && content[1] == 0x00 && content[2] == 0x01 && content[3] == 0x00
	default:
		return false
	}
}

type validatedWorkerABI struct {
	Exports map[string]struct{}
	Imports map[string]struct{}
}

func validateWorkerABIDescriptor(m manifest.Manifest, files map[string][]byte) (validatedWorkerABI, error) {
	if len(m.Workers) == 0 {
		return validatedWorkerABI{Exports: map[string]struct{}{}, Imports: map[string]struct{}{}}, nil
	}
	raw, ok := files[workerABIPath]
	if !ok {
		return validatedWorkerABI{}, fmt.Errorf("%s is required for packages with workers", workerABIPath)
	}
	var descriptor workerABIDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return validatedWorkerABI{}, fmt.Errorf("%s: %w", workerABIPath, err)
	}
	if descriptor.ABIVersion != "redevplugin-wasm-worker-v2" {
		return validatedWorkerABI{}, fmt.Errorf("%s: abi_version must be redevplugin-wasm-worker-v2", workerABIPath)
	}
	exports, err := validateWorkerABISet(workerABIPath, "exports", descriptor.Exports, allowedWorkerABIExports())
	if err != nil {
		return validatedWorkerABI{}, err
	}
	if len(exports) == 0 {
		return validatedWorkerABI{}, fmt.Errorf("%s: exports must not be empty", workerABIPath)
	}
	imports, err := validateWorkerABISet(workerABIPath, "imports", descriptor.Imports, allowedWorkerABIImports())
	if err != nil {
		return validatedWorkerABI{}, err
	}
	return validatedWorkerABI{Exports: exports, Imports: imports}, nil
}

func validateWorkerABISet(abiPath string, field string, values []string, allowed map[string]struct{}) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%s: %s[%d] is empty", abiPath, field, i)
		}
		if _, ok := allowed[value]; !ok {
			return nil, fmt.Errorf("%s: %s[%d] %q is not supported", abiPath, field, i, value)
		}
		if _, exists := out[value]; exists {
			return nil, fmt.Errorf("%s: %s[%d] %q is duplicated", abiPath, field, i, value)
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func allowedWorkerABIExports() map[string]struct{} {
	return map[string]struct{}{
		"redevplugin_worker_invoke": {},
	}
}

func allowedWorkerABIImports() map[string]struct{} {
	return map[string]struct{}{
		"redevplugin.storage": {},
		"redevplugin.network": {},
	}
}

const wasmPageBytes = 64 * 1024

type wasmFunctionType struct {
	Params  []byte
	Results []byte
}

type wasmImportFunction struct {
	Module    string
	Name      string
	TypeIndex uint32
}

type wasmExportDefinition struct {
	Kind  byte
	Index uint32
}

type wasmModuleContract struct {
	Types             []wasmFunctionType
	FunctionTypeIndex []uint32
	Imports           []wasmImportFunction
	ImportModules     map[string]struct{}
	Exports           map[string]wasmExportDefinition
	TableInitialSize  []uint32
	MemoryInitialPage []uint32
}

func (contract wasmModuleContract) FunctionExports() map[string]struct{} {
	exports := map[string]struct{}{}
	for name, definition := range contract.Exports {
		if definition.Kind == 0x00 {
			exports[name] = struct{}{}
		}
	}
	return exports
}

func inspectWASMModule(module []byte) (wasmModuleContract, error) {
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, module)
	if err != nil {
		return wasmModuleContract{}, fmt.Errorf("validate wasm module: %w", err)
	}
	defer compiled.Close(ctx)
	if len(module) < 8 {
		return wasmModuleContract{}, errors.New("wasm module is too short")
	}
	if !bytes.Equal(module[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return wasmModuleContract{}, errors.New("wasm magic header is invalid")
	}
	if !bytes.Equal(module[4:8], []byte{0x01, 0x00, 0x00, 0x00}) {
		return wasmModuleContract{}, errors.New("wasm version must be 1")
	}
	contract := wasmModuleContract{ImportModules: map[string]struct{}{}, Exports: map[string]wasmExportDefinition{}}
	offset := 8
	seenSections := map[byte]struct{}{}
	for offset < len(module) {
		sectionID := module[offset]
		offset++
		payloadLength, err := readWASMVarUint32(module, &offset)
		if err != nil {
			return wasmModuleContract{}, fmt.Errorf("section %d length: %w", sectionID, err)
		}
		payloadEnd := offset + int(payloadLength)
		if payloadEnd < offset || payloadEnd > len(module) {
			return wasmModuleContract{}, fmt.Errorf("section %d exceeds module size", sectionID)
		}
		if sectionID != 0 {
			if _, exists := seenSections[sectionID]; exists {
				return wasmModuleContract{}, fmt.Errorf("duplicate wasm section %d", sectionID)
			}
			seenSections[sectionID] = struct{}{}
		}
		payload := module[offset:payloadEnd]
		switch sectionID {
		case 1:
			contract.Types, err = readWASMTypeSection(payload)
		case 2:
			contract.Imports, contract.ImportModules, err = readWASMImportSection(payload)
		case 3:
			contract.FunctionTypeIndex, err = readWASMFunctionSection(payload)
		case 4:
			contract.TableInitialSize, err = readWASMTableSection(payload)
		case 5:
			contract.MemoryInitialPage, err = readWASMMemorySection(payload)
		case 7:
			contract.Exports, err = readWASMExportSection(payload)
		}
		if err != nil {
			return wasmModuleContract{}, fmt.Errorf("wasm section %d: %w", sectionID, err)
		}
		offset = payloadEnd
	}
	if offset != len(module) {
		return wasmModuleContract{}, errors.New("wasm section parsing ended outside module boundary")
	}
	for i, typeIndex := range contract.FunctionTypeIndex {
		if int(typeIndex) >= len(contract.Types) {
			return wasmModuleContract{}, fmt.Errorf("function[%d] references missing type %d", i, typeIndex)
		}
	}
	for i, imported := range contract.Imports {
		if int(imported.TypeIndex) >= len(contract.Types) {
			return wasmModuleContract{}, fmt.Errorf("import[%d] references missing type %d", i, imported.TypeIndex)
		}
	}
	return contract, nil
}

func validateWASMWorkerContract(contract wasmModuleContract, memoryLimitBytes int64) error {
	if len(contract.TableInitialSize) > 1 {
		return fmt.Errorf("worker must define at most one table, found %d", len(contract.TableInitialSize))
	}
	for i, initialElements := range contract.TableInitialSize {
		if initialElements > maxWASMTableElements {
			return fmt.Errorf("worker table[%d] initial size %d exceeds limit %d", i, initialElements, maxWASMTableElements)
		}
	}
	if len(contract.MemoryInitialPage) != 1 {
		return fmt.Errorf("worker must define exactly one linear memory, found %d", len(contract.MemoryInitialPage))
	}
	initialBytes := int64(contract.MemoryInitialPage[0]) * wasmPageBytes
	if initialBytes > memoryLimitBytes {
		return fmt.Errorf("worker initial memory %d exceeds manifest limit %d", initialBytes, memoryLimitBytes)
	}
	memoryExport, ok := contract.Exports["memory"]
	if !ok || memoryExport.Kind != 0x02 || memoryExport.Index != 0 {
		return errors.New("worker must export its only linear memory as \"memory\"")
	}
	required := map[string]wasmFunctionType{
		"redevplugin_worker_alloc":   {Params: []byte{0x7f}, Results: []byte{0x7f}},
		"redevplugin_worker_dealloc": {Params: []byte{0x7f, 0x7f}},
		"redevplugin_worker_invoke":  {Params: []byte{0x7f, 0x7f}, Results: []byte{0x7e}},
	}
	for name, signature := range required {
		actual, err := contract.exportedFunctionType(name)
		if err != nil {
			return err
		}
		if !sameWASMFunctionType(actual, signature) {
			return fmt.Errorf("worker export %q has an invalid function signature", name)
		}
	}
	allowedHostcalls := map[string]map[string]struct{}{
		"redevplugin.storage": {"files": {}, "kv": {}, "sqlite": {}},
		"redevplugin.network": {"execute": {}},
	}
	hostcallSignature := wasmFunctionType{Params: []byte{0x7f, 0x7f, 0x7f, 0x7f}, Results: []byte{0x7f}}
	for _, imported := range contract.Imports {
		functions, ok := allowedHostcalls[imported.Module]
		if !ok {
			return fmt.Errorf("worker import module %q is unsupported", imported.Module)
		}
		if _, ok := functions[imported.Name]; !ok {
			return fmt.Errorf("worker import %s/%s is unsupported", imported.Module, imported.Name)
		}
		if !sameWASMFunctionType(contract.Types[imported.TypeIndex], hostcallSignature) {
			return fmt.Errorf("worker import %s/%s has an invalid function signature", imported.Module, imported.Name)
		}
	}
	return nil
}

func (contract wasmModuleContract) exportedFunctionType(name string) (wasmFunctionType, error) {
	exported, ok := contract.Exports[name]
	if !ok || exported.Kind != 0x00 {
		return wasmFunctionType{}, fmt.Errorf("required function export %q is missing", name)
	}
	functionIndex := int(exported.Index)
	if functionIndex < len(contract.Imports) {
		return contract.Types[contract.Imports[functionIndex].TypeIndex], nil
	}
	definedIndex := functionIndex - len(contract.Imports)
	if definedIndex < 0 || definedIndex >= len(contract.FunctionTypeIndex) {
		return wasmFunctionType{}, fmt.Errorf("function export %q references missing function %d", name, exported.Index)
	}
	return contract.Types[contract.FunctionTypeIndex[definedIndex]], nil
}

func sameWASMFunctionType(left wasmFunctionType, right wasmFunctionType) bool {
	return bytes.Equal(left.Params, right.Params) && bytes.Equal(left.Results, right.Results)
}

func sameStringSet(left map[string]struct{}, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, ok := right[value]; !ok {
			return false
		}
	}
	return true
}

func readWASMTypeSection(section []byte) ([]wasmFunctionType, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, fmt.Errorf("type count: %w", err)
	}
	types := make([]wasmFunctionType, 0, count)
	for i := uint32(0); i < count; i++ {
		if offset >= len(section) || section[offset] != 0x60 {
			return nil, fmt.Errorf("type[%d] is not a function type", i)
		}
		offset++
		params, err := readWASMValueTypes(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("type[%d].params: %w", i, err)
		}
		results, err := readWASMValueTypes(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("type[%d].results: %w", i, err)
		}
		types = append(types, wasmFunctionType{Params: params, Results: results})
	}
	if offset != len(section) {
		return nil, errors.New("type section has trailing bytes")
	}
	return types, nil
}

func readWASMValueTypes(section []byte, offset *int) ([]byte, error) {
	count, err := readWASMVarUint32(section, offset)
	if err != nil {
		return nil, err
	}
	values := make([]byte, int(count))
	for i := range values {
		if *offset >= len(section) {
			return nil, errors.New("value type is missing")
		}
		value := section[*offset]
		*offset = *offset + 1
		if value != 0x7f && value != 0x7e && value != 0x7d && value != 0x7c && value != 0x70 && value != 0x6f {
			return nil, fmt.Errorf("unsupported value type 0x%x", value)
		}
		values[i] = value
	}
	return values, nil
}

func readWASMImportSection(section []byte) ([]wasmImportFunction, map[string]struct{}, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, nil, fmt.Errorf("import count: %w", err)
	}
	imports := make([]wasmImportFunction, 0, count)
	modules := map[string]struct{}{}
	for i := uint32(0); i < count; i++ {
		module, err := readWASMName(section, &offset)
		if err != nil {
			return nil, nil, fmt.Errorf("import[%d].module: %w", i, err)
		}
		name, err := readWASMName(section, &offset)
		if err != nil {
			return nil, nil, fmt.Errorf("import[%d].name: %w", i, err)
		}
		if offset >= len(section) || section[offset] != 0x00 {
			return nil, nil, fmt.Errorf("import[%d] must be a function", i)
		}
		offset++
		typeIndex, err := readWASMVarUint32(section, &offset)
		if err != nil {
			return nil, nil, fmt.Errorf("import[%d].type: %w", i, err)
		}
		imports = append(imports, wasmImportFunction{Module: module, Name: name, TypeIndex: typeIndex})
		modules[module] = struct{}{}
	}
	if offset != len(section) {
		return nil, nil, errors.New("import section has trailing bytes")
	}
	return imports, modules, nil
}

func readWASMFunctionSection(section []byte) ([]uint32, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, fmt.Errorf("function count: %w", err)
	}
	types := make([]uint32, 0, count)
	for i := uint32(0); i < count; i++ {
		typeIndex, err := readWASMVarUint32(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("function[%d].type: %w", i, err)
		}
		types = append(types, typeIndex)
	}
	if offset != len(section) {
		return nil, errors.New("function section has trailing bytes")
	}
	return types, nil
}

func readWASMTableSection(section []byte) ([]uint32, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, fmt.Errorf("table count: %w", err)
	}
	initialSizes := make([]uint32, 0, count)
	for i := uint32(0); i < count; i++ {
		if offset >= len(section) || (section[offset] != 0x70 && section[offset] != 0x6f) {
			return nil, fmt.Errorf("table[%d] reference type is unsupported", i)
		}
		offset++
		flags, err := readWASMVarUint32(section, &offset)
		if err != nil || flags > 1 {
			return nil, fmt.Errorf("table[%d] limits are unsupported", i)
		}
		minimum, err := readWASMVarUint32(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("table[%d].minimum: %w", i, err)
		}
		if flags == 1 {
			maximum, err := readWASMVarUint32(section, &offset)
			if err != nil || maximum < minimum {
				return nil, fmt.Errorf("table[%d].maximum is invalid", i)
			}
		}
		initialSizes = append(initialSizes, minimum)
	}
	if offset != len(section) {
		return nil, errors.New("table section has trailing bytes")
	}
	return initialSizes, nil
}

func readWASMMemorySection(section []byte) ([]uint32, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, fmt.Errorf("memory count: %w", err)
	}
	initialPages := make([]uint32, 0, count)
	for i := uint32(0); i < count; i++ {
		flags, err := readWASMVarUint32(section, &offset)
		if err != nil || flags > 1 {
			return nil, fmt.Errorf("memory[%d] limits are unsupported", i)
		}
		minimum, err := readWASMVarUint32(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("memory[%d].minimum: %w", i, err)
		}
		if flags == 1 {
			maximum, err := readWASMVarUint32(section, &offset)
			if err != nil || maximum < minimum {
				return nil, fmt.Errorf("memory[%d].maximum is invalid", i)
			}
		}
		initialPages = append(initialPages, minimum)
	}
	if offset != len(section) {
		return nil, errors.New("memory section has trailing bytes")
	}
	return initialPages, nil
}

func readWASMExportSection(section []byte) (map[string]wasmExportDefinition, error) {
	offset := 0
	count, err := readWASMVarUint32(section, &offset)
	if err != nil {
		return nil, fmt.Errorf("export count: %w", err)
	}
	exports := map[string]wasmExportDefinition{}
	for i := uint32(0); i < count; i++ {
		name, err := readWASMName(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("export[%d].name: %w", i, err)
		}
		if offset >= len(section) {
			return nil, fmt.Errorf("export[%d].kind is missing", i)
		}
		kind := section[offset]
		offset++
		index, err := readWASMVarUint32(section, &offset)
		if err != nil {
			return nil, fmt.Errorf("export[%d].index: %w", i, err)
		}
		if kind > 0x04 {
			return nil, fmt.Errorf("export[%d].kind is unsupported", i)
		}
		if _, exists := exports[name]; exists {
			return nil, fmt.Errorf("export[%d].name %q is duplicated", i, name)
		}
		exports[name] = wasmExportDefinition{Kind: kind, Index: index}
	}
	if offset != len(section) {
		return nil, errors.New("export section has trailing bytes")
	}
	return exports, nil
}

func readWASMName(section []byte, offset *int) (string, error) {
	length, err := readWASMVarUint32(section, offset)
	if err != nil {
		return "", err
	}
	end := *offset + int(length)
	if end < *offset || end > len(section) {
		return "", errors.New("name exceeds section")
	}
	value := section[*offset:end]
	*offset = end
	if !utf8.Valid(value) {
		return "", errors.New("name is not UTF-8")
	}
	return string(value), nil
}

func readWASMVarUint32(data []byte, offset *int) (uint32, error) {
	var value uint32
	for shift := uint(0); shift <= 28; shift += 7 {
		if *offset >= len(data) {
			return 0, errors.New("unexpected end of data")
		}
		b := data[*offset]
		*offset = *offset + 1
		if shift == 28 && b&0xf0 != 0 {
			return 0, errors.New("varuint32 exceeds 32 bits")
		}
		value |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("varuint32 exceeds 32 bits")
}

func makeEntry(entryPath string, content []byte) (Entry, error) {
	if _, err := validateEntryPath(entryPath); err != nil {
		return Entry{}, err
	}
	sum := sha256.Sum256(content)
	return Entry{
		Path:        entryPath,
		Size:        int64(len(content)),
		SHA256:      "sha256:" + hex.EncodeToString(sum[:]),
		Mode:        "0644",
		ContentType: contentType(entryPath, content),
	}, nil
}

func canonicalHashes(entries []Entry, manifestHash string) (entriesHash string, packageHash string, err error) {
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		return "", "", err
	}
	entriesSum := sha256.Sum256(entriesJSON)
	packageInput := struct {
		ManifestSHA256 string  `json:"manifest_sha256"`
		EntriesSHA256  string  `json:"entries_sha256"`
		Entries        []Entry `json:"entries"`
	}{
		ManifestSHA256: manifestHash,
		EntriesSHA256:  "sha256:" + hex.EncodeToString(entriesSum[:]),
		Entries:        entries,
	}
	packageJSON, err := json.Marshal(packageInput)
	if err != nil {
		return "", "", err
	}
	packageSum := sha256.Sum256(packageJSON)
	return "sha256:" + hex.EncodeToString(entriesSum[:]), "sha256:" + hex.EncodeToString(packageSum[:]), nil
}

func sha256String(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func parsePackageSignature(signatureFiles map[string][]byte, m manifest.Manifest, manifestHash string, entriesHash string, packageHash string) (*PackageSignature, error) {
	if len(signatureFiles) == 0 {
		return nil, nil
	}
	raw, ok := signatureFiles[PackageSignaturePath]
	if !ok {
		return nil, fmt.Errorf("%s is required when signature files are present", PackageSignaturePath)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var sig PackageSignature
	if err := decoder.Decode(&sig); err != nil {
		return nil, fmt.Errorf("%s: %w", PackageSignaturePath, err)
	}
	if sig.SchemaVersion != PackageSignatureSchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schema_version %q", PackageSignaturePath, sig.SchemaVersion)
	}
	if sig.Algorithm != PackageSignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("%s: unsupported algorithm %q", PackageSignaturePath, sig.Algorithm)
	}
	if strings.TrimSpace(sig.KeyID) == "" {
		return nil, fmt.Errorf("%s: key_id is required", PackageSignaturePath)
	}
	if strings.TrimSpace(sig.Signature) == "" {
		return nil, fmt.Errorf("%s: signature is required", PackageSignaturePath)
	}
	if sig.PublisherID != "" && sig.PublisherID != m.Publisher.PublisherID {
		return nil, fmt.Errorf("%s: publisher_id mismatch", PackageSignaturePath)
	}
	if sig.PluginID != "" && sig.PluginID != m.PluginID() {
		return nil, fmt.Errorf("%s: plugin_id mismatch", PackageSignaturePath)
	}
	if sig.ManifestHash != manifestHash {
		return nil, fmt.Errorf("%s: manifest_hash mismatch", PackageSignaturePath)
	}
	if sig.EntriesHash != entriesHash {
		return nil, fmt.Errorf("%s: entries_hash mismatch", PackageSignaturePath)
	}
	if sig.PackageHash != packageHash {
		return nil, fmt.Errorf("%s: package_hash mismatch", PackageSignaturePath)
	}
	return &sig, nil
}

func marshalPackageSignature(sig PackageSignature) ([]byte, error) {
	if sig.SchemaVersion == "" {
		sig.SchemaVersion = PackageSignatureSchemaVersion
	}
	return json.Marshal(sig)
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
}

func sortedFilePaths(files map[string][]byte) []string {
	paths := make([]string, 0, len(files))
	for entryPath := range files {
		paths = append(paths, entryPath)
	}
	sort.Strings(paths)
	return paths
}

func cloneFiles(files map[string][]byte) map[string][]byte {
	if files == nil {
		return nil
	}
	cloned := make(map[string][]byte, len(files))
	for entryPath, content := range files {
		cloned[entryPath] = append([]byte(nil), content...)
	}
	return cloned
}

func contentType(entryPath string, content []byte) string {
	if entryPath == "manifest.json" || strings.HasSuffix(entryPath, ".json") {
		return "application/json"
	}
	if detected := http.DetectContentType(content); detected == "image/png" || detected == "image/jpeg" || detected == "image/gif" || detected == "image/webp" {
		return detected
	}
	if ext := path.Ext(entryPath); ext != "" {
		if detected := mime.TypeByExtension(ext); detected != "" {
			return detected
		}
	}
	return "application/octet-stream"
}
