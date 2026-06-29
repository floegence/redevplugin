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
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
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
	MaxCompressionRatio  int64 `json:"max_compression_ratio"`
}

const PackageSignaturePath = "signatures/package.sig"

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

	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return Package{}, errors.New("manifest.json is required")
	}
	decodedManifest, err := manifest.Decode(bytes.NewReader(manifestBytes))
	if err != nil {
		return Package{}, fmt.Errorf("manifest.json: %w", err)
	}
	if err := validateManifestArtifacts(decodedManifest, files); err != nil {
		return Package{}, err
	}

	entries := make([]Entry, 0, len(files))
	for entryPath, content := range files {
		entry, err := makeEntry(entryPath, content)
		if err != nil {
			return Package{}, err
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)

	canonicalManifest, err := canonicalJSON(decodedManifest)
	if err != nil {
		return Package{}, err
	}
	manifestHash := sha256String(canonicalManifest)
	entriesHash, packageHash, err := canonicalHashes(entries, manifestHash)
	if err != nil {
		return Package{}, err
	}
	packageSignature, err := parsePackageSignature(signatureFiles, decodedManifest, manifestHash, entriesHash, packageHash)
	if err != nil {
		return Package{}, err
	}

	zipWriter := zip.NewWriter(w)
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			_ = zipWriter.Close()
			return Package{}, ctx.Err()
		default:
		}
		header := &zip.FileHeader{
			Name:   entry.Path,
			Method: zip.Deflate,
		}
		header.SetMode(0o644)
		header.SetModTime(deterministicModTime)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			_ = zipWriter.Close()
			return Package{}, err
		}
		if _, err := writer.Write(files[entry.Path]); err != nil {
			_ = zipWriter.Close()
			return Package{}, err
		}
	}
	signaturePaths := sortedFilePaths(signatureFiles)
	for _, entryPath := range signaturePaths {
		select {
		case <-ctx.Done():
			_ = zipWriter.Close()
			return Package{}, ctx.Err()
		default:
		}
		header := &zip.FileHeader{
			Name:   entryPath,
			Method: zip.Deflate,
		}
		header.SetMode(0o644)
		header.SetModTime(deterministicModTime)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			_ = zipWriter.Close()
			return Package{}, err
		}
		if _, err := writer.Write(signatureFiles[entryPath]); err != nil {
			_ = zipWriter.Close()
			return Package{}, err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return Package{}, err
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

func Read(ctx context.Context, r io.ReaderAt, size int64, opts ReadOptions) (Package, error) {
	if opts == (ReadOptions{}) {
		opts = DefaultReadOptions()
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return Package{}, err
	}
	if opts.MaxFiles > 0 && len(zr.File) > opts.MaxFiles {
		return Package{}, fmt.Errorf("too many files: %d > %d", len(zr.File), opts.MaxFiles)
	}

	files := map[string][]byte{}
	signatureFiles := map[string][]byte{}
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
		if _, ok := files[entryPath]; ok {
			return Package{}, fmt.Errorf("duplicate entry %q", entryPath)
		}
		if file.FileInfo().Mode()&fs.ModeSymlink != 0 {
			return Package{}, fmt.Errorf("symlink entry %q is not allowed", entryPath)
		}
		if strings.HasSuffix(entryPath, "/") {
			return Package{}, fmt.Errorf("directory entry %q is not allowed", entryPath)
		}
		if opts.MaxEntryBytes > 0 && int64(file.UncompressedSize64) > opts.MaxEntryBytes {
			return Package{}, fmt.Errorf("entry %q too large", entryPath)
		}
		if opts.MaxCompressionRatio > 0 && file.CompressedSize64 > 0 && int64(file.UncompressedSize64/file.CompressedSize64) > opts.MaxCompressionRatio {
			return Package{}, fmt.Errorf("entry %q compression ratio exceeds limit", entryPath)
		}
		total += int64(file.UncompressedSize64)
		if opts.MaxUncompressedBytes > 0 && total > opts.MaxUncompressedBytes {
			return Package{}, fmt.Errorf("package too large")
		}
		rc, err := file.Open()
		if err != nil {
			return Package{}, err
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, int64(file.UncompressedSize64)+1))
		closeErr := rc.Close()
		if readErr != nil {
			return Package{}, readErr
		}
		if closeErr != nil {
			return Package{}, closeErr
		}
		if uint64(len(content)) != file.UncompressedSize64 {
			return Package{}, fmt.Errorf("entry %q size mismatch", entryPath)
		}
		if strings.HasPrefix(entryPath, "signatures/") {
			if entryPath != PackageSignaturePath {
				return Package{}, fmt.Errorf("unsupported signature entry %q", entryPath)
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
		return Package{}, errors.New("manifest.json is required")
	}
	decodedManifest, err := manifest.Decode(bytes.NewReader(manifestBytes))
	if err != nil {
		return Package{}, fmt.Errorf("manifest.json: %w", err)
	}
	if err := validateManifestArtifacts(decodedManifest, files); err != nil {
		return Package{}, err
	}
	entries := make([]Entry, 0, len(files))
	for entryPath, content := range files {
		entry, err := makeEntry(entryPath, content)
		if err != nil {
			return Package{}, err
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)
	canonicalManifest, err := canonicalJSON(decodedManifest)
	if err != nil {
		return Package{}, err
	}
	manifestHash := sha256String(canonicalManifest)
	entriesHash, packageHash, err := canonicalHashes(entries, manifestHash)
	if err != nil {
		return Package{}, err
	}
	packageSignature, err := parsePackageSignature(signatureFiles, decodedManifest, manifestHash, entriesHash, packageHash)
	if err != nil {
		return Package{}, err
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
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink entry %q is not allowed", entryPath)
		}
		if d.IsDir() {
			return nil
		}
		if opts.MaxFiles > 0 && len(files)+1 > opts.MaxFiles {
			return fmt.Errorf("too many files")
		}
		if opts.MaxEntryBytes > 0 && info.Size() > opts.MaxEntryBytes {
			return fmt.Errorf("entry %q too large", entryPath)
		}
		total += info.Size()
		if opts.MaxUncompressedBytes > 0 && total > opts.MaxUncompressedBytes {
			return fmt.Errorf("package too large")
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if strings.HasPrefix(entryPath, "signatures/") {
			if entryPath != PackageSignaturePath {
				return fmt.Errorf("unsupported signature entry %q", entryPath)
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
		return "", errors.New("empty entry path")
	}
	if strings.Contains(entryPath, "\\") {
		return "", fmt.Errorf("entry %q must use slash separators", entryPath)
	}
	clean := path.Clean(entryPath)
	if clean == "." || clean != entryPath {
		return "", fmt.Errorf("entry %q is not canonical", entryPath)
	}
	if path.IsAbs(entryPath) || strings.HasPrefix(entryPath, "../") || strings.Contains(entryPath, "/../") || entryPath == ".." {
		return "", fmt.Errorf("entry %q escapes package root", entryPath)
	}
	if strings.HasPrefix(entryPath, ".") || strings.Contains(entryPath, "/.") {
		return "", fmt.Errorf("hidden entry %q is not allowed", entryPath)
	}
	return entryPath, nil
}

func validateManifestArtifacts(m manifest.Manifest, files map[string][]byte) error {
	for i, worker := range m.Workers {
		artifact, err := validateEntryPath(worker.Artifact)
		if err != nil {
			return fmt.Errorf("workers[%d].artifact: %w", i, err)
		}
		if _, ok := files[artifact]; !ok {
			return fmt.Errorf("workers[%d].artifact %q is not present in package", i, artifact)
		}
	}
	return nil
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
		ContentType: contentType(entryPath),
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
	if sig.SchemaVersion != "redevplugin.package_signature.v1" {
		return nil, fmt.Errorf("%s: unsupported schema_version %q", PackageSignaturePath, sig.SchemaVersion)
	}
	if strings.TrimSpace(sig.Algorithm) == "" {
		return nil, fmt.Errorf("%s: algorithm is required", PackageSignaturePath)
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

func contentType(entryPath string) string {
	if entryPath == "manifest.json" || strings.HasSuffix(entryPath, ".json") {
		return "application/json"
	}
	if ext := path.Ext(entryPath); ext != "" {
		if detected := mime.TypeByExtension(ext); detected != "" {
			return detected
		}
	}
	return "application/octet-stream"
}
