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

type Package struct {
	Manifest          manifest.Manifest `json:"manifest"`
	PackageHash       string            `json:"package_hash"`
	ManifestHash      string            `json:"manifest_hash"`
	CanonicalManifest string            `json:"canonical_manifest"`
	Entries           []Entry           `json:"entries"`
	EntriesHash       string            `json:"entries_hash"`
}

type ReadOptions struct {
	MaxUncompressedBytes int64 `json:"max_uncompressed_bytes"`
	MaxFiles             int   `json:"max_files"`
	MaxEntryBytes        int64 `json:"max_entry_bytes"`
	MaxCompressionRatio  int64 `json:"max_compression_ratio"`
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
	files, err := collectFiles(srcDir, opts)
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
		if strings.HasPrefix(entryPath, "signatures/") {
			continue
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
		files[entryPath] = content
	}

	return packageFromFiles(files)
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

func packageFromFiles(files map[string][]byte) (Package, error) {
	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return Package{}, errors.New("manifest.json is required")
	}
	decodedManifest, err := manifest.Decode(bytes.NewReader(manifestBytes))
	if err != nil {
		return Package{}, fmt.Errorf("manifest.json: %w", err)
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
	return Package{
		Manifest:          decodedManifest,
		PackageHash:       packageHash,
		ManifestHash:      manifestHash,
		CanonicalManifest: string(canonicalManifest),
		Entries:           entries,
		EntriesHash:       entriesHash,
	}, nil
}

func collectFiles(srcDir string, opts ReadOptions) (map[string][]byte, error) {
	files := map[string][]byte{}
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
		if strings.HasPrefix(entryPath, "signatures/") {
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
		files[entryPath] = content
		return nil
	})
	return files, err
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

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
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
